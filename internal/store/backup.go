package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// S3Client abstracts the S3 operations needed for backup.
type S3Client interface {
	Upload(ctx context.Context, bucket, key string, body io.Reader) error
	Download(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, bucket, key string) error
	Exists(ctx context.Context, bucket, key string) (bool, error)
}

// BackupConfig holds configuration for S3 backups.
type BackupConfig struct {
	Bucket     string
	Prefix     string
	Interval   time.Duration
	InstanceID string
}

// lockEntry represents a distributed lock in S3.
type lockEntry struct {
	InstanceID string    `json:"instance_id"`
	Heartbeat  time.Time `json:"heartbeat"`
}

const (
	lockStaleTimeout  = 5 * time.Minute
	heartbeatInterval = 1 * time.Minute
)

// BackupManager handles periodic SQLite backups to S3 with distributed locking,
// restore-on-startup, heartbeat, file change detection, and final backup on shutdown.
type BackupManager struct {
	db      *SQLiteStore
	s3      S3Client
	cfg     BackupConfig
	lockKey string
	dbKey   string
	done    chan struct{} // closed when Run() finishes (after final backup + lock release)
}

// NewBackupManager creates a new backup manager. The manager does not hold a reference
// to the SQLite store until SetStore is called (since restore happens before DB open).
func NewBackupManager(s3 S3Client, cfg BackupConfig) *BackupManager {
	return &BackupManager{
		s3:      s3,
		cfg:     cfg,
		lockKey: cfg.Prefix + "lock.json",
		dbKey:   cfg.Prefix + "relay.db",
		done:    make(chan struct{}),
	}
}

// Wait blocks until Run() has completed its shutdown (final backup + lock release).
// Must be called after Run() has been started in a goroutine.
func (m *BackupManager) Wait() {
	<-m.done
}

// SetStore sets the SQLite store reference. Must be called after the database is opened
// and before Run() is started.
func (m *BackupManager) SetStore(db *SQLiteStore) {
	m.db = db
}

// AcquireLock acquires the distributed lock in S3.
// Must be called before Restore or Run.
func (m *BackupManager) AcquireLock(ctx context.Context) error {
	return m.acquireLock(ctx)
}

// Restore checks if a backup exists in S3 and restores it to the local database path.
// Should be called BEFORE the database is opened. Returns true if a backup was restored.
func (m *BackupManager) Restore(ctx context.Context, dbPath string) (bool, error) {
	exists, err := m.s3.Exists(ctx, m.cfg.Bucket, m.dbKey)
	if err != nil {
		return false, fmt.Errorf("check backup: %w", err)
	}
	if !exists {
		log.Printf("backup: no existing backup found at s3://%s/%s", m.cfg.Bucket, m.dbKey)
		return false, nil
	}

	log.Printf("backup: found existing backup at s3://%s/%s, restoring...", m.cfg.Bucket, m.dbKey)

	rc, err := m.s3.Download(ctx, m.cfg.Bucket, m.dbKey)
	if err != nil {
		return false, fmt.Errorf("download backup: %w", err)
	}
	defer rc.Close()

	// Ensure parent directory exists
	if err = os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return false, fmt.Errorf("create db dir: %w", err)
	}

	data, err := io.ReadAll(rc)
	if err != nil {
		return false, fmt.Errorf("read backup: %w", err)
	}

	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		return false, fmt.Errorf("write db file: %w", err)
	}

	log.Printf("backup: restored %d bytes to %s", len(data), dbPath)
	return true, nil
}

// StartHeartbeat starts a goroutine that periodically updates the lock heartbeat.
// Blocks until ctx is cancelled.
func (m *BackupManager) StartHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.writeHeartbeat(ctx); err != nil {
				log.Printf("backup: heartbeat: %v", err)
			}
		}
	}
}

// Run starts the periodic backup loop. It blocks until the context is cancelled.
// On shutdown, it performs a final backup and releases the lock, then signals
// completion via the done channel (see Wait).
func (m *BackupManager) Run(ctx context.Context) {
	if m.db == nil {
		log.Fatal("backup: Run called before SetStore")
	}
	defer close(m.done)

	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()

	var lastModTime time.Time

	for {
		select {
		case <-ctx.Done():
			// Final backup before shutdown (use fresh context)
			log.Printf("backup: performing final backup before shutdown")
			if err := m.backupDB(context.Background()); err != nil {
				log.Printf("backup: final backup failed: %v", err)
			} else {
				log.Printf("backup: final backup completed")
			}
			m.releaseLock(context.Background())
			return

		case <-ticker.C:
			// Only backup if the database file has been modified
			stat, err := os.Stat(m.db.path)
			if err != nil {
				log.Printf("backup: stat db: %v", err)
				continue
			}
			if !stat.ModTime().After(lastModTime) {
				continue
			}

			if err := m.backupDB(ctx); err != nil {
				log.Printf("backup: %v", err)
			} else {
				lastModTime = stat.ModTime()
			}
		}
	}
}

// backupDB performs a single backup: checkpoint WAL, copy DB, upload to S3, update heartbeat.
func (m *BackupManager) backupDB(ctx context.Context) error {
	if err := m.acquireLock(ctx); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}

	// Checkpoint WAL to ensure all writes are flushed to the main DB file
	if _, err := m.db.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("wal checkpoint: %w", err)
	}

	// Copy the database file to a temp file for upload (avoids holding a read lock)
	dbPath := m.db.path
	tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("backup-%s.db", m.cfg.InstanceID))
	if err := copyFile(dbPath, tmpPath); err != nil {
		return fmt.Errorf("copy db: %w", err)
	}
	defer os.Remove(tmpPath)

	f, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer f.Close()

	if err := m.s3.Upload(ctx, m.cfg.Bucket, m.dbKey, f); err != nil {
		return fmt.Errorf("upload: %w", err)
	}

	// Update heartbeat after successful backup
	if err := m.writeHeartbeat(ctx); err != nil {
		log.Printf("backup: heartbeat: %v", err)
	}

	log.Printf("backup: uploaded to s3://%s/%s", m.cfg.Bucket, m.dbKey)
	return nil
}

// acquireLock uses a best-effort distributed lock via S3. This is NOT strictly
// safe against concurrent writes — two instances may both take a stale lock.
// In the worst case, two backups run simultaneously, which is harmless.
func (m *BackupManager) acquireLock(ctx context.Context) error {
	rc, err := m.s3.Download(ctx, m.cfg.Bucket, m.lockKey)
	if err != nil {
		// No lock exists — take it
		return m.writeHeartbeat(ctx)
	}
	defer rc.Close()

	var lock lockEntry
	if err := json.NewDecoder(rc).Decode(&lock); err != nil {
		// Corrupted lock — take it
		return m.writeHeartbeat(ctx)
	}

	// If the lock is ours or stale, take it
	if lock.InstanceID == m.cfg.InstanceID || time.Since(lock.Heartbeat) > lockStaleTimeout {
		if lock.InstanceID != m.cfg.InstanceID {
			log.Printf("backup: taking over stale lock from instance %q (last heartbeat %s)",
				lock.InstanceID, lock.Heartbeat.Format(time.RFC3339))
		}
		return m.writeHeartbeat(ctx)
	}

	return fmt.Errorf("lock held by instance %q (heartbeat %s)", lock.InstanceID, lock.Heartbeat.Format(time.RFC3339))
}

func (m *BackupManager) writeHeartbeat(ctx context.Context) error {
	data, _ := json.Marshal(lockEntry{
		InstanceID: m.cfg.InstanceID,
		Heartbeat:  time.Now().UTC(),
	})

	return m.s3.Upload(ctx, m.cfg.Bucket, m.lockKey, bytes.NewReader(data))
}

func (m *BackupManager) releaseLock(ctx context.Context) {
	if err := m.s3.Delete(ctx, m.cfg.Bucket, m.lockKey); err != nil {
		log.Printf("backup: release lock: %v", err)
	} else {
		log.Printf("backup: lock released")
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
