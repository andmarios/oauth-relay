package store

import (
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

const lockStaleTimeout = 5 * time.Minute

// BackupManager handles periodic SQLite backups to S3.
type BackupManager struct {
	db      *SQLiteStore
	s3      S3Client
	cfg     BackupConfig
	lockKey string
	dbKey   string
}

// NewBackupManager creates a new backup manager.
func NewBackupManager(db *SQLiteStore, s3 S3Client, cfg BackupConfig) *BackupManager {
	return &BackupManager{
		db:      db,
		s3:      s3,
		cfg:     cfg,
		lockKey: cfg.Prefix + "lock.json",
		dbKey:   cfg.Prefix + "relay.db",
	}
}

// Run starts the periodic backup loop. It blocks until the context is cancelled.
func (m *BackupManager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Release lock on shutdown
			m.releaseLock(context.Background())
			return
		case <-ticker.C:
			if err := m.RunOnce(ctx); err != nil {
				log.Printf("backup: %v", err)
			}
		}
	}
}

// RunOnce performs a single backup cycle: acquire lock, checkpoint WAL, copy DB, upload.
func (m *BackupManager) RunOnce(ctx context.Context) error {
	if err := m.acquireLock(ctx); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}

	// Checkpoint WAL to ensure all writes are flushed
	if _, err := m.db.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("wal checkpoint: %w", err)
	}

	// Copy the database file to a temp file for upload
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

	// Update heartbeat
	if err := m.writeHeartbeat(ctx); err != nil {
		log.Printf("backup heartbeat: %v", err)
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
		return m.writeHeartbeat(ctx)
	}

	return fmt.Errorf("lock held by instance %q (heartbeat %s)", lock.InstanceID, lock.Heartbeat.Format(time.RFC3339))
}

func (m *BackupManager) writeHeartbeat(ctx context.Context) error {
	data, _ := json.Marshal(lockEntry{
		InstanceID: m.cfg.InstanceID,
		Heartbeat:  time.Now().UTC(),
	})

	r, w := io.Pipe()
	go func() {
		w.Write(data)
		w.Close()
	}()

	return m.s3.Upload(ctx, m.cfg.Bucket, m.lockKey, r)
}

func (m *BackupManager) releaseLock(ctx context.Context) {
	if err := m.s3.Delete(ctx, m.cfg.Bucket, m.lockKey); err != nil {
		log.Printf("backup: release lock: %v", err)
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
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	return out.Close()
}
