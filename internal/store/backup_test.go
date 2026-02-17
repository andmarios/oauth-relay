package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockS3 implements S3Client in-memory.
type mockS3 struct {
	mu      sync.Mutex
	objects map[string][]byte // "bucket/key" → data
}

func newMockS3() *mockS3 {
	return &mockS3{objects: make(map[string][]byte)}
}

func (m *mockS3) Upload(_ context.Context, bucket, key string, body io.Reader) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[bucket+"/"+key] = data
	return nil
}

func (m *mockS3) Download(_ context.Context, bucket, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		return nil, fmt.Errorf("not found: %s/%s", bucket, key)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *mockS3) Delete(_ context.Context, bucket, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, bucket+"/"+key)
	return nil
}

func (m *mockS3) get(bucket, key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[bucket+"/"+key]
	return data, ok
}

func TestBackupRunOnce(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	// Insert some data to back up
	s.CreateUser(ctx, &User{ID: "u1", Email: "a@b.com", Name: "A", Role: "user"})

	s3 := newMockS3()
	mgr := NewBackupManager(s, s3, BackupConfig{
		Bucket:     "test-bucket",
		Prefix:     "backups/",
		Interval:   time.Hour,
		InstanceID: "inst-1",
	})

	if err := mgr.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// Verify DB was uploaded
	data, ok := s3.get("test-bucket", "backups/relay.db")
	if !ok {
		t.Fatal("backup file not found in S3")
	}
	if len(data) == 0 {
		t.Error("backup file is empty")
	}

	// Verify lock was written
	lockData, ok := s3.get("test-bucket", "backups/lock.json")
	if !ok {
		t.Fatal("lock file not found in S3")
	}
	var lock lockEntry
	if err := json.Unmarshal(lockData, &lock); err != nil {
		t.Fatalf("parse lock: %v", err)
	}
	if lock.InstanceID != "inst-1" {
		t.Errorf("lock instance = %q, want inst-1", lock.InstanceID)
	}
}

func TestBackupLockContention(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()
	s3 := newMockS3()

	// Simulate another instance holding the lock with a fresh heartbeat
	otherLock, _ := json.Marshal(lockEntry{
		InstanceID: "other-instance",
		Heartbeat:  time.Now().UTC(),
	})
	s3.Upload(ctx, "test-bucket", "backups/lock.json", strings.NewReader(string(otherLock)))

	mgr := NewBackupManager(s, s3, BackupConfig{
		Bucket:     "test-bucket",
		Prefix:     "backups/",
		Interval:   time.Hour,
		InstanceID: "inst-1",
	})

	err := mgr.RunOnce(ctx)
	if err == nil {
		t.Fatal("expected error due to lock contention")
	}
	if !strings.Contains(err.Error(), "lock held by") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBackupStaleLockTakeover(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()
	s.CreateUser(ctx, &User{ID: "u1", Email: "a@b.com", Name: "A", Role: "user"})

	s3 := newMockS3()

	// Simulate a stale lock (heartbeat 10 minutes ago)
	staleLock, _ := json.Marshal(lockEntry{
		InstanceID: "dead-instance",
		Heartbeat:  time.Now().UTC().Add(-10 * time.Minute),
	})
	s3.Upload(ctx, "test-bucket", "backups/lock.json", strings.NewReader(string(staleLock)))

	mgr := NewBackupManager(s, s3, BackupConfig{
		Bucket:     "test-bucket",
		Prefix:     "backups/",
		Interval:   time.Hour,
		InstanceID: "inst-1",
	})

	// Should succeed — stale lock gets taken over
	if err := mgr.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// Verify lock now belongs to us
	lockData, _ := s3.get("test-bucket", "backups/lock.json")
	var lock lockEntry
	json.Unmarshal(lockData, &lock)
	if lock.InstanceID != "inst-1" {
		t.Errorf("lock instance = %q, want inst-1", lock.InstanceID)
	}
}

func TestBackupReleaseLock(t *testing.T) {
	s := newTestSQLite(t)
	s3 := newMockS3()

	mgr := NewBackupManager(s, s3, BackupConfig{
		Bucket:     "test-bucket",
		Prefix:     "backups/",
		InstanceID: "inst-1",
	})

	// Write a lock then release it
	mgr.writeHeartbeat(context.Background())
	if _, ok := s3.get("test-bucket", "backups/lock.json"); !ok {
		t.Fatal("lock should exist before release")
	}

	mgr.releaseLock(context.Background())
	if _, ok := s3.get("test-bucket", "backups/lock.json"); ok {
		t.Error("lock should be deleted after release")
	}
}
