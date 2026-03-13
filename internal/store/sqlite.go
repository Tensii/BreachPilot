package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"breachpilot/internal/models"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &SQLiteStore{db: db}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) init() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  target TEXT,
  status TEXT,
  created_at TEXT,
  updated_at TEXT,
  payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_target_status ON jobs(target, status);
`)
	return err
}

func (s *SQLiteStore) Upsert(job *models.Job) error {
	if job == nil {
		return nil
	}
	b, _ := json.Marshal(job)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
INSERT INTO jobs(id,target,status,created_at,updated_at,payload)
VALUES(?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET target=excluded.target,status=excluded.status,updated_at=excluded.updated_at,payload=excluded.payload
`, job.ID, job.Target, string(job.Status), job.CreatedAt.Format(time.RFC3339), now, string(b))
	return err
}

func (s *SQLiteStore) Get(id string) (*models.Job, error) {
	var payload string
	err := s.db.QueryRow(`SELECT payload FROM jobs WHERE id=?`, id).Scan(&payload)
	if err != nil {
		return nil, err
	}
	var j models.Job
	if err := json.Unmarshal([]byte(payload), &j); err != nil {
		return nil, err
	}
	return &j, nil
}

func (s *SQLiteStore) HasActiveTarget(target string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM jobs WHERE target=? AND status IN ('queued','running')`, target).Scan(&n)
	return n > 0, err
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) Health() error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}
	return s.db.Ping()
}
