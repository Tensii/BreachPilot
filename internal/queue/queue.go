package queue

import (
	"context"
	"errors"
	"log"
	"sync"

	"breachpilot/internal/engine"
	"breachpilot/internal/models"
	"breachpilot/internal/notify"
	"breachpilot/internal/store"
)

type Manager struct {
	ch       chan *models.Job
	jobs     map[string]*models.Job
	running  map[string]context.CancelFunc
	mu       sync.RWMutex
	engOpt   engine.Options
	notifier *notify.Webhook
	store    *store.SQLiteStore
}

func New(size int, engOpt engine.Options, notifier *notify.Webhook, st *store.SQLiteStore) *Manager {
	return &Manager{
		ch:       make(chan *models.Job, size),
		jobs:     make(map[string]*models.Job),
		running:  make(map[string]context.CancelFunc),
		engOpt:   engOpt,
		notifier: notifier,
		store:    st,
	}
}

func (m *Manager) StartWorkers(n int) {
	for i := 0; i < n; i++ {
		go func(id int) {
			for job := range m.ch {
				if job.Status == models.JobCancelled {
					continue
				}
				ctx, cancel := context.WithCancel(context.Background())
				m.mu.Lock()
				m.running[job.ID] = cancel
				m.mu.Unlock()
				m.persist(job)

				if m.notifier != nil {
					m.notifier.Send("job.started", job)
				}
				if err := engine.Process(ctx, job, m.engOpt); err != nil {
					job.Status = models.JobFailed
					job.Error = err.Error()
					if m.notifier != nil {
						m.notifier.Send("job.failed", job)
					}
				} else {
					switch job.Status {
					case models.JobRejected:
						if m.notifier != nil {
							m.notifier.Send("job.rejected", job)
						}
					case models.JobCancelled:
						if m.notifier != nil {
							m.notifier.Send("job.cancelled", job)
						}
					default:
						if m.notifier != nil {
							m.notifier.Send("job.completed", job)
						}
					}
				}
				m.mu.Lock()
				delete(m.running, job.ID)
				m.jobs[job.ID] = job
				m.mu.Unlock()
				m.persist(job)
				log.Printf("worker=%d job=%s status=%s findings=%d", id, job.ID, job.Status, job.FindingsCount)
			}
		}(i + 1)
	}
}

func (m *Manager) Enqueue(job *models.Job) error {
	if job == nil {
		return errors.New("job is nil")
	}
	if target := job.Target; target != "" {
		if m.hasActiveTarget(target) {
			return errors.New("target already has active job")
		}
	}
	m.mu.Lock()
	m.jobs[job.ID] = job
	m.mu.Unlock()
	m.persist(job)
	m.ch <- job
	return nil
}

func (m *Manager) hasActiveTarget(target string) bool {
	m.mu.RLock()
	for _, j := range m.jobs {
		if j.Target == target && (j.Status == models.JobQueued || j.Status == models.JobRunning) {
			m.mu.RUnlock()
			return true
		}
	}
	m.mu.RUnlock()
	if m.store != nil {
		ok, err := m.store.HasActiveTarget(target)
		return err == nil && ok
	}
	return false
}

func (m *Manager) Get(id string) (*models.Job, bool) {
	m.mu.RLock()
	j, ok := m.jobs[id]
	m.mu.RUnlock()
	if ok {
		return j, true
	}
	if m.store != nil {
		j2, err := m.store.Get(id)
		if err == nil && j2 != nil {
			return j2, true
		}
	}
	return nil, false
}

func (m *Manager) Cancel(id string) (*models.Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		if m.store != nil {
			if sj, err := m.store.Get(id); err == nil && sj != nil {
				j = sj
				ok = true
			}
		}
		if !ok {
			return nil, false
		}
	}
	if j.Status == models.JobDone || j.Status == models.JobFailed || j.Status == models.JobRejected || j.Status == models.JobCancelled {
		return j, true
	}
	j.Status = models.JobCancelled
	j.Error = "cancel requested"
	if cancel, exists := m.running[id]; exists {
		cancel()
	}
	m.jobs[id] = j
	m.persist(j)
	return j, true
}

func (m *Manager) persist(job *models.Job) {
	if m.store != nil {
		_ = m.store.Upsert(job)
	}
}
