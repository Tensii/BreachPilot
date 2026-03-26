package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"breachpilot/internal/models"
)

// StateFile is the name of the state checkpoint inside a job directory.
const StateFile = ".breachpilot.state"

// StateManager persists the execution state of a job to allow resumption.
type StateManager struct {
	path       string
	state      models.JobState
	modulesSet map[string]struct{}
	mu         sync.Mutex
}

// NewStateManager creates or loads a state manager for a job directory.
func NewStateManager(jobDir string, job *models.Job) (*StateManager, error) {
	if jobDir == "" {
		return nil, fmt.Errorf("jobDir is required")
	}
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create job dir: %w", err)
	}

	sm := &StateManager{
		path: filepath.Join(jobDir, StateFile),
		state: models.JobState{
			JobID:           job.ID,
			Target:          job.Target,
			Mode:            job.Mode,
			ReconPath:       job.ReconPath,
			StartedAt:       time.Now().UTC().Format(time.RFC3339),
			ModulesFinished: []string{},
		},
		modulesSet: make(map[string]struct{}),
	}

	// Try to load existing state
	if err := sm.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load existing state: %w", err)
	}

	// Save initial state if it didn't exist
	if err := sm.Save(); err != nil {
		return nil, fmt.Errorf("failed to save initial state: %w", err)
	}

	return sm, nil
}

// NewStateManagerFromPath loads an existing state from a .breachpilot.state file.
func NewStateManagerFromPath(statePath string) (*StateManager, error) {
	sm := &StateManager{
		path:       statePath,
		modulesSet: make(map[string]struct{}),
	}
	if err := sm.Load(); err != nil {
		return nil, fmt.Errorf("failed to load state from %s: %w", statePath, err)
	}
	return sm, nil
}

// Load reads the state from disk.
func (sm *StateManager) Load() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	data, err := os.ReadFile(sm.path)
	if err != nil {
		return err
	}

	var state models.JobState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	if state.ModulesFinished == nil {
		state.ModulesFinished = []string{}
	}
	sm.state = state
	sm.modulesSet = make(map[string]struct{}, len(state.ModulesFinished))
	for _, m := range state.ModulesFinished {
		sm.modulesSet[m] = struct{}{}
	}
	return nil
}

// Save writes the current state to disk.
func (sm *StateManager) Save() error {
	// Marshal under the lock for a consistent snapshot, then release before disk I/O.
	sm.mu.Lock()
	sm.state.LastUpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(sm.state, "", "  ")
	sm.mu.Unlock()
	if err != nil {
		return err
	}

	// Always use atomic temp-file swap to prevent partial writes on crash.
	tmp := sm.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, sm.path)
}

// MarkReconCompleted flags the recon phase as finished.
func (sm *StateManager) MarkReconCompleted(reconPath string) error {
	sm.mu.Lock()
	sm.state.ReconCompleted = true
	sm.state.ReconPath = reconPath
	sm.mu.Unlock()
	return sm.Save()
}

// MarkNucleiCompleted flags the nuclei phase as finished.
func (sm *StateManager) MarkNucleiCompleted() error {
	sm.mu.Lock()
	sm.state.NucleiCompleted = true
	sm.mu.Unlock()
	return sm.Save()
}

// MarkModuleCompleted flags a specific custom module as finished.
func (sm *StateManager) MarkModuleCompleted(moduleName string) error {
	sm.mu.Lock()
	if sm.modulesSet == nil {
		sm.modulesSet = make(map[string]struct{})
	}
	if _, exists := sm.modulesSet[moduleName]; !exists {
		sm.modulesSet[moduleName] = struct{}{}
		sm.state.ModulesFinished = append(sm.state.ModulesFinished, moduleName)
	}
	sm.mu.Unlock()
	return sm.Save()
}

// IsReconCompleted returns true if recon is fully completed.
func (sm *StateManager) IsReconCompleted() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.state.ReconCompleted
}

// IsNucleiCompleted returns true if nuclei is fully completed.
func (sm *StateManager) IsNucleiCompleted() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.state.NucleiCompleted
}

// IsModuleCompleted returns true if the specific module is completed.
func (sm *StateManager) IsModuleCompleted(moduleName string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	_, ok := sm.modulesSet[moduleName]
	return ok
}

// State returns a copy of the current job state.
func (sm *StateManager) State() models.JobState {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.state
}
