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

// StateManager persists the execution state of a job to allow resumption.
type StateManager struct {
	path  string
	state models.JobState
	mu    sync.Mutex
}

// NewStateManager creates or loads a state manager.
func NewStateManager(artifactsRoot, jobID string) (*StateManager, error) {
	if artifactsRoot == "" || jobID == "" {
		return nil, fmt.Errorf("artifactsRoot and jobID are required")
	}
	dir := filepath.Join(artifactsRoot, jobID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create artifacts dir: %w", err)
	}

	sm := &StateManager{
		path: filepath.Join(dir, ".breachpilot_state.json"),
		state: models.JobState{
			JobID:           jobID,
			StartedAt:       time.Now().UTC().Format(time.RFC3339),
			ModulesFinished: []string{},
		},
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
	return nil
}

// Save writes the current state to disk.
func (sm *StateManager) Save() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.state.LastUpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(sm.state, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(sm.path, data, 0644)
	if err != nil {
		// Try temp file swap for atomic write
		tmp := sm.path + ".tmp"
		if err := os.WriteFile(tmp, data, 0644); err == nil {
			return os.Rename(tmp, sm.path)
		}
	}
	return err
}

// MarkReconCompleted flags the recon phase as finished.
func (sm *StateManager) MarkReconCompleted() error {
	sm.mu.Lock()
	sm.state.ReconCompleted = true
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
	found := false
	for _, m := range sm.state.ModulesFinished {
		if m == moduleName {
			found = true
			break
		}
	}
	if !found {
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
	for _, m := range sm.state.ModulesFinished {
		if m == moduleName {
			return true
		}
	}
	return false
}
