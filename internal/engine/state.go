package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"breachpilot/internal/models"
)

// StateFile is the name of the state checkpoint inside a job directory.
const StateFile = ".breachpilot.state"
const stateBackupSuffix = ".bak"
const stateTempSuffix = ".tmp"

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

	var state models.JobState
	loadedFrom, err := sm.loadStateWithRecovery(&state)
	if err != nil {
		return err
	}

	state.ModulesFinished = normalizeModulesList(state.ModulesFinished)
	sm.state = state
	sm.modulesSet = make(map[string]struct{}, len(state.ModulesFinished))
	for _, m := range state.ModulesFinished {
		sm.modulesSet[m] = struct{}{}
	}

	// If recovery succeeded from backup/temp, immediately re-seal the primary file.
	if loadedFrom != sm.path {
		if err := sm.saveLocked(); err != nil {
			return fmt.Errorf("state recovered from %s but failed to rewrite primary: %w", loadedFrom, err)
		}
	}
	return nil
}

// Save writes the current state to disk.
func (sm *StateManager) Save() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.saveLocked()
}

// MarkReconCompleted flags the recon phase as finished.
func (sm *StateManager) MarkReconCompleted(reconPath string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state.ReconCompleted = true
	sm.state.ReconPath = reconPath
	return sm.saveLocked()
}

// MarkNucleiCompleted flags the nuclei phase as finished.
func (sm *StateManager) MarkNucleiCompleted() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state.NucleiCompleted = true
	return sm.saveLocked()
}

// SetNucleiResumeCfg saves the path to the nuclei resume.cfg file
func (sm *StateManager) SetNucleiResumeCfg(cfgPath string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state.NucleiResumeCfg = cfgPath
	return sm.saveLocked()
}

// MarkModuleCompleted flags a specific custom module as finished.
func (sm *StateManager) MarkModuleCompleted(moduleName string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.modulesSet == nil {
		sm.modulesSet = make(map[string]struct{})
	}
	if _, exists := sm.modulesSet[moduleName]; !exists {
		sm.modulesSet[moduleName] = struct{}{}
		sm.state.ModulesFinished = append(sm.state.ModulesFinished, moduleName)
	}
	return sm.saveLocked()
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

func (sm *StateManager) loadStateWithRecovery(dst *models.JobState) (string, error) {
	candidates := []string{
		sm.path,
		sm.path + stateBackupSuffix,
		sm.path + stateTempSuffix,
	}

	type parseFailure struct {
		path string
		err  error
	}
	failures := make([]parseFailure, 0, len(candidates))
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			failures = append(failures, parseFailure{path: p, err: err})
			continue
		}
		if err := json.Unmarshal(b, dst); err != nil {
			failures = append(failures, parseFailure{path: p, err: err})
			continue
		}
		if strings.TrimSpace(dst.JobID) == "" {
			failures = append(failures, parseFailure{path: p, err: fmt.Errorf("missing job_id")})
			continue
		}
		return p, nil
	}

	if len(failures) == 0 {
		return "", os.ErrNotExist
	}
	last := failures[len(failures)-1]
	return "", fmt.Errorf("state file unreadable (last candidate %s): %w", last.path, last.err)
}

func normalizeModulesList(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func (sm *StateManager) saveLocked() error {
	sm.state.LastUpdatedAt = time.Now().UTC().Format(time.RFC3339)
	sm.state.ModulesFinished = normalizeModulesList(sm.state.ModulesFinished)

	data, err := json.MarshalIndent(sm.state, "", "  ")
	if err != nil {
		return err
	}

	// Keep backup aligned with the latest committed snapshot so recovery preserves progress.
	if err := writeFileWithSync(sm.path+stateBackupSuffix, data, 0o644); err != nil {
		return fmt.Errorf("write state backup: %w", err)
	}

	tmp := sm.path + stateTempSuffix
	if err := writeFileWithSync(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, sm.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename state temp file: %w", err)
	}
	if err := syncParentDir(sm.path); err != nil {
		return err
	}
	return nil
}

func writeFileWithSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func syncParentDir(path string) error {
	dir := filepath.Dir(path)
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer df.Close()
	return df.Sync()
}
