package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"breachpilot/internal/models"
)

func TestStateManager(t *testing.T) {
	tempDir := t.TempDir()
	jobID := "test-job-id"
	job := &models.Job{ID: jobID, Target: "example.com", Mode: "full"}

	// 1. Creation
	jobDir := filepath.Join(tempDir, jobID)
	sm, err := NewStateManager(jobDir, job)
	if err != nil {
		t.Fatalf("failed to create state manager: %v", err)
	}

	statePath := filepath.Join(jobDir, StateFile)
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		t.Fatalf("expected state file at %s but not found", statePath)
	}

	// 2. Mark Recon
	if sm.IsReconCompleted() {
		t.Fatalf("expected recon not completed initially")
	}
	expectedReconPath := "/tmp/recon/summary.json"
	if err := sm.MarkReconCompleted(expectedReconPath); err != nil {
		t.Fatalf("failed to mark recon completed: %v", err)
	}
	if !sm.IsReconCompleted() {
		t.Fatalf("expected recon marked as completed")
	}
	if sm.State().ReconPath != expectedReconPath {
		t.Fatalf("expected recon path %s but got %s", expectedReconPath, sm.State().ReconPath)
	}

	// 3. Mark Nuclei
	if err := sm.MarkNucleiCompleted(); err != nil {
		t.Fatalf("failed to mark nuclei completed: %v", err)
	}
	if !sm.IsNucleiCompleted() {
		t.Fatalf("expected nuclei marked as completed")
	}

	// 4. Mark Modules
	if sm.IsModuleCompleted("test-module") {
		t.Fatalf("expected module not completed initially")
	}
	if err := sm.MarkModuleCompleted("test-module"); err != nil {
		t.Fatalf("failed to mark module completed: %v", err)
	}
	if !sm.IsModuleCompleted("test-module") {
		t.Fatalf("expected module marked as completed")
	}

	// 5. Reload from disk
	sm2, err := NewStateManager(jobDir, job)
	if err != nil {
		t.Fatalf("failed to reload state manager: %v", err)
	}

	if !sm2.IsReconCompleted() {
		t.Fatalf("reloaded state lost recon completion")
	}
	if sm2.State().ReconPath != expectedReconPath {
		t.Fatalf("reloaded state lost recon path: expected %s, got %s", expectedReconPath, sm2.State().ReconPath)
	}
	if !sm2.IsNucleiCompleted() {
		t.Fatalf("reloaded state lost nuclei completion")
	}
	if !sm2.IsModuleCompleted("test-module") {
		t.Fatalf("reloaded state lost module completion")
	}

	// Verify JSON structure on disk directly
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("failed to read written JSON: %v", err)
	}
	var state models.JobState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("failed to unmarshal written JSON: %v", err)
	}
	if state.JobID != jobID {
		t.Fatalf("unexpected job id in json: %v", state.JobID)
	}
	if state.Target != "example.com" {
		t.Fatalf("unexpected target in state: %v", state.Target)
	}

	// 6. Test NewStateManagerFromPath
	sm3, err := NewStateManagerFromPath(statePath)
	if err != nil {
		t.Fatalf("failed to load state from path: %v", err)
	}
	if !sm3.IsReconCompleted() {
		t.Fatalf("state loaded from path lost recon completion")
	}
}

func TestStateManagerRecoversFromBackupWhenPrimaryCorrupt(t *testing.T) {
	tempDir := t.TempDir()
	job := &models.Job{ID: "recover-job", Target: "example.com", Mode: "full"}
	jobDir := filepath.Join(tempDir, job.ID)

	sm, err := NewStateManager(jobDir, job)
	if err != nil {
		t.Fatalf("failed to create state manager: %v", err)
	}
	if err := sm.MarkReconCompleted("/tmp/recon/summary.json"); err != nil {
		t.Fatalf("mark recon completed: %v", err)
	}
	if err := sm.MarkModuleCompleted("dom-xss"); err != nil {
		t.Fatalf("mark module completed: %v", err)
	}

	statePath := filepath.Join(jobDir, StateFile)
	backupPath := statePath + stateBackupSuffix
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("expected backup state file at %s: %v", backupPath, err)
	}

	if err := os.WriteFile(statePath, []byte("{corrupt-json"), 0o644); err != nil {
		t.Fatalf("failed to corrupt primary state file: %v", err)
	}

	loaded, err := NewStateManagerFromPath(statePath)
	if err != nil {
		t.Fatalf("expected recovery from backup, got error: %v", err)
	}
	if !loaded.IsReconCompleted() {
		t.Fatalf("recovered state missing recon completion")
	}
	if !loaded.IsModuleCompleted("dom-xss") {
		t.Fatalf("recovered state missing completed module")
	}
}

func TestStateManagerConcurrentModuleMarksPersistAll(t *testing.T) {
	tempDir := t.TempDir()
	job := &models.Job{ID: "concurrency-job", Target: "example.com", Mode: "full"}
	jobDir := filepath.Join(tempDir, job.ID)

	sm, err := NewStateManager(jobDir, job)
	if err != nil {
		t.Fatalf("failed to create state manager: %v", err)
	}

	const total = 30
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sm.MarkModuleCompleted("m" + strconv.Itoa(i))
		}()
	}
	wg.Wait()

	statePath := filepath.Join(jobDir, StateFile)
	reloaded, err := NewStateManagerFromPath(statePath)
	if err != nil {
		t.Fatalf("failed to reload state: %v", err)
	}
	if len(reloaded.State().ModulesFinished) != total {
		t.Fatalf("expected %d completed modules, got %d", total, len(reloaded.State().ModulesFinished))
	}
	for i := 0; i < total; i++ {
		name := "m" + strconv.Itoa(i)
		if !reloaded.IsModuleCompleted(name) {
			t.Fatalf("missing completed module %s after concurrent writes", name)
		}
	}
}
