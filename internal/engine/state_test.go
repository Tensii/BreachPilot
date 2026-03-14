package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	if err := sm.MarkReconCompleted(); err != nil {
		t.Fatalf("failed to mark recon completed: %v", err)
	}
	if !sm.IsReconCompleted() {
		t.Fatalf("expected recon marked as completed")
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
