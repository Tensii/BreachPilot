package ingest

import "testing"

func TestTargetFromWorkdir(t *testing.T) {
	tests := []struct {
		name    string
		workdir string
		want    string
	}{
		{
			name:    "artifacts host and port",
			workdir: "artifacts/example.com_8080/1/recon",
			want:    "example.com:8080",
		},
		{
			name:    "outputs ip and port",
			workdir: "outputs/127.0.0.1_3001/1",
			want:    "127.0.0.1:3001",
		},
		{
			name:    "sanitized path segment not reversed",
			workdir: "artifacts/example.com_api_v1/2/recon",
			want:    "example.com_api_v1",
		},
		{
			name:    "no outputs or artifacts marker returns empty",
			workdir: "/tmp/random/recon",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TargetFromWorkdir(tt.workdir)
			if got != tt.want {
				t.Fatalf("TargetFromWorkdir(%q)=%q want=%q", tt.workdir, got, tt.want)
			}
		})
	}
}
