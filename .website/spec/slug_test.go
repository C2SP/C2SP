package spec

import "testing"

func TestSlugger(t *testing.T) {
	// Expected values verified against GitHub's rendering of the C2SP specs.
	tests := []struct {
		text, want string
	}{
		{"The Tagged Recipient Types", "the-tagged-recipient-types"},
		{"keyed_hash of Multiple Chunks", "keyed_hash-of-multiple-chunks"},
		{"2.2. Initial Value (IV)", "22-initial-value-iv"},
		{"Appendix A — Security Analysis of Reusing a Witness Key",
			"appendix-a--security-analysis-of-reusing-a-witness-key"},
		{"Phase 1 [client, uni-directional]", "phase-1-client-uni-directional"},
		{"Phase 1 [client, uni-directional]", "phase-1-client-uni-directional-1"},
		{"Phase 1 [client, uni-directional]", "phase-1-client-uni-directional-2"},
		{"éxample Ünicode", "éxample-ünicode"},
	}
	var s Slugger
	for _, tt := range tests {
		if got := s.Slug(tt.text); got != tt.want {
			t.Errorf("Slug(%q) = %q, want %q", tt.text, got, tt.want)
		}
	}
}
