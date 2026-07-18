package commands

import "testing"

func TestTokenType(t *testing.T) {
	cases := map[string]string{
		"github_pat_abc123": "github_pat",
		"ghp_abc123":        "ghp",
		"gho_abc123":        "gho",
		"ghs_abc123":        "ghs",
		"random-token":      "",
		"":                  "",
	}
	for in, want := range cases {
		if got := tokenType(in); got != want {
			t.Errorf("tokenType(%q) = %q, want %q", in, got, want)
		}
	}
}
