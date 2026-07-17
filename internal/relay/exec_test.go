package relay

import (
	"slices"
	"testing"
)

func TestSplitWords(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		// The four exec strings spike/relay-ssh recorded from git 2.53.0.
		{
			name: "suffixed path",
			in:   `git-upload-pack '/owner/repo.git'`,
			want: []string{"git-upload-pack", "/owner/repo.git"},
		},
		{
			name: "unsuffixed path",
			in:   `git-upload-pack '/owner/repo'`,
			want: []string{"git-upload-pack", "/owner/repo"},
		},
		{
			name: "space survives inside quotes",
			in:   `git-upload-pack '/owner/my repo.git'`,
			want: []string{"git-upload-pack", "/owner/my repo.git"},
		},
		{
			// The case a first-and-last-quote strip gets wrong: it would
			// yield /owner/it'\''s.git.
			name: "apostrophe is POSIX-escaped",
			in:   `git-upload-pack '/owner/it'\''s.git'`,
			want: []string{"git-upload-pack", "/owner/it's.git"},
		},
		{
			name: "push exec",
			in:   `git-receive-pack '/owner/repo.git'`,
			want: []string{"git-receive-pack", "/owner/repo.git"},
		},

		{name: "unquoted", in: `git-upload-pack /owner/repo`, want: []string{"git-upload-pack", "/owner/repo"}},
		{name: "runs of whitespace", in: "  a \t\t b  ", want: []string{"a", "b"}},
		{name: "empty", in: ``, want: nil},
		{name: "only whitespace", in: `   `, want: nil},
		{name: "empty quoted word", in: `a '' b`, want: []string{"a", "", "b"}},
		{name: "double quotes", in: `a "b c"`, want: []string{"a", "b c"}},
		{name: "escape inside double quotes", in: `a "b\"c"`, want: []string{"a", `b"c`}},
		{name: "non-escape inside double quotes", in: `a "b\nc"`, want: []string{"a", `b\nc`}},
		{name: "backslash escape outside quotes", in: `a b\ c`, want: []string{"a", "b c"}},
		{name: "adjacent runs concatenate", in: `pre'mid'post`, want: []string{"premidpost"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitWords(tc.in)
			if err != nil {
				t.Fatalf("splitWords(%q): %v", tc.in, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("splitWords(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSplitWordsErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"unterminated single quote", `git-upload-pack '/owner/repo`},
		{"unterminated double quote", `git-upload-pack "/owner/repo`},
		{"trailing backslash", `git-upload-pack /owner/repo\`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := splitWords(tc.in); err == nil {
				t.Errorf("splitWords(%q) = nil error, want error", tc.in)
			}
		})
	}
}
