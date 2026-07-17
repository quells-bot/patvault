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

func TestParseExecAccepts(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantOp   string
		wantRepo string
	}{
		// Spike-recorded shapes.
		{"fetch, suffixed", `git-upload-pack '/owner/repo.git'`, opFetch, "owner/repo"},
		{"fetch, unsuffixed", `git-upload-pack '/owner/repo'`, opFetch, "owner/repo"},
		{"push, suffixed", `git-receive-pack '/owner/repo.git'`, opPush, "owner/repo"},

		// The spec's other legitimate inputs: git echoes the user's remote
		// URL path, so any of these can arrive.
		{"no leading slash", `git-upload-pack 'owner/repo'`, opFetch, "owner/repo"},
		{"trailing slash", `git-upload-pack '/owner/repo/'`, opFetch, "owner/repo"},
		{"suffix and trailing slash", `git-upload-pack '/owner/repo.git/'`, opFetch, "owner/repo"},
		{"unquoted", `git-upload-pack /owner/repo.git`, opFetch, "owner/repo"},

		{"case is preserved", `git-upload-pack '/Owner/Repo.git'`, opFetch, "Owner/Repo"},
		{"hyphens, underscores, dots", `git-upload-pack '/my-org/my_repo.js.git'`, opFetch, "my-org/my_repo.js"},
		{"digits", `git-upload-pack '/owner2/repo2.git'`, opFetch, "owner2/repo2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op, repo, err := parseExec(tc.in)
			if err != nil {
				t.Fatalf("parseExec(%q): %v", tc.in, err)
			}
			if op != tc.wantOp {
				t.Errorf("op = %q, want %q", op, tc.wantOp)
			}
			if repo != tc.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tc.wantRepo)
			}
		})
	}
}

func TestParseExecRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		// Command allowlist. git-upload-archive is rejected on purpose: it
		// would expose git archive --remote through the relay.
		{"upload-archive", `git-upload-archive '/owner/repo.git'`},
		{"shell", ``},
		{"shell command", `bash -c 'id'`},
		{"bare binary", `sh`},
		{"space form, not the hyphen form git sends", `git upload-pack '/owner/repo'`},
		{"unknown command", `scp -t /tmp/x`},
		{"no path", `git-upload-pack`},
		{"extra argument", `git-upload-pack '/owner/repo' --stateless-rpc`},

		// Shape check.
		{"traversal", `git-upload-pack '/../../etc/passwd'`},
		{"traversal inside", `git-upload-pack '/owner/../../etc'`},
		{"extra segments", `git-upload-pack '/owner/repo/extra'`},
		{"single segment", `git-upload-pack '/repo.git'`},
		{"empty owner", `git-upload-pack '//repo.git'`},
		{"empty path", `git-upload-pack ''`},
		{"dot repo", `git-upload-pack '/owner/.'`},
		{"dotdot repo", `git-upload-pack '/owner/..'`},

		// Not GitHub repo names; the last two are the spike-recorded paths
		// whose quoting Task 3 pins.
		{"space in name", `git-upload-pack '/owner/my repo.git'`},
		{"apostrophe in name", `git-upload-pack '/owner/it'\''s.git'`},
		{"query string", `git-upload-pack '/owner/repo?x=1'`},
		{"host injection", `git-upload-pack '/owner/repo@evil.example'`},
		{"colon in name", `git-upload-pack '/owner/repo:x'`},

		// Unparseable.
		{"unterminated quote", `git-upload-pack '/owner/repo`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op, repo, err := parseExec(tc.in)
			if err == nil {
				t.Fatalf("parseExec(%q) = (%q, %q, nil), want error", tc.in, op, repo)
			}
			if op != "" || repo != "" {
				t.Errorf("on error got (%q, %q), want empty strings", op, repo)
			}
		})
	}
}
