package urlparse

import "testing"

func TestNormalizePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"owner/repo", "owner/repo"},
		{"owner/repo.git", "owner/repo"},
		{"owner/repo/", "owner/repo"},
		{"owner/repo.git/", "owner/repo"},
		{"owner/repo/.git", "owner/repo"},
		{"OWNER/Repo", "OWNER/Repo"}, // case preserved
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizePath(c.in); got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseRepoURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		host    string
		path    string
		wantErr bool
	}{
		{"plain", "https://github.com/quells-bot/patvault", "github.com", "quells-bot/patvault", false},
		{"with git", "https://github.com/quells-bot/patvault.git", "github.com", "quells-bot/patvault", false},
		{"trailing slash", "https://github.com/quells-bot/patvault/", "github.com", "quells-bot/patvault", false},
		{"wrong scheme", "http://github.com/owner/repo", "", "", true},
		{"missing path", "https://github.com", "", "", true},
		{"garbage", "://not a url", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, path, err := ParseRepoURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr {
				if host != tc.host || path != tc.path {
					t.Errorf("got host=%q path=%q, want host=%q path=%q", host, path, tc.host, tc.path)
				}
			}
		})
	}
}
