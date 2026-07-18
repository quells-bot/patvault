package commands

import "strings"

// patPrefixes are GitHub's token-type prefixes, longest first so github_pat_
// matches before any shorter prefix. Fine-grained tokens (github_pat_) are the
// first-class case, so we must not stop at the first underscore.
var patPrefixes = []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

// tokenType classifies a PAT by its prefix, returning the prefix label without
// the trailing underscore (e.g. "github_pat"), or "" if unrecognized. Runs only
// at write time to populate the stored token_type column.
func tokenType(pat string) string {
	for _, p := range patPrefixes {
		if strings.HasPrefix(pat, p) {
			return strings.TrimSuffix(p, "_")
		}
	}
	return ""
}
