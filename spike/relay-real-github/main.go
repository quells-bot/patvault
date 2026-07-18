// Command relay-real-github is a THROWAWAY probe closing the last two of
// patvault's relay §"Unverified assumptions". This program covers the
// status→message half: it issues smart-HTTP advertisement GETs against real
// GitHub and reports the observed HTTP status for the accessible repo, a
// nonexistent repo, and a no-access repo. It is READ-ONLY — it writes nothing.
//
// The other half (GitHub accepting a chunked git-receive-pack body) is confirmed
// by the manual real-relay push in this slice's run procedure, not here, so this
// probe never has to build a packfile.
//
// Run (use a PRIVATE SPIKE_REPO — a public repo serves the advertisement
// unauthenticated and the observations prove nothing):
//
//	SPIKE_TOKEN=<fine-grained PAT> SPIKE_REPO=owner/repo go run ./spike/relay-real-github
//
// Optional observations, each skipped if its env var is unset:
//
//	SPIKE_MISSING_REPO=owner/does-not-exist-xyz   # the "nonexistent -> ?" question
//	SPIKE_NOACCESS_REPO=owner/other-private       # a real repo the token is NOT scoped to
//	SPIKE_READONLY_TOKEN=<read-only PAT>          # receive-pack adv under a read-only token
package main

import (
	"fmt"
	"net/http"
	"os"
)

// gitEndpoint is GitHub's smart-HTTP Git base for a repo.
func gitEndpoint(repo string) string { return "https://github.com/" + repo + ".git" }

// advStatus issues the smart-HTTP advertisement GET for service against repo
// under token (empty token = unauthenticated) and returns the HTTP status.
// Basic auth, not Bearer — GitHub's Git transport takes Basic (v2/push spikes).
func advStatus(repo, service, token string) (int, error) {
	url := gitEndpoint(repo) + "/info/refs?service=" + service
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	if token != "" {
		req.SetBasicAuth("x-access-token", token)
	}
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("User-Agent", "git/2.43.0")
	req.Header.Set("Accept", "application/x-"+service+"-advertisement")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

type observation struct {
	label  string
	status int
}

func main() {
	token := os.Getenv("SPIKE_TOKEN")
	repo := os.Getenv("SPIKE_REPO")
	if token == "" || repo == "" {
		fmt.Fprintln(os.Stderr, "set SPIKE_TOKEN=<fine-grained PAT> and SPIKE_REPO=owner/repo (private)")
		os.Exit(2)
	}

	var obs []observation
	record := func(label, repo, service, tok string) {
		st, err := advStatus(repo, service, tok)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %s: request error: %v\n", label, err)
			os.Exit(1)
		}
		obs = append(obs, observation{label, st})
	}

	// Sanity: the token reads its own repo (expect 200), and unauthenticated is
	// refused (expect 401 — the fail-before-first-byte trigger point).
	record("authed upload-pack (accessible repo)", repo, "git-upload-pack", token)
	record("unauth upload-pack (accessible repo)", repo, "git-upload-pack", "")

	// The actionable status→message questions.
	if missing := os.Getenv("SPIKE_MISSING_REPO"); missing != "" {
		record("authed upload-pack (nonexistent repo)", missing, "git-upload-pack", token)
	}
	if noaccess := os.Getenv("SPIKE_NOACCESS_REPO"); noaccess != "" {
		record("authed upload-pack (no-access repo)", noaccess, "git-upload-pack", token)
	}

	// Insufficient-scope maps to the auth row: a read-only token on the
	// receive-pack advertisement. The accessible-repo receive-pack adv under the
	// main token is the 200 baseline for comparison.
	record("authed receive-pack (accessible repo)", repo, "git-receive-pack", token)
	if ro := os.Getenv("SPIKE_READONLY_TOKEN"); ro != "" {
		record("read-only token receive-pack (accessible repo)", repo, "git-receive-pack", ro)
	}

	fmt.Println("\n=== observed statuses (paste into the findings note) ===")
	for _, o := range obs {
		fmt.Printf("  %-48s %d\n", o.label, o.status)
	}
	fmt.Println("\nInterpretation guide (drives Task 3 reconciliation):")
	fmt.Println("  authed 200 + unauth 401            -> happy path + fail-before-first-byte confirmed")
	fmt.Println("  nonexistent 404 AND no-access 404  -> classifyStatus 404->errGitHubNotFound correct as-is")
	fmt.Println("  no-access 403 (not 404)            -> no-access hits the AUTH row; Task 3 branch C decides wording")
	fmt.Println("  read-only receive-pack 403         -> insufficient-scope -> errGitHubAuth (correct)")
}
