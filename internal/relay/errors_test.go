package relay

import (
	"testing"
	"time"
)

// Each case is a row of the base spec's §"Errors and exit codes" table, with the
// message copied from the spec rather than paraphrased: the wording is the
// contract, because it is what tells the agent whether retrying can help.
func TestRelayErrorTable(t *testing.T) {
	tests := []struct {
		name      string
		err       *relayError
		want      string
		exit      uint32
		retryable bool
	}{
		{
			name:      "expired PAT",
			err:       errExpiredPAT("owner/repo", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)),
			want:      "patvault: token for github.com/owner/repo expired 2026-07-01; run 'patvault add' on the host to refresh — this will not succeed until then",
			exit:      1,
			retryable: false,
		},
		{
			name:      "no PAT",
			err:       errNoPAT("owner/repo"),
			want:      "patvault: no token stored for github.com/owner/repo; run 'patvault add' on the host — this will not succeed until then",
			exit:      1,
			retryable: false,
		},
		{
			name:      "fetch without protocol v2",
			err:       errNotV2(),
			want:      "patvault: relay requires git wire protocol v2; run 'git config --global protocol.version 2' (default since git 2.26)",
			exit:      1,
			retryable: false,
		},
		{
			name:      "disallowed exec",
			err:       errDisallowedExec(),
			want:      "patvault: only git fetch/push are permitted",
			exit:      128,
			retryable: false,
		},
		{
			name:      "internal fault",
			err:       errInternal(),
			want:      "patvault: relay failed internally; check the relay's log on the host",
			exit:      1,
			retryable: false,
		},
		{
			name:      "github 401/403",
			err:       errGitHubAuth("owner/repo"),
			want:      "patvault: github rejected the token for owner/repo (revoked or insufficient scope); refresh with 'patvault add' on the host — this will not succeed until then",
			exit:      1,
			retryable: false,
		},
		{
			name:      "github 404",
			err:       errGitHubNotFound("owner/repo"),
			want:      "patvault: owner/repo not found, or the stored token cannot see it",
			exit:      1,
			retryable: false,
		},
		{
			name:      "github 5xx",
			err:       errGitHubUnreachable(503),
			want:      "patvault: github unreachable (503); safe to retry shortly",
			exit:      1,
			retryable: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() =\n%q\nwant\n%q", got, tc.want)
			}
			if got := tc.err.Exit(); got != tc.exit {
				t.Errorf("Exit() = %d, want %d", got, tc.exit)
			}
			if got := tc.err.Retryable(); got != tc.retryable {
				t.Errorf("Retryable() = %v, want %v", got, tc.retryable)
			}
		})
	}
}

// The expiry date is rendered in UTC regardless of the stored instant's zone, so
// the message does not change with the host's locale.
func TestErrExpiredPATFormatsDateInUTC(t *testing.T) {
	zone := time.FixedZone("UTC+14", 14*60*60)
	// 2026-07-02 10:00 +14:00 is 2026-07-01 20:00 UTC.
	err := errExpiredPAT("owner/repo", time.Date(2026, 7, 2, 10, 0, 0, 0, zone))
	want := "patvault: token for github.com/owner/repo expired 2026-07-01; run 'patvault add' on the host to refresh — this will not succeed until then"
	if got := err.Error(); got != want {
		t.Errorf("Error() =\n%q\nwant\n%q", got, want)
	}
}

// A transport-level failure (DNS, refused, timeout) has no HTTP status. The
// spec's "(503)" is an example for the 5xx case; a network failure omits the
// parenthetical rather than inventing a code, and stays retryable.
func TestErrGitHubUnreachableOmitsCodeForNetworkFailure(t *testing.T) {
	err := errGitHubUnreachable(0)
	want := "patvault: github unreachable; safe to retry shortly"
	if got := err.Error(); got != want {
		t.Errorf("Error() =\n%q\nwant\n%q", got, want)
	}
	if !err.Retryable() {
		t.Error("Retryable() = false, want true")
	}
	if err.Exit() != 1 {
		t.Errorf("Exit() = %d, want 1", err.Exit())
	}
}
