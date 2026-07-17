package relay

import (
	"fmt"
	"time"
)

// upstreamHost is the only forge the relay fronts. It is the host half of the
// stored credential's (host, path) key.
const upstreamHost = "github.com"

// relayError is one row of the base spec's §"Errors and exit codes" table: what
// the client is told, the exit status it is closed with, and whether retrying
// could ever help. Every refusal the relay sends a client is one of these.
//
// The message wording is a contract, not decoration: it is written to tell the
// calling agent whether to retry, so an agent does not loop on a terminal
// failure.
type relayError struct {
	msg       string
	exit      uint32
	retryable bool
}

func (e *relayError) Error() string { return e.msg }

// Exit is the SSH exit-status the channel is closed with. Git treats any
// non-zero as failure, so these are low-stakes: 1 for credential and upstream
// refusals, 128 (git's fatal convention) for protocol violations.
func (e *relayError) Exit() uint32 { return e.exit }

// Retryable reports whether the same request could succeed later without an
// operator touching the host. It mirrors the table's retry column and feeds the
// operational log.
func (e *relayError) Retryable() bool { return e.retryable }

// errNoPAT is the never-added half of the table's "No/expired PAT" row. The
// row's message names an expiry date, which a repo that was never added does not
// have; the disposition is the row's.
func errNoPAT(repo string) *relayError {
	return &relayError{
		msg: fmt.Sprintf(
			"patvault: no token stored for %s/%s; run 'patvault add' on the host — this will not succeed until then",
			upstreamHost, repo),
		exit:      1,
		retryable: false,
	}
}

// errExpiredPAT is the expired half of the same row. The date is UTC so the
// message does not shift with the host's locale.
func errExpiredPAT(repo string, expires time.Time) *relayError {
	return &relayError{
		msg: fmt.Sprintf(
			"patvault: token for %s/%s expired %s; run 'patvault add' on the host to refresh — this will not succeed until then",
			upstreamHost, repo, expires.UTC().Format("2006-01-02")),
		exit:      1,
		retryable: false,
	}
}

// errNotV2 refuses a fetch that did not announce protocol v2. The wording is the
// base spec's §"Wire protocol" code block, which carries the "(default since git
// 2.26)" the §Errors table drops — that parenthetical is the actionable part.
func errNotV2() *relayError {
	return &relayError{
		msg:       "patvault: relay requires git wire protocol v2; run 'git config --global protocol.version 2' (default since git 2.26)",
		exit:      1,
		retryable: false,
	}
}

// errDisallowedExec is the one answer to every way an exec can be unacceptable:
// a shell, a pty, an unknown command, git-upload-archive, or an unparseable
// path. The distinctions are for the host's log, never the client's.
func errDisallowedExec() *relayError {
	return &relayError{
		msg:       "patvault: only git fetch/push are permitted",
		exit:      128,
		retryable: false,
	}
}

// errInternal covers a host-side fault — unreadable database, locked keychain,
// failed decrypt. The base spec's table has no row for these, and they cannot be
// silent. It is deliberately vague: the client can do nothing about any of them,
// and the detail belongs in the operational log.
func errInternal() *relayError {
	return &relayError{
		msg:       "patvault: relay failed internally; check the relay's log on the host",
		exit:      1,
		retryable: false,
	}
}

// errGitHubAuth is the 401/403 row: GitHub rejected the token. The wording is
// the base spec's §"Errors and exit codes" table, copied verbatim. The spec
// marks this status→message mapping as inferred, not observed (§"Unverified
// assumptions"); slice 5 confirms it against the real Git endpoints. The repo is
// formatted bare (no host prefix) — the message already names "github".
func errGitHubAuth(repo string) *relayError {
	return &relayError{
		msg: fmt.Sprintf(
			"patvault: github rejected the token for %s (revoked or insufficient scope); refresh with 'patvault add' on the host — this will not succeed until then",
			repo),
		exit:      1,
		retryable: false,
	}
}

// errGitHubNotFound is the 404 row: the repo does not exist, or the token cannot
// see it. GitHub's Git endpoint returns 404 for both a missing repo and a
// private repo the token lacks access to — the same existence-hiding ambiguity
// the REST API uses.
func errGitHubNotFound(repo string) *relayError {
	return &relayError{
		msg: fmt.Sprintf(
			"patvault: %s not found, or the stored token cannot see it",
			repo),
		exit:      1,
		retryable: false,
	}
}

// errGitHubUnreachable is the 5xx / network row. status is the HTTP status code
// when one was received, or 0 for a transport-level failure (DNS, refused,
// timeout). The "(503)" in the spec's table is an example; the code is
// interpolated so 502/503/504 all read correctly, and a network failure omits
// the parenthetical rather than inventing a code. Always retryable.
func errGitHubUnreachable(status int) *relayError {
	qualifier := ""
	if status > 0 {
		qualifier = fmt.Sprintf(" (%d)", status)
	}
	return &relayError{
		msg:       fmt.Sprintf("patvault: github unreachable%s; safe to retry shortly", qualifier),
		exit:      1,
		retryable: true,
	}
}
