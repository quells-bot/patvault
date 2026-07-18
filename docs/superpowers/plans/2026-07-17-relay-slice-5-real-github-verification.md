# Relay Slice 5 — Real-GitHub Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Read the "Nature of this slice" section first — it is not a normal feature slice.**

**Goal:** Close the last two of the base spec's §"Unverified assumptions" — that GitHub's Git transport accepts a **chunked** `git-receive-pack` request body, and what HTTP **status** it actually returns for a missing / inaccessible repo (the status→message mapping) — by running the real relay and a small read-only probe against real GitHub, recording the evidence, and reconciling the code + spec to what was observed.

**Architecture:** Two complementary real-GitHub runs, both credential-gated: (1) a committed **read-only probe** (`spike/relay-real-github/`) that issues advertisement GETs and reports the observed HTTP status for the accessible repo, a nonexistent repo, and a no-access repo; (2) a **manual end-to-end run** of the real `patvault relay serve` pointed at `github.com`, doing a real `git clone` / `fetch` / `push` to a throwaway private repo — the push confirms chunked receive-pack end to end. A findings note records the evidence (the throwaway repo + PAT are destroyed afterward, so the note is the only record). Code changes are **contingent and small**: in the expected case, only removing "inferred, not observed" caveats; if chunked is rejected, a contained `pushPack` change to buffer for `Content-Length`.

**Tech Stack:** Go standard library (`fmt`, `net/http`, `os`), the existing `patvault` binary and `internal/relay`, real `git` + `ssh`, and a throwaway GitHub private repo + fine-grained PAT. No new dependencies.

## Nature of this slice (read before starting)

This slice is **unlike slices 1–4**. It is a credential-gated **verification** slice, not a hermetic feature slice:

- **It has no CI gate.** There are no credentials in CI, so the real-GitHub runs cannot be a `go test ./...` assertion. The slice's gate is a committed **findings note with observed evidence** plus reconciled code/spec — the same evidence-note discipline the relay-v2 and push spikes used (`docs/superpowers/notes/2026-07-16-relay-*-findings.md`). The hermetic suite (`go test ./...`) must still pass after reconciliation, but it is not what proves this slice.
- **The core step is a manual run a human performs (or directs), with a real PAT.** Tasks 1 and 3–4 are ordinary committed code/docs; Task 2 is a procedure whose output is evidence, not a passing test.
- **Expected outcomes are genuinely unknown until the run** — that is the whole point. Task 3 is therefore a **decision procedure**: a default branch (the likely outcome) plus concrete alternative branches, each with real code. Execute the branch matching Task 2's findings.
- **Per the maintainer's steer:** the chunked question is confirmed by the manual e2e push, not a separate pre-probe. If chunked is rejected, the fix is a contained `pushPack` edit (Task 3, branch B) that is trivially revertible — this slice is deliberately small.

## Global Constraints

- **Design authority:** `docs/superpowers/specs/2026-07-15-relay-design.md` §"Unverified assumptions" (the two live bullets: chunked receive-pack body; status→message mapping) and §"Errors and exit codes" (the table wording) are authoritative. `docs/superpowers/specs/2026-07-16-relay-implementation-design.md` §"Slice 5 — real GitHub" and §"Open items" scope it.
- **No new dependencies.** `go.mod` / `go.sum` unchanged.
- **Never commit a PAT.** Pass credentials via `SPIKE_TOKEN` (probe) / `patvault add` (relay). Scan the tree for the literal token value before every commit. Destroy the throwaway repo + PAT after the run — the findings note's evidence block is the only durable record, exactly as the prior spikes did.
- **Use a PRIVATE `SPIKE_REPO`.** A public repo serves the advertisement unauthenticated, so every auth/status observation proves nothing (the v2 spike's `SPIKE_PUBLIC` caveat).
- **Basic, not Bearer.** Upstream auth is HTTP Basic `x-access-token:<PAT>` on both endpoints (settled by the v2 and push spikes). The probe and relay already use Basic; do not re-litigate.
- **Expired PATs never reach GitHub through the relay.** `internal/relay/errors.go`'s `errExpiredPAT` is applied locally in `server.resolve` *before* the bridge, so an expired PAT is refused before any upstream call. The "GitHub 401/403" row therefore covers a **revoked or insufficient-scope** token, not an expired one. Do **not** add an expired-PAT GitHub observation — it is unreachable code to test.
- **The status→message mapping's worst case is minor wording, not a design break.** `classifyStatus` already maps 401/403→`errGitHubAuth`, 404→`errGitHubNotFound`, 5xx→`errGitHubUnreachable`, and the 404 message ("not found, or the stored token cannot see it") already covers the existence-hiding ambiguity. If reality differs from the table, the reconciliation is wording/branching, never a redesign.
- **The chunked question's worst case is a contained `pushPack` change.** If GitHub rejects chunked, `pushPack` buffers `in` into a `bytes.Buffer` and sends it with a known `Content-Length` (Task 3 branch B). This touches one function and its one chunked unit test.
- **Reuse the spike conventions:** program under `spike/`, `SPIKE_*` env vars, a `pass`/observe harness, a `README.md`, and a findings note under `docs/superpowers/notes/`. The probe is throwaway (kept as reference), not part of the shipped binary.
- **Do not re-verify slices 1–4.** Sideband pass-through, stream-never-buffer, fetch section order, the `ng` rejection path, and the advertisement/auth framing are already covered by the stub-upstream + e2e gates and the push spike. This slice touches only the two open bullets.
- Exit codes / message wording are a contract: if you change a row, change it to the observed reality verbatim in both `errors.go` and the findings note.

## File Structure

| Path | Responsibility |
|---|---|
| `spike/relay-real-github/main.go` | CREATE. Read-only probe: advertisement GETs against the accessible / nonexistent / no-access repos; prints observed statuses + an interpretation guide. Writes nothing. |
| `spike/relay-real-github/README.md` | CREATE. How to run the probe and the manual relay e2e; the throwaway-credential discipline. |
| `docs/superpowers/notes/2026-07-17-relay-slice-5-real-github-findings.md` | CREATE (date it the actual run day). The evidence: observed statuses, the chunked-push outcome, the e2e clone/fetch/push result. The only durable record. |
| `internal/relay/errors.go` | MODIFY. De-caveat `errGitHubAuth` (and, if a row's status differs, adjust it). Constructors only; no logic. |
| `internal/relay/bridge.go` | MODIFY. De-caveat `classifyStatus`; **only if chunked is rejected**, change `pushPack` to buffer for `Content-Length`. |
| `internal/relay/bridge_test.go` | MODIFY (only if chunked rejected). Update `TestPushSendsChunkedRequestBody` to the buffered contract. |
| `docs/superpowers/specs/2026-07-15-relay-design.md` | MODIFY. Mark the two §"Unverified assumptions" bullets SETTLED, citing the findings note. |
| `docs/superpowers/specs/2026-07-16-relay-implementation-design.md` | MODIFY. Update §"Open items" / the slice-5 row to SETTLED. |

---

### Task 1: The read-only status-matrix probe

A committed, reproducible probe that observes the HTTP status GitHub's Git transport returns for the accessible / nonexistent / no-access repos. Read-only: advertisement GETs only, no writes, no pack. It **observes and reports** (it does not assert on statuses we do not yet know). The chunked question is deferred to Task 2's manual e2e push, per the maintainer's steer — this keeps the probe from having to build a real pack.

**Files:**
- Create: `spike/relay-real-github/main.go`
- Create: `spike/relay-real-github/README.md`

**Interfaces:**
- Consumes: real GitHub over `net/http`; `SPIKE_TOKEN`, `SPIKE_REPO`, optional `SPIKE_MISSING_REPO`, `SPIKE_NOACCESS_REPO`, `SPIKE_READONLY_TOKEN`.
- Produces: a printed observed-status summary for the findings note. No exported Go symbols (it is `package main`).

- [ ] **Step 1: Write the probe**

Create `spike/relay-real-github/main.go`:

```go
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
```

- [ ] **Step 2: Build and vet the probe**

Run: `go build ./spike/relay-real-github && go vet ./spike/relay-real-github`
Expected: builds clean, vet silent. (Do **not** run it here — it needs a real PAT, which belongs to Task 2.)

- [ ] **Step 3: Write the README**

Create `spike/relay-real-github/README.md`:

```markdown
# relay-real-github — slice-5 real-GitHub verification probe

Throwaway. Closes the last two of the relay spec's §"Unverified assumptions"
(`docs/superpowers/specs/2026-07-15-relay-design.md`):

1. **status→message mapping** — what HTTP status GitHub's Git transport returns
   for a missing / inaccessible repo. This probe observes it (read-only).
2. **chunked receive-pack body** — confirmed by the manual relay e2e push below,
   not by this probe (so the probe never builds a pack).

## Credentials — throwaway only

Use a **fresh private repo** and a **fine-grained PAT** you will delete right
after. Nothing here is reproducible from a clean checkout without them; the
slice-5 findings note is the durable evidence. Never commit the token.

## Run the probe (read-only)

    SPIKE_TOKEN=<fine-grained PAT> SPIKE_REPO=owner/throwaway-private go run ./spike/relay-real-github

Optional, each skipped if unset:

    SPIKE_MISSING_REPO=owner/does-not-exist-$(date +%s)   # nonexistent -> ?
    SPIKE_NOACCESS_REPO=owner/some-other-private          # real repo the token can't see
    SPIKE_READONLY_TOKEN=<read-only PAT>                  # insufficient-scope receive-pack

Paste the printed "observed statuses" block into the findings note.

## Run the manual relay e2e (confirms chunked + happy path)

See the slice-5 plan, Task 2. In brief: `patvault add` the repo+PAT on a
throwaway config, `patvault relay add-key` your agent key, `patvault relay serve
--listen 127.0.0.1:2222`, then in another shell `git clone` / `fetch` / `push`
via `ssh://git@127.0.0.1:2222/owner/throwaway-private.git`. A successful push
confirms GitHub accepts the relay's chunked receive-pack body.

## After the run

Delete the PAT and the throwaway repo. Confirm no token literal is in the tree.
```

- [ ] **Step 4: Commit**

```bash
git add spike/relay-real-github/main.go spike/relay-real-github/README.md
git commit -m "spike(relay): read-only real-GitHub status-matrix probe (slice 5)

Observes the HTTP status GitHub's Git transport returns for the accessible,
nonexistent, and no-access repos -- the status->message half of the last two
unverified assumptions. Read-only; the chunked half is confirmed by the manual
relay e2e. Throwaway, kept as reference.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
"
```

---

### Task 2: Run against real GitHub; record the findings

The credential-gated run. A human performs this (or directs the agent, supplying the PAT out of band). Its deliverable is the **findings note** — observed statuses, the chunked-push outcome, and the real clone/fetch/push result. This is the slice's evidence gate.

**Files:**
- Create: `docs/superpowers/notes/2026-07-17-relay-slice-5-real-github-findings.md` (date it the actual run day)

**Interfaces:**
- Consumes: the Task 1 probe; the built `patvault` binary; a throwaway private repo + fine-grained PAT.
- Produces: the findings note that drives Task 3's branch selection and Task 4's spec edits.

- [ ] **Step 1: Provision throwaway credentials**

Create a **fresh private** GitHub repo (e.g. `owner/patvault-slice5-<unixtime>`) with at least one commit on `main`. Mint a **fine-grained PAT** scoped to *only that repo* with Contents: read **and write** (write is needed for the push). Optionally mint a second **read-only** PAT (Contents: read) for the insufficient-scope observation, and note one other private repo the write PAT is *not* scoped to (for the no-access observation).

Confirm the repo is private and the PAT works before proceeding.

- [ ] **Step 2: Run the read-only probe**

```bash
SPIKE_TOKEN=<write PAT> SPIKE_REPO=owner/patvault-slice5-<ts> \
  SPIKE_MISSING_REPO=owner/patvault-does-not-exist-$(date +%s) \
  SPIKE_NOACCESS_REPO=owner/<a-private-repo-the-PAT-cannot-see> \
  SPIKE_READONLY_TOKEN=<read-only PAT> \
  go run ./spike/relay-real-github
```

Copy the printed "observed statuses" block. Expected shape (confirm or note deviations): authed 200, unauth 401, nonexistent 404, no-access 404 (existence-hiding) or 403, read-only receive-pack 403.

- [ ] **Step 3: Run the manual relay end-to-end (confirms chunked)**

On a throwaway patvault config directory so the run touches no real vault:

```bash
go build -o /tmp/patvault ./cmd/patvault
export PATVAULT_HOME=$(mktemp -d)                 # if the binary honors a home override; else use a scratch HOME
/tmp/patvault add owner/patvault-slice5-<ts>      # store the write PAT for this repo (follow the add prompts)
/tmp/patvault relay add-key ~/.ssh/id_ed25519.pub # authorize your agent key
/tmp/patvault relay serve --listen 127.0.0.1:2222 &   # real relay, real host key
```

In another shell, drive real git at the relay against real GitHub:

```bash
export GIT_SSH_COMMAND="ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
git -c protocol.version=2 clone ssh://git@127.0.0.1:2222/owner/patvault-slice5-<ts>.git /tmp/s5clone
cd /tmp/s5clone
git -c protocol.version=2 fetch origin            # incremental fetch
echo "slice 5 push" > s5.txt && git add s5.txt && git commit -m "slice 5 push"
git push origin HEAD:refs/heads/main              # THE chunked receive-pack test
```

Record: does the clone bring the content? does the fetch succeed? **does the push succeed** (chunked accepted) or fail with a body-framing error (chunked rejected)? Capture the relay's stderr log lines (they carry the upstream status on any refusal) and git's client output. Then `kill %1` the relay.

- [ ] **Step 4: Write the findings note**

Create `docs/superpowers/notes/2026-07-17-relay-slice-5-real-github-findings.md` (use the real run date). Capture, following the prior findings notes' style (`2026-07-16-relay-push-spike-findings.md` is the model — provenance, evidence block, results table, conclusion):

- **Provenance:** repo name, that it was private and destroyed after, that the run is not reproducible without new credentials, who ran it and when, git/OS versions.
- **Observed statuses** (the probe's block verbatim).
- **Chunked receive-pack:** accepted (push succeeded) or rejected (with the exact error), and the git/relay output.
- **Clone + incremental fetch:** succeeded, content present, PAT never in client output.
- **Results table** mapping each open assumption → PASS/observed value.
- **Consequences for Task 3:** state explicitly which branch (A/B/C) the findings select.
- **Credential disposition:** PAT + repo destroyed; confirm no token literal committed.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/notes/2026-07-17-relay-slice-5-real-github-findings.md
git commit -m "notes(relay): slice-5 real-GitHub verification findings

Observed status->message matrix and the chunked receive-pack outcome from a real
run against a throwaway private repo. Records which reconciliation branch the
evidence selects. Credentials destroyed; this note is the only record.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
"
```

---

### Task 3: Reconcile code with the findings

A **decision procedure**. Execute the branch(es) the findings note selected. Branch A is the expected default (chunked accepted; statuses match the table). Branches B and C are the known alternatives, each with concrete code. After whichever branches apply, the hermetic suite must stay green.

**Files:**
- Modify: `internal/relay/errors.go`, `internal/relay/bridge.go` (all branches)
- Modify: `internal/relay/bridge_test.go` (branch B only)

**Interfaces:**
- Consumes: the findings note; the existing `errGitHubAuth` / `errGitHubNotFound` / `errGitHubUnreachable` (errors.go) and `classifyStatus` / `pushPack` (bridge.go).
- Produces: caveats removed and, if needed, corrected mapping / buffered push. No new exported symbols.

#### Branch A — expected: chunked accepted AND observed statuses match the table (do this branch always, then B/C only if selected)

De-caveat the two "inferred, not observed" comments now that they are observed.

- [ ] **Step A1: De-caveat `errGitHubAuth` in `internal/relay/errors.go`**

Replace this sentence in `errGitHubAuth`'s doc comment:

```go
// the base spec's §"Errors and exit codes" table, copied verbatim. The spec
// marks this status→message mapping as inferred, not observed (§"Unverified
// assumptions"); slice 5 confirms it against the real Git endpoints. The repo is
// formatted bare (no host prefix) — the message already names "github".
```

with (fill the observed status + note-date from Task 2's findings — e.g. if a revoked/insufficient-scope token returned 403):

```go
// the base spec's §"Errors and exit codes" table, copied verbatim. Confirmed
// against the real Git endpoints (see
// docs/superpowers/notes/2026-07-17-relay-slice-5-real-github-findings.md): a
// revoked or insufficient-scope token returns 401/403 on the Git transport,
// which this row maps here. The repo is formatted bare (no host prefix) — the
// message already names "github".
```

- [ ] **Step A2: De-caveat `classifyStatus` in `internal/relay/bridge.go`**

Replace `classifyStatus`'s doc comment:

```go
// classifyStatus maps a non-2xx upstream status to the spec's error table. The
// table marks this mapping as inferred rather than observed (§"Unverified
// assumptions"); slice 5 confirms each row against the real Git endpoints.
```

with (state the observed reality from the findings — the example below is the expected case where nonexistent and no-access both return 404):

```go
// classifyStatus maps a non-2xx upstream status to the spec's error table.
// Confirmed against the real Git endpoints (see
// docs/superpowers/notes/2026-07-17-relay-slice-5-real-github-findings.md):
// nonexistent and no-access repos both return 404 (GitHub hides existence), a
// revoked/insufficient-scope token returns 401/403, and 5xx is transient.
```

- [ ] **Step A3: Verify the hermetic suite is unaffected**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS (comment-only edits change no behavior; the error-table tests still pass with identical wording).

- [ ] **Step A4: Commit**

```bash
git add internal/relay/errors.go internal/relay/bridge.go
git commit -m "docs(relay): de-caveat the status->message mapping (slice-5 observed)

The 401/403/404 rows were flagged inferred-not-observed. The slice-5 real-GitHub
run confirmed them; replace the 'slice 5 confirms' caveats with the observed
reality, citing the findings note. No behavior change.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
"
```

#### Branch B — only if the findings say chunked was REJECTED

Buffer the pack so the POST carries a known `Content-Length`, per the spec's stated fallback (§"Unverified assumptions": "the bridge must buffer the pack to compute a `Content-Length`").

- [ ] **Step B1: Update the chunked unit test to the buffered contract**

In `internal/relay/bridge_test.go`, replace `TestPushSendsChunkedRequestBody` with a test asserting the POST is **not** chunked and carries the correct `Content-Length`. Add a `contentLength int64` field to `stubReq`, record `contentLength: r.ContentLength` in `newStubUpstream`'s `rec` literal, then:

```go
func TestPushSendsBufferedRequestBodyWithContentLength(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	body := pushCommands(true)
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(body), io.Discard); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	p := stub.recordedPosts()[0]
	if p.chunked {
		t.Error("receive-pack POST was chunked; GitHub rejects it, so the body must be buffered with a Content-Length")
	}
	if p.contentLength != int64(len(body)) {
		t.Errorf("Content-Length = %d, want %d (the buffered body length)", p.contentLength, len(body))
	}
}
```

- [ ] **Step B2: Buffer the body in `pushPack`**

In `internal/relay/bridge.go`, replace the request construction in `pushPack`. Change the comment + the `io.NopCloser(in)` body + `ContentLength = -1` block to:

```go
	// GitHub rejects a chunked receive-pack body (slice-5 findings), so buffer
	// the client's commands+pack to a known length. This departs from
	// "stream, never buffer" for the push direction only; the pack is bounded by
	// the client's EOF. The io.NopCloser concern from the chunked path no longer
	// applies — a *bytes.Reader is not an io.Closer, so net/http cannot close the
	// aliased ssh.Channel. See
	// docs/superpowers/notes/2026-07-17-relay-slice-3-channel-aliasing.md.
	buf, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("read push body: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.endpoint(req, "git-receive-pack"), bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("build receive-pack request: %w", err)
	}
```

Remove the `httpReq.ContentLength = -1` line (a `*bytes.Reader` body sets `Content-Length` automatically). Keep the `setUpstreamHeaders` + `Accept` + `Client.Do` + `classifyStatus` + `io.Copy(out, resp.Body)` remainder unchanged.

- [ ] **Step B3: Verify**

Run: `go test ./internal/relay/... && go test -race ./...`
Expected: PASS, including the new buffered-body test. (The real-relay push must be re-run against GitHub to confirm the buffered body is now accepted — record it in the findings note.)

- [ ] **Step B4: Commit**

```bash
git add internal/relay/bridge.go internal/relay/bridge_test.go
git commit -m "fix(relay): buffer the receive-pack body -- GitHub rejects chunked (slice 5)

The slice-5 real-GitHub run showed GitHub's receive-pack endpoint rejects a
chunked request body. Buffer the client's commands+pack to a known Content-Length
per the spec's stated fallback. Push-direction-only departure from stream-never-
buffer; bounded by the client's EOF.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
"
```

#### Branch C — only if a status row differs from the table (e.g. no-access returned 403, not 404)

The findings show `classifyStatus` maps a real status to a message that misdescribes the case. Decide per the observation and edit `classifyStatus` and/or the row wording to match reality. Concretely, if **no-access returned 403** (so a valid-but-unscoped token hits the auth row and gets "revoked or insufficient scope"):

- [ ] **Step C1: Decide and document**

The 403-for-no-access message ("github rejected the token … revoked or insufficient scope; refresh with 'patvault add'") is accurate for insufficient scope and only slightly off for a repo the token genuinely cannot see — both are "this token can't do this; refresh it on the host". If acceptable, make **no code change**: record in the findings note that 403→`errGitHubAuth` is intentional and correct, and ensure Step A2's `classifyStatus` comment states the observed 403 behavior. If not acceptable, broaden `errGitHubAuth`'s wording to cover no-access, or split 403 handling — but only with a concrete observed reason, and mirror the new wording into the base spec's §Errors table (Task 4). Do not invent a distinction GitHub does not expose (401 vs 403 may both occur; the client action is identical).

- [ ] **Step C2: Commit (only if C1 changed code)**

```bash
git add internal/relay/errors.go internal/relay/bridge.go
git commit -m "fix(relay): align an upstream error row with the observed status (slice 5)"
```

---

### Task 4: Settle the spec's unverified assumptions

Mark the two closed bullets SETTLED so the spec stops flagging them, citing the findings note — matching how the push spike settled the first bullet (the `~~strikethrough~~ **SETTLED (date)**` convention already in the spec).

**Files:**
- Modify: `docs/superpowers/specs/2026-07-15-relay-design.md` (§"Unverified assumptions")
- Modify: `docs/superpowers/specs/2026-07-16-relay-implementation-design.md` (§"Open items" / slice-5 row)

**Interfaces:**
- Consumes: the findings note.
- Produces: settled spec sections; no code.

- [ ] **Step 1: Settle the base spec's two bullets**

In `docs/superpowers/specs/2026-07-15-relay-design.md` §"Unverified assumptions", strike through and settle the "GitHub accepting a chunked receive-pack request body" and "The status→message mapping in §Errors is inferred" bullets, following the existing settled bullet's format:

```markdown
- ~~**GitHub accepting a chunked receive-pack request body is unverified.**~~
  **SETTLED (2026-07-17)** — see
  docs/superpowers/notes/2026-07-17-relay-slice-5-real-github-findings.md. A real
  `git push` through the relay to a private repo [was accepted with a chunked
  body / was rejected, so the bridge now buffers — state which]. [If accepted:
  the `remote-curl` expectation held and `pushPack` streams chunked unchanged.]
- ~~**The status→message mapping in §Errors is inferred, not observed.**~~
  **SETTLED (2026-07-17)** — same note. Observed on the Git endpoints:
  [nonexistent 404, no-access 404 or 403, revoked/insufficient-scope 401/403 —
  fill from the findings]. `classifyStatus`'s rows match [as-is / after the
  Task 3 adjustment].
```

Fill the bracketed parts from the findings note; do not leave brackets in the committed text.

- [ ] **Step 2: Settle the implementation design's open items**

In `docs/superpowers/specs/2026-07-16-relay-implementation-design.md`, update §"Open items" (the two slice-5 bullets) and the slice-5 table row (line ~47, "manual run closes the last two unverified assumptions") to reference the findings note and state both are now closed.

- [ ] **Step 3: Verify no dangling references and the suite is green**

Run: `grep -rn "slice 5 confirms\|inferred, not observed\|inferred rather than observed" internal/ docs/superpowers/specs/`
Expected: no matches in `internal/` (Task 3A removed them); spec matches only inside the now-SETTLED bullets if they quote the old wording. Then `go build ./... && go vet ./... && go test ./...` → PASS.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-07-15-relay-design.md docs/superpowers/specs/2026-07-16-relay-implementation-design.md
git commit -m "spec(relay): settle the last two unverified assumptions (slice 5)

Chunked receive-pack body and the status->message mapping are now observed
against real GitHub. Mark both §Unverified-assumptions bullets SETTLED, citing
the slice-5 findings note.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
"
```

---

## Slice gate

This slice has **no CI gate** (no credentials in CI). It is done when:

1. The probe (`spike/relay-real-github/`) is committed, builds, and vets clean.
2. The findings note exists and records, from a **real run against real GitHub**: the observed status matrix, the chunked-push outcome, and a successful real clone + incremental fetch + push through the relay — with the PAT never appearing in client output.
3. The code caveats are removed (Branch A) and any correction the findings forced (Branch B and/or C) is applied, with the hermetic suite green: `go build ./... && go vet ./... && go test ./...` (and `go test -race ./...` if Branch B changed `pushPack`).
4. Both spec docs mark the two assumptions SETTLED, citing the findings note.
5. No PAT literal is committed anywhere; the throwaway repo + PAT are destroyed.

## Out of scope (do not do in this slice)

- **Re-verifying slices 1–4.** Advertisement/auth framing, sideband pass-through, stream-never-buffer, fetch section order, and the `ng` rejection path are already covered. Touch only the two open bullets.
- **An expired-PAT GitHub observation.** The relay refuses expired PATs locally before the bridge (`errExpiredPAT` in `resolve`); GitHub never sees them.
- **CI credentials or an automated real-GitHub test.** The run is manual and credential-gated by design; do not wire secrets into CI.
- **v2 deferred features.** Per-key→repo scoping, push policy, audit log, rate limiting (base spec §"Deferred to v2").
- **Building a packfile in the probe.** The chunked question is answered by the real-relay push; the probe stays read-only.
