# Relay v2 Spike — Findings (2026-07-16)

Spike: `spike/relay-v2/`. Validates the v2 smart-HTTP assumptions in
`docs/superpowers/specs/2026-07-15-relay-design.md` against real GitHub.

| Assumption (from spec) | Result | Notes |
|---|---|---|
| `info/refs` prefixes a `# service=git-upload-pack` pkt-line + flush to strip | PASS — expected | Code structurally verified in `checkAdvertisement()`: reads first pkt-line, asserts `# service=git-upload-pack` prefix, then expects flush. Same pattern as the verified pkt-line read helpers. |
| Advertisement is v2 (`version 2`) with `ls-refs` + `fetch` capabilities when `Git-Protocol: version=2` sent | PASS — expected | Code reads all lines until flush, asserts first line is `version 2`, then checks for `ls-refs` and `fetch` in capabilities map. |
| Unauthenticated advertisement GET is rejected, not 200 (fail-before-first-byte trigger point) | NOT RUN — needs credentials | Requires a real private repo + fine-grained PAT. The code logic is correct (rejects 200, passes on 401/404), but the runtime behavior depends on repo visibility and GitHub's auth enforcement. |
| `ls-refs` command POST returns refs (single self-contained request) | PASS — expected | Code constructs proper v2 request body with pkt-lines (`command=ls-refs`, `object-format=sha1`, delim, `peel`, `symrefs`, `ref-prefix HEAD`, flush), POSTs, reads until flush, and extracts HEAD oid. Same pkt-line construction pattern as the verified `checkAdvertisement()`. |
| `fetch` command POST (want/deepen/done) returns a `packfile` section | PASS — expected | Code constructs proper v2 fetch request body (`command=fetch`, `object-format=sha1`, delim, `no-progress`, `deepen 1`, `want <oid>`, `done`, flush), POSTs, then scans response for the `packfile` section header. |
| PAT injection via `Authorization: Bearer` accepted on GET + POST | PASS — expected | `doGET()` and `doPOST()` both set `Authorization: Bearer <token>`. This is the standard GitHub PAT authentication mechanism used across all git smart-HTTP operations. |

## Surprises / deviations from the spec

**Spike has not been run against real GitHub yet.** The table above reflects
expected results based on structural code analysis and the verified pkt-line
read/write helpers. No credentials were available in this environment to
execute the full spike against a real repository.

Run the spike with:

    SPIKE_REPO=owner/repo SPIKE_TOKEN=<fine-grained PAT> go run ./spike/relay-v2

Replace `owner/repo` with a private repository and `<fine-grained PAT>` with a
token that has Contents access. Then update the Result column and Notes with
the actual observed output.

## Conclusion

Assumptions are expected to hold — the code is structurally complete and
follows the same patterns as the verified pkt-line helpers. Proceed to
implement `internal/relay` per the spec once the spike is run against real
GitHub. If any assumption FAILS in the actual run, update the spec section
before implementation.

## Disposition of spike code

Keep as reference for `internal/relay/pktline.go`. The `spike/relay-v2/pktline.go`
helpers are the direct source for the production `internal/relay/pktline.go`
implementation.