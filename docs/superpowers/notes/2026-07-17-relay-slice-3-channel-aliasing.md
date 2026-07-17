# Slice 3 Handoff — `ssh.Channel` Is Both `in` and `out` (2026-07-17)

Surfaced in the slice 2 review. `internal/relay/server.go`'s `dispatch` hands
the bridge the **same** `ssh.Channel` as both the request body reader and the
response body writer:

```go
// server.go:346-350
switch op {
case opFetch:
    err = s.Bridge.Fetch(ctx, req, ch, ch)
case opPush:
    err = s.Bridge.Push(ctx, req, ch, ch)
}
```

This is deliberate — `bridge` is declared as
`Fetch(ctx, req, in io.Reader, out io.Writer)` / `Push(...)` so the bridge
never sees SSH and its tests need none. But it means the bridge is reading and
writing **one duplex channel**, not two independent streams.

## What slice 3 must not do

- **Do not `io.Copy(out, in)`.** That echoes the client's own bytes back into
  the channel's read side. Git's transport is request-then-response, not a
  loopback; echoing corrupts the protocol.
- **Do not assume `in` and `out` are independently closeable.** They are the
  same `ssh.Channel`. `Close()` on one closes both halves.
- **Do not wrap `in` in a buffered reader that discards bytes on EOF.** Any
  read-ahead on `in` eats bytes the client never gets back; push's pack
  drains to a raw EOF (see the push-framing probe) and a read-ahead that drops
  the tail loses the pack.

## What slice 3 should do

- Read the request body from `in` to its natural terminator (fetch: commands
  up to the flush-pkt; push: commands + flush + raw pack to EOF — per the
  push-framing probe). Then **stop reading**.
- Write the upstream response to `out`, framed exactly as GitHub sends it
  (fetch v2: the pkt-line stream as-is; push: sideband-framed per the probe's
  §Findings).
- When done, signal the channel close the SSH way — `ch.CloseWrite()` /
  `ch.Close()` — not by closing the `io.Writer` the bridge received. The
  bridge owns the stream's end-of-data; `dispatch` owns the channel's
  end-of-channel.

## Why it is safe despite the alias

`ssh.Channel` is an ordered, reliable, **duplex** stream: the read and write
halves are independent directions on the same channel, not the same buffer.
Reading from `in` consumes client-to-relay bytes; writing to `out` produces
relay-to-client bytes. They do not collide as long as the bridge treats the
stream as half-duplex in time (read the request fully, then write the
response), which is exactly what both git transports do.

The risk is only the loopback case above — a copy that feeds `out` back into
`in`. Pin that with a test in slice 3's bridge suite: a fake channel whose
`Write` is observable, asserting no response byte is ever read back from `in`.

## Provenance

Read from `internal/relay/server.go` at the slice 2 review (commit
`de55da7`). Not a probe, not a spike — a static observation of the seam slice
2 left for slice 3.
