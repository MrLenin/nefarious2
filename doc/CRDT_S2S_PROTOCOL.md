# CRDT-Mesh — End-to-End S2S Protocol Specification

> Branch: `crdt-mesh`. This specifies the **on-the-wire** server-to-server protocol the CRDT mesh adds
> to P10: the `CR` and `CRDTMESH` tokens, their framing, the binary payload formats, and the
> state machines (anti-entropy, liveness, ephemeral messaging) — plus how they interleave with the
> retained P10 tree.
>
> Companion: **`CRDT_MESH_IMPLEMENTATION.md`** (architecture & code). This document is wire-first; it
> cites code only to anchor each claim.
>
> Conventions: byte layouts are **big-endian** (network order) unless noted. `[name:N]` = an N-byte
> field. `b64(x)` = RFC-4648 standard-alphabet base64 of the bytes `x`. `<YXX>` = a P10 server numeric
> (2 base64 chars); `<numeric>`/`<NN>` = a 5-char client numeric (server YY + client XXX). All P10
> lines are capped at **512 bytes** including the trailing CRLF.

---

## 1. Scope, layering & guarantees

The CRDT mesh replicates *network state* (users, channels, membership, modes, topics, bans) as a
commutative CRDT **document** that converges independently of message order or a designated
synchroniser. It is carried over the existing P10 link as two new tokens and is **additive**: it
only flows between CRDT-aware peers and only when `FEAT_CRDT_ENABLED`.

```
 ┌─────────────────────────── one P10 line (≤512 B) ───────────────────────────┐
 │  :<src>  CR  <sub>  <args…>  :<trailing>                                      │   wire framing (§3-4)
 └──────────────────────────────────────┬───────────────────────────────────────┘
                                         │ s2s_chunk reassembly (D/U/F)            §3.3
                                         ▼
                              b64-decode (RFC 4648)                                §3.4
                                         ▼
                         big-endian binary: SV | op | delta | snapshot            §6
                                         ▼
                              CRDT engine merge (HLC / LWW / OR-Set)
```

Guarantees: **eventual consistency** (commutative, idempotent merge — duplicate or reordered deltas
are harmless; dedup is by per-origin state vector); **causal-stability-bounded GC** (an op is reclaimed
only once every connected peer has it); **partition tolerance** (a mesh-reachable but tree-departed
server's state is retained until its liveness beacon goes stale). It is **not** a total order and
makes no real-time delivery guarantee for durable state (ephemeral CR M messages are best-effort).

---

## 2. Tokens & registration

| Long (`MSG_*`) | Token (`TOK_*`) | Purpose | Handler row (`parse.c`) |
|---|---|---|---|
| `CRDT` | `CR` | CRDT replication + gossip + beacon (subcommanded) | `{ mr_crdt, m_not_oper, ms_crdt, mo_crdt, m_ignore }` (`parse.c:1089`) |
| `CRDTMESH` | `CM` | CR-only overlay link handshake | `{ mr_crdtmesh, m_ignore, m_ignore, m_ignore, m_ignore }`, flags `MFLG_SLOW\|MFLG_UNREG\|MFLG_NOSHUN` (`parse.c:1102`) |

(`include/msg.h:591-597`.) The five-slot handler tuple is `{ UNREG, CLIENT, SERVER, OPER, SERVICE }`.
For `CR`: a non-oper client typing `/CRDT` gets `m_not_oper`; an oper gets `mo_crdt` (the `/CRDT
[map|peers|status]` introspection command); a **server** peer dispatches to `ms_crdt`; an **overlay**
peer (unregistered, see §5.2) dispatches to `mr_crdt`, which gates on `IsCrdtOverlay` and forwards to
`ms_crdt` (`m_crdt.c:515`).

---

## 3. Carrier framing

### 3.1 P10 line shape

A CR line is an ordinary P10 server message:

```
:<src> CR <sub> <arg1> <arg2> … :<trailing>
```

`<src>` is the **relaying** server's numeric prefix (the original origin for a relayed op is encoded
*inside* the binary payload, not in the P10 prefix). `<sub>` is a single uppercase letter
(`S D U F V M H`). The trailing parameter (after `:`) carries the base64 chunk or free text.

> On a `CRDTMESH` overlay link the parser ignores the P10 sender prefix (the connection is
> unregistered); `ms_crdt` keys the peer by `base64toint(cli_yxx(cptr))`, the numeric stored at
> handshake (§5.2).

### 3.2 Subcommand summary

| Sub | Name | Direction | Carries | §|
|---|---|---|---|---|
| `S` | sync request | peer→peer (periodic) | state vector + doc digest | 7 |
| `D` | delta | response to `S`, and eager relay | binary delta (chunked) | 7 |
| `U` | update | push of own new ops | binary delta (chunked) | 7 |
| `F` | full snapshot | fallback / BURST-replacement | binary snapshot (chunked) | 7 |
| `V` | version | **received-only** (no sender) | state vector | 7.5 |
| `M` | message | gossip flood | ephemeral PRIVMSG/NOTICE/TAGMSG | 8 |
| `H` | beacon | gossip flood (periodic) | liveness + capacity + mesh peers | 9 |

### 3.3 Chunking (`s2s_chunk`, D / U / F)

A binary payload that exceeds one P10 line is base64'd then split into chunks of **≤400 base64
chars** (`CR_CHUNK_LEN`, `m_crdt.c:45`):

```
:<src> CR <D|U|F> <id> <+|.> :<b64-chunk>
```

- `<id>` = `<cli_yxx(sender)><counter>` (e.g. `AB7`) — unique per stream per link (`m_crdt.c:56`).
- `<+|.>` = `+` more chunks follow, `.` final chunk.
- Reassembly is keyed by **(link, id)** so multiple streams over one link, and the same id over
  different links, don't collide. Max 64 concurrent reassemblies network-wide (`S2S_CHUNK_MAX`,
  `s2s_chunk.h:24`). In-flight reassemblies are dropped on peer SQUIT (`s2s_chunk_cleanup_link`).
- The receiver applies the payload only when the final (`.`) chunk completes the stream.

`S`, `V`, `M`, `H` are **single-line** (no chunking).

### 3.4 Base64 & compression

`crdt_b64_encode`/`decode` (`crdt_wire.c:480/510`) use the RFC-4648 **standard** alphabet
(`A–Za–z0–9+/`, `=` padding). Decode skips non-alphabet bytes (so embedded whitespace is tolerated)
and stops at `=`.

> **No compression is applied.** The wire payload is `base64(raw-binary)`. (The `crdt_wire.h:6`
> reference to zstd is aspirational; no zstd call exists in the CR path.)

---

## 4. Capability negotiation

A server advertises CRDT support with the flag char **`C`** in the `+`-flags field of its `SERVER`
greeting (alongside `h` hub, `s` service, `6` IPv6, `o` oplevels, `v` IRCv3-aware, `F` BX-F-aware).
`set_server_flags` (`m_server.c:491`) maps `C` → `FLAG_CRDT_AWARE` (`SetCrdtAware`). Example
self-greeting (`s_serv.c:144`, this build is always CRDT-aware):

```
SERVER <me> 1 <ts> <ts> J<MAJOR_PROTOCOL> <NumServCap(me)> +<h?>6<o?>vFC :<info>
```

A relayed server is introduced with `C` only if it is itself CRDT-aware:

```
<src> SERVER <name> <hop> 0 <ts> J<NN> <NumServCap> +<h?><s?><6?><o?><v?><F?><C?> :<info>
```

(S-2 `s_serv.c:204`, S-3 `s_serv.c:281`, relay `m_server.c:957`.) **CRDT-awareness is capability-only**
— actual sync still requires `FEAT_CRDT_ENABLED` at both ends. The runtime predicate for "a directly
connected peer I exchange CR with" is `IsCrdtSyncTarget(x) = MyConnect(x) && IsCrdtAware(x) &&
(IsServer(x) || IsCrdtOverlay(x))` (`client.h:1200`).

---

## 5. Link establishment

### 5.1 CRDT-aware P10 link

A normal P10 link whose `SERVER` greeting carried `C`. After `server_estab` (SERVER tree + gline/shun/
jupe/zline bursts), the **state burst is replaced** (§10.1): a CRDT-primary sender emits a `CR F`
snapshot instead of the P10 user/channel/session BURST, then EOB/EOB_ACK. CR tokens on this link
dispatch through `ms_crdt`. Immediately after handshake the sender issues a `CR S` to pull the peer's
state (`s_serv.c` / via the verify cadence).

### 5.2 CRDTMESH overlay link

A dedicated **CR-only edge that is never a P10 tree edge** — it gives the mesh redundant paths so a
leaf stays mesh-reachable when its P10 parent splits. Configured with a bare `crdtmesh;` attribute in
a `Connect{}` block (`CONF_CRDTMESH = 0x0200`, `s_conf.h:38`).

Handshake (token `CM`):

```
            initiator                                  acceptor
  completed_connection (s_bsd.c:552):
    [PASS :<pass>]                       ───────▶
    CRDTMESH <myname> <myYY> :<myinfo>   ───────▶   mr_crdtmesh (m_server.c:704):
                                                       verify CONF_CRDTMESH + SSL fp + pass
                                                       verify numeric agreement vs FindNServer
                                                       make_server (NO SetServerYXX / server_estab / add_dlink)
                                                       store peer numeric in cli_yxx
                                                       SetCrdtOverlay + SetCrdtAware + SetHandshake
                                          ◀───────   [PASS] + CRDTMESH <name> <YY> :<info>   (acceptor replies)
                                                       crdt_sync_request(peer)   →  CR S …
```

Key properties:

- The overlay peer **never becomes `IsServer`**: no `SetServerYXX`, not in `server_list[]`, not in the
  P10 routing tree, not in the SQUIT cascade. It stays permanently `STAT_HANDSHAKE`
  (`UNREGISTERED_HANDLER`), so its CR tokens dispatch through `mr_crdt` (UNREG slot), which forwards
  to `ms_crdt` only if `IsCrdtOverlay` (so an ordinary unregistered socket can never inject state).
- **Numeric agreement**: the handshake numeric must match the canonical P10 server of that name if it
  is linked; if not linked (partition), the claimed numeric is accepted (partition tolerance).
- Overlay links are **exempt from the registration ping timeout** (`ircd.c:644`); liveness is by TCP
  EOF and the periodic anti-entropy/beacon writes failing on a dead socket.
- `FLAG_CRDT_OVERLAY` is deliberately **not** set on the outbound side until the handshake handler
  runs, so a hung connect is still reaped by the normal timeout.

---

## 6. Binary payload formats

All produced by `crdt_wire.c`, big-endian, then base64'd onto the wire. Decoders are bounds-checked
and return -1 on overflow/malformed input.

### 6.1 State vector (`crdt_sv_encode`, `crdt_wire.c:76`)

```
[count:2]  then count × [origin:2][seq:8]
```

Only non-zero entries are emitted. `seq[origin]` = the highest op sequence number the sender has from
that origin server. The SV is the dedup + causal-stability primitive (full vector is 4096×8 = 32 KB in
memory, but only populated origins go on the wire).

### 6.2 Single operation (`crdt_op_encode`, `crdt_wire.c:107`)

```
[origin:2][seq:8][type:1][coll:1]
[chan_len:2][chan]                       (chan present for CHAN_MEMBERS/BANS/EXCEPTS/CTIME; else len 0)
[key_len:2][key]
[tag.origin:2][tag.seq:8][priority:1]    (OR-Set add/remove identity + removal priority)
[hlc.physical_ms:8][hlc.logical:2][hlc.node_id:2][writer:2]   (LWW timestamp + writer)
[val_len:4][val]                         (LWW value blob; len 0 for delete / OR-Set ops)
```

- `type` ∈ {`ADD=0`, `REMOVE=1`, `SET=2`, `DELETE=3`} (`crdt_state.h:117`).
- `coll` ∈ the 12 collection enum values (see §6.5) — **a wire contract**.
- All integers fixed-width (no varints). The HLC is 12 bytes on the wire (physical 8 + logical 2 +
  node 2), distinct from its 16-byte in-memory struct.
- For a `SET` op, `val` is the memcpy'd record struct (e.g. a 368-byte `CrdtUserRecord`); its byte
  layout — including struct padding — is part of the value and is hashed/compared byte-for-byte, so
  producers must zero records before filling (the integration layer does, §`CRDT_MESH_IMPLEMENTATION.md`).

### 6.3 Delta (`crdt_delta_encode`, `crdt_wire.c:166`)

```
[count:4]  then count × <encoded op §6.2>
```

A delta contains exactly the ops with `seq > remote_sv.seq[origin]` for each origin — the wire form of
`crdt_state_sync`. The receiver (`crdt_delta_apply`, `:188`) decodes each op and applies it iff not
already covered by `local_sv` (idempotent), then resumes its seq allocator (restart-epoch fix).

### 6.4 Full snapshot — CR F (`crdt_snapshot_encode`, `crdt_wire.c:284`)

```
[sv_len:2][sv §6.1]
[lww_total:4]  then each:
    [coll:1][key_len:2][key][deleted:1]
    [ts.physical:8][ts.logical:2][ts.node:2][writer:2]
    [val_len:4][val]                          (val_len 0 if deleted)
[chan_count:4] then each:
    [name_len:2][name]
    members  OR-Set:  [add_count:4]  add ×[key_len:2][key][tag.origin:2][tag.seq:8]
                      [tomb_count:4] tomb×[tag.origin:2][tag.seq:8][priority:1]
    bans     OR-Set:  (same shape)
    excepts  OR-Set:  (same shape)
    ctime:   [value:8][set.physical:8][set.logical:2][set.node:2]
                      [del.physical:8][del.logical:2][del.node:2]
```

The LWW section serialises all eight LWW maps (servers, users, nicks, topics, modes, members_status,
kick_info, chanmeta), routed on decode by the `coll` byte — so adding a new LWW map needs no decoder
change. (The `chan\0numeric` keys of members_status/kick_info carry an embedded NUL; the counted
`key_len` preserves it.) **Apply is a MERGE**, never an assign: LWW adopt-if-newer, OR-Set union (adds
**and** tombstones), ctime min-register merge — so the receiver's own newer/unsent state survives a
snapshot. After applying, `local_sv` **and** `gc_floor` are raised to the snapshot's SV. CR F is the
fallback when a peer has fallen behind the GC floor (the ops it lacks are gone from the oplog) and the
authoritative replacement for the P10 BURST (§10.1).

### 6.5 Collection enum (wire-critical)

```
SERVERS=0  USERS=1  NICKS=2  CHAN_MEMBERS=3  TOPICS=4  MODES=5
MEMBER_STATUS=6  CHANMETA=7  CHAN_BANS=8  CHAN_EXCEPTS=9  CHAN_CTIME=10  KICK_INFO=11
```

(`crdt_state.h:124-137`.) These integers are the 1-byte `coll` field in every op and snapshot LWW
entry. **Reordering the enum is a protocol break.**

---

## 7. Anti-entropy protocol (S / D / U / F / V)

The durable-state sync. Each node, on its 30 s verify tick, broadcasts a `CR S` to every direct CRDT
peer (`crdt_sync_broadcast` → `crdt_sync_request`, `m_crdt.c:111`).

### 7.1 CR S — sync request

```
:<src> CR S <digest:016x> :<b64(state_vector)>      (Fix-A form, parc≥4)
:<src> CR S :<b64(state_vector)>                     (legacy form, parc==3 — no digest)
```

`<digest>` is the sender's full `crdt_state_digest` as 16 lowercase hex chars (`m_crdt.c:128`). On
receipt (`m_crdt.c:263`), the responder:

1. records the peer's SV (`crdt_shadow_record_peer_sv`, keyed by the peer numeric) for GC;
2. if the peer is **behind the GC floor** → reply `CR F` (snapshot — a delta would be incomplete);
3. else if (Fix-A) the peer's **SV equals ours but its digest differs** → reply `CR F`. This is an
   *SV-invisible divergence* a delta cannot repair (the delta would be empty); the snapshot's
   commutative HLC-merge is the only content-level reconcile. Because both peers broadcast `CR S` each
   cycle, the merge converges both in one round. The SV-equal gate keeps this from firing during
   normal op-lag.
4. else → reply `CR D` with the delta the peer lacks.

### 7.2 CR D / CR U — delta chunks

```
:<src> CR D <id> <+|.> :<b64-chunk>      (delta: ops the recipient lacks, or an eager relay)
:<src> CR U <id> <+|.> :<b64-chunk>      (update: the sender's own new ops since last push)
```

Both carry a §6.3 binary delta and are reassembled per §3.3. `CR U` (`crdt_sync_push`, `m_crdt.c:142`)
fans the sender's own newly-created ops to all direct peers (encoded once). `CR D` is the response to
`CR S` **and** the **eager multi-hop relay** (`crdt_relay_delta`, `m_crdt.c:171`): on applying a
delta with ≥1 new op, a node re-emits the whole blob as `CR D` to its *other* CRDT peers (gossip
flood). Termination: a peer that already has the ops applies 0 and does not re-relay (the `applied>0`
guard + SV dedup), so the cascade dies out — and under redundant mesh paths the same dedup makes
duplicate arrivals harmless.

On a successful delta apply, the receiver runs the reconcile suite (materialize doc→live + §17.7
gateway to legacy) in dependency order: users → topics → modes → create-channels → members →
birth-modes → removes → member-status → bans → user-removes (`m_crdt.c:319-328`).

### 7.3 CR F — full snapshot chunks

```
:<src> CR F <id> <+|.> :<b64-chunk>
```

Carries a §6.4 snapshot. Applied once fully reassembled (`crdt_shadow_apply_snapshot`); if the
receiver is CRDT-primary and still mid-burst from this peer (`IsBurstOrBurstAck`), it then builds live
state from the doc (`crdt_shadow_materialize_live`) — the authoritative BURST replacement (§10.1).

### 7.5 CR V — version broadcast

```
:<src> CR V :<b64(state_vector)>
```

Defined and **handled** (`m_crdt.c:361`: record the peer's SV for causal-stability GC) but **no
sender emits it** in the current code — `CR S` carries the SV for both anti-entropy and GC. CR V is
effectively reserved/received-only; a peer that never hears CR V still has its SV recorded from CR S.

---

## 8. Ephemeral messaging — CR M

A live `PRIVMSG`/`NOTICE`/`TAGMSG` to a user (or channel) that is mesh-reachable but tree-partitioned
is gossiped as an **ephemeral** CR M line. It **never enters the doc/oplog/snapshot**.

```
:<src> CR M <msgid> <cmd> <srcYXX> <target> :<payload>
```

- `<msgid>` — the message id, or `*` if none. Dedup is by a **time-windowed** set
  (`CRDT_M_SEEN_WINDOW = 90 s`, `m_crdt.c:203`) so a duplicate arriving via a slower mesh path is
  still recognised; `*` is never deduped against another `*`.
- `<cmd>` — `P` PRIVMSG, `N` NOTICE, `T` TAGMSG (payload is the client-only tag string).
- `<srcYXX>` — the source user's 5-char numeric; the source identity (`nick!ident@host`) is
  reconstructed on each receiver from the converged doc (the sender may not be live there).
- `<target>` — a 5-char user numeric (unicast) or a `#`/`&` channel.

Each receiver (`m_crdt.c:368`): drop if msgid already seen (flood dedup); deliver to the **local**
target (a local user, or all local members of a channel) with the reconstructed prefix; then **relay**
onward to its other CRDT peers (excluding the source) — exactly-once via the dedup. A second per-server
local-delivery dedup (`crdt_shadow_chan_local_check_add`) prevents a redundant CR-M local delivery
when the P10 tree already delivered the same msgid, while still relaying the flood. On a gateway node
the channel message is also re-emitted to **legacy** P10 peers (forbid CRDT-aware) so legacy members
reachable only via the gateway receive it once (R6b); a mesh-only source is skipped (legacy can't
place it — that is the R6c presentation case, see the implementation doc).

---

## 9. Liveness — CR H beacon

```
:<src> CR H <srvYXX> <emit_ts> <nn_capacity> <peers> :<name>     (full, parc≥7)
:<src> CR H <srvYXX> <emit_ts> <nn_capacity> :<name>            (no peers, parc==6)
:<src> CR H <srvYXX> <emit_ts>                                  (minimal, parc==4)
```

Each node gossips its own beacon every 30 s (`crdt_gossip_beacon`, `m_crdt.c:238`). Fields:

- `<srvYXX>` — the beaconing server's numeric (single-writer-per-key: only the owner emits its own).
- `<emit_ts>` — `CurrentTime` at emit (decimal seconds).
- `<nn_capacity>` — the server's client-numeric capacity (3 base64 chars); lets a receiver build a
  right-sized synthetic anchor.
- `<peers>` — the emitter's comma-joined direct-CRDT-peer numerics, or `*` if none. This is the
  **mesh-map** adjacency row: single-writer, ephemeral, **outside the digest** (cannot cause
  divergence). Receivers assemble these rows and derive reachability by **local BFS**, pruning
  beacon-stale rows — observability only (the `/CRDT` diagram + presence-diff), never routing.
- `<name>` — the server name (always the trailing param, so older receivers reading
  `cap=parv[4], name=parv[parc-1]` stay correct and just ignore the inserted `peers` field —
  forward-compatible append-only extension).

Receiver (`m_crdt.c:474` → `crdt_shadow_beacon_record`, `crdt_shadow.c:89`): record into
`crdt_beacon[srvYXX]` and **relay if the emit_ts is newer** than the last seen for that server; a
dup/old beacon is dropped (terminating the flood). A beacon older than **`CRDT_BEACON_STALE = 90 s`**
(three verify intervals) marks the server gone: the verify server census ignores it, the materialize
keep-gate refuses to anchor it, and the 30 s timer sweeps any `STAT_MESH_SERVER` stub whose beacon has
gone stale. **The beacon set is the presence oracle.**

---

## 10. Interplay with the P10 tree

### 10.1 BURST → CR F

A CRDT-primary sender, bursting to a CRDT-aware peer whose doc-source is ready, sends a **CR F
snapshot instead of the P10 user/channel/session BURST**, then EOB + EOB_ACK (`server_finish_burst`,
`s_serv.c:335`). The SERVER tree and ban-class bursts (gline/shun/jupe/zline) are sent first in
`server_estab`, so routing + bans hold. If the local doc is not yet a complete source (cold boot,
`!crdt_shadow_doc_ready`), it falls back to a normal P10 BURST. (`m_burst.c` has no CRDT gate, so a
real BURST received by a CRDT peer is applied normally — the cutover is sender-side only.)

### 10.2 SERVER — kept

P10 SERVER introductions are **always emitted** among CRDT peers (the routing-prefix hierarchy is
preserved). See §4 for the formats. **Full SERVER retirement is not part of this protocol** — P10's
flat-namespace hierarchical delivery requires every relaying server's prefix to be known
network-wide, so a SERVER intro cannot be suppressed without orphaning everything sourced through it
(e.g. legacy servers relayed into the mesh). Retiring SERVER would require mesh-native routing, out of
scope.

### 10.3 SQUIT — suppressed among CRDT peers (R7a)

A server departure is **not** SQUIT-broadcast to CRDT-aware-both-ends peers; it rides the CR H beacon
instead (the beacon goes stale → the keep-gate + sweep retire the server). Suppression rule:

```
suppress  ⇔  FEAT_CRDT_MESHMAP_PRESENCE  ∧  FEAT_CRDT_PRIMARY
              ∧  receiver is a CRDT-aware server  ∧  subject is a CRDT-aware server
```

(`crdt_should_suppress_tree`, `crdt_meshmap.c:222`; applied at the direct-to-victim SQUIT
`s_misc.c:909` and the downlink broadcast `s_misc.c:1047`.) A legacy subject (no beacon) or a legacy
receiver (never learns the beacon) is **never** suppressed — they still get the P10 SQUIT. A
*presented* partition stub is SQUIT to legacy exactly once on retire/relink (R6c,
`crdt_shadow_retire_mesh_stub`, `s_misc.c:796`).

The user-departure (QUIT) relay is likewise suppressed to CRDT peers (`s_misc.c:1075`); the leave
rides the doc (a `users` delete-tombstone) and is gateway-re-emitted to legacy.

### 10.4 The §17.7 gateway (doc → legacy P10)

Doc-originated changes reach legacy peers as ordinary P10 because the reconcilers drive them through
the real handlers (`set_nick_name`/`set_user_mode`/`exit_client`/JOIN-PART-MODE emits) with
`cptr =` the CRDT uplink; the handler's relay is gated to legacy-only (`forbid = FLAG_CRDT_AWARE`) and
its CRDT write-hook self-skips (the change came *from* a CRDT peer). So a legacy server on the far
side of a CRDT mesh sees a faithful P10 stream (NICK/JOIN/MODE/KICK/PART/QUIT/PRIVMSG) with real
source identities. See `CRDT_MESH_IMPLEMENTATION.md §6`.

---

## 11. Constants & limits

| Constant | Value | Where | Meaning |
|---|---|---|---|
| `CR_CHUNK_LEN` | 400 | `m_crdt.c:45` | base64 chars per D/U/F chunk line |
| `CR_DELTA_MAX` | 65536 | `m_crdt.c:43` | max raw delta bytes per exchange |
| `CR_SNAP_MAX` | 262144 | `m_crdt.c:44` | max raw snapshot bytes |
| `S2S_CHUNK_MAX` | 64 | `s2s_chunk.h:24` | max concurrent reassemblies network-wide |
| `CRDT_BEACON_STALE` | 90 s | `crdt_shadow.c:77` | beacon staleness = "server gone" |
| `CRDT_M_SEEN_WINDOW` | 90 s | `m_crdt.c:203` | CR M dedup window |
| `CRDT_VERIFY_INTERVAL` | 30 s | `crdt_shadow.c:69` | verify/anti-entropy/beacon cadence |
| `CRDT_MAX_SERVERS` | 4096 | `crdt_types.h:32` | SV / beacon array dimension (= NN_MAX_SERVER) |
| HLC | 12 B wire | `crdt_wire.h:34` | physical(8) + logical(2) + node(2) |
| digest | 16 hex | `m_crdt.c:128` | full doc digest in CR S |

---

## 12. HLC & message-id seeding

The engine HLC (`§CRDT_MESH_IMPLEMENTATION.md 3.2`) is the same clock that seeds the S2S message-id.
`generate_msgid` (`send.c:444`) advances `hlc_global_event()` and emits a 14-char id =
`YY(node_id) + LLL(logical, 3×b64) + QQQQQQQQQ(counter, 9×b64)`; the full S2S tag form is
`@A<time_b64_7><msgid_14>`, with `physical_ms` carried as the 7-char time field. On receive
(`parse.c:1883`), the remote HLC is reconstructed (physical from the time field, logical+node from the
msgid) and folded in via `hlc_global_receive`. Thus durable op timestamps and the message-id share one
causal clock per server.

---

## 13. Versioning & compatibility

- **CR is additive and gated.** A non-CRDT peer never receives CR (it lacks `C`), and a CRDT build
  with `FEAT_CRDT_ENABLED` off neither emits nor applies it.
- **Append-only beacon.** The `<peers>` field was appended *before* the trailing `<name>`; older
  receivers that read `cap=parv[4], name=parv[parc-1]` remain correct and ignore peers (§9). Future
  beacon fields must follow the same trailing-name discipline.
- **Enum-order = wire contract.** `enum CrdtCollection` and `enum CrdtOpType` integer values ride on
  the wire (§6.2, §6.5). They are append-only; reordering breaks compatibility.
- **Struct-blob layout.** LWW `SET` values are raw struct memcpys, so record layout (field order +
  padding) is part of the wire format and must match across peers of the same build. Records are
  zero-filled before encoding so padding is deterministic. (A cross-architecture deployment would need
  the layout pinned — currently it assumes a common build.)
- **Mixed CR versions** interoperate at the subcommand level (an unknown sub is ignored; CR V is
  already a received-only example), but **not** across an op/snapshot binary-format change without an
  explicit version negotiation, which this protocol does not yet carry.

---

## 14. Quick reference — every CR line

```
:<src> CR S <digest16> :<b64(SV)>                         sync request (+digest, Fix-A)
:<src> CR S :<b64(SV)>                                    sync request (legacy, no digest)
:<src> CR D <id> <+|.> :<b64(delta)>                      delta chunk (reply / eager relay)
:<src> CR U <id> <+|.> :<b64(delta)>                      own-ops update chunk
:<src> CR F <id> <+|.> :<b64(snapshot)>                   full snapshot chunk (BURST replacement)
:<src> CR V :<b64(SV)>                                    version broadcast (received-only)
:<src> CR M <msgid> <P|N|T> <srcYXX> <target> :<payload>  ephemeral message gossip
:<src> CR H <srvYXX> <emit_ts> <nn_cap> <peers> :<name>   liveness beacon (+mesh-map peers)
       CRDTMESH <name> <numeric> :<info>                  (token CM) overlay-link handshake
```
