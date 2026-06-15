# CRDT-Mesh — As-Implemented Reference

> Branch: `crdt-mesh`. This is a **parallel-exploration fork** of Nefarious (evilnet/nefarious2),
> not the production path. It replaces P10 tree replication of network state with a custom-C CRDT
> document synchronised over a mesh, bridged back to the legacy P10 tree by a P10↔CRDT gateway.
>
> Companion document: **`CRDT_S2S_PROTOCOL.md`** — the byte-exact wire protocol. This document
> describes the *implementation* (architecture, data structures, control flow); the protocol doc
> describes the *wire*. They cross-reference.
>
> All file:line citations are against the `crdt-mesh` branch at the time of writing and are meant as
> navigation aids, not guarantees of stability across edits.

---

## 1. Overview & design stance

The fork keeps the full P10 server-to-server tree but makes a **CRDT document** the authoritative
source for network *state* (users, channels, membership, modes, topics, bans) among CRDT-aware
servers. The document converges by commutative merge (LWW maps + OR-Sets + an HLC clock), so the
order in which deltas arrive does not matter and a partition heals without a designated
re-synchroniser.

Three properties shape every design decision:

1. **Additive and feature-gated.** Nothing activates unless the relevant `FEAT_CRDT_*` flag is set
   (all default **off** — `ircd/ircd_features.c:1359-1367`). A stock build behaves exactly like
   upstream P10. The fork was developed as a staged ladder of flags (shadow → sync → mesh → primary)
   so each layer could be measured before the next was trusted.

2. **The legacy tree is never abandoned.** P10 SERVER introductions are *kept* among CRDT peers —
   they are the routing-prefix hierarchy P10 delivery depends on, and legacy (non-CRDT) servers
   reached *through* the mesh rely on them (see §9, "R7 outcome"). Only the **P10 BURST** of state
   and the **SQUIT** departure signal are replaced/suppressed for CRDT-aware peers; the §17.7 gateway
   re-emits doc-driven changes to legacy peers as ordinary P10.

3. **Convergence is observable.** Every node runs a 30 s verify timer that logs a document digest, a
   *materialized* digest (the true convergence metric), a doc-vs-live mismatch count, and a
   beacon-derived server census. A gossiped mesh-map + the oper `/CRDT` command expose topology and
   presence.

### Feature-flag ladder (`include/ircd_features.h:498-506`, `ircd/ircd_features.c:1359-1367`)

| Flag | Default | Role |
|---|---|---|
| `FEAT_CRDT_ENABLED` | off | Master switch. Builds the doc, runs the verify timer, accepts/relays CR tokens (`shadow_on()` = `g_inited && FEAT_CRDT_ENABLED`, `crdt_shadow.c:221`). |
| `FEAT_CRDT_SYNC` | off | (reserved) sync staging. |
| `FEAT_CRDT_MESH` | off | (reserved) mesh staging. |
| `FEAT_CRDT_PRIMARY` | off | The cutover: the doc *drives live state* (materialize from doc, reconcile suite, §17.7 gateway, CR-F-instead-of-BURST). Without it the doc is shadow-only (observe + digest). |
| `FEAT_CRDT_GC_INTERVAL` | 60 | (int) GC cadence knob. |
| `FEAT_CRDT_BATCH_MS` | 10 | (int) delta batching window. |
| `FEAT_CRDT_STALE_TIMEOUT` | 300 | (int) staleness knob. |
| `FEAT_CRDT_OPLOG_MAX` | 100000 | (int) oplog ceiling. |
| `FEAT_CRDT_MESHMAP_PRESENCE` | off | Tier-2/R7a: derive the keep-gate + presence from the **beacon set** (vs the coarse "any live transport" heuristic), and enable **R7a SQUIT suppression** among CRDT peers. |

---

## 2. Layered architecture & file map

```
   live IRC events (JOIN, NICK, MODE, …)         doc deltas from peers (CR D/U/F)
            │  write-hooks                                  │  apply
            ▼                                               ▼
   ┌──────────────────────────  crdt_shadow.c  ──────────────────────────┐
   │  capture live → doc        materialize doc → live      §17.7 gateway │   integration layer
   │  reconcile suite           anchors / mesh stubs        verify timer  │
   └───────────────┬───────────────────────────────────────┬────────────┘
                   │ engine API                             │ P10 emits (legacy-only)
                   ▼                                        ▼
   ┌──────── crdt_state.c / crdt_types.c / crdt_hlc.c ──────┐   ┌── s_serv.c / m_server.c ──┐
   │  LWW maps · OR-Sets · oplog · HLC · digest · GC · SV    │   │  link estab · BURST→CR-F  │   P10 interop
   └────────────────────────┬───────────────────────────────┘   │  SERVER kept · SQUIT R7a  │
                            │ encode/decode                       └────────────┬─────────────┘
                            ▼                                                   │
                   ┌──── crdt_wire.c ────┐   ┌──── m_crdt.c ────┐   ┌── s_misc.c ──┐
                   │ binary op/SV/snap   │   │ CR token I/O      │   │ exit_client  │
                   │ base64 (RFC4648)    │   │ chunk · relay     │   │ keep-gate    │
                   └─────────────────────┘   │ beacon · CR M     │   └──────────────┘
                                             └────────┬─────────┘
                                                      ▼
                                         s2s_chunk.c (reassembly)
```

| File | Role |
|---|---|
| `ircd/crdt_types.c` / `include/crdt_types.h` | CRDT primitives: LWW map, OR-Set (+priority), oplog, tags/tombstones, state-vector, msgid dedup set. Pure libc, cmocka-tested. |
| `ircd/crdt_state.c` / `include/crdt_state.h` | The document (`CrdtNetworkState`): 12 collections, record structs, op application, digest/mdigest, GC. Pure libc. |
| `ircd/crdt_hlc.c` / `include/crdt_hlc.h` | Hybrid Logical Clock. Pure libc. |
| `ircd/crdt_wire.c` / `include/crdt_wire.h` | Big-endian binary serialization of SV / op / delta / snapshot + RFC-4648 base64. Pure libc. |
| `ircd/crdt_shadow.c` / `include/crdt_shadow.h` | **Integration layer** (~2700 lines): write-hooks, materialize, reconcile suite, §17.7 gateway, anchors/stubs, verify timer, beacon record + presence. The only file coupled to `struct Client`. |
| `ircd/crdt_meshmap.c` / `include/crdt_meshmap.h` | Gossiped topology map (single-writer adjacency, local BFS reachability). Pure libc, cmocka-tested. Includes the pure `crdt_should_suppress_tree()` R7a gate. |
| `ircd/m_crdt.c` | The `CR` P10 token handler: subcommand dispatch, chunked send, anti-entropy, eager relay, CR M gossip, CR H beacon. |
| `ircd/m_crdtinfo.c` | The oper `/CRDT [map\|peers\|status]` command (`mo_crdt`). |
| `ircd/crdt_sim.c` | Off-line CRDT simulator (development harness; not in the live path). |
| `ircd/s2s_chunk.c` / `include/s2s_chunk.h` | Generic (link,id)-keyed reassembly for oversized base64 payloads spanning multiple P10 lines. |

P10 integration points live in the stock files: `m_server.c` (SERVER parse + `mr_crdtmesh`), `s_serv.c`
(link establishment, BURST cutover), `s_misc.c` (`exit_client` keep-gate + SQUIT suppression +
`crdt_shadow_retire_mesh_stub`), `s_bsd.c` (overlay outbound handshake + ping exemption), `parse.c`
(msgtab), `s_user.c` (NICK/umode gateway relays).

---

## 3. The engine — document model

### 3.1 CRDT primitives (`crdt_types.{c,h}`)

**LWW map** (`CrdtLWWMap`, `crdt_types.h:195`) — last-writer-wins register map, 256 fixed buckets, no
rehash. A value (`CrdtLWWValue`, `:180`) is `{ void *data; uint32_t data_len; struct HLC ts; uint16_t
writer; }`. `crdt_lwwmap_set` (`crdt_types.c:375`) applies a write **iff strictly newer** by
`hlc_compare` (a tie is a no-op — HLC compares break ties on `node_id`, so a true tie is the same
write). **Delete is an LWW write** with `data=NULL, data_len=0` and an `int deleted=1` flag on the
entry — there is no separate tombstone store; `crdt_lwwmap_get` returns NULL for absent *or* deleted,
while `crdt_lwwmap_is_deleted` (`:423`) distinguishes an explicit tombstone from absence (the
delete-on-leave gate).

**OR-Set** (`CrdtORSet`, `crdt_types.h:103`) — observed-remove set with removal priorities, 64 fixed
buckets for entries + 64 for tombstones, no rehash. An add creates an add-tag `CrdtTag {uint16_t
origin; uint64_t seq;}`; a remove writes a `CrdtTombstone {CrdtTag tag; uint8_t priority;}` for each
currently-uncovered add-tag. `crdt_orset_contains` (`crdt_types.c:199`): present iff some add-tag has
**no** tombstone *and* no add-tag is covered by a **priority>0** tombstone. So:

- **priority 0** (PART / voluntary leave, `CRDT_PRIORITY_USER`): add-wins — a concurrent re-add
  (new tag) survives a priority-0 remove.
- **priority > 0** (`CRDT_PRIORITY_CHANOP=2` KICK, `CRDT_PRIORITY_SERVICES=3`, `CRDT_PRIORITY_IRCD=4`):
  suppresses the **whole element** regardless of concurrent adds (a kicked user cannot instantly
  re-appear via a racing JOIN). (Value 1 is unused.)

`crdt_orset_is_explicitly_removed` (`:213`) returns false for an absent element and true only for a
tombstoned one — the doc→live reconcile-remove gate that fires on tombstone, never on absence (the
sync-lag safety: a not-yet-materialized user is *absent*, not *deleted*).

**Oplog** (`CrdtOpLog`, `crdt_state.h:159`) — singly-linked FIFO of `CrdtOp` (`:139`). Op types
(`enum CrdtOpType`, `:117`): `CRDT_OP_ADD=0`, `CRDT_OP_REMOVE=1` (OR-Set), `CRDT_OP_SET=2`,
`CRDT_OP_DELETE=3` (LWW). Each op carries `{origin, seq, type, coll, chan?, key, tag+priority (OR-Set)
| val+ts+writer (LWW)}`. Every local mutation `record()`s (`crdt_state.c:180`): append to oplog +
`crdt_sv_update(local_sv, origin, next_seq++)`.

### 3.2 HLC — hybrid logical clock (`crdt_hlc.{c,h}`)

`struct HLC { uint64_t physical_ms; uint16_t logical; uint16_t node_id; }` (`crdt_hlc.h:16`).
Separate integer fields (not bit-packed). `hlc_compare` is lexicographic
physical_ms → logical → node_id. The global clock is seeded at `ircd.c:1243` with
`hlc_init(base64toint(cli_yxx(&me)))` (node_id = own server numeric). `hlc_local_event` bumps logical
within the same millisecond; `hlc_receive` advances on inbound timestamps (four cases, each
overflow-guarded). The engine HLC is the same clock that seeds the S2S message-id (see
`CRDT_S2S_PROTOCOL.md §7`).

### 3.3 The document — 12 collections (`CrdtNetworkState`, `crdt_state.h:191`)

| Collection | CRDT type | Key | Value | `coll` enum |
|---|---|---|---|---|
| `servers` | LWW map | numeric (decimal) | `CrdtServerRecord{state}` (ACTIVE/SPLIT) | `CRDT_COLL_SERVERS=0` |
| `users` | LWW map | client numeric | `CrdtUserRecord` (368 B) | `CRDT_COLL_USERS=1` |
| `nicks` | LWW map | lowercased nick | `CrdtNickClaim` (80 B) | `CRDT_COLL_NICKS=2` |
| channel `members` | OR-Set | user numeric | (tags) | `CRDT_COLL_CHAN_MEMBERS=3` |
| `topics` | LWW map | channel name | topic string | `CRDT_COLL_TOPICS=4` |
| `modes` | LWW map | channel name | mode-snapshot blob | `CRDT_COLL_MODES=5` |
| `members_status` | LWW map | `chan\0numeric` | `CrdtMemberRecord{status,oplevel}` | `CRDT_COLL_MEMBER_STATUS=6` |
| `chanmeta` | LWW map | channel name | `CrdtChanMeta{ctime,topic_time,topic_nick}` | `CRDT_COLL_CHANMETA=7` |
| channel `bans` | OR-Set | +b mask | (tags) | `CRDT_COLL_CHAN_BANS=8` |
| channel `excepts` | OR-Set | +e mask | (tags) | `CRDT_COLL_CHAN_EXCEPTS=9` |
| channel `ctime` | MIN-register | (per channel) | `uint64 ctime` (+set/del HLC) | `CRDT_COLL_CHAN_CTIME=10` |
| `kick_info` | LWW map | `chan\0numeric` | `CrdtKickInfo{kicker,reason}` | `CRDT_COLL_KICK_INFO=11` |

> **The `coll` integer values are a wire contract** — they ride as the 1-byte `coll` field of every
> op and snapshot entry (`crdt_op_encode`, `crdt_wire.c:113`). Reordering `enum CrdtCollection`
> (`crdt_state.h:124-137`) is a protocol break.

**Key record structs** (memcpy'd whole-struct into LWW values; sizes are gcc x86-64 LP64):

- `CrdtUserRecord` (368 B, `crdt_state.h:54`): `nick[32]`, `ident[16]`, `host[80]` (displayed),
  `realhost[80]` (real, kept separate so the gateway emits the real host and oper WHOIS / ban-match
  see it), `realname[56]`, `account[32]`, `umodes[32]` (`umode_str` form), `ip6[16]`, `nick_ts`,
  `acc_create`, `server` (owning numeric, for SQUIT visibility). Hopcount is deliberately **not**
  stored (observer-relative; recomputed at materialize).
- `CrdtMemberRecord` (4 B, `:80`): `status` bitmask (`OP=0x01|VOICE=0x02|HALFOP=0x04`) + `oplevel`.
- `CrdtKickInfo` (166 B, `:90`): `kicker[6]` numeric + `reason[160]`. KICK-vs-PART is decided by
  comparing this entry's HLC against the `members_status` last-join HLC.
- `CrdtNickClaim` (80 B, `:105`): `numeric[6]`, `claimed_at` HLC, `ident[16]`, `ip` (IPv4 only),
  `account[32]`.
- Channel `ctime` is a per-channel **incarnation MIN-register** on `CrdtChannel` (`:169`): live iff
  `ctime_set > ctime_del`; merge keeps `max(del)` and, among still-live incarnations, the **lower
  ctime value** (IRC's lower-TS-wins, *not* LWW — a key correctness point: LWW would converge to the
  higher TS and permanently split CRDT-vs-legacy).

> **Determinism note.** These blobs are memcpy'd and hashed byte-for-byte (including struct padding).
> The integration layer `memset`-zeroes every record before filling it (`crdt_shadow.c:320, 331, 412,
> 446`), so padding is deterministic in practice. The engine itself does **not** enforce this; a future
> caller that fills a record without zeroing first would diverge. (The ctime payload additionally
> field-copies its HLCs, `crdt_state.c:397-404`.)

### 3.4 State vector, dedup, causal stability

`CrdtStateVector { uint64_t seq[CRDT_MAX_SERVERS=4096]; }` (`crdt_types.h:247`) — `seq[n]` = highest op
seq seen from server `n` (32 KB/vector). `local_sv` = what this node has seen; `gc_floor` = highest
reclaimed. Dedup: `crdt_state_apply_op` (`crdt_state.c:665`) drops an op already covered by
`crdt_sv_has_seen(local_sv, origin, seq)`. The **causal-stability floor** is the component-wise min
across `local_sv` and every connected peer's cached SV (`crdt_sv_global_min`); an op below the floor
has been seen by everyone and is safe to GC.

A **separate** dedup set, `CrdtMsgidDedup` (`crdt_types.h:281`, time-windowed open-addressing, 8192
slots), dedups the *ephemeral* CR M gossip — distinct from the SV (which dedups the durable oplog).

### 3.5 Digest vs materialized digest (`crdt_state.c:887` / `:935`)

Both are order-independent FNV-64 XOR-folds; HLC and tags are hashed field-by-field (no padding),
LWW values as raw blobs.

- **`crdt_state_digest`** (the "full" digest) hashes LWW values **and** OR-Set add-tags **and**
  tombstones. Two nodes that have GC'd different tombstone subsets produce **different** full
  digests even though their *visible* state is identical.
- **`crdt_state_digest_materialized`** (mdigest) hashes only **present** OR-Set elements (no tags, no
  tombstones) plus the LWW values. This is the **true convergence metric** — it is invariant under
  GC timing. (All testbed convergence gating uses mdigest, never the full digest.)

### 3.6 Garbage collection (`crdt_state_gc`, `crdt_state.c:1058`)

Driven by the causal-stability floor. (1) Oplog GC frees causally-stable ops; if a stable op is a
`CRDT_OP_DELETE`, also reclaim the matching LWW delete-tombstone via `crdt_lwwmap_gc_deleted`
(frees only if still a tombstone at the op's exact ts → delete/re-add safe). (2) OR-Set tombstone GC
(`crdt_orset_gc`) drops stable tombstoned add-tags, then empty entries, then stable tombstones.
(3) `gc_floor` rises to the stable SV; a peer below `gc_floor` can no longer be served a delta and is
escalated to a CR-F snapshot. A separate pass (`crdt_state_reclaim_orphan_member_meta`, `:1033`) mints
DELETE ops for `members_status`/`kick_info` of members fully gone from the OR-Set, so that metadata
rides tombstone GC instead of leaking.

> **Known caveat** (`crdt_types.h:147-154`): OR-Set GC is only fully sound over priority-0 churn; a
> late concurrent add can resurrect once a suppressing priority>0 tombstone is freed. Acknowledged
> latent issue; in practice KICK tombstones outlive the rejoin window. See §9.

---

## 4. Integration layer — capture (live → doc)

When `FEAT_CRDT_ENABLED`, live IRC events call write-hooks that record ops into the doc:
`crdt_shadow_user_add` (`crdt_shadow.c:444`), `crdt_shadow_user_remove` (`:469`),
`crdt_shadow_join` (`:352`), `crdt_shadow_part` (`:382`), `crdt_shadow_kick` (`:397`),
`crdt_shadow_modes` (`:795`), `crdt_shadow_topic` (`:744`), `crdt_shadow_lists` (`:861`), etc.

Every hook begins with the **self-skip**:

```c
static int from_crdt_peer(struct Client *from)              /* crdt_shadow.c:249 */
{
  return from && from != &me &&
         (IsServer(from) || IsMeshStub(from)) && IsCrdtAware(from);
}
```

`if (from_crdt_peer(from)) return;` — when a change *originated* from a CRDT peer (i.e. it is being
applied to live state by the gateway, see §6), the hook does **not** re-mint an op. This is what lets
the gateway drive a change through the real handler without creating a feedback loop or mutating the
doc mid-walk. (`from != &me` matters because `&me` is itself CRDT-aware + IsServer.)

---

## 5. Integration layer — materialize (doc → live)

### 5.1 One user (`crdt_materialize_one_user`, `crdt_shadow.c:1406`)

Turns a `users` doc entry into a live remote `Client`. Gate order:

1. record sanity (`data_len == sizeof(CrdtUserRecord)`);
2. **idempotency**: `if (findNUser(numbuf)) return NULL;` — already live;
3. resolve owning server `srv = FindNServer(srvnum)`:
   - **not found** → **synthetic anchor (Case B)**: if the server's CR H **beacon is fresh**
     (`CurrentTime - crdt_beacon[sidx].recv_ts <= CRDT_BEACON_STALE`) build one via
     `crdt_shadow_make_anchor`; if stale (full partition) return NULL → the user stays hidden
     (correct SPLIT);
   - **found but not a usable parent** (handshake) → retry next pass;
4. `make_client(cli_from(srv), STAT_UNKNOWN)`, recompute hopcount, resolve the §17.5 nick collision
   (`crdt_nick_take` — take the nick or fall back to the numeric), `make_user`, `SetRemoteNumNick`,
   copy ident/host/realhost/realname/account/ip6, `user_apply_umode_str` (flags only), `SetUser`,
   bump `UserStats`.

### 5.2 Anchors & mesh stubs — the partition model

A CRDT server can be reachable via the mesh while gone from the P10 tree. Two representations:

- **Case A — in-place stub** (`crdt_shadow_convert_to_stub`, `:660`): a directly-linked CRDT server
  that SQUITs but is still beacon-fresh is flipped to `STAT_MESH_SERVER` (`SetMeshStub`) in place.
  Its remote users share its (now dead, fd=-1) Connection, so they auto-route to a dead sink
  (presence-only) and stay visible + addressable.
- **Case B — synthetic anchor** (`crdt_shadow_make_anchor`, `:692`): a server we have *no* P10 link
  to but that is beacon-fresh gets a fresh `STAT_MESH_SERVER` `Client` with a fresh owned Connection,
  a beacon-derived real name + right-sized numeric capacity, `SetServerYXX` (so `FindNServer` resolves
  it) but **no routing DLink** (excluded from the tree/burst/SQUIT walks).

`STAT_MESH_SERVER` (`client.h:1023`) is excluded from `IsServer/IsClient/IsRegistered` masks;
`%C` formatting treats a stub as a server (`ircd_snprintf.c`). The keep-gate decides A-vs-teardown:

```c
int crdt_shadow_mesh_reachable(struct Client *srv)          /* crdt_shadow.c:525 */
  → 0 unless shadow_on() && FEAT_CRDT_PRIMARY
  → 0 unless IsServer && IsCrdtAware && cli_serv
  → 0 unless MyConnect(srv)            /* DIRECT peers only — relayed stub crashed */
  → FEAT_CRDT_MESHMAP_PRESENCE ? beacon_ok : coarse_ok
```

`beacon_ok` = the server's own beacon is fresh; `coarse_ok` = any other live CRDT transport exists.
`crdt_shadow_retire_mesh_stub` (defined in `s_misc.c:786`, because it reuses file-static
`exit_one_client`) tears a stub + its held users down on relink or beacon-staleness; for a *presented*
stub (§6) it first emits exactly one legacy SQUIT so the real SERVER intro lands without collision.

### 5.3 Bulk materialize & the reconcile suite

- **Bulk (CR-F):** `crdt_shadow_materialize_live` (`:1577`) walks the whole doc — users first, then
  each channel (skipping dead/draining channels with `ctime==0`, the "zombie" guard) — building live
  state. It is the authoritative replacement for a P10 BURST. The caller gates it on *no inbound
  burst in progress*.
- **Steady-state:** the **reconcile suite** runs every 30 s (and after every applied delta) to drive
  any doc→live drift and §17.7-gateway each change to legacy. All are gated `shadow_on() &&
  FEAT_CRDT_PRIMARY`:

| Reconciler (`crdt_shadow.c`) | Drives | Gate / rule |
|---|---|---|
| `reconcile_users` (`:1797`) | create not-live users + NICK gateway; nick/umode drift | per-user legacy-uplink burst guard; **runs first** |
| `reconcile_user_removes` (`:1828`) | `exit_client` tombstoned users (QUIT) | **only** `crdt_user_is_explicitly_removed` (never absence); collect-then-exit |
| `reconcile_create_channels` (`:1913`) | birth not-live channels | members>0, `!FindChannel`, **`ctime>0`** (zombie guard); local-only |
| `reconcile_members` (`:2294`) | JOIN-add members + JOIN gateway | never creates a channel; oplevel sentinel `MAXOPLEVEL+1` |
| `reconcile_removes` (`:2332`) | PART/KICK + `remove_user_from_channel` | only `is_explicitly_removed`; KICK-vs-PART by `kick_info` HLC > `members_status` HLC |
| `reconcile_member_status` (`:2145`) | +o/+v/+h via `modebuf_flush_nomirror` | doc==live echo guard |
| `reconcile_bans` (`:2218`) | +b/+e ADD (present) / REMOVE (tombstoned) | ADD echo-guarded; REMOVE only `is_explicitly_removed` |
| `reconcile_topics` (`:2002`) | set `chptr->topic` + local TOPIC + gateway | `strcmp(doc,live)==0` echo guard |
| `reconcile_modes` (`:2065`) | persistent channel modes +/− delta | `memcmp` echo guard; `&= CRDT_MODE_MASK` |
| `gateway_birth_modes` (`:1891`) | emit birth-modes of channels born this pass to legacy | runs **after** members place the channel on legacy |

---

## 6. The §17.7 P10↔CRDT gateway

The single most important integration pattern. When `FEAT_CRDT_PRIMARY` is on, the normal P10 relays
inside the *real* handlers (`set_nick_name`, `set_user_mode`, `exit_client`, JOIN/PART/MODE emit
loops) are gated to fire **to legacy peers only** (`forbid = FLAG_CRDT_AWARE`). To bridge a
doc-originated change to legacy, the reconciler drives the change **through that real handler** with
`cptr =` the CRDT uplink:

1. The real handler runs its proven apply logic on live state, **and**
2. its now-legacy-only P10 relay becomes the gateway emit (CRDT peers already have it via the doc), **and**
3. the handler's own `crdt_shadow_*` write-hook **self-skips** via `from_crdt_peer` (the uplink is
   CRDT-aware) — so no op is re-minted and the doc isn't mutated mid-walk.

Canonical example — `crdt_reconcile_user_update` (`crdt_shadow.c:1708`):

| Doc change | Driven through | Legacy relay (the gateway) |
|---|---|---|
| nick | `set_nick_name(cli_from(live), live, newn, 3, …)` | `s_user.c:1264-1280` (`FEAT_CRDT_PRIMARY` → forbid `FLAG_CRDT_AWARE`) |
| umode | `set_user_mode(cli_from(live), live, 3, …)` | `send_umode_out` crdt_gate path, `s_user.c:1581-1596` |
| quit  | `exit_client(cli_from(v), v, v, "Quit")` | QUIT relay loop, `s_misc.c:1060-1090` |
| squit | (R7a suppressed, §8) | `s_misc.c:1056` |

A few changes are emitted **directly** rather than through a handler:
`crdt_gateway_user_intro` (`:1643`, two-call FLAG_IPV6-split NICK sourced from the owning server),
JOIN/PART/KICK/TOPIC emits inside the reconcilers, and channel modes via `modebuf_flush_nomirror`.

### R6c — presenting a partitioned subtree to legacy

When a CRDT server becomes a mesh-only stub on a gateway node that *also* has a legacy peer, legacy
has already SQUIT'd it and cannot place its users. `crdt_present_stub` (`:635`) emits a SERVER intro
for the stub to legacy-only and sets `FLAG_CRDT_PRESENTED`. The single predicate
`crdt_user_is_mesh_only(u)` = `IsMeshStub(srv) && !IsPresented(srv)` (`:265`) flips every §17.7 gate
at once: a *presented* stub is no longer "mesh-only", so all the gateway emits start including its
users. On relink, `crdt_shadow_retire_mesh_stub` emits one matching SQUIT then hands back to the real
SERVER.

---

## 7. Presence & liveness

### 7.1 The CR H beacon

Every node, every 30 s, gossips `crdt_gossip_beacon` (`m_crdt.c:238`):
`CR H <ourYXX> <CurrentTime> <nn_capacity> <peers> :<name>` to all direct CRDT peers. Receivers
record it (`crdt_shadow_beacon_record`, `crdt_shadow.c:89`) into `crdt_beacon[CRDT_MAX_SERVERS]`
(`{emit_ts, recv_ts, name, nn_cap}`) and **relay it if newer** (terminating the flood on a stale/dup
emit_ts). A beacon older than `CRDT_BEACON_STALE = 90 s` (three verify intervals) is treated as gone.
The beacon is the **presence oracle**: the verify's server census counts beacon-fresh numerics
(`crdt_shadow.c:994`), the materialize keep-gate uses beacon freshness, and the 30 s timer sweeps any
`STAT_MESH_SERVER` stub whose beacon has gone stale.

### 7.2 The mesh-map (`crdt_meshmap.{c,h}`)

The beacon carries a `<peers>` field — the emitter's comma-joined direct-CRDT-peer numerics
(**single-writer per node**, ephemeral, **outside the digest** — so it can never cause a digest
divergence). Each node assembles these rows into `g_meshmap` and derives reachability **locally** by
BFS (`crdt_meshmap_reachable`), pruning beacon-stale rows. This is the modelling split that fixes the
abandoned multi-writer "servers-map": *topology* (per-owner, single-writer, convergent) is
replicated; *reachability* (per-viewpoint) is derived locally, never replicated. It is
**observability-only** — it feeds the `/CRDT` diagram and the presence-diff log line, not routing.

`crdt_shadow_presence_diff` (`:1034`) logs, each tick, the set-difference between BFS reachability,
the beacon set, and the P10-tree set — the shadow oracle that validated the model.

### 7.3 `/CRDT` (`m_crdtinfo.c`, `mo_crdt`)

Oper command `/CRDT [map|peers|status]`: an ASCII spanning-tree + cross-edge diagram, the adjacency
list, and a status census (verify + presence-diff + role counts).

---

## 8. P10 interop

### 8.1 CRDT-awareness & the two link kinds

A server advertises CRDT support with `C` in its SERVER flag string; `set_server_flags`
(`m_server.c:491`) sets `FLAG_CRDT_AWARE`. `IsCrdtSyncTarget(x) = MyConnect(x) && IsCrdtAware(x) &&
(IsServer(x) || IsCrdtOverlay(x))` (`client.h:1200`) is the universal "directly-connected CRDT peer"
predicate.

1. **CRDT-aware P10 link** — a normal `STAT_SERVER` whose greeting carried `C`. Carries the P10 tree
   + CR tokens (which dispatch through the SERVER handler slot `ms_crdt`).
2. **CRDT overlay link** (`crdtmesh`) — a dedicated CR-only edge that is **never** a P10 tree edge.
   The conf attribute `crdtmesh;` inside a `Connect{}` block sets `CONF_CRDTMESH` (`s_conf.h:38`).
   Outbound (`s_bsd.c:552`) sends `CRDTMESH <name> <numeric> :<info>` instead of `PASS`+`SERVER`;
   inbound (`mr_crdtmesh`, `m_server.c:704`) verifies the conf + numeric, calls `make_server` but
   **not** `SetServerYXX`/`server_estab`/`add_dlink` (so it never becomes `IsServer`, never enters
   `server_list[]` or the SQUIT cascade), stores the peer numeric in `cli_yxx`, sets
   `FLAG_CRDT_OVERLAY` + `FLAG_CRDT_AWARE`, and stays permanently in `STAT_HANDSHAKE`. Its CR tokens
   dispatch through the UNREG slot `mr_crdt` (gated strictly on `IsCrdtOverlay`). Overlay links are
   exempt from the registration ping timeout (`ircd.c:644`); liveness is by TCP EOF + failing
   anti-entropy writes. The overlay gives the mesh redundant paths so a leaf stays mesh-reachable
   when its P10 parent splits.

### 8.2 BURST → CR-F cutover

`server_finish_burst` (`s_serv.c:335`): if the peer is `IsCrdtAware && FEAT_CRDT_PRIMARY &&
crdt_shadow_doc_ready()`, send `crdt_send_snapshot(cptr)` (a CR-F full snapshot) **instead of** the
P10 user/channel/session BURST, then EOB + EOB_ACK as normal. The SERVER tree and gline/shun/jupe/
zline bursts were already sent earlier in `server_estab`, so routing + bans hold. `crdt_shadow_doc_ready`
guards a cold boot (incomplete doc → fall back to a real BURST). `m_burst.c` has **no** CRDT gate, so
a CRDT peer that *does* receive a real BURST applies it normally — the cutover is purely a
sender-side decision.

### 8.3 SERVER kept; SQUIT suppressed (R7a)

SERVER introductions are **kept** among CRDT peers — all three relay loops (`s_serv.c:204` S-2,
`s_serv.c:281` S-3, `m_server.c:957` ms_server relay) emit the `C` flag and have no CRDT suppression.
This is deliberate: see §9.

SQUIT is suppressed among CRDT-aware-both-ends peers (**R7a**). In `exit_client` (`s_misc.c`):

- direct-to-victim SQUIT (`:909`) and the downlink SQUIT broadcast (`:1047`) are each guarded by
  `crdt_tree_presence_suppress(peer, victim, "SQUIT")`;
- the **keep-vs-teardown** branch (`:1094`): if `crdt_shadow_mesh_reachable(victim)`, tear down the
  deeper subtree, convert the (now-leaf) victim to a stub, and (if it had downlinks) re-materialize
  the subtree via synthetic anchors (R2); otherwise cascade normally and set `crdt_resync_subtree` so
  a beacon-fresh relayed subtree is promptly re-materialized via anchors (and a genuinely partitioned
  one correctly stays gone).

A departed CRDT server is thus discovered by **beacon-staleness** (the keep-gate + sweep) instead of
an up-front SQUIT. The user's beacon is always present at suppress-time, so there is never silent loss
— only a bounded (≤90 s) delay that the keep-gate already imposed regardless of the SQUIT.

The pure decision is cmocka-pinned:

```c
int crdt_should_suppress_tree(int meshmap_on, int primary,             /* crdt_meshmap.c:222 */
                              int peer_aware, int subject_aware)
{ return meshmap_on && primary && peer_aware && subject_aware; }       /* the both-ends rule */
```

`crdt_tree_presence_suppress` (`crdt_shadow.c:590`) feeds it the live flags + per-end `IsCrdtAware`;
while the flag is off but the both-ends candidate holds, it emits a one-line "R7-shadow" measurement
instead of suppressing.

---

## 9. Lifecycle walk-throughs

**Cold link-up (CRDT peer).** SERVER handshake (`C` flag → `SetCrdtAware`) → `server_estab` sends the
SERVER tree + glines etc. → `server_finish_burst` sends a CR-F snapshot instead of BURST → receiver
`crdt_shadow_apply_snapshot` merges it (LWW adopt-if-newer, OR-Set union) → if mid-burst,
`crdt_shadow_materialize_live` builds live state from the doc → EOB. Anti-entropy + beacons then keep
it converged.

**Steady-state op (e.g. JOIN on node A).** Live JOIN → `crdt_shadow_join` records an OR-Set add op →
`crdt_sync_push` fans a CR U delta to direct peers → each applies it (`crdt_shadow_apply_delta`),
**eager-relays** it to *its* other peers (gossip flood, SV-dedup terminates), and runs the reconcile
suite → `reconcile_members` adds the member live + gateways a JOIN to legacy. Periodic CR S
anti-entropy repairs anything missed.

**Partition.** A link drops → the adjacent node's `exit_client` keep-gate converts the peer to a
stub (Case A) or its subtree re-materializes as anchors (Case B), keeping users visible. Beacons stop
arriving; at 90 s the stale-beacon sweep retires the stub and the users go (correct SPLIT). On a
gateway with a legacy peer, R6c presents the stub so legacy keeps seeing the partitioned users.

**Relink.** The real SERVER returns → `crdt_shadow_retire_mesh_stub` SQUITs the presented stub to
legacy (once, at the stub's timestamp) and tears it down → `server_estab`/`server_finish_burst`
re-establish via CR-F → converge.

---

## 10. Known issues, caveats & out-of-scope

- **R7b (full SERVER-tree retirement) is architecturally infeasible** in a hybrid CRDT+legacy P10
  network and was **not** shipped. P10 is a flat server namespace with hierarchical delivery: a
  relayed SERVER carries a source-prefix every downstream server must already know. Suppressing a
  CRDT server's SERVER intro orphans everything sourced through it — notably legacy servers relayed
  into the mesh (e.g. `x3.services` behind the gateway): a leaf with no direct P10 link to the
  suppressed introducer drops the `:introducer SERVER <legacy>` line and can never materialize that
  server's users (and legacy servers don't beacon, so the anchor fallback can't fire). Retiring
  SERVER requires mesh-native routing (flat presentation), not prefix-hiding. SQUIT, by contrast,
  only delays teardown and hides no prefix, so **R7a (SQUIT-only) is the shipped extent.**
- **OR-Set GC vs priority>0 tombstones** (`crdt_types.h:147`): GC is only fully sound over priority-0
  churn; a late concurrent add can resurrect once a suppressing KICK tombstone is freed. Acknowledged;
  mitigated in practice because tombstones outlive the rejoin window.
- **Record blob determinism** relies on the integration layer's `memset`-before-fill (§3.3). The
  engine does not enforce it.
- **`CrdtNickClaim.ip` is IPv4-only** (32-bit) while `CrdtUserRecord.ip6` is full IPv6 — an asymmetry
  in the nick-claim collision metadata.
- **`CrdtChanMeta.creationtime` (LWW) vs the channel `ctime` MIN-register** are two representations of
  creationtime; the MIN-register is authoritative for the incarnation, `chanmeta` carries
  topic-time/topic-nick alongside.
- **CR V is received-only** (records a peer SV for GC); no sender emits it — CR S carries the SV for
  anti-entropy. **No compression** is applied in the CR path today (payload is raw binary → base64 →
  chunk); the `crdt_wire.h` "zstd" comment is aspirational.
- The self-greeting (`s_serv.c:144`) hard-codes the `6vFC` flag tail (this build is always
  CRDT/IPv6/IRCv3/BX-F-aware), whereas the relay loops emit those flags conditionally per server.
- **Transport not yet on CRDT:** chathistory federation, metadata, read-marker and bouncer state still
  ride P10; folding them onto the doc is future work.

---

## 11. Validation status

R7a was validated on the 5-node testnet mesh (`nef3–nef7`, a hybrid with legacy `testnet`/`x3.services`
behind the gateway): cold bringup converged to `5/5/0` single-mdigest with every node at full user
materialization, R7a SQUIT suppression active (no SQUIT to CRDT peers, departures via beacon), zero
crashes, and a clean commanded `/SQUIT`. Engine primitives are cmocka-gated (`crdt_types`,
`crdt_state`, `crdt_meshmap`, `crdt_wire`); the build runs the suites and the image is gated on them.

See also: `CRDT_S2S_PROTOCOL.md` (wire), and the project plans under
`.claude/para/projects/crdt-mesh-*.md`.
