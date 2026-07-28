---
name: crdt-mesh
description: CRDT-mesh S2S subsystem reference for the nefarious-crdt fork — the custom-C CRDT engine (HLC/LWW/OR-Set/state-vector/oplog/GC), the crdt_shadow integration + §17.7 P10↔CRDT gateway, the CR S/D/U/F/V/M/H wire protocol + gossip flood, the FLAG_CRDT_OVERLAY edge, Tier-1 (digest-aware anti-entropy) + Tier-2 (mesh-stub/anchor presence, CR M live delivery, CR H liveness), and the HARD INVARIANTS + audit rules that prevent divergence, resurrection, and STAT_MESH_SERVER crashes. Read before touching any crdt_* code or the CR tokens.
---

# CRDT-mesh Skill

Reference for the `nefarious-crdt` submodule (branch `crdt-mesh`): the experiment that replaces P10
tree/timestamp S2S with a **CRDT mesh + §17.7 hybrid P10↔CRDT gateway**. Custom-C CRDT engine; the
event model (users/channels/topics/modes/members/bans/kicks) is fully CRDT-authoritative. Read this
before writing or modifying any `crdt_*` code, the `CR` tokens, the mesh stub/anchor, or the gateway.

Roadmap + the P10-retirement arc: `.claude/para/projects/crdt-mesh-roadmap.md`. Live per-phase state:
personal memory `project_crdt_mesh_phase0.md`. Testnet topology (expanded to **5 CRDT nodes**
2026-06-11; build/gotcha details in `.claude/para/projects/crdt-mesh-testbed-expansion.md`):
2-deep, 2-branch P10 tree `primary(.2) ← nef3(hub2,.6) ← { nef4(leaf2,.7) ← nef6(leaf4,.14) ;
nef5(leaf3,.9) ← nef7(leaf5,.15) }`, **plus** 4 CR-only overlays nef4↔nef5, nef6↔nef3, nef7↔nef3,
nef7↔nef6 (≥2 disjoint CR paths between most pairs — the R2-depth + R4-multi-path substrate).
Numerics nef3=3 nef4=4 nef5=6 nef6=7 nef7=8; client ports 6669/6670/6672/6673/6674.
**Bring-up gotchas**: depth-2 needs the intermediate `"HUB"="TRUE"` + bare `hub;` on hub2's downlink
Connect block; the `pgrep` healthcheck greens before the 4496 listener (valgrind boot) so sequence
targets-before-initiators or autoconnect gets "refused" → backoff; force a stuck P10 uplink with oper
`CONNECT`; overlays only re-autoconnect on the 10-min `try_connections` cycle (can't force via CONNECT)
— never restart 3+ nodes at once.
**A just-restarted quiet node that logs NOTHING after `Server Ready` (no 30s verify NOTICEs) was in
an event-loop COMA, not merely waiting for overlays** — root-caused 2026-07-28 via `/proc/PID/syscall`:
`engine_epoll.c` passed a NEGATIVE timeout (next-timer overdue after the slow valgrind boot) to
`epoll_wait`, which treats any negative as INFINITE; a node with no clients and no inbound links (it
initiates its overlays) then sleeps until the first external packet — nef7 slept 91 min and woke on a
probe connect. FIXED (clamp overdue→0) in BOTH trees' engine_epoll.c; the sibling engines
(poll/select/kqueue/devpoll) share the pattern and are NOT yet fixed (unused on Linux, each has its
own timeout semantics). If a node goes silent on an old binary: one TCP connect to its client port
wakes it. Verify ticks every 30s in the log are the liveness signal.
 (Older 3-node star nef3+nef4/nef5+overlay is the subset still
described in many notes below.)

## Three layers (keep them straight)

1. **Engine** — `ircd/crdt_types.c` + `ircd/crdt_state.c` + `ircd/crdt_hlc.c` + `ircd/crdt_wire.c`.
   Pure data structures + merge logic. **NO `Client`/`CurrentTime`/event-loop/`feature_int` deps** —
   so it links in the cmocka harness with only `test_stub.o`. Read feature flags / wall-clock in the
   integration layer and pass values in (e.g. `crdt_dedup_check_add(d, id, now, window)`). This purity
   is a HARD RULE — it's what makes the engine TDD-able (`ircd/test/crdt_cmocka.c`, gates the image).
2. **Shadow integration** — `ircd/crdt_shadow.c`. Bridges the live IRCd (`Client`/`Channel`) to the
   engine: hooks that mirror live events INTO the doc, reconcilers that materialize doc state into live
   `Client`s, the §17.7 gateway that re-emits CRDT state to legacy P10, the mesh-stub/anchor model, the
   periodic `crdt_shadow_verify_cb` (30s) that reconciles + GCs + emits beacons.
3. **Wire** — `ircd/m_crdt.c`. The `CR` P10 token family + the gossip substrate.

## Engine primitives (`crdt_types.c` / `crdt_state.c`)

- **HLC** (`crdt_hlc.c`, `struct HLC{uint64 physical_ms; uint16 logical; uint16 node_id;}`) — hybrid
  logical clock; total causal order. **sizeof is 16 but only 12 bytes are used → 4 trailing pad bytes.**
  See the padding audit rule below.
- **LWW map** (`CrdtLWWMap`) — last-write-wins register keyed by string; value + HLC + writer per entry.
  Used for users, nicks, topics, member_status, kick_info, servers(dormant), channel ctime.
- **OR-Set** (`CrdtORSet`) — observed-remove set (add-tags + tombstones); used for channel members,
  bans, excepts. `crdt_orset_contains` (present) vs `crdt_orset_is_explicitly_removed` (tombstoned but
  gone) vs absent — the safe reconcile-remove gate removes only the *explicitly-removed*, never the
  merely-absent (sync-lag guard).
- **State vector** (`CrdtStateVector.seq[CRDT_MAX_SERVERS]`) — per-origin highest op-seq seen. The
  dedup/anti-entropy key. **Summarises op COUNTS, not content** (see the SV-invisible-divergence rule).
- **Oplog** — the replicated op stream (CRDT_OP_SET / CRDT_OP_DELETE), chunked + gossiped as deltas.
- **Causal-stability GC** (`crdt_state_gc`) — frees ops/tombstones every peer has seen (`stable` =
  component-wise min SV across all connected CRDT peers; live `IsCrdtSyncTarget` links ONLY — a split
  peer leaves the set at link-death; zero peers → GC skips entirely). Reclaims oplog + LWW
  delete-tombstones + OR-Set tombstones. Sibling orphan reclaims (all GC-cycle, all mint real ops):
  `crdt_state_reclaim_orphan_member_meta` (members_status/kick_info of fully-departed members),
  `_orphan_chan_meta` (topic/modes/chanmeta of fully-gone channels), `_orphan_silences` +
  `_orphan_tempshuns` (user-anchored: owner wholly absent), `_orphan_members` (2026-07-26: membership
  add-tags of wholly-absent users — the partition-cycle member-residue leak; heal re-merges a healed
  node's still-present adds after the remove-tombstones were GC'd during the darkness). **The USERS-layer
  twin (live-reproduced 2026-07-26: quit-during-partition users RESURRECT network-wide as unkillable
  doc-present zombies when heal lands after complete mainland tombstone GC; KILL can't clean them —
  non-owner exits self-skip the tombstone and reconcile re-materializes) is closed by
  `crdt_shadow_own_user_sweep` (crdt_shadow.c, verify tick, kill-switch `FEAT_CRDT_OWNER_SWEEP`):
  each node reaps its OWN-origin user records with no live Client by minting the DELETE itself
  (single-writer clean; !bursting + 2-pass debounce; also covers restart re-import residue + hookless
  teardowns; live-gated via docker-kill owner death). Op-less-tombstone stickiness (pinned by
  `test_owner_remove_beats_snapshot_reimport`): a snapshot-delivered LWW tombstone has no local oplog
  op so `crdt_state_gc` never reclaims it — safe (anti-resurrection anchor) but permanent local
  residue; a change to either behavior must be conscious.** **DECOMMISSION (2026-07-26,
  "jupe without the jupe part"): `CRDT_COLL_DECOMMISSIONS` standing marker (2-char srvnum →
  {oper,reason}) minted via oper `/CRDT decommission <server|numeric> [remove|<reason>]` (refused
  while target present/beacon-fresh); `crdt_shadow_decomm_sweep` (tick+eager+EOB) reaps the marked
  server's user records + bconns (sessions/leases untouched — revive path owns them) and
  AUTO-DISSOLVES the marker the moment the server returns (dissolve runs BEFORE any reap; never a
  link ban). `crdt_shadow_own_user_reassert` (tick+EOB) is the recovery completion: a live local
  registered user with an absent/tombstoned record is always wrong → re-mint (heals
  wrong-decommission-while-partitioned-alive). **Membership re-assert (`cb88069`): a doc-driven
  PART may NEVER remove a LIVE local member — every legitimate local removal applies live-first,
  so a tombstone that still finds a live MyUser member without KICK attribution is reap residue:
  the reconcile-remove refuses and re-mints join+status in place (fresh add-tag beats old
  tombstones; mainland re-JOINs). Remote KICK-via-doc still applies via the kick_info gate.**
- **Digest vs mdigest** — `crdt_state_digest` (the Fix-A wire digest, on CR S) hashes LIVE content
  ONLY: LWW tombstones and OR-Set covered-tags/tombstones are SKIPPED (**GC-INVARIANT since
  2026-07-26** — hashing per-node GC bookkeeping into the reconciliation trigger drove a live
  PERMANENT full-snapshot oscillation between reclaimed-vs-retained nodes; snapshot exchange cannot
  converge tombstone presence, so it must not be compared). `crdt_state_digest_materialized`
  (mdigest) hashes the live materialized view (also GC-invariant, the convergence oracle — the
  verify NOTICE logs both). Related pinned fact: a snapshot-delivered LWW tombstone has no local
  oplog op and is NEVER reclaimed by `crdt_state_gc` (op-less stickiness — safe anti-resurrection
  anchor, permanent local residue; `test_owner_remove_beats_snapshot_reimport`).
- **`CrdtMsgidDedup`** (R3) — time-windowed open-addressing hash set; `crdt_dedup_check_add(d,id,now,
  window)` → 1 if seen within `window`, else records. Replaces the old count-bounded ring.

## Wire protocol — the `CR` token family (`m_crdt.c`)

All ride normal P10 framing as `:<src> CR <sub> …`. Gossiped to every `IsCrdtSyncTarget` peer
(`MyConnect && IsCrdtAware && (IsServer || IsCrdtOverlay)`):

- **CR S** `<digest> :<sv>` — state-vector advertise (anti-entropy request). Receiver replies with a
  delta the peer lacks, OR a CR F snapshot if the peer is below gc_floor, OR **(Fix A)** a CR F if the
  peer's SV == ours but its digest differs (the SV-invisible-divergence repair).
- **CR D / CR U** `<id> <+|.> :<b64>` — op-delta chunks (D=request reply, U=eager own-origin push).
- **CR F** `<id> <+|.> :<b64>` — full snapshot (chunked); the ONLY content-level reconcile (HLC-merges,
  bypassing SV dedup). Replaces P10 BURST for CRDT-primary peers (`s_serv.c:348`).
- **CR V** `:<sv>` — version broadcast (records a peer's SV for GC).
- **CR M** `<msgid> <cmd> <srcYXX> <target> :<payload>` — **ephemeral** live message (cmd P/N/T;
  target = 5-char YXX or #chan). NEVER touches the doc. msgid-deduped; delivered to the local target/
  channel members with the source prefix reconstructed from the doc (`crdt_shadow_user_record`); then
  relayed onward. The Tier-2 live-traffic substrate.
- **CR H** `<yxx> <emit_ts>` — **ephemeral** liveness beacon, emitted UNCONDITIONALLY every verify
  cycle by every CRDT-primary server; receivers track last-beacon per server (`crdt_beacon[]`); a mesh
  stub whose beacon goes stale (>90s = unreachable via every CRDT path) is retired.

Gossip is a **loop-free flood**: eager multi-hop relay (`crdt_relay_delta`) forwards just-applied ops
to other peers; termination via `applied>0` guard + SV dedup (deltas) / msgid dedup (CR M/H).

## The overlay (`FLAG_CRDT_OVERLAY`)

A CR-only redundant edge between two CRDT servers that carries CR tokens but **never joins the P10
tree** (never `IsServer`, never `SetServerYXX`/`make_server`/`add_dlink`, never trips
`check_loop_and_lh`). `mr_crdtmesh` (m_server.c) registers it; it's auto-excluded from routing/WHO/
links/SQUIT-cascade because it's not `STAT_SERVER`. It IS a first-class **CR-plane** routing edge
(in `IsCrdtSyncTarget`). This is the substrate the P10-routing-retirement (roadmap Track B) builds on.

## Tier-1 — redundant state paths (DONE)

The doc converges across any single partition. **Fix A (digest-aware anti-entropy):** the SV summarises
op counts, not content, so two replicas can share an SV yet hold different content (e.g. a CR F merge or
ctime change that bypasses the oplog). Pure SV-based anti-entropy emits an empty delta for such a pair
and never repairs it. Fix A carries the doc digest on CR S and escalates to a CR F when SV==ours but
digest differs — gated on SV-equality so it never fires during normal op-lag.

## Tier-2 — live-traffic failover + presence (DONE: T2-a/b/c, P1, P2, beacon)

On a CRDT-server SQUIT, instead of cascade-tombstoning, the departed server is KEPT:
- **Mesh stub** (`STAT_MESH_SERVER`, 0x100) — Case A: the directly-linked departed server is converted
  in place (`crdt_shadow_convert_to_stub`); its users stay live + addressable. close_connection already
  left a dead-sink Connection (fd=-1; every send path skips `IsDead || cli_fd(cli_from)<0`).
- **Synthetic anchor** (P2, Case B) — a server with no direct link (reached via another) builds a
  synthetic `STAT_MESH_SERVER` via `crdt_shadow_make_anchor`: `make_client(NULL)` (FRESH owned dead
  Connection) + `make_server` + `SetServerYXX` (FindNServer-resolvable, MAX client mask) but **NO
  add_dlink** (never a routing downlink). Creation gated on a FRESH CR H beacon (mesh-reachable);
  retired by the beacon staleness sweep.
- **Live delivery** — CR M gossip carries PRIVMSG/NOTICE/TAGMSG to/from mesh-only users when the P10
  path is a dead-sink. Hooks in `ircd_relay.c` (relay_* + server_relay_*) and `m_tagmsg.c`. echo-message
  + history fall through for mesh-only unicast targets (the `mesh_delivered` flag pattern).
- **Presence** (P1/P2) — split-born users (connected during the split) materialize onto the stub/anchor
  so they're visible network-wide; on relink they converge with no dup, no tombstone storm.

## HARD INVARIANTS & AUDIT RULES (the expensive lessons — violate at your peril)

1. **Single-writer gate covers mesh stubs.** `from_crdt_peer(from)` =
   `from && from!=&me && (IsServer(from) || IsMeshStub(from)) && IsCrdtAware(from)`. `IsServer` is EXACT
   `cli_status==STAT_SERVER` (0x040); a stub is `STAT_MESH_SERVER` (0x100). Held users' `cli_from` IS
   the stub — if the gate misses `IsMeshStub`, every shadow hook (user_remove/part/…) mints a spurious
   tombstone on stub teardown → HLC-bearing divergence (Fix C).
2. **`IsServer`-exact branches CRASH on a stub used as a message SOURCE.** A `STAT_MESH_SERVER` has
   `cli_serv` set and **`cli_user == NULL`**. Any `IsServer(x) ? server : user` branch (notably the `%C`
   formatter, ircd_snprintf.c) takes the user branch for a stub → derefs `cli_user(stub)->server` →
   SIGSEGV. Treat `IsMeshStub` like a server in those spots (the %C fix), OR don't emit the stub as a
   `%C` source (reconstruct the prefix into `sendrawto`, the CR M pattern). Run the c-auditor on any new
   stub-as-source path. A mesh-only user must NOT be §17.7-gateway'd to legacy (legacy already SQUIT'd
   its server — `crdt_user_is_mesh_only` gate).
3. **Use op-recording setters, never raw primitives.** State cut over to CRDT transport MUST go through
   `crdt_*_set`/`crdt_*_remove` (which `op_new`+`record`), NOT a raw `crdt_lwwmap_set`/`crdt_orset_add`
   — else it only replicates via the CR F snapshot, never via a delta (silent partial replication).
4. **Struct padding into `op->val`: copy HLC fields FIELD-BY-FIELD.** A struct serialized whole into
   `op->val` (memdup) puts its trailing alignment padding on the wire. `struct HLC` is sizeof 16 vs 12
   used; HLCs passed BY VALUE (hlc_max etc.) leave the local's 4 pad bytes uninit. **A `memset` before a
   whole-struct field assignment (`pl.set_hlc = now`) is USELESS** — gcc copies the source's padding
   back. Copy the members (physical_ms/logical/node_id) instead. (And the digest hashes FIELDS not the
   struct, so it's padding-independent — keep it that way.)
5. **Reclaiming a LIVE LWW entry: mint a DELETE tombstone, never local-free.** A local free is
   resurrected by a peer's CR F snapshot that still holds the entry → digest flap. A real DELETE op
   propagates + LWW-wins + rides the existing tombstone GC. Gate the reclaim on the subject being FULLY
   gone (`!contains && !is_explicitly_removed` = removal causally stable). Multi-writer (every peer
   mints) is benign: idempotent + LWW-dedup'd + GC-fast.
6. **SV-equal / digest-different is unrepairable by delta.** Only a CR F snapshot (HLC-merge, bypasses
   SV dedup) reconciles content. Fix A is the trigger. If you change anti-entropy, preserve this.
7. **`ctime` (channel creationtime) is a MIN-register incarnation, NOT LWW.** IRC is lower-TS-wins; LWW
   converges to the higher TS → permanent split. Merge = max(del_hlc) + min(value) within the surviving
   incarnation; `ctime_del` is per-server-local (digest hashes only the live value). Reconcile-create +
   materialize require a LIVE ctime (`>0`), not just members>0 (the ts=0-zombie guard).
8. **The full-walk reconcile is load-bearing — don't scope it prematurely.** Reconciling the WHOLE doc
   on every delta is what makes out-of-order cross-entity deltas robust (a member-op arriving before the
   user-op it references; whichever lands later re-runs everything). Scoped per-collection reconcile
   sacrifices that → do it only WITH scale/Phase 4 + a deliberate dependency cascade.
9. **The beacon emits UNCONDITIONALLY every cycle.** Liveness must be traffic-independent — an idle-but-
   reachable server still beacons → stays fresh → not retired. (Avoids the SV-staleness false-positive
   that sank the replicated servers-map.)
10. **The replicated `servers`-map / per-viewpoint reachability is ABANDONED** (4a). Reachability is a
    LOCAL determination (`FindNServer` + the beacon), never replicated CRDT state ("no amount of
    patching makes a per-viewpoint value robust as shared state"). Don't resurrect it — path-vector
    routing would, which is why the roadmap recommends gossip-flood instead.
11. **Doc-REMOVAL reconciles must LIVE-WALK + gate on `*_is_explicitly_removed()` (NOT `!*_present()`),
    NEVER foreach the tombstone.** `crdt_lwwmap_foreach` (crdt_types.c) **skips deleted entries**
    (`if (!e->deleted)`), and OR-Set iteration is similar — so a reconcile callback's `!val->data` /
    tombstone branch is UNREACHABLE for a removal. To act on a doc removal (e.g. de-materialize a
    replica/alias whose owner tombstoned its record), walk the LIVE local objects (the session/account
    hashes, channel lists), collect-then-act (no mid-walk mutation), and gate on
    **`crdt_*_is_explicitly_removed()` (= `crdt_lwwmap_is_deleted`), NOT on `!*_present()` /
    `crdt_*_get()==NULL`.** `get()==NULL` is true for a tombstone **AND a never-written key**, so an
    absence-gate wrongly reaps a record NO CRDT node ever wrote — e.g. a legacy-hosted session/alias
    (a `bsess`/`bconn` is written only by its CRDT host). This is the pattern EVERY reap already uses
    (user/metadata/gline/shun/zline/jupe/bans/members). **The two bouncer reaps `bounce_crdt_replica_reap`
    (sessions) / the alias reap originally gated on `!*_present()` and spuriously destroyed LIVE
    legacy-hosted sessions/aliases every verify tick (BS X/BX X) — fixed 2026-07-23 (P3-5b2) by
    re-gating on `*_is_explicitly_removed`.** Tombstones persist until causally stable (crdt_state_gc
    reclaims only after every peer acked → reap-before-GC in verify_cb guarantees the tombstone is seen),
    so a genuine removal always reaps; a crashed host that never tombstones is the ORPHAN-REAP track's
    job, not these reaps. Cost of the foreach-trap half: M6c-1 BX Inc-2 shipped a de-mat in the (dead)
    tombstone branch — it never fired; the legacy P10 BX X silently masked it until BX X suppression made
    the de-mat the sole path and exposed the strand. Reconcile-CREATE in the `val->data` branch is fine
    (live entries ARE walked); only REMOVAL needs the live-walk.

## Build / test / verify

- Build: `scripts/dc.sh -l --profile multi up -d --build nefarious3 nefarious4 nefarious5`. cmocka runs
  in the build + **gates the image** (a failing engine test fails the build).
- **Freshness (NB6, recurring):** a stale Docker layer can report exit 0 with the OLD binary. ALWAYS
  verify the `ircd.YYYYMMDDHHMM` symlink ADVANCES (`docker exec <c> readlink /home/nefarious/bin/ircd`);
  for logic-only changes (no new greppable string) the symlink is the freshness oracle; `build
  --no-cache` if stale. The `--no-cache` build can fill the disk — `docker builder prune -f` is safe.
- **Verify under the activity that mints the op, not a quiet window.** (The #1-padding false-positive:
  "6→0" right after a quiet startup, then resurfaced when a channel-ctime op was actually minted. Always
  exercise the path — a fresh JOIN, a real partition — before reading valgrind/digests.)
- valgrind runs in-container (`/home/nefarious/ircd/cores/valgrind.log`); a crashed container keeps it —
  `docker cp <c>:/home/nefarious/ircd/cores/valgrind.log` to extract before restart.
- Tests/scaffolding live in `/tmp/crdt4c/` (throwaway, NOT committed): partition via a netns sidecar
  (`docker run --net=container:nefarious5 --cap-add NET_ADMIN nicolaka/netshoot` + `ss -K dst <ip>` +
  `iptables -j DROP`); OPER is async (Keycloak — wait for the 381 numeric before CONNECT).
- **cmocka is the gate for engine logic** (TDD-first per CLAUDE.md). Integration-layer behavior
  (Client/Connection/server_list lifecycle — CR M delivery, materialize, anchors) is verified LIVE, not
  via cmocka (note that in the plan/memory per `feedback_no_silent_defer`).

## Key files

| File | What |
|---|---|
| `ircd/crdt_types.c/.h` | LWW/OR-Set/HLC-helpers/state-vector/`CrdtMsgidDedup`; `fnv1a` |
| `ircd/crdt_state.c/.h` | doc model, op log, merge, GC, digest, ctime, member/kick meta, orphan reclaim |
| `ircd/crdt_hlc.c/.h` | hybrid logical clock |
| `ircd/crdt_wire.c/.h` | op/snapshot/SV (de)serialize, b64, CR F apply |
| `ircd/crdt_shadow.c/.h` | live↔doc hooks, materialize, reconcile, §17.7 gateway, stub/anchor, beacon, verify_cb |
| `ircd/m_crdt.c` | CR S/D/U/F/V/M/H handlers, gossip flood, eager relay, dedup, beacon emit |
| `ircd/m_server.c` | `mr_crdtmesh` overlay registration, `check_loop_and_lh`, BURST/CR F cutover decisions |
| `ircd/s_serv.c` | `server_estab`, `crdt_send_snapshot` (BURST replacement, ~:348) |
| `ircd/s_misc.c` | SQUIT keep/cascade branch, `crdt_shadow_retire_mesh_stub` (updown-branch: Case A vs synthetic) |
| `ircd/ircd_relay.c` / `m_tagmsg.c` | CR M live-delivery hooks (relay_*/server_relay_*; mesh_delivered flag) |
| `include/client.h` | `STAT_MESH_SERVER`/`IsMeshStub`/`FLAG_CRDT_OVERLAY`/`IsCrdtAware`/`IsCrdtSyncTarget` |
| `ircd/test/crdt_cmocka.c` | the engine test suite (the image gate) |

Keep this skill and the submodule copy (`nefarious-crdt/.claude/skills/crdt-mesh/`) in sync when editing.
