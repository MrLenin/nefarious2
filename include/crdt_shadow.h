/*
 * crdt_shadow.h - Phase 1 shadow-mode bridge: mirror live IRCd state into the
 * CRDT document and detect divergence, gated behind FEAT_CRDT_ENABLED.
 *
 * This is the IRCd-coupled integration layer (proposal §7.3 / §11 Phase 1).
 * It is the ONLY place that reads feature flags and touches struct Client /
 * struct Channel — the crdt_types/crdt_state engine stays dependency-light.
 *
 * Increment 1 covers channel membership (add_user_to_channel /
 * remove_user_from_channel choke points) + a periodic verify() that compares
 * the CRDT member set to the real chptr->users. User-lifecycle, nick-change,
 * and mode mirroring land in later increments.
 *
 * Shadow mode is purely additive: when FEAT_CRDT_ENABLED is off (default),
 * every hook is a no-op and there is zero behavior change.
 */

#ifndef INCLUDED_crdt_shadow_h
#define INCLUDED_crdt_shadow_h

#include <stdint.h>
#include <stddef.h>
#include <time.h>            /* time_t — crdt_shadow_beacon_record() */

struct Channel;
struct Client;
struct Gline;
struct Shun;
struct Zline;
struct Jupe;

/*
 * M12 (Theme-B, ban lastmod tie-break): when a CRDT reconcile drives a legacy ban
 * (gline/shun/zline) whose doc-winning content differs from the live copy but whose
 * @a lastmod EQUALS it, the legacy *_modify version gate treats the equal lastmod as
 * "already have that version" and rejects the update (gline.c:812 / shun.c:848 /
 * zline.c:621) — so the doc-winner never drives live and the reconcile churns +
 * diverges. Break the tie toward the doc-winner: return the doc's lastmod when it
 * already beats the live one, else force exactly one past the live one. This is the
 * legacy make_gline force-increase pattern (gline.c:660-665) lifted to the reconcile,
 * which has the doc's HLC total order behind it — so every node forces the SAME
 * content and converges (the legacy-only equal-lastmod gate is deliberately left
 * untouched: it prevents legacy<->legacy ping-pong that has no HLC tiebreak).
 *
 * Pure (no Client/CurrentTime dep); `static inline` in the header so the engine cmocka
 * suite gates it directly. ONLY correct inside a reconcile's echo-guard content-
 * DIFFERENCE branch (never the create branch, never on a content match — a bump with
 * no real change would mint pointless live churn). See reconcile_{gline,shun,zline}_
 * add_cb in crdt_shadow.c.
 */
static inline time_t force_lastmod(time_t live_lastmod, time_t doc_lastmod)
{
  return (doc_lastmod > live_lastmod) ? doc_lastmod : live_lastmod + 1;
}

/*
 * M2 + U6 (Theme-B, liveness clock-source fix): the pure per-verify-tick staleness
 * decision for one liveness slot.  Design B counts CONSECUTIVE missed verify cycles
 * instead of a wall-clock delta (CurrentTime - recv_ts) that an NTP correction or a
 * VM-resume clock step makes lie — a backward step freezes the delta (M2, retire a
 * live server) and a forward step >90s makes it exceed the window for every slot at
 * once (U6, mass-reap).  Counting ticks is step-robust: a forward wall-clock step
 * fires the TT_PERIODIC verify timer AT MOST ONCE early (timer_run re-enqueues the
 * periodic timer on the post-step CurrentTime, so its next expiry is CurrentTime+30
 * > CurrentTime and the timer_run loop breaks — verified in ircd_events.c
 * timer_run/timer_enqueue), so a missed tick advances *miss by exactly 1, never N.
 *
 * Shared by the mesh-stub sweep (seen = a CR H beacon arrived this window, tracked
 * by crdt_beacon[].seen_since_tick, set in crdt_shadow_beacon_record ABOVE the relay
 * gate) and the overlay change-detector (seen = cli_lasttime moved since last tick).
 *
 * Pure integer logic — no Client / timer / CurrentTime dep; `static inline` in the
 * header so the cmocka suite gates it directly (guards the design-§2.6 hazard: a
 * wrong reset silently disables retirement -> ghost mesh-only users).
 *
 * @param[in]     seen  non-zero if a liveness signal arrived since the last tick.
 * @param[in,out] miss  running count of consecutive missed ticks (reset on seen).
 * @return 1 if the slot is now stale (>= CRDT_BEACON_MISS_TICKS consecutive misses
 *         -> full-partition retire / overlay teardown), else 0.
 */
#define CRDT_BEACON_MISS_TICKS 3   /* = CRDT_BEACON_STALE(90s) / CRDT_VERIFY_INTERVAL(30s) */
static inline int crdt_beacon_tick_stale(int seen, uint8_t *miss)
{
  if (seen) {
    *miss = 0;
    return 0;
  }
  if (*miss < 255)                 /* saturate: a retired stub stops ticking long before this */
    (*miss)++;
  return *miss >= CRDT_BEACON_MISS_TICKS;
}

/*
 * Account-prop leaf defect (2026-07-24): under tree-retirement a CRDT leaf's
 * P10 tree is truncated, but its hub still tree-relays commands SOURCED from
 * servers beyond that horizon (services: AC, SVSMODE, ...). The leaf resolves
 * such a source to its doc-materialized mesh anchor (STAT_MESH_SERVER, cli_from
 * = self dead-sink — never the arriving link), so parse.c's fake-direction
 * guard (cli_from(from) != cptr) rejected every such command as spoofed:
 * accounts were never stamped on leaves (WHOIS 330 empty), breaking every
 * account-anchored feature there. The doc cannot heal it — reconcile carries
 * no account clause and skips local users — so the guard must admit these.
 *
 * The exemption predicate: accept a beyond-horizon source ONLY when (a) it is
 * a mesh stub/anchor that is itself mesh-plane-owned (CRDT-aware), AND (b) the
 * message arrived on a real P10 server link that is a CRDT peer. A CRDT peer
 * already holds full doc-write authority, so this stays inside the existing
 * trust boundary; every legitimate fake-direction drop (a real server on the
 * wrong link, a legacy or hostile peer sourcing a stub) still fires.
 * SECURITY: never relax this to the stub check alone — without the
 * CRDT-server link gate a legacy peer could forge services-sourced commands.
 *
 * Pure (no Client dep); `static inline` so the engine cmocka suite gates the
 * full 16-row truth table (exactly one row accepts). Call sites extract the
 * booleans via CrdtAcceptBeyondHorizonSource below.
 */
static inline int crdt_accept_beyond_horizon(int from_is_mesh_stub,
                                             int from_is_crdt_aware,
                                             int link_is_server,
                                             int link_is_crdt_aware)
{
  return from_is_mesh_stub && from_is_crdt_aware
      && link_is_server && link_is_crdt_aware;
}

/* Client-typed extraction for the parse.c guard sites. Expands client.h
 * macros at the call site so this header stays Client-free (engine purity). */
#define CrdtAcceptBeyondHorizonSource(from, cptr) \
  crdt_accept_beyond_horizon(IsMeshStub(from), IsCrdtAware(from), \
                             IsServer(cptr), IsCrdtAware(cptr))

/** Initialise the shadow CRDT document for this server and arm the periodic
 *  verify timer. Idempotent; safe to call once at startup. */
void crdt_shadow_init(uint16_t my_numeric);

/** Mirror a channel join (called from add_user_to_channel). @a flags are the
 *  membership flags so the bridge can skip bouncer aliases. */
void crdt_shadow_join(struct Channel *chptr, struct Client *who,
                      unsigned int flags);

/** Mirror a channel part/kick/quit-from-channel (called from
 *  remove_user_from_channel, for non-alias members). */
void crdt_shadow_part(struct Channel *chptr, struct Client *who);

/** Phase 3j: mark a channel's CRDT creationtime incarnation boundary (called from
 *  destruct_channel). Bumps the LOCAL ctime_del so a later recreate to a higher TS
 *  is not resurrected to the stale value. No-op unless FEAT_CRDT_ENABLED. */
void crdt_shadow_channel_destroy(struct Channel *chptr);

/** Phase 3k: mirror a channel KICK into the doc (called from m_kick/ms_kick). Mints
 *  a PRIORITY_USER member tombstone (a kicked user must be able to rejoin, so NOT a
 *  priority>0 tombstone, which would suppress the element permanently) + kick
 *  metadata (kicker + reason) so reconcile-remove emits a KICK not a PART (the
 *  distinction is the metadata, not the priority). @a from is the kick's incoming
 *  link; the single-writer gate skips when it's a CRDT-aware peer (they already
 *  minted it). No-op unless FEAT_CRDT_ENABLED. */
void crdt_shadow_kick(struct Channel *chptr, struct Client *who,
                      struct Client *kicker, const char *reason,
                      struct Client *from);

/** Mirror a registered user into the shadow user registry (called from
 *  register_user on success). Skips bouncer aliases. Idempotent — also safe
 *  to call on nick change to refresh the record. */
void crdt_shadow_user_add(struct Client *cptr);

/** Mirror a user removal (called from exit_one_client for IsUser clients). */
void crdt_shadow_user_remove(struct Client *cptr);

/** 5-5e M2 (doc-native bouncer, SHADOW): mirror/remove a bouncer-session record in the
 *  BSESSIONS doc collection.  Callers enforce single-writer (primary holder). */
struct CrdtBouncerSession;
void crdt_shadow_bsess_set(const char *account, const char *sessid,
                           const struct CrdtBouncerSession *rec);
void crdt_shadow_bsess_remove(const char *account, const char *sessid);
/** 5-5e M3: doc-derived cross-sessid election winner for @a account (NULL if none). */
const char *crdt_shadow_bsess_winner(const char *account, char *out, size_t outsz);
/** 5-5e M6a-3: 1 iff a non-tombstone bsessions doc record exists (replica-reap gate). */
int crdt_shadow_bsess_present(const char *account, const char *sessid);
/** Batch P3-5b2 (crdt-mesh INVARIANT 11): 1 iff the bsessions record is EXPLICITLY
 *  tombstoned (a genuine owner-side destroy minted a DELETE), not merely absent —
 *  the replica-reap gate.  Absent != removed: a legacy-primaried or not-yet-synced
 *  session is absent, not tombstoned, and must be spared. */
int crdt_shadow_bsess_removed(const char *account, const char *sessid);
/** M6c-1 BX Inc-2: 1 iff a non-tombstone bconns doc record exists (alias-reap gate). */
int crdt_shadow_bconn_present(const char *account, const char *sessid,
                             const char *connnum);
/** Batch P3-5b2 (crdt-mesh INVARIANT 11): 1 iff the bconns record is EXPLICITLY
 *  tombstoned (a genuine owner-side alias teardown minted a DELETE), not merely
 *  absent — the alias-reap gate (supersedes the M14 FindNServer host-gate). */
int crdt_shadow_bconn_removed(const char *account, const char *sessid,
                             const char *connnum);
/** 5-5e M6d: full P10 numeric of the doc-recorded PRIMARY connection (or NULL). */
const char *crdt_shadow_bconn_primary(const char *account, const char *sessid,
                                      char *out, size_t outsz);

/** 5-5e M4: per-connection roster mirror/remove + reap of stale-owned connections. */
struct CrdtBouncerConn;
void crdt_shadow_bconn_set(const char *account, const char *sessid,
                           const char *connnum, const struct CrdtBouncerConn *rec);
void crdt_shadow_bconn_remove(const char *account, const char *sessid,
                              const char *connnum);
void crdt_shadow_bconn_reap(void);
/* Dead-node doc-residue reap, Increment 0: detect-and-log only (no delete). */
void crdt_shadow_orphan_reap_scan(void);
int crdt_shadow_bconn_roster_count(const char *account, const char *sessid);

/** 5-5e M5 (liveness lease, SHADOW): claim/refresh, tombstone, and read the per-session
 *  liveness lease in the BLEASES comparator-merge register.  crdt_shadow_blease_get returns
 *  the converged lease (NULL if none); crdt_shadow_server_beacon_fresh reports whether a
 *  server's CR-H beacon is FRESH (the locally-derived liveness signal the revive gate uses). */
struct CrdtBouncerLease;
const struct CrdtBouncerLease *crdt_shadow_blease_get(const char *account,
                                                      const char *sessid);
void crdt_shadow_blease_claim(const char *account, const char *sessid, uint16_t host,
                              uint32_t generation, uint64_t claim_ms);
void crdt_shadow_blease_remove(const char *account, const char *sessid);
int crdt_shadow_server_beacon_fresh(uint16_t num);

/** 5-5e M6a (cutover): doc->live reconcile of bouncer session records — materialize a
 *  replica BouncerSession on non-holder nodes from the converged doc.  Gated
 *  FEAT_CRDT_BOUNCER_DOC; inert while BS/BX relay still flows (idempotent). */
void crdt_shadow_reconcile_bouncer(void);

/** Tier2 P1: true if @a u is a "mesh-only" user — its owning server is a
 *  STAT_MESH_SERVER stub (tree-departed but mesh-reachable).  Legacy (non-CRDT)
 *  peers already received the SQUIT for its server and never got its NICK, so the
 *  §17.7 legacy gateway emits (NICK/JOIN/PART/KICK/umode) MUST be skipped for it —
 *  the change rides the doc to other CRDT peers, and the real P10 introduction
 *  returns when its server relinks.  (Defined in crdt_shadow.c.) */
int crdt_user_is_mesh_only(struct Client *u);

/** Tier B services-anchor bridge: 1 if SERVER @a srv is reachable ONLY via the mesh
 *  (a STAT_MESH_SERVER anchor, no live P10 link) so a P10 send to it dead-sinks.  Used on
 *  a LEAF to decide CR-X routing vs P10 for a services target.  (Defined in crdt_shadow.c.) */
int crdt_server_is_mesh_only(struct Client *srv);

/** R6c flood-on-partition: non-zero if this node currently holds any STAT_MESH_SERVER stub,
 *  i.e. it is (partially) partitioned and its live channel views may be missing members
 *  reachable only via the mesh/gateway — so it should flood channel traffic unconditionally.
 *  crdt_mesh_stub_dec() is called by crdt_shadow_retire_mesh_stub when a stub is freed. */
int crdt_have_mesh_stub(void);
void crdt_mesh_stub_dec(void);

/** Phase 4a (SQUIT-as-SPLIT, §17.3): record a directly-linked CRDT-aware server
 *  as ACTIVE in the doc (called from server_estab; fires on both ends of every
 *  direct CRDT link, so each server's state is written by its direct uplink).
 *  Clears any prior SPLIT on relink.  Multi-writer LWW — NOT single-writer gated.
 *  No-op for non-CRDT peers / non-CRDT-primary. */
void crdt_shadow_server_add(struct Client *srv);

/** Tier2 T2-a/c: keep-vs-teardown gate — non-zero iff @a srv is a CRDT-aware
 *  server still reachable via SOME live CRDT transport other than the dying link
 *  (so its users should be kept alive as a mesh stub rather than torn down). */
int crdt_shadow_mesh_reachable(struct Client *srv);

/** S4/R7a (SQUIT-only): gate (+ shadow-measure) the P10 SQUIT for @a subject toward
 *  the directly-linked @a peer.  Non-zero IFF the caller should SKIP the SQUIT emit
 *  (cutover flag on + both ends CRDT-aware — then the departure rides the CR H
 *  beacon set: stale beacon + keep-gate + sweep retire the server).  While the flag
 *  is off, a both-ends candidate emits one "R7-shadow" measurement line instead.
 *  @a kind labels the log ("SQUIT").  NB: this is the SQUIT half (R7a); the SERVER half
 *  is crdt_server_intro_suppress (MR-5) — R7b's "infeasible" verdict was overturned once
 *  legacy servers (MR-3a) AND CRDT servers (self-beacon) became anchorable. */
int crdt_tree_presence_suppress(struct Client *peer, struct Client *subject,
                                const char *kind);

/** MR-3c: gate the P10 SERVER intro for a LEGACY @a subject toward a directly-linked
 *  CRDT-aware @a peer (the CRDT peer learns it via the proxy-beacon + Case-B anchor,
 *  MR-3a). Inverted subject-awareness vs crdt_tree_presence_suppress; NEVER suppresses
 *  a CRDT subject or toward a legacy peer. Returns nonzero IFF the caller should SKIP
 *  the SERVER emit. No-op unless FEAT_CRDT_LEGACY_PRESENCE + FEAT_CRDT_PRIMARY. */
int crdt_intro_presence_suppress(struct Client *peer, struct Client *subject);

/** MR-5: suppress a CRDT @a subject's own SERVER intro toward a CRDT-aware @a peer (the
 *  SERVER half of tree-retirement; the peer learns it via the subject's self-beacon +
 *  Case-B anchor). Same both-ends gate as crdt_tree_presence_suppress but on a SEPARATE
 *  flag FEAT_CRDT_TREE_RETIRE (controlled cutover, independent of the live R7a SQUIT
 *  suppression). Returns nonzero IFF the caller should SKIP the SERVER emit; while the
 *  flag is off it shadow-logs the would-suppress candidates ("MR-5-shadow SERVER"). */
int crdt_server_intro_suppress(struct Client *peer, struct Client *subject);

/** Tier2 T2-a/c: convert a (now-leaf) departed server into a STAT_MESH_SERVER
 *  dead-sink stub in place — its users stay live + addressable.  Call only after
 *  the caller has torn down any tree-downlinks (exit_client does this for T2-c). */
void crdt_shadow_convert_to_stub(struct Client *srv);

/** Tier2 T2-a: tear down a mesh stub (relink reconciliation).  Removes its held
 *  users (no doc tombstone -> they re-materialize on re-burst) and frees the stub
 *  + its server_list[] slot.  Call BEFORE the relinking peer re-registers its
 *  numeric (SetServerYXX), so the slot is clean. */
void crdt_shadow_retire_mesh_stub(struct Client *stub, const char *comment);

/** Tier2 T2-b: doc lookup of a user record by 5-char numeric (CR M source-prefix
 *  reconstruction).  Returns NULL if absent / not initialised. */
const struct CrdtUserRecord *crdt_shadow_user_record(const char *numeric);

/** Tier2 full-partition liveness: record a peer's CR H beacon (its server numeric
 *  + emit timestamp).  Returns 1 if the beacon is FRESH (newer than the last seen
 *  for that server -> caller should relay it onward), 0 if a dup/old beacon (drop,
 *  terminating the gossip flood). */
int crdt_shadow_beacon_record(unsigned int num, time_t emit_ts,
                              const char *nn_cap, const char *name,
                              const char *peers, const char *fronted_by);

/** MR-4d: 1 if this gateway should STAND DOWN from re-emitting CR-M traffic for legacy
 *  server @a num because a fresh lower-numeric gateway also fronts it (double-delivery
 *  election).  @a my_yxx = our own server numeric.  0 when we are the active emitter. */
int crdt_shadow_should_standby(unsigned int num, const char *my_yxx);

/** MR-5 event-driven beacon-burst: hand a freshly-linked CRDT @a peer the full current
 *  beacon set at link time (our self + proxy-legacy beacons, plus a replay of every fresh
 *  far-server beacon we hold), so it can anchor far servers + materialize their users at
 *  once instead of waiting for the periodic flood.  Closes the cold-link bringup window
 *  tree-retirement opened.  Call from server_finish_burst for any CRDT-aware peer. */
void crdt_shadow_beacon_burst(struct Client *peer);

/** B0/MR-3d: present every beacon-known CRDT MESH server to our legacy peer (MR-3's missing
 *  OUT direction), so legacy/x3 learns the leaves and a services reply addressed to a leaf
 *  routes naturally over P10 to this gateway (which tunnels CR-X onward).  Proactive full
 *  sweep; gateway-only + FEAT_CRDT_LEGACY_PRESENCE-gated internally; idempotent.  Call from
 *  the verify timer (backstop). */
void crdt_shadow_present_mesh_servers(void);

/** B0/MR-3d: present a single just-learned mesh server (CR-H ingest fast path) so a cold leaf
 *  is presentable to legacy the moment its beacon arrives.  @a yxx = 2-char server numeric. */
void crdt_shadow_present_one_num(const char *yxx);

/** R6c gap fix: backfill presented mesh stubs to a freshly-linked LEGACY peer.
 *  present_stub broadcasts at stub-detection time only, so a peer linking later
 *  never learns the stub (its users then can't be placed).  Call at the top of
 *  server_finish_burst's legacy path; targeted, so existing peers are untouched. */
void crdt_shadow_present_stubs_to(struct Client *cptr);

/** Build this server's own direct-CRDT-peer set (comma-joined base64 numerics)
 *  into @a out for the CR H beacon AND record our own mesh-map row locally.
 *  Returns the peer count.  Observability-only (see crdt_meshmap.h). */
int crdt_shadow_local_peers(char *out, size_t outsz);

/** Active overlay liveness probe: 1 iff @a ov is a CRDT overlay that has received no
 *  CR traffic for >CRDT_BEACON_STALE (a half-open/black-holed silently-dead edge the
 *  passive EOF/write-failure checks miss).  check_pings tears such an edge down so the
 *  reap→try_connections reconnect runs.  See the definition for the full rationale. */
int crdt_overlay_is_stale(const struct Client *ov);

/** The gossiped mesh-topology map (read-only) for the /CRDT command.  Forward-
 *  declared so callers that only pass the pointer need not include crdt_meshmap.h. */
struct CrdtMeshMap;
const struct CrdtMeshMap *crdt_shadow_meshmap(void);
/** MR-2: 1 if the mesh-map has been structurally stable long enough that every
 *  node agrees on the canonical broadcast tree (safe to tree-forward); 0 during
 *  the convergence-lag window after a topology change (-> flood, gap-free). */
int crdt_shadow_mesh_bcast_stable(time_t now);

/** Beacon-derived metadata for rendering a node by numeric. */
const char *crdt_shadow_beacon_name(unsigned int num);  /**< "" if unknown */
time_t      crdt_shadow_beacon_recv(unsigned int num);  /**< last local recv time */
time_t      crdt_shadow_beacon_stale_secs(void);        /**< staleness window */

/** R4a (channel-over-mesh): per-server local-delivery dedup for a channel message,
 *  keyed by msgid, shared by the tree (sendcmdto_channel_butone via the relay) and the
 *  CR-M plane.  Returns 1 if this msgid was already delivered to our locals within the
 *  window (caller should SKIP local delivery; relay/flood is unaffected), else records
 *  it and returns 0 (caller delivers).  A missing/"*" msgid never dedupes. */
int crdt_shadow_chan_local_check_add(const char *msgid);

/** Mirror a channel topic (called from do_settopic and the burst topic-clear).
 *  Records chptr->topic into the shadow topics map. @a from is the incoming
 *  link the change arrived on (cptr), or the local source; the single-writer
 *  gate skips mirroring when @a from is a CRDT-aware peer. */
void crdt_shadow_topic(struct Channel *chptr, struct Client *from);

/** Mirror a channel's mode state (called from modebuf_flush). Snapshots the
 *  persistent mode bits + limit + key into the shadow modes map. @a from is the
 *  mode change's incoming link (mbuf->mb_connect) for the single-writer gate. */
void crdt_shadow_modes(struct Channel *chptr, struct Client *from);

/** Reconcile the shadow ban/except OR-Sets to the channel's banlist/exceptlist
 *  (called from modebuf_flush). @a from is the change's incoming link for the
 *  single-writer gate. */
void crdt_shadow_lists(struct Channel *chptr, struct Client *from);

/** Tier C F1-c: per-user SILENCE convergence over the mesh.
 *  crdt_shadow_silences mirrors a LOCAL user's live silence list into the doc
 *  (home server is the single-writer); crdt_shadow_sync_user_silences brings a
 *  REMOTE/materialized user's live list into line with the doc (doc-authoritative).
 *  Additive — the legacy P10 SILENCE token is not suppressed. */
void crdt_shadow_silences(struct Client *cptr);
void crdt_shadow_sync_user_silences(struct Client *live);

/** Tier C F2-a: read-marker (MR) convergence. crdt_shadow_marker_set mirrors a local
 *  account-anchored marker into the doc (max-register, opaque storage key);
 *  crdt_shadow_reconcile_markers drives the local readmarkers_cf from the doc. Additive
 *  (the P10 MR token is not suppressed). */
void crdt_shadow_marker_set(const char *account, const char *target, const char *ts);
void crdt_shadow_reconcile_markers(void);

/** Tier C F3: mint a TEMPSHUN flip into the doc at the ENTRY server (the oper's
 *  server for /TEMPSHUN, the §17.7 gateway edge for X3-sourced TS); the victim's
 *  HOME server applies it via the reconcile suite. active=0 = un-shun (a live
 *  doc entry, never a delete). */
void crdt_shadow_tempshun(struct Client *victim, int active, const char *reason);
/** Tier C F3: apply doc tempshun state to LOCAL victims (home-server-only flag
 *  semantics). Part of the reconcile suite; safe/no-op elsewhere. */
void crdt_shadow_reconcile_tempshuns(void);

/** Tier C F2-b: account metadata (MD) convergence. crdt_shadow_metadata_set mirrors a
 *  PERMANENT account-metadata set (or a delete of a doc-present key) into the doc
 *  (plain LWW, opaque account\0key); TTL-bound sets are skipped (per-server caches).
 *  crdt_shadow_reconcile_metadata drives the local metadata_cf from the doc (SET heal +
 *  DELETE store-walk). crdt_shadow_metadata_suspend toggles the single-writer guard so
 *  a P10-relayed apply (ms_metadata) does NOT re-mirror. Additive (P10 MD not
 *  suppressed). */
void crdt_shadow_metadata_set(const char *account, const char *key,
                              const char *value, int permanent);
/** Mint a doc metadata tombstone for a pre-formed storage key (account\0key). Raw-key
 *  variant of crdt_shadow_metadata_set's delete branch, for metadata_account_clear's
 *  bulk store-delete (which bypasses the (account,key) chokepoint). Same gates; skips
 *  keys not doc-present. */
void crdt_shadow_metadata_remove_key(const void *key, uint32_t klen);
void crdt_shadow_reconcile_metadata(void);
void crdt_shadow_metadata_suspend(int on);

/** Global-state track (GLINE step 2 shadow-write): mirror a global G-line into the
 *  GLINES doc collection (keyed by its ban mask). Called from the canonical gline.c
 *  state-change points (add/activate/deactivate/modify). @a from is the change's
 *  incoming link (cptr / cli_from(sptr)); the single-writer gate skips when it is a
 *  CRDT-aware peer (the mesh entry server owns the write, peers receive it via CR
 *  sync). Local G-lines self-skip (they never replicate). SHADOW-ONLY: writes the
 *  doc, no behavior change — live G-lines still propagate via P10. No-op unless
 *  FEAT_CRDT_ENABLED. */
void crdt_shadow_gline_add(struct Gline *gline, struct Client *from);

/** Global-state track (GLINE step 2): tombstone a global G-line in the doc. Called
 *  before gline_free at the explicit-removal points (deactivate-that-frees /
 *  gline_remove) AND from gline_free_expired at the wall-clock lifetime-expiry arm of
 *  the gliter macro (M13: expiry is terminal, so the doc + CR F snapshots must not
 *  retain the record; the reconcile ADD pass never re-materializes an expired entry).
 *  Same single-writer gate + local self-skip as crdt_shadow_gline_add. No-op unless
 *  FEAT_CRDT_ENABLED. */
void crdt_shadow_gline_remove(struct Gline *gline, struct Client *from);

/** SHUN (global-state track, GLINE sibling): mirror a global Shun into / tombstone it
 *  in the SHUNS doc collection. Same single-writer gate + local self-skip + re-entrancy
 *  guard as the gline hooks. No-op unless FEAT_CRDT_ENABLED. */
void crdt_shadow_shun_add(struct Shun *shun, struct Client *from);
void crdt_shadow_shun_remove(struct Shun *shun, struct Client *from);

/** ZLINE (global-state track, GLINE/SHUN sibling): mirror a global Z-line into /
 *  tombstone it in the ZLINES doc collection. Same gates as the gline/shun hooks. */
void crdt_shadow_zline_add(struct Zline *zline, struct Client *from);
void crdt_shadow_zline_remove(struct Zline *zline, struct Client *from);

/** JUPE (global-state track): mirror a juped server into / tombstone it in the JUPES
 *  doc collection. Same gates as the gline/shun/zline hooks. */
void crdt_shadow_jupe_add(struct Jupe *jupe, struct Client *from);
void crdt_shadow_jupe_remove(struct Jupe *jupe, struct Client *from);

/** GLINE step 3 (cutover): drive live global G-lines FROM the doc GLINES collection +
 *  §17.7 gateway to legacy. ADD/heal/drift via gline_add/gline_modify (under a re-entrancy
 *  guard so the shadow hook self-skips — no doc re-mint); REMOVE any live global G-line the
 *  doc EXPLICITLY tombstoned (never on mere absence) + gateway a -mask. Idempotent + a no-op
 *  while P10 still delivers G-lines (field echo guard) — safe to enable before 3b P10-GL
 *  suppression. No-op unless FEAT_CRDT_GLINE_CUTOVER + FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_glines(void);

/** SHUN cutover (GLINE sibling): drive live global Shuns FROM the doc + §17.7 gateway.
 *  No-op unless FEAT_CRDT_SHUN_CUTOVER + FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_shuns(void);

/** ZLINE cutover (GLINE sibling): drive live global Z-lines FROM the doc + §17.7 gateway.
 *  No-op unless FEAT_CRDT_ZLINE_CUTOVER + FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_zlines(void);

/** JUPE cutover: drive live juped servers FROM the doc + §17.7 gateway. Recreate-on-drift
 *  (jupe has no modify). No-op unless FEAT_CRDT_JUPE_CUTOVER + FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_jupes(void);

/** §17.7 birth-modes bridge (3j gap fix): emit to legacy the persistent modes of
 *  channels born from the doc THIS reconcile pass — called AFTER reconcile_members
 *  has placed the channel on legacy. No-op on a node with no legacy peer. */
void crdt_shadow_gateway_birth_modes(void);

/** Compare the shadow CRDT membership to the real channel state and report any
 *  divergence.  @a to == NULL -> the system log (the verify timer); a Client ->
 *  the lines are NOTICE'd to that oper (/CRDT status).  No-op unless shadow_on. */
void crdt_shadow_verify(struct Client *to);

/** Tier-2 Stage 1 SHADOW ORACLE (log-only, mutates nothing): report the
 *  per-server divergences between mesh-map BFS reachability, the per-node beacon
 *  set, and P10-tree reachability — to validate which signal is the right
 *  presence oracle for R7 before anything depends on it. @a to == NULL -> log;
 *  a Client -> NOTICE (/CRDT status). */
void crdt_shadow_presence_diff(struct Client *to);

/** MR-0 ROUTING SHADOW ORACLE (log-only, mutates nothing): for every CRDT-aware
 *  destination server, diff the derived mesh next-hop (crdt_meshmap_nexthop from
 *  this node) against the P10 tree's actual next-hop (cli_from), and report the
 *  per-destination agreement: agree / mismatch / meshOnly (mesh routes it, the
 *  tree doesn't — overlay/stub win) / p10Only (tree reaches it, the mesh has no
 *  path — an adjacency gap to close before MR-1 trusts the table).  Measures the
 *  routing table before anything routes over it.  @a to == NULL -> system log
 *  (verify timer); a Client -> NOTICE (/CRDT route). */
void crdt_shadow_route_diff(struct Client *to);

/** MR-3a SHADOW ORACLE (log-only): for every legacy (non-CRDT) server known via P10,
 *  report whether a FRESH proxy-beacon for it has also reached us (Case-B anchorable).
 *  The headline = a no-direct-link leaf showing beacon=FRESH for a legacy server it
 *  reaches only via CR. No-op unless FEAT_CRDT_LEGACY_PRESENCE. @a to==NULL -> log. */
void crdt_shadow_legacy_presence_diff(struct Client *to);

/** Phase 3b dry-run: walk the doc and confirm every entity could be rebuilt
 *  from it with field-for-field fidelity against live state. Logs reconstruction
 *  gaps; mutates nothing. No-op unless FEAT_CRDT_ENABLED. */
void crdt_shadow_materialize_check(void);

/** Phase 3c: materialize live state (struct Client/Channel + memberships) FROM
 *  the doc — the create-analog of the dry-run. Idempotent (skips anything already
 *  live). No-op unless FEAT_CRDT_ENABLED. Used as the CRDT-authoritative
 *  replacement for P10 BURST on a CRDT-primary leaf. */
void crdt_shadow_materialize_live(void);

/** Phase 3d: drive live channel topics from the doc (topics that propagated via
 *  CRDT, not P10) and bridge them to the legacy P10 tree (§17.7 gateway).
 *  Idempotent (acts only when doc topic != live). No-op unless FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_topics(void);

/** Phase 3e: same as reconcile_topics but for persistent channel modes (the
 *  CRDT_MODE_MASK set). Drives live modes from the doc + §17.7 gateway to legacy.
 *  Idempotent (acts only when the doc mode-snapshot != live). No-op unless
 *  FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_modes(void);

/** Phase 3l: create not-yet-live users from the doc users map + §17.7-gateway each
 *  onward to the legacy P10 tree (a P10 NICK introduce, sourced from the owning
 *  server). The user-level analog of reconcile_members (JOIN-add): introduce rides
 *  CRDT, removal/nick-change/umode stay on P10 (deferred 3m/3n). Self-guards against
 *  a concurrent inbound BURST. Must run BEFORE the channel reconcilers (channels
 *  reference users by numeric). No-op unless FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_users(void);

/** Phase 3m: exit live remote users the doc has EXPLICITLY tombstoned (QUIT /
 *  delete-on-leave) + §17.7-gateway a QUIT to legacy. Gated on
 *  crdt_user_is_explicitly_removed (never on mere absence — the sync-lag safety).
 *  SQUIT stays on P10. No-op unless FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_user_removes(void);

/** Phase 3f: drive live channel membership (the JOIN/add direction) from the doc
 *  members OR-Set + §17.7 gateway to legacy. Adds present-in-doc-not-live members
 *  into already-live channels only (never creates a channel); op/voice + the
 *  remove direction (PART/KICK/QUIT) stay on P10. Idempotent (find_member_link
 *  guard). No-op unless FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_members(void);

/** Phase 3j: birth a not-yet-live channel locally from the doc (present members +
 *  not FindChannel) so members/modes/bans can reconcile into it; must run BEFORE
 *  crdt_shadow_reconcile_members. LOCAL ONLY (no gateway — legacy births via the 3f
 *  JOIN-gateway). creationtime from the incarnation min-register. No-op unless
 *  FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_create_channels(void);

/** Phase 3g: drive live channel membership REMOVE (PART / delete-on-leave) from
 *  the doc + §17.7 gateway. Removes a live member ONLY when the doc OR-Set has
 *  explicitly tombstoned it (crdt_orset_is_explicitly_removed) — never on mere
 *  absence (the sync-lag guard). KICK/QUIT stay P10 (backstop). No-op unless
 *  FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_removes(void);

/** Phase 3h: drive live per-member status (+o/+v/+h) from the doc members_status
 *  LWW + §17.7 gateway to legacy. Diffs each live member's status vs the doc and
 *  emits the delta via modebuf_flush_nomirror (local clients + legacy only).
 *  Echo-guarded; skips not-yet-materialized members. No-op unless FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_member_status(void);

/** Phase 3i: drive live channel bans/excepts (+b/+e) from the doc bans/excepts
 *  OR-Sets + §17.7 gateway. ADD present-not-live masks (3f), tombstone-gated REMOVE
 *  of live masks the doc explicitly removed (3g, crdt_orset_is_explicitly_removed);
 *  emits via modebuf_flush_nomirror (local + legacy only). No-op unless FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_bans(void);

/* ---- Phase 2 wire-sync accessors (used by m_crdt.c) ----
 * These expose the shadow document to the CR token handlers while keeping the
 * CrdtNetworkState itself private to this module. */

/** Non-zero if CRDT sync is active (initialised AND FEAT_CRDT_ENABLED). */
int crdt_shadow_active(void);

/** Phase 3c: non-zero only if the doc is a COMPLETE source of live state (doc
 *  user count > 0 and >= live user count). The burst-skip cutover gates on this
 *  so a not-yet-converged doc (e.g. at cold boot) falls back to a normal P10
 *  BURST instead of sending an empty snapshot that would leave the peer missing
 *  users. */
int crdt_shadow_doc_ready(void);

/** Encode this server's state vector. Returns bytes written, or -1. */
int crdt_shadow_encode_sv(uint8_t *buf, size_t cap);

/** Encode the delta of ops the peer lacks, given the peer's encoded state
 *  vector. Returns bytes written, or -1. */
int crdt_shadow_encode_delta(const uint8_t *remote_sv, size_t sv_len,
                             uint8_t *buf, size_t cap);

/** Decode + apply a delta into the shadow document. Returns ops applied, or -1. */
int crdt_shadow_apply_delta(const uint8_t *buf, size_t len);

/** Encode the ops WE created (origin == my_numeric) that have not yet been
 *  eager-pushed, advancing the high-water mark. Returns bytes (>4 if any ops
 *  were emitted), or <=0. Used by crdt_sync_push for CR U. */
int crdt_shadow_encode_local_unpushed(uint8_t *buf, size_t cap);

/** Digest of the shadow CRDT document (for cross-server convergence checks). */
uint64_t crdt_shadow_digest(void);

/** Record a peer's encoded state vector (from CR S / CR V), keyed by the peer's
 *  server numeric, for causal-stability GC. */
void crdt_shadow_record_peer_sv(uint16_t origin, const uint8_t *sv, size_t len);

/** Encode the full document as a snapshot (CR F payload). Returns bytes, or -1. */
int crdt_shadow_encode_snapshot(uint8_t *buf, size_t cap);

/** Decode + apply a full snapshot into the shadow document. Returns 0, or -1. */
int crdt_shadow_apply_snapshot(const uint8_t *buf, size_t len);

/** Non-zero if a peer with encoded state vector @a sv has fallen behind the GC
 *  floor — the ops it lacks are gone from the oplog, so it needs a snapshot
 *  (CR F) rather than a delta (CR D). */
int crdt_shadow_peer_behind_floor(const uint8_t *sv, size_t len);

/** Tier2 Fix A: non-zero iff the peer's encoded state vector @a sv equals our
 *  local SV on every origin. An equal-SV peer whose CR S digest differs from ours
 *  is an SV-invisible divergence that only a CR F snapshot can repair. */
int crdt_shadow_sv_equal(const uint8_t *sv, size_t len);

#endif /* INCLUDED_crdt_shadow_h */
