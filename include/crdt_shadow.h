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

struct Channel;
struct Client;

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

/** Mirror a registered user into the shadow user registry (called from
 *  register_user on success). Skips bouncer aliases. Idempotent — also safe
 *  to call on nick change to refresh the record. */
void crdt_shadow_user_add(struct Client *cptr);

/** Mirror a user removal (called from exit_one_client for IsUser clients). */
void crdt_shadow_user_remove(struct Client *cptr);

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

/** Compare the shadow CRDT membership to the real channel state and log any
 *  divergence. No-op unless FEAT_CRDT_ENABLED. */
void crdt_shadow_verify(void);

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

/** Phase 3f: drive live channel membership (the JOIN/add direction) from the doc
 *  members OR-Set + §17.7 gateway to legacy. Adds present-in-doc-not-live members
 *  into already-live channels only (never creates a channel); op/voice + the
 *  remove direction (PART/KICK/QUIT) stay on P10. Idempotent (find_member_link
 *  guard). No-op unless FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_members(void);

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

#endif /* INCLUDED_crdt_shadow_h */
