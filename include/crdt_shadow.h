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
 *  Records chptr->topic into the shadow topics map. */
void crdt_shadow_topic(struct Channel *chptr);

/** Mirror a channel's mode state (called from modebuf_flush). Snapshots the
 *  persistent mode bits + limit + key into the shadow modes map. */
void crdt_shadow_modes(struct Channel *chptr);

/** Reconcile the shadow ban/except OR-Sets to the channel's banlist/exceptlist
 *  (called from modebuf_flush). */
void crdt_shadow_lists(struct Channel *chptr);

/** Compare the shadow CRDT membership to the real channel state and log any
 *  divergence. No-op unless FEAT_CRDT_ENABLED. */
void crdt_shadow_verify(void);

/* ---- Phase 2 wire-sync accessors (used by m_crdt.c) ----
 * These expose the shadow document to the CR token handlers while keeping the
 * CrdtNetworkState itself private to this module. */

/** Non-zero if CRDT sync is active (initialised AND FEAT_CRDT_ENABLED). */
int crdt_shadow_active(void);

/** Encode this server's state vector. Returns bytes written, or -1. */
int crdt_shadow_encode_sv(uint8_t *buf, size_t cap);

/** Encode the delta of ops the peer lacks, given the peer's encoded state
 *  vector. Returns bytes written, or -1. */
int crdt_shadow_encode_delta(const uint8_t *remote_sv, size_t sv_len,
                             uint8_t *buf, size_t cap);

/** Decode + apply a delta into the shadow document. Returns ops applied, or -1. */
int crdt_shadow_apply_delta(const uint8_t *buf, size_t len);

#endif /* INCLUDED_crdt_shadow_h */
