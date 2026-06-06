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

/** Compare the shadow CRDT membership to the real channel state and log any
 *  divergence. No-op unless FEAT_CRDT_ENABLED. */
void crdt_shadow_verify(void);

#endif /* INCLUDED_crdt_shadow_h */
