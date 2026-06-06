/*
 * crdt_shadow.c - Phase 1 shadow-mode bridge (see crdt_shadow.h).
 *
 * Mirrors live channel membership into a CRDT document and periodically
 * compares it to the real ircd state, gated behind FEAT_CRDT_ENABLED.
 * Behavior-neutral when the flag is off.
 */

#include "config.h"

#include "crdt_shadow.h"
#include "crdt_state.h"
#include "crdt_types.h"

#include "channel.h"
#include "client.h"
#include "struct.h"          /* struct User (cli_user(c)->server) */
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "numnicks.h"

#include <stdio.h>
#include <string.h>

/** The shadow replica of network state for this server. */
static struct CrdtNetworkState g_crdt;
static int                     g_inited = 0;
static struct Timer            g_verify_timer;

/** How often the shadow is reconciled against real state (seconds). */
#define CRDT_VERIFY_INTERVAL 30

/** Shadow is active only once initialised AND the feature is enabled. */
static int shadow_on(void)
{
  return g_inited && feature_bool(FEAT_CRDT_ENABLED);
}

/** Build the full P10 numeric ("YYXXX") for a user into @a buf. */
static const char *user_numeric(struct Client *who, char *buf, size_t n)
{
  snprintf(buf, n, "%s%s", cli_yxx(cli_user(who)->server), cli_yxx(who));
  return buf;
}

void crdt_shadow_join(struct Channel *chptr, struct Client *who,
                      unsigned int flags)
{
  char num[16];
  if (!shadow_on())
    return;
  if (flags & CHFL_ALIAS)            /* bouncer alias — not a real member */
    return;
  if (!cli_user(who))
    return;
  crdt_chan_join(&g_crdt, chptr->chname, user_numeric(who, num, sizeof num));
}

void crdt_shadow_part(struct Channel *chptr, struct Client *who)
{
  char num[16];
  if (!shadow_on())
    return;
  if (!cli_user(who))
    return;
  crdt_chan_remove(&g_crdt, chptr->chname, user_numeric(who, num, sizeof num),
                   CRDT_PRIORITY_USER);
}

void crdt_shadow_verify(void)
{
  struct Channel *chptr;
  unsigned int checked = 0, mismatches = 0;

  if (!shadow_on())
    return;

  for (chptr = GlobalChannelList; chptr; chptr = chptr->next) {
    struct CrdtChannel *cc = crdt_state_channel(&g_crdt, chptr->chname, 0);
    uint32_t crdt_n = cc ? crdt_orset_size(&cc->members) : 0;
    checked++;
    if (crdt_n != chptr->users) {
      mismatches++;
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT shadow divergence: %s real=%u crdt=%u",
                chptr->chname, chptr->users, crdt_n);
    }
  }

  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT shadow verify: %u channels checked, %u mismatch(es)",
            checked, mismatches);

  /* Single-node shadow mode has no peers, so everything we have applied is
   * causally stable relative to our own state vector — GC keeps the shadow's
   * oplog/tombstones bounded. (Multi-node delta sync replaces this in a
   * later phase.) */
  crdt_state_gc(&g_crdt, &g_crdt.local_sv);
}

/** Periodic timer callback. */
static void crdt_shadow_verify_cb(struct Event *ev)
{
  if (ev_type(ev) != ET_EXPIRE)
    return;
  crdt_shadow_verify();
}

void crdt_shadow_init(uint16_t my_numeric)
{
  if (g_inited)
    return;
  crdt_state_init(&g_crdt, my_numeric);
  g_inited = 1;
  timer_add(timer_init(&g_verify_timer), crdt_shadow_verify_cb, 0,
            TT_PERIODIC, CRDT_VERIFY_INTERVAL);
}
