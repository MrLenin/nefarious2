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
#include "crdt_wire.h"

#include "channel.h"
#include "client.h"
#include "struct.h"          /* struct User (cli_user(c)->server) */
#include "ircd.h"           /* GlobalClientList */
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "numnicks.h"
#include "handlers.h"        /* crdt_sync_broadcast */

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

void crdt_shadow_user_add(struct Client *cptr)
{
  char num[16];
  struct CrdtUserRecord rec;
  if (!shadow_on())
    return;
  if (!cli_user(cptr) || IsBouncerAlias(cptr))   /* non-alias users only */
    return;
  memset(&rec, 0, sizeof rec);
  strncpy(rec.nick, cli_name(cptr), sizeof rec.nick - 1);
  strncpy(rec.ident, cli_user(cptr)->username, sizeof rec.ident - 1);
  rec.server = (uint16_t)base64toint(cli_yxx(cli_user(cptr)->server));
  rec.ip = 0;                                     /* unused in count verify */
  crdt_user_set(&g_crdt, user_numeric(cptr, num, sizeof num), &rec);
}

void crdt_shadow_user_remove(struct Client *cptr)
{
  char num[16];
  if (!shadow_on())
    return;
  if (!cli_user(cptr) || IsBouncerAlias(cptr))
    return;
  crdt_user_remove(&g_crdt, user_numeric(cptr, num, sizeof num));
}

void crdt_shadow_topic(struct Channel *chptr)
{
  if (!shadow_on())
    return;
  /* op-recording setter so the topic replicates (a direct crdt_lwwmap_set
   * would never enter the oplog and never sync — that was the modes/topic
   * convergence bug). */
  crdt_topic_set(&g_crdt, chptr->chname, chptr->topic);
}

/* Persistent channel-mode bits we mirror — excludes per-member CHANOP/VOICE/
 * HALFOP, the list-modes BAN/EXCEPT, and internal flags (BURSTADDED, SAVE,
 * FREE, WASDELJOINS) so transient bits don't cause false divergence. */
#define CRDT_MODE_MASK (MODE_PRIVATE | MODE_SECRET | MODE_MODERATED |          \
                        MODE_TOPICLIMIT | MODE_INVITEONLY | MODE_NOPRIVMSGS |  \
                        MODE_KEY | MODE_LIMIT | MODE_REGONLY | MODE_DELJOINS | \
                        MODE_REGISTERED | MODE_UPASS | MODE_APASS | MODE_REDIRECT)

/** Compact, comparable snapshot of a channel's persistent mode state. */
struct ShadowModeSnap {
  uint32_t mode;
  uint32_t limit;
  char     key[KEYLEN + 1];
};

static void build_mode_snap(struct Channel *chptr, struct ShadowModeSnap *s)
{
  memset(s, 0, sizeof *s);
  s->mode = chptr->mode.mode & CRDT_MODE_MASK;
  if (s->mode & MODE_LIMIT)
    s->limit = chptr->mode.limit;
  if (s->mode & MODE_KEY)
    strncpy(s->key, chptr->mode.key, sizeof s->key - 1);
}

void crdt_shadow_modes(struct Channel *chptr)
{
  struct ShadowModeSnap snap;
  if (!shadow_on() || !chptr)
    return;
  build_mode_snap(chptr, &snap);
  /* op-recording setter so modes replicate (see crdt_shadow_topic). */
  crdt_modes_set(&g_crdt, chptr->chname, &snap, sizeof snap);
}

/* ---- ban/except list-modes: OR-Sets reconciled to the real Ban lists ---- */

#define CRDT_MASKLEN (NICKLEN + USERLEN + HOSTLEN + 3)

static int mask_in_banlist(struct Ban *list, const char *mask)
{
  for (; list; list = list->next)
    if (strcmp(list->banstr, mask) == 0)
      return 1;
  return 0;
}

struct crdt_collect_ctx { char masks[64][CRDT_MASKLEN]; int n; };
static void crdt_collect_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct crdt_collect_ctx *c = ctx;
  if (c->n < 64) {
    uint32_t l = key_len < CRDT_MASKLEN - 1 ? key_len : CRDT_MASKLEN - 1;
    memcpy(c->masks[c->n], key, l);
    c->masks[c->n][l] = '\0';
    c->n++;
  }
}

/** Bring an OR-Set into line with a channel's real Ban list (add new masks,
 *  remove masks no longer present). */
static void reconcile_list(struct CrdtORSet *set, struct Ban *list)
{
  struct Ban *b;
  struct crdt_collect_ctx cc;
  int i;
  for (b = list; b; b = b->next) {
    uint32_t len = (uint32_t)strlen(b->banstr);
    if (!crdt_orset_contains(set, b->banstr, len)) {
      struct CrdtTag tag = { g_crdt.my_numeric, ++g_crdt.next_seq };
      crdt_orset_add(set, b->banstr, len, tag);
    }
  }
  cc.n = 0;
  crdt_orset_foreach(set, crdt_collect_cb, &cc);
  for (i = 0; i < cc.n; i++)
    if (!mask_in_banlist(list, cc.masks[i]))
      crdt_orset_remove(set, cc.masks[i], (uint32_t)strlen(cc.masks[i]),
                        CRDT_PRIORITY_USER, NULL, 0);
}

void crdt_shadow_lists(struct Channel *chptr)
{
  struct CrdtChannel *cc;
  if (!shadow_on() || !chptr)
    return;
  cc = crdt_state_channel(&g_crdt, chptr->chname, 1);
  reconcile_list(&cc->bans, chptr->banlist);
  reconcile_list(&cc->excepts, chptr->exceptlist);
}

void crdt_shadow_verify(void)
{
  struct Channel *chptr;
  struct Client *acptr;
  unsigned int checked = 0, mismatches = 0;
  uint32_t real_users = 0, crdt_users;

  if (!shadow_on())
    return;

  for (chptr = GlobalChannelList; chptr; chptr = chptr->next) {
    struct CrdtChannel *cc = crdt_state_channel(&g_crdt, chptr->chname, 0);
    uint32_t crdt_n = cc ? crdt_orset_size(&cc->members) : 0;
    struct Membership *m;
    char num[16];
    checked++;
    if (crdt_n != chptr->users) {
      mismatches++;
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT shadow count divergence: %s real=%u crdt=%u",
                chptr->chname, chptr->users, crdt_n);
    }
    /* field-level: every real non-alias member must be present in the shadow */
    for (m = chptr->members; m; m = m->next_member) {
      if (m->status & CHFL_ALIAS)
        continue;
      user_numeric(m->user, num, sizeof num);
      if (!cc || !crdt_orset_contains(&cc->members, num, strlen(num))) {
        mismatches++;
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CRDT shadow member missing: %s in %s", num, chptr->chname);
      }
    }
    /* field-level: channel topic must match */
    {
      const struct CrdtLWWValue *tv =
        crdt_lwwmap_get(&g_crdt.topics, chptr->chname, strlen(chptr->chname));
      const char *stopic = tv ? (const char *)tv->data : "";
      if (strcmp(stopic, chptr->topic) != 0) {
        mismatches++;
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CRDT shadow topic divergence: %s shadow=\"%s\" real=\"%s\"",
                  chptr->chname, stopic, chptr->topic);
      }
    }
    /* field-level: channel modes (bits + limit + key) must match */
    {
      struct ShadowModeSnap cur;
      const struct CrdtLWWValue *mv =
        crdt_lwwmap_get(&g_crdt.modes, chptr->chname, strlen(chptr->chname));
      build_mode_snap(chptr, &cur);
      /* a channel with no persistent modes matches an absent shadow entry */
      if ((mv && (mv->data_len != sizeof cur ||
                  memcmp(mv->data, &cur, sizeof cur) != 0)) ||
          (!mv && cur.mode != 0)) {
        mismatches++;
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CRDT shadow mode divergence: %s real_mode=0x%x",
                  chptr->chname, cur.mode);
      }
    }
    /* field-level: every real ban/except must be present in the shadow set */
    if (cc) {
      struct Ban *b;
      for (b = chptr->banlist; b; b = b->next)
        if (!crdt_orset_contains(&cc->bans, b->banstr, strlen(b->banstr))) {
          mismatches++;
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT shadow ban missing: %s in %s", b->banstr, chptr->chname);
        }
      for (b = chptr->exceptlist; b; b = b->next)
        if (!crdt_orset_contains(&cc->excepts, b->banstr, strlen(b->banstr))) {
          mismatches++;
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT shadow except missing: %s in %s", b->banstr, chptr->chname);
        }
    }
  }

  /* user registry: existence + nick-value check for non-alias IsUser clients */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    char num[16];
    const struct CrdtUserRecord *r;
    if (!IsUser(acptr) || IsBouncerAlias(acptr))
      continue;
    real_users++;
    user_numeric(acptr, num, sizeof num);
    r = crdt_user_get(&g_crdt, num);
    if (!r) {
      mismatches++;
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT shadow user missing: %s (%s)", num, cli_name(acptr));
    } else if (strcmp(r->nick, cli_name(acptr)) != 0) {
      mismatches++;
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT shadow nick stale: %s shadow=%s real=%s",
                num, r->nick, cli_name(acptr));
    }
  }
  crdt_users = crdt_lwwmap_size(&g_crdt.users);
  if (real_users != crdt_users) {
    mismatches++;
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT shadow user count divergence: real=%u crdt=%u",
              real_users, crdt_users);
  }

  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT shadow verify: %u channels, %u/%u users, %u mismatch(es) "
            "digest=%016llx",
            checked, crdt_users, real_users, mismatches,
            (unsigned long long)crdt_state_digest(&g_crdt));

  /* NOTE: the oplog is intentionally NOT GC'd against our own state vector
   * here — Phase 2 delta sync needs ops retained until peers have caught up.
   * Causal-stability GC against the min of peer SVs (via CR V) is a later
   * increment; until then the shadow oplog grows (bounded enough for testing). */
}

/* ---- Phase 2 wire-sync accessors ---- */

int crdt_shadow_active(void)
{
  return shadow_on();
}

int crdt_shadow_encode_sv(uint8_t *buf, size_t cap)
{
  if (!g_inited)
    return -1;
  return crdt_sv_encode(&g_crdt.local_sv, buf, cap);
}

int crdt_shadow_encode_delta(const uint8_t *remote_sv, size_t sv_len,
                             uint8_t *buf, size_t cap)
{
  struct CrdtStateVector rsv;
  if (!g_inited)
    return -1;
  if (crdt_sv_decode(&rsv, remote_sv, sv_len) < 0)
    return -1;
  return crdt_delta_encode(&g_crdt.oplog, &rsv, buf, cap);
}

int crdt_shadow_apply_delta(const uint8_t *buf, size_t len)
{
  if (!g_inited)
    return -1;
  return crdt_delta_apply(&g_crdt, buf, len);
}

uint64_t crdt_shadow_digest(void)
{
  return g_inited ? crdt_state_digest(&g_crdt) : 0;
}

/** Periodic timer callback. */
static void crdt_shadow_verify_cb(struct Event *ev)
{
  if (ev_type(ev) != ET_EXPIRE)
    return;
  crdt_shadow_verify();
  crdt_sync_broadcast();   /* periodic anti-entropy: pull deltas from peers */
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
