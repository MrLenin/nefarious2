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
#include "hash.h"            /* FindChannel (Phase 3b dry-run lookup) */
#include "struct.h"          /* struct User (cli_user(c)->server) */
#include "ircd.h"           /* GlobalClientList */
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "numnicks.h"
#include "s_user.h"          /* umode_str (Phase 3b reconstruction payload) */
#include "handlers.h"        /* crdt_sync_broadcast */

#include <stdio.h>
#include <string.h>

/** The shadow replica of network state for this server. */
static struct CrdtNetworkState g_crdt;
static int                     g_inited = 0;
static struct Timer            g_verify_timer;

/** Eager-push high-water mark: the highest own-origin op seq we have already
 *  pushed to peers via CR U. Bounds eager push to ops WE created since last time
 *  (relay of foreign-origin ops stays on the anti-entropy path), keeping it
 *  O(new ops) instead of re-sending a growing cumulative delta each write. */
static uint64_t                g_last_pushed_seq = 0;

/** Recorded peer state vectors, for causal-stability GC (one slot per peer). */
#define CRDT_MAX_PEERS 8
struct crdt_peer_sv {
  int                    used;
  uint16_t               origin;
  time_t                 when;
  struct CrdtStateVector sv;
};
static struct crdt_peer_sv g_peers[CRDT_MAX_PEERS];

/** How often the shadow is reconciled against real state (seconds). */
#define CRDT_VERIFY_INTERVAL 30

/** Shadow is active only once initialised AND the feature is enabled. */
static int shadow_on(void)
{
  return g_inited && feature_bool(FEAT_CRDT_ENABLED);
}

/** Single-writer gate (Phase 3a). Returns true if a state event reached us via
 *  a CRDT-aware peer — in which case that peer is the single writer for it and
 *  we must NOT re-mirror it locally; we receive its op via CR sync. We DO mirror
 *  (we are the writer / CRDT-mesh entry point) when the event is local
 *  (cli_from == self, not a server) or arrived over a non-CRDT P10 link (the
 *  gateway case). `from != &me` matters because &me is itself CrdtAware
 *  (SetCrdtAware(&me) in ircd.c) and IsServer(&me) is true, so a local-origin
 *  change carrying &me as its source must not be mistaken for a peer relay.
 *
 *  Caveat: full-digest convergence holds only within a contiguous CRDT-aware
 *  region. A non-CRDT server bridging two CRDT islands makes each island's entry
 *  server a second writer for cross-bridge users (gateway case at both ends), so
 *  the re-mirror redundancy persists across that bridge. Phase 3d (hybrid
 *  gateway) formalizes the boundary. */
static int from_crdt_peer(struct Client *from)
{
  return from && from != &me && IsServer(from) && IsCrdtAware(from);
}

/** Build the full P10 numeric ("YYXXX") for a user into @a buf. */
static const char *user_numeric(struct Client *who, char *buf, size_t n)
{
  snprintf(buf, n, "%s%s", cli_yxx(cli_user(who)->server), cli_yxx(who));
  return buf;
}

/* ---- Phase 3b reconstruction payload helpers ---- */

/** Copy just the mode-LETTERS of a umode_str() result into @a dst (the first
 *  whitespace-delimited token). Parameters (sethost, account, the volatile
 *  IP-list field) are deliberately dropped: sethost lives in rec.host, account
 *  in rec.account, and param fields can be observer-relative. The bare flags are
 *  S2S-propagated and observer-consistent, so they converge. */
static void umode_letters(char *dst, size_t dstsz, const char *um)
{
  size_t i = 0;
  if (um)
    while (um[i] && um[i] != ' ' && i + 1 < dstsz) { dst[i] = um[i]; i++; }
  dst[i] = '\0';
}

/** Map live Membership status bits to the compact CRDT status byte. */
static uint8_t compact_status(unsigned int st)
{
  uint8_t s = 0;
  if (st & CHFL_CHANOP) s |= CRDT_MEMBER_OP;
  if (st & CHFL_VOICE)  s |= CRDT_MEMBER_VOICE;
  if (st & CHFL_HALFOP) s |= CRDT_MEMBER_HALFOP;
  return s;
}

/** Mirror one member's status+oplevel into the members_status LWW map. */
static void write_member_status(struct Channel *chptr, struct Membership *m)
{
  char num[16];
  struct CrdtMemberRecord rec;
  if (!m || (m->status & CHFL_ALIAS) || !cli_user(m->user))
    return;
  memset(&rec, 0, sizeof rec);
  rec.status = compact_status(m->status);
  rec.oplevel = (uint16_t)m->oplevel;
  crdt_member_status_set(&g_crdt, chptr->chname,
                         user_numeric(m->user, num, sizeof num), &rec);
}

/** Mirror a channel's metadata (creationtime + topic provenance) into chanmeta. */
static void write_chanmeta(struct Channel *chptr)
{
  struct CrdtChanMeta meta;
  memset(&meta, 0, sizeof meta);
  meta.creationtime = (uint64_t)chptr->creationtime;
  meta.topic_time = (uint64_t)chptr->topic_time;
  strncpy(meta.topic_nick, chptr->topic_nick, sizeof meta.topic_nick - 1);
  crdt_chanmeta_set(&g_crdt, chptr->chname, &meta);
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
  if (from_crdt_peer(cli_from(who)))  /* single-writer: peer owns this op */
    return;
  crdt_chan_join(&g_crdt, chptr->chname, user_numeric(who, num, sizeof num));
  /* opped/voiced-on-join (burst @, founder) never hits modebuf_flush, so capture
   * initial member status here; and seed the channel meta (creationtime). */
  if (flags & (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE))
    write_member_status(chptr, find_member_link(chptr, who));
  write_chanmeta(chptr);
  crdt_sync_push();                   /* eager-propagate to CRDT peers */
}

void crdt_shadow_part(struct Channel *chptr, struct Client *who)
{
  char num[16];
  if (!shadow_on())
    return;
  if (!cli_user(who))
    return;
  if (from_crdt_peer(cli_from(who)))  /* single-writer: peer owns this op */
    return;
  crdt_chan_remove(&g_crdt, chptr->chname, user_numeric(who, num, sizeof num),
                   CRDT_PRIORITY_USER);
  crdt_sync_push();                   /* eager-propagate to CRDT peers */
}

void crdt_shadow_user_add(struct Client *cptr)
{
  char num[16];
  struct CrdtUserRecord rec;
  if (!shadow_on())
    return;
  /* non-alias users that are fully numbered (own + server numeric set) — guards
   * against the set_user_mode hook firing mid-registration before the local
   * numeric is assigned (which would mint a malformed server-only key). */
  if (!cli_user(cptr) || !cli_user(cptr)->server || !cli_yxx(cptr)[0] ||
      IsBouncerAlias(cptr))
    return;
  if (from_crdt_peer(cli_from(cptr)))  /* single-writer: peer owns this op */
    return;
  memset(&rec, 0, sizeof rec);
  strncpy(rec.nick, cli_name(cptr), sizeof rec.nick - 1);
  strncpy(rec.ident, cli_user(cptr)->username, sizeof rec.ident - 1);
  strncpy(rec.host, cli_user(cptr)->host, sizeof rec.host - 1);
  strncpy(rec.realname, cli_info(cptr), sizeof rec.realname - 1);
  strncpy(rec.account, cli_user(cptr)->account, sizeof rec.account - 1);
  umode_letters(rec.umodes, sizeof rec.umodes, umode_str(cptr));
  memcpy(rec.ip6, &cli_ip(cptr), sizeof rec.ip6);   /* struct irc_in_addr, 16B */
  rec.nick_ts = (uint64_t)cli_lastnick(cptr);
  rec.acc_create = (uint64_t)cli_user(cptr)->acc_create;
  rec.server = (uint16_t)base64toint(cli_yxx(cli_user(cptr)->server));
  crdt_user_set(&g_crdt, user_numeric(cptr, num, sizeof num), &rec);
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
}

void crdt_shadow_user_remove(struct Client *cptr)
{
  char num[16];
  if (!shadow_on())
    return;
  if (!cli_user(cptr) || IsBouncerAlias(cptr))
    return;
  if (from_crdt_peer(cli_from(cptr)))  /* single-writer: peer owns this op */
    return;
  crdt_user_remove(&g_crdt, user_numeric(cptr, num, sizeof num));
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
}

void crdt_shadow_topic(struct Channel *chptr, struct Client *from)
{
  if (!shadow_on())
    return;
  if (from_crdt_peer(from))            /* single-writer: peer owns this op */
    return;
  /* op-recording setter so the topic replicates (a direct crdt_lwwmap_set
   * would never enter the oplog and never sync — that was the modes/topic
   * convergence bug). */
  crdt_topic_set(&g_crdt, chptr->chname, chptr->topic);
  write_chanmeta(chptr);               /* topic_time/topic_nick + creationtime */
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
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

void crdt_shadow_modes(struct Channel *chptr, struct Client *from)
{
  struct ShadowModeSnap snap;
  if (!shadow_on() || !chptr)
    return;
  if (from_crdt_peer(from))            /* single-writer: peer owns this op */
    return;
  build_mode_snap(chptr, &snap);
  /* op-recording setter so modes replicate (see crdt_shadow_topic). */
  crdt_modes_set(&g_crdt, chptr->chname, &snap, sizeof snap);
  /* modebuf_flush fires on every op/deop/voice — re-assert each present member's
   * status (the single choke for per-member status changes). */
  {
    struct Membership *m;
    for (m = chptr->members; m; m = m->next_member)
      write_member_status(chptr, m);
  }
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
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

void crdt_shadow_lists(struct Channel *chptr, struct Client *from)
{
  struct CrdtChannel *cc;
  if (!shadow_on() || !chptr)
    return;
  if (from_crdt_peer(from))            /* single-writer: peer owns this op */
    return;
  cc = crdt_state_channel(&g_crdt, chptr->chname, 1);
  reconcile_list(&cc->bans, chptr->banlist);
  reconcile_list(&cc->excepts, chptr->exceptlist);
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
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
            "oplog=%u digest=%016llx mdigest=%016llx",
            checked, crdt_users, real_users, mismatches, g_crdt.oplog.count,
            (unsigned long long)crdt_state_digest(&g_crdt),
            (unsigned long long)crdt_state_digest_materialized(&g_crdt));

  /* NOTE: the oplog is intentionally NOT GC'd against our own state vector
   * here — Phase 2 delta sync needs ops retained until peers have caught up.
   * Causal-stability GC against the min of peer SVs (via CR V) is a later
   * increment; until then the shadow oplog grows (bounded enough for testing). */
}

/* ---- Phase 3b dry-run materialization check (doc -> live fidelity) ----
 * The inverse of crdt_shadow_verify (which walks live -> doc). For every entity
 * in the DOC, confirm a live entity exists with field-for-field fidelity over the
 * reconstruction set 3c would rebuild from. Logs "reconstruction gap"s; MUTATES
 * NOTHING. A clean run means the doc is a faithful, complete source of truth. */

#define MAT_LOG_CAP 20      /* cap logged gaps per pass to avoid log spam */

struct mat_user_ctx { unsigned int *gaps; unsigned int *logged; unsigned int *users; };

static void mat_user_cb(const char *key, uint32_t key_len,
                        const struct CrdtLWWValue *val, void *ctx)
{
  struct mat_user_ctx *c = ctx;
  char numbuf[16], miss[256];
  const struct CrdtUserRecord *rec;
  struct Client *live;
  if (key_len >= sizeof numbuf ||
      val->data_len != sizeof(struct CrdtUserRecord)) { (*c->gaps)++; return; }
  memcpy(numbuf, key, key_len); numbuf[key_len] = '\0';
  rec = (const struct CrdtUserRecord *)val->data;
  (*c->users)++;
  live = findNUser(numbuf);
  if (!live || !cli_user(live)) {
    (*c->gaps)++;
    if ((*c->logged)++ < MAT_LOG_CAP)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT mat-check gap: user %s (%s) in doc, not live", numbuf,
                rec->nick);
    return;
  }
  miss[0] = '\0';
#define MCK(cond, name) do { if (cond) \
    strncat(miss, name " ", sizeof miss - strlen(miss) - 1); } while (0)
  MCK(strcmp(rec->nick, cli_name(live)), "nick");
  MCK(strcmp(rec->ident, cli_user(live)->username), "ident");
  MCK(strcmp(rec->host, cli_user(live)->host), "host");
  MCK(strcmp(rec->realname, cli_info(live)), "realname");
  MCK(strcmp(rec->account, cli_user(live)->account), "account");
  MCK(memcmp(rec->ip6, &cli_ip(live), sizeof rec->ip6), "ip");
  MCK(rec->nick_ts != (uint64_t)cli_lastnick(live), "ts");
  { char letters[CRDT_UMODELEN];
    umode_letters(letters, sizeof letters, umode_str(live));
    MCK(strcmp(rec->umodes, letters), "umode"); }
#undef MCK
  if (miss[0]) {
    (*c->gaps)++;
    if ((*c->logged)++ < MAT_LOG_CAP)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT mat-check gap: user %s (%s) fields: %s", numbuf, rec->nick,
                miss);
  }
}

struct mat_chan_ctx {
  struct Channel *live;
  const char     *chname;
  unsigned int   *gaps;
  unsigned int   *logged;
};

/* present doc member -> live membership + status fidelity */
static void mat_member_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct mat_chan_ctx *c = ctx;
  char numbuf[16], mkey[512];
  struct Client *live_u;
  struct Membership *m;
  const struct CrdtLWWValue *sv;
  const struct CrdtMemberRecord *mr;
  uint8_t live_status;
  uint32_t clen, mklen;
  if (key_len >= sizeof numbuf)
    return;
  memcpy(numbuf, key, key_len); numbuf[key_len] = '\0';
  live_u = findNUser(numbuf);
  m = live_u ? find_member_link(c->live, live_u) : NULL;
  if (!m) {
    (*c->gaps)++;
    if ((*c->logged)++ < MAT_LOG_CAP)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT mat-check gap: %s member %s in doc, not live", c->chname,
                numbuf);
    return;
  }
  clen = (uint32_t)strlen(c->chname);
  if (clen + 1 + key_len > sizeof mkey)
    return;
  memcpy(mkey, c->chname, clen); mkey[clen] = '\0';
  memcpy(mkey + clen + 1, key, key_len);
  mklen = clen + 1 + key_len;
  sv = crdt_lwwmap_get(&g_crdt.members_status, mkey, mklen);
  mr = (sv && sv->data_len == sizeof(struct CrdtMemberRecord))
         ? (const struct CrdtMemberRecord *)sv->data : NULL;
  live_status = compact_status(m->status);
  /* a plain member with no status entry is fine; otherwise must match */
  if ((!mr && live_status != 0) ||
      (mr && (mr->status != live_status ||
              mr->oplevel != (uint16_t)m->oplevel))) {
    (*c->gaps)++;
    if ((*c->logged)++ < MAT_LOG_CAP)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT mat-check gap: %s member %s status doc=%u live=%u",
                c->chname, numbuf, mr ? mr->status : 0, live_status);
  }
}

void crdt_shadow_materialize_check(void)
{
  unsigned int gaps = 0, logged = 0, users = 0, chans = 0;
  int bk;
  if (!shadow_on())
    return;

  { struct mat_user_ctx uc = { &gaps, &logged, &users };
    crdt_lwwmap_foreach(&g_crdt.users, mat_user_cb, &uc); }

  for (bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    struct CrdtChannel *dc;
    for (dc = g_crdt.chan_buckets[bk]; dc; dc = dc->next) {
      char nbuf[CHANNELLEN + 1];
      struct Channel *live;
      struct mat_chan_ctx cc;
      const struct CrdtLWWValue *mv, *tv;
      struct ShadowModeSnap cur;
      if (crdt_orset_size(&dc->members) == 0)   /* empty doc channel */
        continue;
      if (dc->name_len >= sizeof nbuf)
        continue;
      memcpy(nbuf, dc->name, dc->name_len); nbuf[dc->name_len] = '\0';
      chans++;
      live = FindChannel(nbuf);
      if (!live) {
        gaps++;
        if (logged++ < MAT_LOG_CAP)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT mat-check gap: channel %s in doc, not live", nbuf);
        continue;
      }
      /* chanmeta: creationtime + topic provenance */
      mv = crdt_lwwmap_get(&g_crdt.chanmeta, nbuf, dc->name_len);
      if (mv && mv->data_len == sizeof(struct CrdtChanMeta)) {
        const struct CrdtChanMeta *meta = (const struct CrdtChanMeta *)mv->data;
        if (meta->creationtime != (uint64_t)live->creationtime ||
            meta->topic_time != (uint64_t)live->topic_time ||
            strcmp(meta->topic_nick, live->topic_nick) != 0) {
          gaps++;
          if (logged++ < MAT_LOG_CAP)
            log_write(LS_SYSTEM, L_NOTICE, 0,
                      "CRDT mat-check gap: %s chanmeta doc_ts=%lu live_ts=%lu",
                      nbuf, (unsigned long)meta->creationtime,
                      (unsigned long)live->creationtime);
        }
      } else {
        gaps++;
        if (logged++ < MAT_LOG_CAP)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT mat-check gap: %s chanmeta missing", nbuf);
      }
      /* topic string */
      tv = crdt_lwwmap_get(&g_crdt.topics, nbuf, dc->name_len);
      if (strcmp(tv ? (const char *)tv->data : "", live->topic) != 0) {
        gaps++;
        if (logged++ < MAT_LOG_CAP)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT mat-check gap: %s topic mismatch", nbuf);
      }
      /* persistent modes */
      build_mode_snap(live, &cur);
      mv = crdt_lwwmap_get(&g_crdt.modes, nbuf, dc->name_len);
      if ((mv && (mv->data_len != sizeof cur ||
                  memcmp(mv->data, &cur, sizeof cur) != 0)) ||
          (!mv && cur.mode != 0)) {
        gaps++;
        if (logged++ < MAT_LOG_CAP)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT mat-check gap: %s modes mismatch (mode=0x%x)", nbuf,
                    cur.mode);
      }
      /* members + per-member status (present doc members only) */
      cc.live = live; cc.chname = nbuf; cc.gaps = &gaps; cc.logged = &logged;
      crdt_orset_foreach(&dc->members, mat_member_cb, &cc);
    }
  }

  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT mat-check: %u users, %u channels, %u reconstruction gap(s)",
            users, chans, gaps);
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

int crdt_shadow_encode_local_unpushed(uint8_t *buf, size_t cap)
{
  static struct CrdtStateVector synth;   /* static: avoid a 32KB stack frame */
  int i, n;
  if (!g_inited)
    return -1;
  /* synthetic SV: "peer" has everything EXCEPT our own ops above the high-water
   * mark -> crdt_delta_encode emits exactly our unpushed own-origin ops. */
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    synth.seq[i] = (uint64_t)-1;
  synth.seq[g_crdt.my_numeric] = g_last_pushed_seq;
  n = crdt_delta_encode(&g_crdt.oplog, &synth, buf, cap);
  if (n > 4)                             /* ops emitted -> consume them */
    g_last_pushed_seq = g_crdt.local_sv.seq[g_crdt.my_numeric];
  return n;
}

uint64_t crdt_shadow_digest(void)
{
  return g_inited ? crdt_state_digest(&g_crdt) : 0;
}

int crdt_shadow_encode_snapshot(uint8_t *buf, size_t cap)
{
  return g_inited ? crdt_snapshot_encode(&g_crdt, buf, cap) : -1;
}

int crdt_shadow_apply_snapshot(const uint8_t *buf, size_t len)
{
  return g_inited ? crdt_snapshot_apply(&g_crdt, buf, len) : -1;
}

int crdt_shadow_peer_behind_floor(const uint8_t *sv, size_t len)
{
  static struct CrdtStateVector peer;   /* static: avoid a 32KB stack frame */
  int i;
  if (!g_inited)
    return 0;
  if (crdt_sv_decode(&peer, sv, len) < 0)
    return 0;
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    if (peer.seq[i] < g_crdt.gc_floor.seq[i])
      return 1;
  return 0;
}

void crdt_shadow_record_peer_sv(uint16_t origin, const uint8_t *sv, size_t len)
{
  int i, slot = -1;
  if (!g_inited)
    return;
  for (i = 0; i < CRDT_MAX_PEERS; i++) {
    if (g_peers[i].used && g_peers[i].origin == origin) { slot = i; break; }
    if (slot < 0 && !g_peers[i].used) slot = i;
  }
  if (slot < 0)
    return;                                  /* table full */
  if (crdt_sv_decode(&g_peers[slot].sv, sv, len) < 0)
    return;
  g_peers[slot].used = 1;
  g_peers[slot].origin = origin;
  g_peers[slot].when = CurrentTime;
}

/* SV cached for a peer numeric (from CR S / CR V), or NULL if not yet reported. */
static const struct CrdtStateVector *peer_sv_lookup(uint16_t origin)
{
  int i;
  for (i = 0; i < CRDT_MAX_PEERS; i++)
    if (g_peers[i].used && g_peers[i].origin == origin)
      return &g_peers[i].sv;
  return NULL;
}

/* Causal-stability GC: reclaim everything below the component-wise min of (our
 * SV, each CONNECTED CRDT peer's SV). Inclusion is by live connection state, not
 * by last-CR-S timestamp: a peer that is currently linked is always counted
 * (with its best-known SV, or all-zero if it hasn't reported yet -> conservative,
 * blocks GC of its component until it does). A peer that has SQUIT simply isn't
 * in the list, so GC advances past it and a CR F snapshot catches it up on
 * rejoin. (The old timestamp-staleness flapped whenever stale_timeout fell below
 * the CR S broadcast interval, risking reclaiming ops a live-but-quiet peer
 * still needed.) This is correct for ANY connected topology, not just a star:
 * a server only ever sends deltas to its direct peers and retains each op until
 * ALL of them have it, and received ops relay hop-by-hop (crdt_state_apply_op
 * re-appends to the oplog). So an op always survives on the frontier between the
 * has-it and lacks-it regions until it finishes propagating -- no transitive
 * (CR V) SV flooding is needed. Proven by test_multihop_relay_gc_converges. */
static void crdt_shadow_gc(void)
{
  static struct CrdtStateVector gmin;        /* static: avoid a 32KB stack frame */
  static struct CrdtStateVector zero;        /* all-zero, for an unreported peer */
  const struct CrdtStateVector *vecs[CRDT_MAX_PEERS + 1];
  int n = 0, npeers = 0, freed;
  struct Client *acptr;
  if (!shadow_on())
    return;
  vecs[n++] = &g_crdt.local_sv;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (IsServer(acptr) && MyConnect(acptr) && IsCrdtAware(acptr)) {
      const struct CrdtStateVector *sv =
        peer_sv_lookup((uint16_t)base64toint(cli_yxx(acptr)));
      vecs[n++] = sv ? sv : &zero;
      npeers++;
      if (n > CRDT_MAX_PEERS)
        break;
    }
  }
  if (npeers < 1)
    return;                                  /* no connected CRDT peer */
  crdt_sv_global_min(&gmin, vecs, n);
  freed = crdt_state_gc(&g_crdt, &gmin);
  if (freed > 0)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT GC: reclaimed %d op/tombstone(s) (causally stable)", freed);
}

/** Periodic timer callback. */
static void crdt_shadow_verify_cb(struct Event *ev)
{
  if (ev_type(ev) != ET_EXPIRE)
    return;
  crdt_shadow_verify();
  crdt_shadow_materialize_check();  /* Phase 3b dry-run: doc -> live fidelity */
  crdt_sync_broadcast();   /* periodic anti-entropy: pull deltas from peers */
  crdt_shadow_gc();        /* reclaim causally-stable ops/tombstones */
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
