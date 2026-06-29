/*
 * crdt_state.h - IRC network state composed from CRDT primitives
 *
 * Composes the crdt_types primitives (proposal §17.1.6) into the IRC network
 * document, plus the operation log used for delta sync, the nick-collision
 * resolution state machine (§17.5), and SQUIT-as-server-state-transition
 * (§17.3). Phase-0 PoC scope: in-memory, no wire protocol — multiple
 * CrdtNetworkState instances in one process simulate a network and are
 * reconciled with crdt_state_sync().
 *
 * libc + crdt_hlc + crdt_types ONLY (see crdt_types.h for the rationale).
 */

#ifndef INCLUDED_crdt_state_h
#define INCLUDED_crdt_state_h

#include <stdint.h>
#include "crdt_hlc.h"
#include "crdt_types.h"

/* Fixed field sizes (PoC; generous vs IRC limits — buffer sizes incl. NUL). */
#define CRDT_NICKLEN     32
#define CRDT_IDENTLEN    16
#define CRDT_ACCOUNTLEN  32
#define CRDT_NUMERICLEN   6   /* 5-char P10 client numeric + NUL */
#define CRDT_HOSTLEN     80   /* >= HOSTLEN(75)+1 */
#define CRDT_REALLEN     56   /* >= REALLEN(50)+1 */
#define CRDT_UMODELEN    32   /* umode_str() form, e.g. "+rix" */
#define CRDT_SWHOISLEN  256   /* services WHOIS line (SWHOIS); the live field is
                               * BUFSIZE+1 but real swhois lines are short — a
                               * >255-char line truncates in the mesh doc (cosmetic) */
#define CRDT_AWAYLEN    256   /* away message; live AWAYLEN=250 (+NUL fits) */
#define CRDT_VERSIONLEN 128   /* MARK_CVERSION client version; live VERSIONLEN=250 but
                               * real CTCP versions are short — >127 truncates (cosmetic) */
#define CRDT_SSLFPLEN    96   /* MARK_SSLCLIFP cert fingerprint; live BUFSIZE+1 but a
                               * SHA-256 CertFP ("SHA256:"+64 hex) is ~71 chars (cosmetic) */
#define CRDT_GEOCODELEN   3   /* GeoIP 2-letter country/continent code + NUL */
#define CRDT_TOPICNICKLEN 120 /* >= NICKLEN+USERLEN+HOSTLEN+3 +1 */

/* Compact per-member channel status bits (mapped from CHFL_* at the shadow
 * boundary; raw CHFL_HALFOP=0x800000 won't fit a byte). */
#define CRDT_MEMBER_OP     0x01
#define CRDT_MEMBER_VOICE  0x02
#define CRDT_MEMBER_HALFOP 0x04

/*
 * Records stored as LWW-Map values (memcpy'd blobs).
 */

/** Server state (proposal §17.3.2). */
enum CrdtServerState {
  CRDT_SRV_ACTIVE = 0,   /**< linked; its users are visible */
  CRDT_SRV_SPLIT  = 1     /**< delinked; its users hidden, NOT tombstoned */
};

struct CrdtServerRecord {
  uint8_t state;          /**< enum CrdtServerState */
};

/* Full reconstruction payload for a user (Phase 3b): everything the BURST/NICK
 * path needs to rebuild a live Client. Populated with memset-then-fill so the
 * blob (incl. padding) is byte-deterministic across replicas. */
struct CrdtUserRecord {
  char     nick[CRDT_NICKLEN];
  char     ident[CRDT_IDENTLEN];
  char     host[CRDT_HOSTLEN];        /**< displayed host (cli_user->host) — the
                                       *   final string for ANY host type (realhost,
                                       *   +x cloak, sethost, fakehost) */
  char     realhost[CRDT_HOSTLEN];    /**< real host (cli_user->realhost) — kept
                                       *   SEPARATE from the displayed host so a
                                       *   materialized user has the correct realhost
                                       *   (oper WHOIS / ban-matching) and the §17.7
                                       *   gateway emits the real host (not a cloak →
                                       *   no legacy double-cloak). Host-rep parity. */
  char     realname[CRDT_REALLEN];    /**< cli_info */
  char     account[CRDT_ACCOUNTLEN];  /**< "" if not logged in */
  char     swhois[CRDT_SWHOISLEN];    /**< services WHOIS line (SWHOIS); "" if none */
  char     away[CRDT_AWAYLEN];        /**< away message ("" if not away) */
  char     version[CRDT_VERSIONLEN];  /**< MARK_CVERSION client version; "" if none */
  char     sslclifp[CRDT_SSLFPLEN];   /**< MARK_SSLCLIFP SSL cert fingerprint; "" if none */
  char     countrycode[CRDT_GEOCODELEN];   /**< MARK_GEOIP country code; "" if unset */
  char     continentcode[CRDT_GEOCODELEN]; /**< MARK_GEOIP continent code; "" if unset */
  char     umodes[CRDT_UMODELEN];     /**< umode_str() form, e.g. "+rix" */
  unsigned char ip6[16];              /**< struct irc_in_addr bytes (host order) */
  uint64_t nick_ts;                   /**< cli_lastnick (TS) */
  uint64_t acc_create;                /**< account timestamp */
  uint16_t server;        /**< owning server numeric (for SQUIT visibility) */
  /* NB: hopcount is deliberately NOT stored — it is observer-relative (distance
   * from each server), so it can't be a shared CRDT value; 3c recomputes it
   * locally at materialize time. (The dry-run surfaced this.) */
};

/* Per-member channel status (Phase 3b): an LWW register keyed by chan\0numeric,
 * parallel to the members OR-Set (presence is set-like; status is last-write). */
struct CrdtMemberRecord {
  uint8_t  status;        /**< CRDT_MEMBER_OP|VOICE|HALFOP */
  uint16_t oplevel;
};

#define CRDT_KICKREASONLEN 160
/* Per-kick metadata (Phase 3k): an LWW register keyed chan\0numeric, parallel to
 * the kick's member tombstone. Lets reconcile-remove emit a KICK (with attribution)
 * instead of a PART. KICK-vs-PART is gated by comparing this entry's HLC against the
 * member's last-join HLC (members_status, rewritten on every join). */
struct CrdtKickInfo {
  char kicker[CRDT_NUMERICLEN];      /**< kicker's P10 numeric */
  char reason[CRDT_KICKREASONLEN];   /**< kick comment (truncated) */
};

/* Per-channel metadata (Phase 3b): creationtime (TS-war) + topic provenance.
 * Stored separately from the topic string so a topic-less channel still carries
 * its creationtime. Timestamps are fixed uint64 (not time_t) for wire stability. */
struct CrdtChanMeta {
  uint64_t creationtime;
  uint64_t topic_time;
  char     topic_nick[CRDT_TOPICNICKLEN];
};

/** Global G-line as CRDT-native doc state (global-state-into-doc track).  Keyed by
 *  the ban mask (user@host / *@ip / realname / badchan) in the GLINES LWW-map; this
 *  fixed-layout record carries the fields for faithful materialization back to a live
 *  G-line at cutover.  Timestamps are uint64 (not time_t) for wire stability; LWW in
 *  the doc is by HLC (the op ts), while gl_lastmod rides as a field. */
#define CRDT_GLINEREASONLEN 256
struct CrdtGlineRecord {
  uint64_t expire;                 /**< gl_expire */
  uint64_t lastmod;                /**< gl_lastmod (P10 conflict ts, carried) */
  uint64_t lifetime;               /**< gl_lifetime */
  uint32_t flags;                  /**< gl_flags subset (active/ipmask/badchan/...) */
  uint8_t  addr[16];               /**< gl_addr (ip-glines) */
  uint8_t  bits;                   /**< gl_bits */
  uint8_t  pad[3];                 /**< explicit pad -> stable layout for the digest */
  char     reason[CRDT_GLINEREASONLEN];
};

/** Global SHUN as CRDT-native doc state — the GLINE sibling (silence ban, P10 SU
 *  token, no badchan).  Keyed by the ban mask (user@host / *@ip / $R realname /
 *  $V version) in the SHUNS LWW-map; same fixed layout as CrdtGlineRecord. */
#define CRDT_SHUNREASONLEN 256
struct CrdtShunRecord {
  uint64_t expire;                 /**< sh_expire */
  uint64_t lastmod;                /**< sh_lastmod (P10 conflict ts, carried) */
  uint64_t lifetime;               /**< sh_lifetime */
  uint32_t flags;                  /**< sh_flags subset (active/ipmask/realname/version/...) */
  uint8_t  addr[16];               /**< sh_addr (ip-shuns) */
  uint8_t  bits;                   /**< sh_bits */
  uint8_t  pad[3];                 /**< explicit pad -> stable layout for the digest */
  char     reason[CRDT_SHUNREASONLEN];
};

/** Global ZLINE as CRDT-native doc state — the GLINE/SHUN sibling (IP ban, P10 ZL
 *  token).  Keyed by the single IP mask (zl_mask) in the ZLINES LWW-map; same fixed
 *  layout as the others. */
#define CRDT_ZLINEREASONLEN 256
struct CrdtZlineRecord {
  uint64_t expire;                 /**< zl_expire */
  uint64_t lastmod;                /**< zl_lastmod (P10 conflict ts, carried) */
  uint64_t lifetime;               /**< zl_lifetime */
  uint32_t flags;                  /**< zl_flags subset (active/ipmask/...) */
  uint8_t  addr[16];               /**< zl_addr (ip-zlines) */
  uint8_t  bits;                   /**< zl_bits */
  uint8_t  pad[3];                 /**< explicit pad -> stable layout for the digest */
  char     reason[CRDT_ZLINEREASONLEN];
};

/** Global JUPE as CRDT-native doc state — the global-state-track sibling that is NOT
 *  a ban: a juped SERVER NAME (P10 JU token).  Keyed by the server name in the JUPES
 *  LWW-map.  Simpler than the ban records: no lifetime, no addr/bits, no realname/
 *  version.  ju_expire is absolute (CurrentTime-based, NOT TStime). */
#define CRDT_JUPEREASONLEN 256
struct CrdtJupeRecord {
  uint64_t expire;                 /**< ju_expire (absolute, CurrentTime-based) */
  uint64_t lastmod;                /**< ju_lastmod (P10 conflict ts, carried) */
  uint32_t flags;                  /**< ju_flags subset (active/...) */
  uint8_t  pad[4];                 /**< explicit pad -> stable layout for the digest */
  char     reason[CRDT_JUPEREASONLEN];
};

/** Nick claim (proposal §17.5.1). */
struct CrdtNickClaim {
  char       numeric[CRDT_NUMERICLEN];  /**< claiming user's numeric */
  struct HLC claimed_at;
  char       ident[CRDT_IDENTLEN];
  uint32_t   ip;
  char       account[CRDT_ACCOUNTLEN];  /**< "" if unauthenticated */
};

#define CRDT_BSESS_NAMELEN   40   /* >= BOUNCER_NAME_LEN (32) */
#define CRDT_BSESS_TOKENLEN  72   /* >= BOUNCER_TOKEN_LEN (64) + NUL */
#define CRDT_BSESS_OPERLEN   31   /* >= NICKLEN(30) + NUL; matches hs_oper_name */
/** Bouncer session as CRDT-native doc state (5-5e doc-native track).  Keyed by
 *  account\0sessid in the `bsessions` LWW-map; the HOLDER node is the single writer.
 *  M2 = SHADOW only (mirrored + verified against live, NOT yet authoritative).
 *  Timestamps are uint64 (not time_t) for wire stability; memset(0) before fill so
 *  the trailing pad is stable for the digest (INVARIANT 4 field-by-field rule). */
struct CrdtBouncerSession {
  char     token[CRDT_BSESS_TOKENLEN];  /**< resume token */
  char     name[CRDT_BSESS_NAMELEN];    /**< user-assigned session name */
  uint64_t created;                     /**< hs_created (TS) */
  uint64_t last_active;                 /**< hs_last_active (TS) */
  uint64_t total_active;                /**< hs_total_active (seconds) */
  uint64_t oper_granted_at;             /**< hs_oper_granted_at (TS; 0 = not opered) — M6b-2 BS O */
  uint32_t attach_count;                /**< hs_attach_count */
  uint32_t connect_count;               /**< hs_connect_count */
  uint8_t  state;                       /**< enum BouncerState (ACTIVE/HOLDING) */
  int8_t   hold_override;               /**< -1=default / 0=no-hold / 1=hold */
  char     oper_name[CRDT_BSESS_OPERLEN];/**< hs_oper_name (empty = not opered) — M6b-2 BS O */
  uint8_t  pad[7];                      /**< explicit pad -> stable digest layout (sizeof=192) */
};

/** Per-connection record (5-5e M4 doc-native bouncer).  Keyed by account\0sessid\0connnum
 *  in the `bconns` LWW-map; the connection's HOST node is the single writer.  The session
 *  roster = the live (non-tombstoned) entries for a given (account,sessid).  An LWWMap
 *  (single-writer per connection) suffices — no OR-Set needed: only the host adds/removes
 *  its own connection, so there is no concurrent add/remove to merge.  M4 = SHADOW only. */
struct CrdtBouncerConn {
  uint64_t last_active;                  /**< per-connection activity TS */
  uint32_t caps;                        /**< BX_CAP_* bitmask (0 if unknown) */
  uint16_t host;                        /**< owning server numeric (single-writer) */
  uint8_t  is_primary;                  /**< 1 = primary connection, 0 = alias */
  uint8_t  caps_known;                  /**< 0 if caps not yet learned */
};

/** Per-session liveness lease (5-5e M5 doc-native bouncer — THE GATE).  Keyed by
 *  account\0sessid in the `bleases` LWW-map (one entry per session).  Unlike a plain LWW
 *  value, the lease is a DETERMINISTIC-MERGE (comparator) register — structurally the
 *  Phase-3j ctime min-register clone — so the authoritative live-socket holder converges
 *  regardless of clock skew or op order: the claim with the HIGHER generation wins (a revive
 *  supersedes a stale predecessor); a tie in generation breaks to the LOWER host numeric (the
 *  symmetric-dual-revive collapse to primary+alias).  Generation is a LOGICAL counter (immune
 *  to clock skew, unlike naive HLC-LWW which the abandoned Phase-4a servers-map proved
 *  diverges).  HARD-INVARIANT-10: liveness is single-writer-per-claimant + LOCALLY-DERIVED
 *  (beacon-gated revive), never naive shared LWW.  M5 = SHADOW only (computed/logged, NOT
 *  authoritative; M6 cutover flips that). */
struct CrdtBouncerLease {
  uint16_t host;        /**< claiming server numeric (the live-socket holder) */
  uint8_t  pad[2];      /**< explicit pad -> stable digest layout */
  uint32_t generation;  /**< supersession counter; bumped on takeover-from-stale */
  uint64_t claim_ms;    /**< wall-clock of the claim (observability; NOT in compare/digest) */
};

/*
 * Operation log — the unit of replication (proposal §17.1.5).
 */

enum CrdtOpType {
  CRDT_OP_ADD,      /**< OR-Set add (channel members) */
  CRDT_OP_REMOVE,   /**< OR-Set remove (channel members) */
  CRDT_OP_SET,      /**< LWW set (servers/users/nicks) */
  CRDT_OP_DELETE    /**< LWW delete (servers/users/nicks) */
};

enum CrdtCollection {
  CRDT_COLL_SERVERS,
  CRDT_COLL_USERS,
  CRDT_COLL_NICKS,
  CRDT_COLL_CHAN_MEMBERS,
  CRDT_COLL_TOPICS,        /**< channel-name -> topic string (LWW) */
  CRDT_COLL_MODES,         /**< channel-name -> mode snapshot blob (LWW) */
  CRDT_COLL_MEMBER_STATUS, /**< chan\0numeric -> CrdtMemberRecord (LWW) */
  CRDT_COLL_CHANMETA,      /**< channel-name -> CrdtChanMeta (LWW) */
  CRDT_COLL_CHAN_BANS,     /**< per-channel +b ban masks (OR-Set) — Phase 3i */
  CRDT_COLL_CHAN_EXCEPTS,  /**< per-channel +e except masks (OR-Set) — Phase 3i */
  CRDT_COLL_CHAN_CTIME,    /**< per-channel creationtime (incarnation min-register) — Phase 3j */
  CRDT_COLL_KICK_INFO,     /**< chan\0numeric -> CrdtKickInfo (LWW) — Phase 3k */
  CRDT_COLL_GLINES,        /**< ban-mask -> CrdtGlineRecord (LWW) — global-state track */
  CRDT_COLL_SHUNS,         /**< ban-mask -> CrdtShunRecord (LWW) — global-state track */
  CRDT_COLL_ZLINES,        /**< ip-mask -> CrdtZlineRecord (LWW) — global-state track */
  CRDT_COLL_JUPES,         /**< server-name -> CrdtJupeRecord (LWW) — global-state track */
  CRDT_COLL_BSESSIONS,     /**< account\0sessid -> CrdtBouncerSession (LWW) — 5-5e doc-native bouncer */
  CRDT_COLL_BCONNS,        /**< account\0sessid\0connnum -> CrdtBouncerConn (LWW) — 5-5e M4 */
  CRDT_COLL_BLEASES,       /**< account\0sessid -> CrdtBouncerLease (comparator-merge) — 5-5e M5 */
  CRDT_COLL_SILENCES       /**< usernumeric\0mask -> per-user silence masks (OR-Set) — Tier C F1-c */
};

struct CrdtOp {
  uint16_t            origin;     /**< server that created the op */
  uint64_t            seq;        /**< per-origin monotonic sequence */
  enum CrdtOpType     type;
  enum CrdtCollection coll;
  char               *chan;       /**< channel name (CHAN_MEMBERS only), else NULL */
  uint32_t            chan_len;
  char               *key;        /**< element/map key (owned copy) */
  uint32_t            key_len;
  /* OR-Set payload */
  struct CrdtTag      tag;
  uint8_t             priority;
  /* LWW payload */
  void               *val;        /**< owned copy, NULL for delete */
  uint32_t            val_len;
  struct HLC          ts;
  uint16_t            writer;
  struct CrdtOp      *next;
};

struct CrdtOpLog {
  struct CrdtOp *head;   /**< oldest */
  struct CrdtOp *tail;   /**< newest */
  uint32_t       count;
};

/*
 * Channel table — name -> members/bans/excepts OR-Sets. (Channel modes/topic
 * live in the CrdtNetworkState LWW-Maps, keyed by channel name.)
 */
struct CrdtChannel {
  char               *name;
  uint32_t            name_len;
  struct CrdtORSet    members;    /**< set of user numerics */
  struct CrdtORSet    bans;       /**< set of +b ban masks */
  struct CrdtORSet    excepts;    /**< set of +e except masks */
  /* Phase 3j: channel creationtime as an incarnation MIN-register. IRC channel
   * TS is lower-TS-wins (NOT LWW), so concurrent creates within one incarnation
   * resolve to min(ctime). ctime_del marks the incarnation boundary (bumped on
   * destroy) so a recreate to a HIGHER TS is not resurrected to the stale value.
   * Live iff hlc_compare(&ctime_set, &ctime_del) > 0. */
  uint64_t            ctime;
  struct HLC          ctime_set;  /**< HLC of the latest create within this incarnation */
  struct HLC          ctime_del;  /**< HLC of the latest destroy (incarnation marker) */
  struct CrdtChannel *next;       /**< bucket chain */
};

#define CRDT_CHAN_BUCKETS 256

/*
 * Top-level network state (one per simulated server).
 */
struct CrdtNetworkState {
  uint16_t                my_numeric;
  uint64_t                next_seq;     /**< local op-sequence allocator */
  struct HLC              clock;        /**< this server's HLC (per-instance,
                                         *   NOT the crdt_hlc global — lets
                                         *   multiple states coexist in-proc) */
  struct CrdtStateVector  local_sv;     /**< what this server has seen */
  struct CrdtStateVector  gc_floor;     /**< highest seq/origin reclaimed from
                                         *   the oplog; a peer whose SV is below
                                         *   this can't be served a delta and
                                         *   needs a full snapshot (CR F) */
  struct CrdtOpLog        oplog;        /**< ops for delta computation */

  struct CrdtLWWMap       servers;      /**< numeric-str -> CrdtServerRecord */
  struct CrdtLWWMap       users;        /**< numeric-str -> CrdtUserRecord */
  struct CrdtLWWMap       nicks;        /**< lc-nick -> CrdtNickClaim */
  struct CrdtLWWMap       topics;       /**< channel-name -> topic string */
  struct CrdtLWWMap       modes;        /**< channel-name -> opaque mode blob */
  struct CrdtLWWMap       members_status; /**< chan\0numeric -> CrdtMemberRecord */
  struct CrdtLWWMap       kick_info;    /**< chan\0numeric -> CrdtKickInfo (Phase 3k) */
  struct CrdtLWWMap       chanmeta;     /**< channel-name -> CrdtChanMeta */
  struct CrdtLWWMap       glines;       /**< ban-mask -> CrdtGlineRecord (global-state) */
  struct CrdtLWWMap       shuns;        /**< ban-mask -> CrdtShunRecord (global-state) */
  struct CrdtLWWMap       zlines;       /**< ip-mask -> CrdtZlineRecord (global-state) */
  struct CrdtLWWMap       jupes;        /**< server-name -> CrdtJupeRecord (global-state) */
  struct CrdtLWWMap       bsessions;    /**< account\0sessid -> CrdtBouncerSession (5-5e) */
  struct CrdtLWWMap       bconns;       /**< account\0sessid\0connnum -> CrdtBouncerConn (5-5e M4) */
  struct CrdtLWWMap       bleases;      /**< account\0sessid -> CrdtBouncerLease (5-5e M5) */
  struct CrdtORSet        silences;     /**< usernumeric\0mask -> per-user silence masks (Tier C F1-c) */
  struct CrdtChannel     *chan_buckets[CRDT_CHAN_BUCKETS];
};

/* ---- lifecycle ---- */
void crdt_state_init(struct CrdtNetworkState *st, uint16_t my_numeric);
void crdt_state_clear(struct CrdtNetworkState *st);

/* ---- local mutations (generate op, apply locally, append to oplog) ---- */
void crdt_user_set(struct CrdtNetworkState *st, const char *numeric,
                   const struct CrdtUserRecord *rec);
void crdt_user_remove(struct CrdtNetworkState *st, const char *numeric);
/** Phase 3m: 1 iff @a numeric has an explicit user delete-tombstone in the doc
 *  (gate for doc->live delete-on-leave; never true for a merely-absent user). */
int crdt_user_is_explicitly_removed(const struct CrdtNetworkState *st,
                                    const char *numeric);
void crdt_nick_claim(struct CrdtNetworkState *st, const char *nick_lc,
                     const struct CrdtNickClaim *claim);
void crdt_chan_join(struct CrdtNetworkState *st, const char *chan,
                    const char *numeric);
void crdt_chan_remove(struct CrdtNetworkState *st, const char *chan,
                      const char *numeric, uint8_t priority);
/** Phase 3i: op-recording add/remove of a +b/+e mask in a channel's bans/excepts
 *  OR-Set (is_except selects the list). Unlike a direct crdt_orset_add, these
 *  record a CRDT_OP so the change replicates via delta sync (not only snapshot). */
void crdt_chan_ban_add(struct CrdtNetworkState *st, const char *chan,
                       const char *mask, int is_except);
void crdt_chan_ban_remove(struct CrdtNetworkState *st, const char *chan,
                          const char *mask, uint8_t priority, int is_except);
/** Tier C F1-c: per-user SILENCE mask add/remove on the global silences OR-Set
 *  (keyed usernumeric\0mask). Op-recording (delta-replicating), mirrors
 *  crdt_chan_ban_add/remove. */
void crdt_silence_add(struct CrdtNetworkState *st, const char *usernumeric,
                      const char *mask);
void crdt_silence_remove(struct CrdtNetworkState *st, const char *usernumeric,
                         const char *mask, uint8_t priority);
/** Phase 3j: set/get a channel's creationtime as an incarnation min-register.
 *  set() merges in {value, set_hlc=now, del_hlc=current}, records a
 *  CRDT_COLL_CHAN_CTIME op (so it replicates via delta). clear() bumps the local
 *  incarnation marker (ctime_del=now) — LOCAL ONLY, no op; the next set-op carries
 *  the new del_hlc to peers. get() returns the live creationtime, or 0 if absent /
 *  destroyed. */
void crdt_chan_ctime_set(struct CrdtNetworkState *st, const char *chan,
                         uint64_t creationtime);
void crdt_chan_ctime_clear(struct CrdtNetworkState *st, const char *chan);
uint64_t crdt_chan_ctime_get(struct CrdtNetworkState *st, const char *chan);
void crdt_server_set(struct CrdtNetworkState *st, uint16_t numeric,
                     enum CrdtServerState state);
/** SQUIT — one LWW write, zero membership tombstones (proposal §17.3.2). */
void crdt_server_squit(struct CrdtNetworkState *st, uint16_t numeric);
void crdt_server_relink(struct CrdtNetworkState *st, uint16_t numeric);
/** Resume our own op-seq above the adopted local_sv floor after applying a peer
 *  snapshot/delta — so a restarted server (next_seq reset, peers remembering its
 *  old seq) does not mint already-seen seqs that peers dedup.  Idempotent. */
void crdt_state_resume_seq(struct CrdtNetworkState *st);
/** Current doc state of server @a numeric: CRDT_SRV_ACTIVE (0), CRDT_SRV_SPLIT
 *  (1), or -1 if absent.  Used by the single-writer self-ACTIVE assert. */
int crdt_server_state(const struct CrdtNetworkState *st, uint16_t numeric);
/** Set a channel topic (LWW). Records a SET op so it replicates. */
void crdt_topic_set(struct CrdtNetworkState *st, const char *chan,
                    const char *topic);
/** Set a channel mode snapshot (opaque blob, LWW). Records a SET op. */
void crdt_modes_set(struct CrdtNetworkState *st, const char *chan,
                    const void *snap, uint32_t snaplen);
/** Set a member's channel status (LWW, keyed chan\0numeric). Records a SET op. */
void crdt_member_status_set(struct CrdtNetworkState *st, const char *chan,
                            const char *numeric,
                            const struct CrdtMemberRecord *rec);
/** Set per-channel metadata (creationtime/topic provenance, LWW). Records a SET. */
void crdt_chanmeta_set(struct CrdtNetworkState *st, const char *chan,
                       const struct CrdtChanMeta *meta);
/** Global-state track: set/remove a G-line in the GLINES LWW-map keyed by @a mask.
 *  set() records a SET op (op-recording -> replicates via delta, not just snapshot);
 *  del() records a DELETE tombstone. */
void crdt_gline_set(struct CrdtNetworkState *st, const char *mask,
                    const struct CrdtGlineRecord *rec);
void crdt_gline_del(struct CrdtNetworkState *st, const char *mask);
/** GLINE step 3: 1 iff @a mask has an explicit gline delete-tombstone in the doc
 *  (gate for doc->live removal; never true for a merely-absent mask). */
int crdt_gline_is_explicitly_removed(const struct CrdtNetworkState *st,
                                     const char *mask);
/** SHUN (global-state track): set/remove a SHUN in the SHUNS LWW-map keyed by @a mask
 *  (op-recording, mirrors crdt_gline_*). */
void crdt_shun_set(struct CrdtNetworkState *st, const char *mask,
                   const struct CrdtShunRecord *rec);
void crdt_shun_del(struct CrdtNetworkState *st, const char *mask);
/** 1 iff @a mask has an explicit shun delete-tombstone (gate for doc->live removal). */
int crdt_shun_is_explicitly_removed(const struct CrdtNetworkState *st,
                                    const char *mask);
/** ZLINE (global-state track): set/remove a Z-line in the ZLINES LWW-map keyed by @a
 *  mask (the single IP mask; op-recording, mirrors the gline/shun setters). */
void crdt_zline_set(struct CrdtNetworkState *st, const char *mask,
                    const struct CrdtZlineRecord *rec);
void crdt_zline_del(struct CrdtNetworkState *st, const char *mask);
/** 1 iff @a mask has an explicit zline delete-tombstone (gate for doc->live removal). */
int crdt_zline_is_explicitly_removed(const struct CrdtNetworkState *st,
                                     const char *mask);
/** JUPE (global-state track): set/remove a juped server in the JUPES LWW-map keyed by
 *  @a server name (op-recording). NB global-jupe "removal" is a deactivate (SET inactive),
 *  not a tombstone — del is for symmetry / a future jupe_destroy. */
void crdt_jupe_set(struct CrdtNetworkState *st, const char *server,
                   const struct CrdtJupeRecord *rec);
void crdt_jupe_del(struct CrdtNetworkState *st, const char *server);
/** 1 iff @a server has an explicit jupe delete-tombstone (gate for doc->live removal). */
int crdt_jupe_is_explicitly_removed(const struct CrdtNetworkState *st,
                                    const char *server);
/** 5-5e doc-native bouncer: set/del/get a session record in the BSESSIONS LWW-map keyed
 *  by @a account \0 @a sessid (op-recording; the holder node is the single writer). */
void crdt_bsess_set(struct CrdtNetworkState *st, const char *account,
                    const char *sessid, const struct CrdtBouncerSession *rec);
void crdt_bsess_del(struct CrdtNetworkState *st, const char *account,
                    const char *sessid);
const struct CrdtBouncerSession *crdt_bsess_get(const struct CrdtNetworkState *st,
                                                const char *account, const char *sessid);
/** 1 iff (account,sessid) has an explicit delete-tombstone (gate for doc->live removal). */
int crdt_bsess_is_explicitly_removed(const struct CrdtNetworkState *st,
                                     const char *account, const char *sessid);
/** 5-5e M3: the cross-sessid election winner = strcmp-lowest sessid among @a account's
 *  LIVE bsessions records (matches bouncer_session.c's strcmp election). Writes the
 *  NUL-terminated winner to @a out; returns out, or NULL if no live session in the doc. */
const char *crdt_bsess_winner(const struct CrdtNetworkState *st, const char *account,
                              char *out, size_t outsz);
/** 5-5e M4: set/del/get a per-connection record in the BCONNS LWW-map keyed by
 *  @a account \0 @a sessid \0 @a connnum (op-recording; the connection HOST is the
 *  single writer). The session roster = the live entries for (account,sessid). */
void crdt_bconn_set(struct CrdtNetworkState *st, const char *account,
                    const char *sessid, const char *connnum,
                    const struct CrdtBouncerConn *rec);
void crdt_bconn_del(struct CrdtNetworkState *st, const char *account,
                    const char *sessid, const char *connnum);
const struct CrdtBouncerConn *crdt_bconn_get(const struct CrdtNetworkState *st,
                                             const char *account, const char *sessid,
                                             const char *connnum);
int crdt_bconn_is_explicitly_removed(const struct CrdtNetworkState *st,
                                     const char *account, const char *sessid,
                                     const char *connnum);
/** 5-5e M4: number of LIVE (non-tombstoned) connections in the (account,sessid) roster. */
int crdt_bconn_roster_count(const struct CrdtNetworkState *st,
                            const char *account, const char *sessid);
/** 5-5e M6a-2: the PRIMARY connection's numeric for (account,sessid) (the is_primary
 *  bconn). Writes NUL-terminated to @a out; returns out, or NULL if no primary in doc. */
const char *crdt_bconn_primary(const struct CrdtNetworkState *st,
                               const char *account, const char *sessid,
                               char *out, size_t outsz);
/** 5-5e M5: the liveness-lease comparator (PURE; the riskiest single piece — cmocka-gated).
 *  Returns >0 if @a a is the authoritative claim, <0 if @a b, 0 if identical.  Order: higher
 *  generation wins; tie -> lower host numeric wins.  A TOTAL order (host numerics unique), so
 *  the register merge keeping the comparator-max is a join-semilattice -> converges regardless
 *  of op/delivery order or clock skew. */
int crdt_blease_compare(const struct CrdtBouncerLease *a,
                        const struct CrdtBouncerLease *b);
/** 5-5e M5: the beacon-gated claim DECISION (PURE; cmocka-gated truth table).  Given the
 *  current converged lease @a cur (NULL if none), whether @a cur's host beacon is FRESH, and
 *  this node's numeric @a me, returns the generation @a me should claim, or -1 to STAND DOWN
 *  (another fresh holder already holds, so this node must not claim).  No lease -> claim gen 0;
 *  cur held by me -> re-affirm @a cur's generation (idempotent); cur held by another but its
 *  beacon STALE -> revive at generation+1 (supersede); cur held by another and FRESH -> -1. */
long crdt_blease_decide(const struct CrdtBouncerLease *cur, int cur_host_fresh,
                        uint16_t me);

/** 5-5e M6d: the AUTHORITATIVE lease ACTION (PURE; cmocka-gated truth table).  Maps the
 *  converged lease to the concrete bouncer operation THIS node must take, layering
 *  have-local-primary + revive-site context onto crdt_blease_decide's generation math:
 *    - no lease / lease is mine          -> NOOP (claim path owns it)
 *    - other holder, beacon FRESH        -> DEMOTE_TO_ALIAS if I hold a live local primary
 *                                           (split-brain loser stands down), else NOOP (replica)
 *    - other holder, beacon STALE        -> REVIVE_LOCAL if this is a revive site (a fresh
 *                                           connection resuming a split-away/dead holder), else
 *                                           NOOP (the periodic claim supersedes the stale holder).
 *  A FRESH holder always wins over want_revive (never revive a live holder). */
enum CrdtBLeaseAction {
  CRDT_BLEASE_NOOP = 0,
  CRDT_BLEASE_REVIVE_LOCAL,
  CRDT_BLEASE_DEMOTE_TO_ALIAS
};
enum CrdtBLeaseAction crdt_blease_action(const struct CrdtBouncerLease *cur, uint16_t me,
                                         int holder_beacon_fresh, int have_local_primary,
                                         int want_revive);
/** 5-5e M5: claim/refresh the lease for (account,sessid) at @a generation, host @a host.
 *  Deterministic-merge: records + applies an op ONLY if the claim beats the current via the
 *  comparator (an idempotent re-affirm is a no-op -> no per-sweep op storm).  Never resurrects
 *  a tombstoned (session-ended) lease key — sessid is single-use. */
void crdt_blease_claim(struct CrdtNetworkState *st, const char *account,
                       const char *sessid, uint16_t host, uint32_t generation,
                       uint64_t claim_ms);
/** 5-5e M5: tombstone the lease (session destroyed). */
void crdt_blease_del(struct CrdtNetworkState *st, const char *account,
                     const char *sessid);
/** 5-5e M5: the current converged lease for (account,sessid), or NULL if none/tombstoned. */
const struct CrdtBouncerLease *crdt_blease_get(const struct CrdtNetworkState *st,
                                               const char *account, const char *sessid);
/** 5-5e M5: snapshot-apply MERGE of a lease blob via the comparator (crdt_wire.c). */
void crdt_blease_merge_snapshot(struct CrdtNetworkState *st, const char *key,
                                uint32_t klen, const struct CrdtBouncerLease *rec,
                                uint16_t writer, struct HLC ts);
/** Phase 3k: set/get per-kick metadata (LWW, keyed chan\0numeric). set() records a
 *  SET op so it replicates via delta; get() returns the LWW value (NULL if absent)
 *  so callers can read both the CrdtKickInfo payload and its HLC (.ts) for the
 *  KICK-vs-PART staleness gate. */
void crdt_kick_info_set(struct CrdtNetworkState *st, const char *chan,
                        const char *numeric, const struct CrdtKickInfo *ki);
const struct CrdtLWWValue *crdt_kick_info_get(struct CrdtNetworkState *st,
                                              const char *chan, const char *numeric);
/** Get a member's status LWW value (NULL if absent), for the KICK-vs-PART HLC gate. */
const struct CrdtLWWValue *crdt_member_status_get(struct CrdtNetworkState *st,
                                                  const char *chan, const char *numeric);

/* ---- sync / merge ---- */
/** The LWW-Map backing a given collection (SERVERS/USERS/NICKS/TOPICS/MODES),
 *  or NULL for OR-Set collections. Exposed for snapshot apply (crdt_wire.c). */
struct CrdtLWWMap *crdt_state_lww_for(struct CrdtNetworkState *st,
                                      enum CrdtCollection coll);
/** Phase 3j: merge a channel ctime register entry (incarnation min-register).
 *  Exposed for snapshot apply (crdt_wire.c), parallel to crdt_lwwmap_set. */
void crdt_chan_ctime_merge(struct CrdtNetworkState *st, const char *chan,
                           uint32_t clen, uint64_t value,
                           struct HLC set_hlc, struct HLC del_hlc);
/** Apply a single remote op (idempotent via state-vector check). */
void crdt_state_apply_op(struct CrdtNetworkState *st, const struct CrdtOp *op);
/** Delta sync: replay every op in src's oplog that dst hasn't seen, into dst.
 *  Models "src sends dst the delta dst is missing." Returns ops applied. */
int  crdt_state_sync(struct CrdtNetworkState *dst,
                     const struct CrdtNetworkState *src);
/** Structural equality of replicated state (for convergence assertions). */
int  crdt_state_equal(const struct CrdtNetworkState *a,
                      const struct CrdtNetworkState *b);

/** Order-independent digest of the ENTIRE CRDT document, including OR-Set
 *  add-tags and tombstones (not just materialized state). Two replicas that
 *  have exchanged all ops produce the same digest; tag divergence (e.g. before
 *  delta sync unions per-origin tags) produces different digests. */
uint64_t crdt_state_digest(const struct CrdtNetworkState *st);

/** Materialized-state digest: PRESENT OR-Set elements + LWW maps only, with no
 *  GC-reclaimable add-tags/tombstones. Invariant under independent GC — the
 *  true convergence metric (two replicas with equal observable state agree even
 *  if they have GC'd different tombstone subsets). */
uint64_t crdt_state_digest_materialized(const struct CrdtNetworkState *st);

/* ---- causal-stability GC ---- */
/** GC oplog + all channel member sets against a stable state vector. Returns
 *  total tombstones+ops freed. (Only sound over priority-0 churn — see
 *  crdt_orset_gc note.) */
int  crdt_state_gc(struct CrdtNetworkState *st,
                   const struct CrdtStateVector *stable);

/** Reclaim orphaned per-member metadata (members_status / kick_info) for members
 *  that have fully departed a channel (gone from the OR-Set, removal causally
 *  stable) by minting DELETE ops so they ride the tombstone GC. Returns the count
 *  reclaimed. Safe + idempotent to call each GC cycle. */
int  crdt_state_reclaim_orphan_member_meta(struct CrdtNetworkState *st);

/* ---- queries ---- */
struct CrdtChannel *crdt_state_channel(struct CrdtNetworkState *st,
                                       const char *chan, int create);
const struct CrdtUserRecord *crdt_user_get(const struct CrdtNetworkState *st,
                                           const char *numeric);
/** Visible iff the user exists and its owning server is ACTIVE (§17.3.3). */
int  crdt_user_visible(const struct CrdtNetworkState *st, const char *numeric);
/** Count of channel members whose owning server is ACTIVE. */
uint32_t crdt_chan_visible_members(struct CrdtNetworkState *st,
                                   const char *chan);

/* ---- nick-collision state machine (proposal §17.5.3) ---- */
/** Resolve a contested nick. registered_owner is the account that owns the
 *  nick per services, or NULL/"" if unregistered. Returns the WINNING claim:
 *    1. account owner match wins (if registered),
 *    2. different user@host -> OLDER claim wins (keep established user),
 *    3. same user@host -> NEWER wins (reconnect),
 *    4. tie -> lower node_id. */
const struct CrdtNickClaim *
crdt_resolve_nick_collision(const struct CrdtNickClaim *local,
                            const struct CrdtNickClaim *remote,
                            const char *registered_owner);

/** Force-rename the losing user to its numeric (NOT a kill, §17.5.4):
 *  updates users[loser->numeric].nick and nicks[<numeric>], stamped at now. */
void crdt_nick_force_rename(struct CrdtNetworkState *st,
                            const struct CrdtNickClaim *loser,
                            struct HLC now);

#endif /* INCLUDED_crdt_state_h */
