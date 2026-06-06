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

/* Fixed field sizes (PoC; generous vs IRC limits). */
#define CRDT_NICKLEN     32
#define CRDT_IDENTLEN    16
#define CRDT_ACCOUNTLEN  32
#define CRDT_NUMERICLEN   6   /* 5-char P10 client numeric + NUL */

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

struct CrdtUserRecord {
  char     nick[CRDT_NICKLEN];
  char     ident[CRDT_IDENTLEN];
  uint32_t ip;
  uint16_t server;        /**< owning server numeric (for SQUIT visibility) */
};

/** Nick claim (proposal §17.5.1). */
struct CrdtNickClaim {
  char       numeric[CRDT_NUMERICLEN];  /**< claiming user's numeric */
  struct HLC claimed_at;
  char       ident[CRDT_IDENTLEN];
  uint32_t   ip;
  char       account[CRDT_ACCOUNTLEN];  /**< "" if unauthenticated */
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
  CRDT_COLL_CHAN_MEMBERS
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
 * Channel table — name -> members OR-Set (PoC keeps bans/modes out of scope).
 */
struct CrdtChannel {
  char               *name;
  uint32_t            name_len;
  struct CrdtORSet    members;    /**< set of user numerics */
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
  struct CrdtOpLog        oplog;        /**< ops for delta computation */

  struct CrdtLWWMap       servers;      /**< numeric-str -> CrdtServerRecord */
  struct CrdtLWWMap       users;        /**< numeric-str -> CrdtUserRecord */
  struct CrdtLWWMap       nicks;        /**< lc-nick -> CrdtNickClaim */
  struct CrdtLWWMap       topics;       /**< channel-name -> topic string */
  struct CrdtChannel     *chan_buckets[CRDT_CHAN_BUCKETS];
};

/* ---- lifecycle ---- */
void crdt_state_init(struct CrdtNetworkState *st, uint16_t my_numeric);
void crdt_state_clear(struct CrdtNetworkState *st);

/* ---- local mutations (generate op, apply locally, append to oplog) ---- */
void crdt_user_set(struct CrdtNetworkState *st, const char *numeric,
                   const struct CrdtUserRecord *rec);
void crdt_user_remove(struct CrdtNetworkState *st, const char *numeric);
void crdt_nick_claim(struct CrdtNetworkState *st, const char *nick_lc,
                     const struct CrdtNickClaim *claim);
void crdt_chan_join(struct CrdtNetworkState *st, const char *chan,
                    const char *numeric);
void crdt_chan_remove(struct CrdtNetworkState *st, const char *chan,
                      const char *numeric, uint8_t priority);
void crdt_server_set(struct CrdtNetworkState *st, uint16_t numeric,
                     enum CrdtServerState state);
/** SQUIT — one LWW write, zero membership tombstones (proposal §17.3.2). */
void crdt_server_squit(struct CrdtNetworkState *st, uint16_t numeric);
void crdt_server_relink(struct CrdtNetworkState *st, uint16_t numeric);

/* ---- sync / merge ---- */
/** Apply a single remote op (idempotent via state-vector check). */
void crdt_state_apply_op(struct CrdtNetworkState *st, const struct CrdtOp *op);
/** Delta sync: replay every op in src's oplog that dst hasn't seen, into dst.
 *  Models "src sends dst the delta dst is missing." Returns ops applied. */
int  crdt_state_sync(struct CrdtNetworkState *dst,
                     const struct CrdtNetworkState *src);
/** Structural equality of replicated state (for convergence assertions). */
int  crdt_state_equal(const struct CrdtNetworkState *a,
                      const struct CrdtNetworkState *b);

/* ---- causal-stability GC ---- */
/** GC oplog + all channel member sets against a stable state vector. Returns
 *  total tombstones+ops freed. (Only sound over priority-0 churn — see
 *  crdt_orset_gc note.) */
int  crdt_state_gc(struct CrdtNetworkState *st,
                   const struct CrdtStateVector *stable);

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
