/*
 * m_crdt.c - CR (CRDT sync) P10 token handler (Phase 2)
 *
 * Wires together the pieces built earlier: the 'C' capability flag
 * (negotiation), s2s_chunk (reassembly), crdt_wire (serialization), and the
 * shadow document (via crdt_shadow_* accessors). Additive and non-authoritative
 * — P10 BURST stays the source of truth; CR only flows between CRDT-aware peers
 * and only when FEAT_CRDT_ENABLED.
 *
 * Wire shapes (S2S):
 *   <src> CR S :<b64(state_vector)>            request: my SV, send me the delta
 *   <src> CR D <id> <+|.> :<b64_chunk>         delta chunk (+ = more follows)
 *   <src> CR U <id> <+|.> :<b64_chunk>         incremental update chunk
 *   <src> CR F <id> <+|.> :<b64_chunk>         full-snapshot chunk (CR F)
 *   <src> CR V :<b64(state_vector)>            version broadcast (GC)
 */

#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "handlers.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"

#include "crdt_shadow.h"
#include "crdt_wire.h"
#include "s2s_chunk.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define CR_DELTA_MAX  65536     /* max raw delta we encode in one exchange */
#define CR_SNAP_MAX   262144    /* max raw full snapshot (CR F) */
#define CR_CHUNK_LEN  400       /* base64 chars per CR D/U/F line */

static unsigned int crdt_stream_ctr = 0;

/** Send base64 @a b64 (length @a b64len) to @a to as a series of CR <sub>
 *  chunks, each carrying a stream id so the receiver can reassemble. */
static void send_crdt_chunks(struct Client *to, char sub,
                             const char *b64, int b64len)
{
  char id[24];
  int off = 0;
  snprintf(id, sizeof id, "%s%u", cli_yxx(&me), ++crdt_stream_ctr);
  do {
    int n = (b64len - off > CR_CHUNK_LEN) ? CR_CHUNK_LEN : (b64len - off);
    int more = (off + n < b64len);
    char piece[CR_CHUNK_LEN + 1];
    memcpy(piece, b64 + off, (size_t)n);
    piece[n] = '\0';
    sendcmdto_one(&me, CMD_CRDT_REPLICATION, to, "%c %s %s :%s",
                  sub, id, more ? "+" : ".", piece);
    off += n;
  } while (off < b64len);
}

/** Compute the delta of ops @a to lacks (given its encoded state vector) and
 *  send it as CR D chunks. */
static void send_crdt_delta(struct Client *to, const uint8_t *remote_sv,
                            int sv_len)
{
  uint8_t *delta = MyMalloc(CR_DELTA_MAX);
  int dn = crdt_shadow_encode_delta(remote_sv, (size_t)sv_len, delta,
                                    CR_DELTA_MAX);
  if (dn > 4) {                 /* 4 bytes = empty op count; nothing to send */
    size_t bcap = (size_t)dn * 4 / 3 + 8;
    char *b64 = MyMalloc(bcap);
    int bn = crdt_b64_encode(delta, (size_t)dn, b64, bcap);
    if (bn > 0)
      send_crdt_chunks(to, 'D', b64, bn);
    MyFree(b64);
  }
  MyFree(delta);
}

/** Encode the full document as a snapshot and send it as CR F chunks. Used
 *  when the peer has fallen behind the GC floor (a delta would be incomplete). */
static void send_crdt_snapshot(struct Client *to)
{
  uint8_t *snap = MyMalloc(CR_SNAP_MAX);
  int sn = crdt_shadow_encode_snapshot(snap, CR_SNAP_MAX);
  if (sn > 0) {
    size_t bcap = (size_t)sn * 4 / 3 + 8;
    char *b64 = MyMalloc(bcap);
    int bn = crdt_b64_encode(snap, (size_t)sn, b64, bcap);
    if (bn > 0)
      send_crdt_chunks(to, 'F', b64, bn);
    MyFree(b64);
  }
  MyFree(snap);
}

void crdt_sync_request(struct Client *peer)
{
  uint8_t sv[8192];
  char b64[12000];
  int n, bn;
  if (!crdt_shadow_active() || !IsServer(peer) || !IsCrdtAware(peer))
    return;
  n = crdt_shadow_encode_sv(sv, sizeof sv);
  if (n < 0)
    return;
  bn = crdt_b64_encode(sv, (size_t)n, b64, sizeof b64);
  if (bn < 0)
    return;
  sendcmdto_one(&me, CMD_CRDT_REPLICATION, peer, "S :%s", b64);
}

void crdt_sync_broadcast(void)
{
  struct Client *acptr;
  if (!crdt_shadow_active())
    return;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsServer(acptr) && MyConnect(acptr) && IsCrdtAware(acptr))
      crdt_sync_request(acptr);
}

int ms_crdt(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *sub;

  if (!crdt_shadow_active() || parc < 3)
    return 0;
  sub = parv[1];

  if (sub[0] == 'S' && !sub[1]) {
    /* peer's state vector -> record it (for GC) + reply with the delta it lacks */
    uint8_t svbytes[8192];
    int svn = crdt_b64_decode(parv[parc - 1], svbytes, sizeof svbytes);
    if (svn >= 0) {
      crdt_shadow_record_peer_sv((uint16_t)base64toint(cli_yxx(cptr)),
                                 svbytes, (size_t)svn);
      /* if the peer is behind the GC floor, the ops it lacks are gone from the
       * oplog -> send a full snapshot instead of an incomplete delta */
      if (crdt_shadow_peer_behind_floor(svbytes, (size_t)svn))
        send_crdt_snapshot(cptr);
      else
        send_crdt_delta(cptr, svbytes, svn);
    }
  } else if ((sub[0] == 'D' || sub[0] == 'U') && !sub[1]) {
    /* delta / incremental chunk: <id> <+|.> :<b64> */
    char *full = NULL;
    size_t flen = 0;
    int r;
    if (parc < 5)
      return 0;
    r = s2s_chunk_feed(cptr, parv[2], parv[parc - 1], parv[3][0] == '+',
                       &full, &flen);
    if (r == 1) {
      uint8_t *bin = MyMalloc(flen ? flen : 1);
      int bn = crdt_b64_decode(full, bin, flen ? flen : 1);
      MyFree(full);
      if (bn > 0) {
        int applied = crdt_shadow_apply_delta(bin, (size_t)bn);
        if (applied > 0)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT sync: applied %d op(s) from %s", applied,
                    cli_name(cptr));
      }
      MyFree(bin);
    }
  } else if (sub[0] == 'F' && !sub[1]) {
    /* full-snapshot chunk: <id> <+|.> :<b64> -> apply once fully reassembled */
    char *full = NULL;
    size_t flen = 0;
    int r;
    if (parc < 5)
      return 0;
    r = s2s_chunk_feed(cptr, parv[2], parv[parc - 1], parv[3][0] == '+',
                       &full, &flen);
    if (r == 1) {
      uint8_t *bin = MyMalloc(flen ? flen : 1);
      int bn = crdt_b64_decode(full, bin, flen ? flen : 1);
      MyFree(full);
      if (bn > 0 && crdt_shadow_apply_snapshot(bin, (size_t)bn) == 0)
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CRDT sync: applied full snapshot (%d bytes) from %s", bn,
                  cli_name(cptr));
      MyFree(bin);
    }
  } else if (sub[0] == 'V' && !sub[1]) {
    /* version broadcast: record the peer's SV for causal-stability GC */
    uint8_t svbytes[8192];
    int svn = crdt_b64_decode(parv[parc - 1], svbytes, sizeof svbytes);
    if (svn >= 0)
      crdt_shadow_record_peer_sv((uint16_t)base64toint(cli_yxx(cptr)),
                                 svbytes, (size_t)svn);
  }
  return 0;
}
