/*
 * crdt_wire.h - Binary wire serialization for CRDT sync (Phase 2)
 *
 * Encodes/decodes CRDT state vectors, operations, and deltas to a compact
 * big-endian binary form for S2S transport (the CR P10 token, later chunked +
 * zstd'd + base64'd onto the wire). The in-process delta logic already lives in
 * crdt_state_sync(); this is its on-the-wire counterpart.
 *
 * libc + crdt_types + crdt_state only — no IRCd coupling, fully unit-testable.
 *
 * All multi-byte integers are big-endian (network order). Functions return the
 * number of bytes written / consumed, or -1 on error (buffer too small or
 * malformed input).
 */

#ifndef INCLUDED_crdt_wire_h
#define INCLUDED_crdt_wire_h

#include <stdint.h>
#include <stddef.h>
#include "crdt_types.h"
#include "crdt_state.h"

/* ---- state vector ----
 * Layout: [count:2] then count * [origin:2][seq:8]. Only non-zero entries. */
int crdt_sv_encode(const struct CrdtStateVector *sv, uint8_t *buf, size_t cap);
int crdt_sv_decode(struct CrdtStateVector *sv, const uint8_t *buf, size_t len);

/* ---- single operation ----
 * Layout: [origin:2][seq:8][type:1][coll:1]
 *         [chan_len:2][chan][key_len:2][key]
 *         [tag.origin:2][tag.seq:8][priority:1]
 *         [hlc.physical_ms:8][hlc.logical:2][hlc.node_id:2][writer:2]
 *         [val_len:4][val]
 * crdt_op_decode fills *op with malloc'd chan/key/val — release with
 * crdt_op_free_fields() (does NOT free the struct itself). */
int  crdt_op_encode(const struct CrdtOp *op, uint8_t *buf, size_t cap);
int  crdt_op_decode(struct CrdtOp *op, const uint8_t *buf, size_t len);
void crdt_op_free_fields(struct CrdtOp *op);

/* ---- delta ----
 * Layout: [count:4] then count encoded ops. Encodes every oplog op with
 * seq > remote->seq[op->origin] (the wire form of crdt_state_sync). */
int crdt_delta_encode(const struct CrdtOpLog *log,
                      const struct CrdtStateVector *remote,
                      uint8_t *buf, size_t cap);

/* Decode + apply a delta into st (idempotent via crdt_state_apply_op).
 * Returns the number of ops applied, or -1 on malformed input. */
int crdt_delta_apply(struct CrdtNetworkState *st,
                     const uint8_t *buf, size_t len);

#endif /* INCLUDED_crdt_wire_h */
