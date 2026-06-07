/*
 * s2s_chunk.h - Shared S2S chunk reassembly for oversized base64 payloads
 *
 * P10 lines cap at 512 bytes, so large base64 payloads are sent as a sequence
 * of chunks with a "more follows" flag. SASL and chathistory federation each
 * rolled this pattern independently (and chathistory's lacked per-link cleanup,
 * leaking on mid-stream SQUIT). This is the unified helper; the CR (CRDT sync)
 * token uses it first, and SASL/chathistory can migrate onto it later.
 *
 * Keyed by (link, id): multiple streams over one link, and the same id over
 * different links, don't collide. `link` is an opaque owner pointer (the
 * directly-connected struct Client* in the ircd; compared by identity only) so
 * this module stays pure libc and unit-testable.
 */

#ifndef INCLUDED_s2s_chunk_h
#define INCLUDED_s2s_chunk_h

#include <stddef.h>

/** Max concurrent reassemblies across all links. */
#define S2S_CHUNK_MAX 64

/** Feed one base64 chunk for (link, id). @a more != 0 means more chunks follow.
 *  On the final chunk (more == 0) the fully reassembled base64 is handed back
 *  via *out (malloc'd — caller frees) and *out_len, and the entry is consumed.
 *  Returns 1 = complete (*out set), 0 = buffered, -1 = error / no free slot. */
int s2s_chunk_feed(void *link, const char *id, const char *b64, int more,
                   char **out, size_t *out_len);

/** Drop any in-flight reassembly for (link, id) (e.g. on abort). */
void s2s_chunk_drop(void *link, const char *id);

/** Drop all in-flight reassemblies owned by @a link (call on peer SQUIT). */
void s2s_chunk_cleanup_link(void *link);

#endif /* INCLUDED_s2s_chunk_h */
