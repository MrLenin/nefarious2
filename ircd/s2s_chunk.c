/*
 * s2s_chunk.c - Shared S2S chunk reassembly (see s2s_chunk.h).
 *
 * Pure libc; keyed by (link, id) with per-link cleanup. Fixed-size table.
 */

#include "s2s_chunk.h"

#include <stdlib.h>
#include <string.h>

#define S2S_CHUNK_IDLEN 24

struct chunk_entry {
  int    used;
  void  *link;
  char   id[S2S_CHUNK_IDLEN];
  char  *buf;
  size_t len;
  size_t alloc;
};

static struct chunk_entry table[S2S_CHUNK_MAX];

static struct chunk_entry *chunk_find(void *link, const char *id)
{
  int i;
  for (i = 0; i < S2S_CHUNK_MAX; i++)
    if (table[i].used && table[i].link == link &&
        strcmp(table[i].id, id) == 0)
      return &table[i];
  return NULL;
}

static struct chunk_entry *chunk_alloc(void *link, const char *id)
{
  int i;
  for (i = 0; i < S2S_CHUNK_MAX; i++) {
    if (!table[i].used) {
      struct chunk_entry *e = &table[i];
      e->used = 1;
      e->link = link;
      strncpy(e->id, id, sizeof e->id - 1);
      e->id[sizeof e->id - 1] = '\0';
      e->alloc = 512;
      e->buf = malloc(e->alloc);
      if (!e->buf) {
        memset(e, 0, sizeof *e);
        return NULL;
      }
      e->buf[0] = '\0';
      e->len = 0;
      return e;
    }
  }
  return NULL;
}

static void chunk_free(struct chunk_entry *e)
{
  free(e->buf);
  memset(e, 0, sizeof *e);
}

int s2s_chunk_feed(void *link, const char *id, const char *b64, int more,
                   char **out, size_t *out_len)
{
  struct chunk_entry *e = chunk_find(link, id);
  size_t add;
  if (!e) {
    e = chunk_alloc(link, id);
    if (!e)
      return -1;
  }
  add = strlen(b64);
  /* Receive-side ceiling: the send side caps its payloads, but the receiver
   * must not trust the peer to terminate — an endless "more follows" stream
   * would otherwise grow the slot without bound.  Abort + free on exceed;
   * the caller treats -1 as "drop this transfer". */
  if (e->len + add + 1 > S2S_CHUNK_MAX_LEN) {
    chunk_free(e);
    return -1;
  }
  if (e->len + add + 1 > e->alloc) {
    size_t na = (e->len + add + 1) * 2;
    char *nb;
    if (na > S2S_CHUNK_MAX_LEN + 1)
      na = S2S_CHUNK_MAX_LEN + 1;
    nb = realloc(e->buf, na);
    if (!nb) {                     /* never memcpy after a failed alloc */
      chunk_free(e);
      return -1;
    }
    e->buf = nb;
    e->alloc = na;
  }
  memcpy(e->buf + e->len, b64, add + 1);   /* include the NUL */
  e->len += add;

  if (more)
    return 0;

  *out = e->buf;          /* transfer ownership to caller */
  *out_len = e->len;
  e->buf = NULL;          /* detach before clearing the slot */
  memset(e, 0, sizeof *e);
  return 1;
}

void s2s_chunk_drop(void *link, const char *id)
{
  struct chunk_entry *e = chunk_find(link, id);
  if (e)
    chunk_free(e);
}

void s2s_chunk_cleanup_link(void *link)
{
  int i;
  for (i = 0; i < S2S_CHUNK_MAX; i++)
    if (table[i].used && table[i].link == link)
      chunk_free(&table[i]);
}
