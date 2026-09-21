/*
 * IRC - Internet Relay Chat, ircd/crdt_p10.c
 *
 * Pure P10 line helpers (see crdt_p10.h).  Strings only.
 */
#include "config.h"
#include "crdt_p10.h"

#include <string.h>

static const char *skip_spaces(const char *p, const char *end)
{
  while (p < end && *p == ' ')
    p++;
  return p;
}

static const char *find_space(const char *p, const char *end)
{
  while (p < end && *p != ' ')
    p++;
  return p;
}

int crdt_p10_line_parse(const char *line, size_t len, struct CrdtP10Line *out)
{
  const char *p, *end, *e;

  if (!line || !out)
    return 0;
  memset(out, 0, sizeof *out);
  end = line + len;
  while (end > line && (end[-1] == '\r' || end[-1] == '\n'))
    end--;                                  /* the wire CRLF is not content */
  p = skip_spaces(line, end);
  if (p < end && *p == '@') {               /* compact S2S tag word */
    e = find_space(p, end);
    out->tags = p;
    out->tags_len = (size_t)(e - p);
    p = skip_spaces(e, end);
  }
  if (p >= end)
    return 0;
  e = find_space(p, end);                   /* source numeric */
  out->src = (*p == ':') ? p + 1 : p;        /* a colon-prefixed prefix is the same numeric */
  out->src_len = (size_t)(e - out->src);
  if (out->src_len != 2 && out->src_len != 5)
    return 0;
  p = skip_spaces(e, end);
  if (p >= end)
    return 0;
  e = find_space(p, end);                   /* token / numeric */
  out->tok = p;
  out->tok_len = (size_t)(e - p);
  if (!out->tok_len)
    return 0;
  p = (e < end) ? e + 1 : end;              /* exactly one space, then the rest */
  out->rest = p;
  out->rest_len = (size_t)(end - p);
  return 1;
}

int crdt_p10_tok_is_numeric(const char *tok, size_t len)
{
  return tok && len == 3 && tok[0] >= '0' && tok[0] <= '9' &&
         tok[1] >= '0' && tok[1] <= '9' && tok[2] >= '0' && tok[2] <= '9';
}

int crdt_p10_split(char *s, char **parv, int max)
{
  int n = 0;

  if (!parv || max <= 0)
    return 0;
  while (s && *s && n < max) {
    while (*s == ' ')
      *s++ = '\0';
    if (!*s)
      break;
    if (*s == ':') {                        /* trailing parameter: rest of line */
      parv[n++] = ++s;
      break;
    }
    parv[n++] = s;
    while (*s && *s != ' ')
      s++;
  }
  if (n < max)
    parv[n] = NULL;
  return n;
}
