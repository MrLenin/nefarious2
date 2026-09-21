/*
 * IRC - Internet Relay Chat, include/crdt_p10.h
 *
 * Pure P10 line helpers for the mesh carriers that move a VERBATIM server-
 * form P10 line (a numeric reply, a NOTICE, a hunted command) instead of an
 * event: the reply direction (CR M 'Y') and the hunt request (CR X 'L').
 * Strings only -- no Client, no ircd headers -- so the cmocka engine harness
 * links it (engine-purity rule, crdt-mesh skill).
 */
#ifndef INCLUDED_crdt_p10_h
#define INCLUDED_crdt_p10_h

#include <stddef.h>

/** The pieces of a server-form P10 line
 *  "[@A<tags> ]<src> <tok> <rest>[\r\n]".  Every pointer aims INTO the line
 *  passed to crdt_p10_line_parse; nothing is copied or terminated. */
struct CrdtP10Line {
  const char *tags;   /**< the "@..." word without its trailing space, or NULL */
  size_t      tags_len;
  const char *src;    /**< source numeric: 2 chars = server form, 5 = user */
  size_t      src_len;
  const char *tok;    /**< command token or 3-digit numeric */
  size_t      tok_len;
  const char *rest;   /**< everything after "<tok> " (may be empty) */
  size_t      rest_len; /**< excludes any trailing CR/LF */
};

/** Parse @a len bytes of @a line.  Returns 1 and fills @a out, or 0 when the
 *  line has no source or no token. */
extern int crdt_p10_line_parse(const char *line, size_t len, struct CrdtP10Line *out);

/** 1 when @a tok (of @a len) is a 3-digit numeric. */
extern int crdt_p10_tok_is_numeric(const char *tok, size_t len);

/** Split the P10 parameter tail @a s IN PLACE into @a parv[0..max-1] under
 *  the P10 rules: space-separated, a leading ':' starts the trailing
 *  parameter (the rest of the line verbatim, colon dropped); when @a max is
 *  reached the last slot keeps the rest of the line unsplit (parse_server's
 *  rule).  Returns the count; @a parv[count] is set to NULL when count < max. */
extern int crdt_p10_split(char *s, char **parv, int max);

#endif /* INCLUDED_crdt_p10_h */
