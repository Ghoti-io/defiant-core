/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Defiant Core.
 *
 * Ghoti.io Defiant Core is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version
 * 3 as published by the Free Software Foundation.
 *
 * Ghoti.io Defiant Core is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Conditions as data: the parser, the validator, the canonical text, the hash
 * and the plain-English explanation. The evaluator is condition_eval.c.
 *
 * The parser is a small hand-written recursive descent. It recurses once per
 * level of parentheses and the depth limit (16) stops it, so its stack use
 * is a constant. A parsed condition is one fixed block, so nothing it
 * allocates depends on the input but the choice of "one block".
 */

#include <ghoti.io/defiant-core/macros.h>
#include <ghoti.io/defiant-core/condition.h>
#include <ghoti.io/defiant-core/module.h>

#include "condition_internal.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/sha256.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { kMaxPasses = 300 };

static const char kMsgEmpty[] = "the condition is empty";
static const char kMsgLong[] = "the condition is longer than 4096 bytes";
static const char kMsgNul[] = "a NUL byte is not allowed";
static const char kMsgUtf8[] = "the text is not valid UTF-8";
static const char kMsgExpr[] = "a condition was expected";
static const char kMsgHead[] = "an operator was expected";
static const char kMsgOp[] = "an unknown operator";
static const char kMsgOperand[] = "an operand was expected";
static const char kMsgWord[] = "an unknown operand";
static const char kMsgList[] = "a list of constants was expected";
static const char kMsgConst[] = "a constant was expected";
static const char kMsgClose[] = "a closing parenthesis was expected";
static const char kMsgDepth[] = "the condition is nested more than 16 levels deep";
static const char kMsgNodes[] = "the condition has more than 256 nodes";
static const char kMsgBigConst[] = "a text constant is longer than 256 bytes";
static const char kMsgOpen[] = "a text constant is not closed";
static const char kMsgEscape[] = "an unknown escape in a text constant";
static const char kMsgControl[] = "a control character in a text constant";
static const char kMsgChar[] = "an unexpected character";
static const char kMsgInt[] = "an invalid integer";
static const char kMsgBigInt[] = "an integer is too large";
static const char kMsgRelated[] =
    "related is written (related \"relation\" (operand ...))";
static const char kMsgRelName[] = "a relation name in quotes was expected";
static const char kMsgRelOperands[] =
    "a related takes one to four operands in a list";
static const char kMsgManyRel[] =
    "a condition may name at most four relations";
static const char kMsgNoRelation[] = "no such relation";
static const char kMsgRelArity[] =
    "the number of operands is not the number of columns";
static const char kMsgRelOperand[] = "this operand does not suit the column";
static const char kMsgRenamed[] =
    "actor is revision.creator since edition 2; creator is the entity's";
static const char kMsgTrail[] = "unexpected text after the condition";
static const char kMsgFieldName[] = "a field name was expected after field.";
static const char kMsgNoField[] = "no such field";
static const char kMsgNoType[] = "no such type";
static const char kMsgNoState[] = "no such state";
static const char kMsgInternal[] = "the condition could not be written";
static const char kMsgWritten[] =
    "the condition is longer than 4096 bytes once written out";

static const GDEFCORE_Allocator * alloc_default(void) {
  return gdefcore_allocator_default();
}

static void set_error(GDEFCORE_Condition_Error * out, size_t offset,
    const char * message) {
  if (out != NULL) {
    out->size = sizeof *out;
    out->offset = offset;
    out->message = message;
  }
}

int cond_parse_int(const char * p, size_t n, int64_t * out) {
  size_t i = 0;
  int64_t v = 0;
  int neg = 0;
  if (n > 0 && p[0] == '-') {
    neg = 1;
    i = 1;
  }
  if (n - i < 1 || n - i > 18) {
    return 0;
  }
  for (; i < n; i++) {
    if (p[i] < '0' || p[i] > '9') {
      return 0;
    }
    v = v * 10 + (p[i] - '0');
  }
  *out = neg ? -v : v;
  return 1;
}

/* The size of the readable rendering of a parsed condition, or (size_t)-1 on
 * an allocation failure. Defined with the canonical text, below. */
static size_t written_size(const GDEFCORE_Condition * c);

/* ---- the parser ------------------------------------------------------- */

typedef struct Parser {
  const char * s;
  size_t len;
  size_t pos;
  GDEFCORE_Condition * c;
  const char * msg;
  size_t off;
  size_t nrelated;
} Parser;

static int fail(Parser * p, size_t off, const char * msg) {
  if (p->msg == NULL) {
    p->msg = msg;
    p->off = off;
  }
  return -1;
}

static int is_ws(char ch) {
  return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r';
}

static int is_atom_char(unsigned char ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '!' ||
         ch == '<' || ch == '>' || ch == '=' || ch == '-';
}

static int is_delim(char ch) {
  return is_ws(ch) || ch == '(' || ch == ')' || ch == '"';
}

static void skip_ws(Parser * p) {
  while (p->pos < p->len && is_ws(p->s[p->pos])) {
    p->pos += 1;
  }
}

static int word_is(const char * s, size_t n, const char * word) {
  size_t wn = strlen(word);
  return n == wn && memcmp(s, word, n) == 0;
}

/* The first problem with the bytes themselves: length, NUL, UTF-8. */
static int check_bytes(const char * s, size_t len, size_t * off,
    const char ** msg) {
  size_t i = 0;
  if (len == 0) {
    *off = 0;
    *msg = kMsgEmpty;
    return 0;
  }
  if (len > GDEFCORE_CONDITION_MAX_BYTES) {
    *off = GDEFCORE_CONDITION_MAX_BYTES;
    *msg = kMsgLong;
    return 0;
  }
  while (i < len) {
    unsigned char b = (unsigned char)s[i];
    size_t need;
    uint32_t cp;
    size_t k;
    if (b == 0) {
      *off = i;
      *msg = kMsgNul;
      return 0;
    }
    if (b < 0x80) {
      i += 1;
      continue;
    }
    if (b >= 0xC2 && b <= 0xDF) {
      need = 1;
      cp = b & 0x1Fu;
    } else if (b >= 0xE0 && b <= 0xEF) {
      need = 2;
      cp = b & 0x0Fu;
    } else if (b >= 0xF0 && b <= 0xF4) {
      need = 3;
      cp = b & 0x07u;
    } else {
      *off = i;
      *msg = kMsgUtf8;
      return 0;
    }
    if (i + need >= len) {
      *off = i;
      *msg = kMsgUtf8;
      return 0;
    }
    for (k = 1; k <= need; k++) {
      unsigned char cc = (unsigned char)s[i + k];
      if ((cc & 0xC0u) != 0x80u) {
        *off = i;
        *msg = kMsgUtf8;
        return 0;
      }
      cp = (cp << 6) | (cc & 0x3Fu);
    }
    if ((need == 2 && cp < 0x800u) || (need == 3 && cp < 0x10000u) ||
        (cp >= 0xD800u && cp <= 0xDFFFu) || cp > 0x10FFFFu) {
      *off = i;
      *msg = kMsgUtf8;
      return 0;
    }
    i += need + 1;
  }
  return 1;
}

static int new_node(Parser * p, int kind, size_t pos) {
  GDEFCORE_Condition * c = p->c;
  CNode * n;
  if (c->nnodes >= kMaxNodes) {
    return fail(p, pos, kMsgNodes);
  }
  n = &c->nodes[c->nnodes];
  memset(n, 0, sizeof *n);
  n->kind = (uint8_t)kind;
  n->pos = (uint32_t)pos;
  return (int)c->nnodes++;
}

static int set_kids(Parser * p, int parent, const uint16_t * kids, size_t n) {
  GDEFCORE_Condition * c = p->c;
  if ((size_t)c->nkids + n > kMaxNodes) {
    return fail(p, c->nodes[parent].pos, kMsgNodes);
  }
  c->nodes[parent].first = c->nkids;
  c->nodes[parent].count = (uint16_t)n;
  if (n > 0) {
    memcpy(c->kids + c->nkids, kids, n * sizeof *kids);
  }
  c->nkids = (uint16_t)(c->nkids + n);
  return 0;
}

static int pool_put(Parser * p, const char * s, size_t n, size_t pos,
    uint32_t * off) {
  GDEFCORE_Condition * c = p->c;
  if ((size_t)c->pool_len + n > kMaxPool) {
    return fail(p, pos, kMsgLong);
  }
  *off = c->pool_len;
  if (n > 0) {
    memcpy(c->pool + c->pool_len, s, n);
  }
  c->pool_len += (uint32_t)n;
  return 0;
}

/* An atom: the characters up to a delimiter. Returns 1, or 0 when there is
 * none, or -1 on a character an atom may not hold. */
static int read_atom(Parser * p, size_t * start, size_t * n) {
  skip_ws(p);
  *start = p->pos;
  while (p->pos < p->len && !is_delim(p->s[p->pos])) {
    if (!is_atom_char((unsigned char)p->s[p->pos])) {
      return fail(p, p->pos, kMsgChar);
    }
    p->pos += 1;
  }
  *n = p->pos - *start;
  return *n > 0 ? 1 : 0;
}

/* A text constant: p->pos is at the opening quote. */
static int parse_text(Parser * p) {
  size_t at = p->pos;
  int idx;
  size_t n = 0;
  uint32_t off;
  char buf[GDEFCORE_CONDITION_MAX_CONSTANT];
  p->pos += 1;
  for (;;) {
    unsigned char ch;
    if (p->pos >= p->len) {
      return fail(p, at, kMsgOpen);
    }
    ch = (unsigned char)p->s[p->pos];
    if (ch == '"') {
      p->pos += 1;
      break;
    }
    if (ch < 0x20 || ch == 0x7f) {
      return fail(p, p->pos, kMsgControl);
    }
    if (ch == '\\') {
      char e;
      if (p->pos + 1 >= p->len) {
        return fail(p, at, kMsgOpen);
      }
      e = p->s[p->pos + 1];
      if (e == '"' || e == '\\') {
        ch = (unsigned char)e;
      } else if (e == 'n') {
        ch = '\n';
      } else if (e == 't') {
        ch = '\t';
      } else {
        return fail(p, p->pos, kMsgEscape);
      }
      p->pos += 1;
    }
    if (n >= sizeof buf) {
      return fail(p, at, kMsgBigConst);
    }
    buf[n++] = (char)ch;
    p->pos += 1;
  }
  idx = new_node(p, kText, at);
  if (idx < 0 || pool_put(p, buf, n, at, &off) < 0) {
    return -1;
  }
  p->c->nodes[idx].str = off;
  p->c->nodes[idx].str_len = (uint32_t)n;
  return idx;
}

/* An integer atom already read. */
static int make_int(Parser * p, size_t start, size_t n) {
  const char * a = p->s + start;
  int64_t v = 0;
  char text[24];
  size_t k = 0;
  size_t i = 0;
  int neg = 0;
  int idx;
  uint32_t off;
  if (n > 0 && a[0] == '-') {
    neg = 1;
    i = 1;
  }
  if (n - i == 0) {
    return fail(p, start, kMsgInt);
  }
  for (k = i; k < n; k++) {
    if (a[k] < '0' || a[k] > '9') {
      return fail(p, start, kMsgInt);
    }
  }
  if (n - i > 18) {
    return fail(p, start, kMsgBigInt);
  }
  (void)cond_parse_int(a, n, &v);
  {
    int wn = snprintf(text, sizeof text, "%lld", (long long)v);
    if (wn <= 0 || (size_t)wn >= sizeof text) {
      return fail(p, start, kMsgInt);
    }
    k = (size_t)wn;
  }
  (void)neg;
  idx = new_node(p, kInt, start);
  if (idx < 0 || pool_put(p, text, k, start, &off) < 0) {
    return -1;
  }
  p->c->nodes[idx].str = off;
  p->c->nodes[idx].str_len = (uint32_t)k;
  p->c->nodes[idx].ival = v;
  return idx;
}

static int parse_operand(Parser * p) {
  size_t start;
  size_t n;
  int got;
  int idx;
  skip_ws(p);
  if (p->pos >= p->len) {
    return fail(p, p->pos, kMsgOperand);
  }
  if (p->s[p->pos] == '"') {
    return parse_text(p);
  }
  got = read_atom(p, &start, &n);
  if (got < 0) {
    return -1;
  }
  if (got == 0) {
    return fail(p, p->pos, kMsgOperand);
  }
  if (word_is(p->s + start, n, "related")) {
    return fail(p, start, kMsgRelated);
  }
  if (word_is(p->s + start, n, "type")) {
    return new_node(p, kType, start);
  }
  if (word_is(p->s + start, n, "state")) {
    idx = new_node(p, kState, start);
    if (idx >= 0) {
      p->c->uses |= GDEFCORE_CONDITION_USES_ENTITY;
    }
    return idx;
  }
  if (word_is(p->s + start, n, "actor")) {
    /* The edition 1 spelling. Stored conditions are upcast before they are
     * parsed (gdefcore_condition_upcast); text a person writes now is not. */
    return fail(p, start, kMsgRenamed);
  }
  if (word_is(p->s + start, n, "revision.creator")) {
    idx = new_node(p, kRevCreator, start);
    if (idx >= 0) {
      p->c->uses |= GDEFCORE_CONDITION_USES_ENTITY |
                    GDEFCORE_CONDITION_USES_PRINCIPAL;
    }
    return idx;
  }
  if (word_is(p->s + start, n, "creator")) {
    idx = new_node(p, kCreator, start);
    if (idx >= 0) {
      p->c->uses |= GDEFCORE_CONDITION_USES_ENTITY |
                    GDEFCORE_CONDITION_USES_PRINCIPAL;
    }
    return idx;
  }
  if (word_is(p->s + start, n, "principal")) {
    idx = new_node(p, kPrincipal, start);
    if (idx >= 0) {
      p->c->uses |= GDEFCORE_CONDITION_USES_PRINCIPAL;
    }
    return idx;
  }
  if (word_is(p->s + start, n, "now")) {
    idx = new_node(p, kNow, start);
    if (idx >= 0) {
      p->c->uses |= GDEFCORE_CONDITION_USES_TIME;
    }
    return idx;
  }
  if (n >= 6 && memcmp(p->s + start, "field.", 6) == 0) {
    size_t i;
    uint32_t off;
    if (n - 6 == 0 || n - 6 > kMaxFieldName) {
      return fail(p, start, kMsgFieldName);
    }
    for (i = 6; i < n; i++) {
      char ch = p->s[start + i];
      if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '_')) {
        return fail(p, start, kMsgFieldName);
      }
    }
    idx = new_node(p, kField, start);
    if (idx < 0 || pool_put(p, p->s + start + 6, n - 6, start, &off) < 0) {
      return -1;
    }
    p->c->nodes[idx].str = off;
    p->c->nodes[idx].str_len = (uint32_t)(n - 6);
    p->c->uses |= GDEFCORE_CONDITION_USES_ENTITY;
    return idx;
  }
  if ((p->s[start] >= '0' && p->s[start] <= '9') || p->s[start] == '-') {
    return make_int(p, start, n);
  }
  return fail(p, start, kMsgWord);
}

static int parse_const(Parser * p) {
  size_t start;
  size_t n;
  int got;
  skip_ws(p);
  if (p->pos >= p->len) {
    return fail(p, p->pos, kMsgConst);
  }
  if (p->s[p->pos] == '"') {
    return parse_text(p);
  }
  got = read_atom(p, &start, &n);
  if (got < 0) {
    return -1;
  }
  if (got > 0 && word_is(p->s + start, n, "related")) {
    return fail(p, start, kMsgRelated);
  }
  if (got > 0 &&
      ((p->s[start] >= '0' && p->s[start] <= '9') || p->s[start] == '-')) {
    return make_int(p, start, n);
  }
  return fail(p, got > 0 ? start : p->pos, kMsgConst);
}

static int expect_close(Parser * p) {
  skip_ws(p);
  if (p->pos >= p->len || p->s[p->pos] != ')') {
    return fail(p, p->pos, kMsgClose);
  }
  p->pos += 1;
  return 0;
}

static int cmp_op(const char * s, size_t n) {
  if (word_is(s, n, "=")) {
    return kEq;
  }
  if (word_is(s, n, "!=")) {
    return kNe;
  }
  if (word_is(s, n, "<")) {
    return kLt;
  }
  if (word_is(s, n, "<=")) {
    return kLe;
  }
  if (word_is(s, n, ">")) {
    return kGt;
  }
  if (word_is(s, n, ">=")) {
    return kGe;
  }
  return 0;
}

static int parse_expr(Parser * p, int depth) {
  size_t start;
  size_t n;
  int got;
  skip_ws(p);
  if (p->pos >= p->len) {
    return fail(p, p->pos, kMsgExpr);
  }
  if (p->s[p->pos] != '(') {
    got = read_atom(p, &start, &n);
    if (got < 0) {
      return -1;
    }
    if (got > 0 && word_is(p->s + start, n, "related")) {
      return fail(p, start, kMsgRelated);
    }
    if (got > 0 && word_is(p->s + start, n, "true")) {
      return new_node(p, kTrue, start);
    }
    if (got > 0 && word_is(p->s + start, n, "false")) {
      return new_node(p, kFalse, start);
    }
    return fail(p, got > 0 ? start : p->pos, kMsgExpr);
  }
  {
    size_t open = p->pos;
    int op;
    int idx;
    uint16_t kids[kMaxNodes];
    size_t nk = 0;
    if (depth + 1 > GDEFCORE_CONDITION_MAX_DEPTH) {
      return fail(p, open, kMsgDepth);
    }
    p->pos += 1;
    got = read_atom(p, &start, &n);
    if (got < 0) {
      return -1;
    }
    if (got == 0) {
      return fail(p, p->pos, kMsgHead);
    }
    if (word_is(p->s + start, n, "related")) {
      /* (related "name" (operand ...)): kids[0] is the name, the rest the
       * operands, a `_` being a column left free. */
      int name;
      size_t list_at;
      idx = new_node(p, kRelated, open);
      if (idx < 0) {
        return -1;
      }
      if (p->nrelated >= GDEFCORE_CONDITION_MAX_RELATIONS) {
        return fail(p, start, kMsgManyRel);
      }
      p->nrelated += 1;
      skip_ws(p);
      if (p->pos >= p->len || p->s[p->pos] != '"') {
        return fail(p, p->pos, kMsgRelName);
      }
      name = parse_text(p);
      if (name < 0) {
        return -1;
      }
      kids[nk++] = (uint16_t)name;
      skip_ws(p);
      if (p->pos >= p->len || p->s[p->pos] != '(') {
        return fail(p, p->pos, kMsgRelOperands);
      }
      list_at = p->pos;
      if (depth + 2 > GDEFCORE_CONDITION_MAX_DEPTH) {
        return fail(p, list_at, kMsgDepth);
      }
      p->pos += 1;
      for (;;) {
        int k;
        size_t astart;
        size_t an;
        skip_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ')') {
          break;
        }
        if (p->pos < p->len && p->s[p->pos] == '_' &&
            (p->pos + 1 >= p->len || is_delim(p->s[p->pos + 1]))) {
          astart = p->pos;
          an = 1;
          (void)an;
          p->pos += 1;
          k = new_node(p, kAny, astart);
        } else {
          k = parse_operand(p);
        }
        if (k < 0) {
          return -1;
        }
        if (nk > GDEFCORE_CONDITION_MAX_RELATED_OPERANDS) {
          return fail(p, p->c->nodes[k].pos, kMsgRelOperands);
        }
        kids[nk++] = (uint16_t)k;
      }
      if (nk < 2) {
        return fail(p, p->pos, kMsgRelOperands);
      }
      p->pos += 1;
      if (expect_close(p) < 0 || set_kids(p, idx, kids, nk) < 0) {
        return -1;
      }
      p->c->uses |= GDEFCORE_CONDITION_USES_RELATION;
      return idx;
    }
    if (word_is(p->s + start, n, "and") || word_is(p->s + start, n, "or")) {
      idx = new_node(p, word_is(p->s + start, n, "and") ? kAnd : kOr, open);
      if (idx < 0) {
        return -1;
      }
      for (;;) {
        int child;
        skip_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ')') {
          break;
        }
        child = parse_expr(p, depth + 1);
        if (child < 0) {
          return -1;
        }
        kids[nk++] = (uint16_t)child;
      }
      if (nk == 0) {
        return fail(p, p->pos, kMsgExpr);
      }
      if (expect_close(p) < 0 || set_kids(p, idx, kids, nk) < 0) {
        return -1;
      }
      return idx;
    }
    if (word_is(p->s + start, n, "not")) {
      int child;
      idx = new_node(p, kNot, open);
      if (idx < 0) {
        return -1;
      }
      child = parse_expr(p, depth + 1);
      if (child < 0) {
        return -1;
      }
      kids[0] = (uint16_t)child;
      if (expect_close(p) < 0 || set_kids(p, idx, kids, 1) < 0) {
        return -1;
      }
      return idx;
    }
    op = cmp_op(p->s + start, n);
    if (op != 0) {
      int a;
      int b;
      idx = new_node(p, kCmp, open);
      if (idx < 0) {
        return -1;
      }
      p->c->nodes[idx].op = (uint8_t)op;
      a = parse_operand(p);
      if (a < 0) {
        return -1;
      }
      b = parse_operand(p);
      if (b < 0) {
        return -1;
      }
      kids[0] = (uint16_t)a;
      kids[1] = (uint16_t)b;
      if (expect_close(p) < 0 || set_kids(p, idx, kids, 2) < 0) {
        return -1;
      }
      return idx;
    }
    if (word_is(p->s + start, n, "in")) {
      int a;
      size_t list_at;
      idx = new_node(p, kIn, open);
      if (idx < 0) {
        return -1;
      }
      a = parse_operand(p);
      if (a < 0) {
        return -1;
      }
      kids[nk++] = (uint16_t)a;
      skip_ws(p);
      if (p->pos >= p->len || p->s[p->pos] != '(') {
        return fail(p, p->pos, kMsgList);
      }
      list_at = p->pos;
      if (depth + 2 > GDEFCORE_CONDITION_MAX_DEPTH) {
        return fail(p, list_at, kMsgDepth);
      }
      p->pos += 1;
      for (;;) {
        int k;
        skip_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ')') {
          break;
        }
        k = parse_const(p);
        if (k < 0) {
          return -1;
        }
        kids[nk++] = (uint16_t)k;
      }
      if (nk < 2) {
        return fail(p, p->pos, kMsgConst);
      }
      p->pos += 1;
      if (expect_close(p) < 0 || set_kids(p, idx, kids, nk) < 0) {
        return -1;
      }
      return idx;
    }
    return fail(p, start, kMsgOp);
  }
}

GDEFCORE_Result gdefcore_condition_parse(const char * text, size_t len,
    GDEFCORE_Condition ** out_condition, GDEFCORE_Condition_Error * out_error) {
  Parser p;
  GDEFCORE_Condition * c;
  size_t off = 0;
  const char * msg = NULL;
  int root;
  if (out_condition != NULL) {
    *out_condition = NULL;
  }
  if (text == NULL) {
    if (len != 0) {
      set_error(out_error, 0, kMsgEmpty);
      return GDEFCORE_ERR_INVALID;
    }
    text = "";
  }
  if (!check_bytes(text, len, &off, &msg)) {
    set_error(out_error, off, msg);
    return GDEFCORE_ERR_INVALID;
  }
  c = (GDEFCORE_Condition *)gcu_allocator_calloc(alloc_default(), 1, sizeof *c);
  if (c == NULL) {
    return GDEFCORE_ERR_OOM;
  }
  memset(&p, 0, sizeof p);
  p.s = text;
  p.len = len;
  p.c = c;
  root = parse_expr(&p, 0);
  if (root >= 0) {
    skip_ws(&p);
    if (p.pos < p.len) {
      root = fail(&p, p.pos, kMsgTrail);
    }
  }
  if (root < 0) {
    set_error(out_error, p.off, p.msg != NULL ? p.msg : kMsgExpr);
    gcu_allocator_free(alloc_default(), c);
    return GDEFCORE_ERR_INVALID;
  }
  c->root = (uint16_t)root;
  /* The text given is at most 4096 bytes, but the canonical form puts a space
   * between tokens the author ran together, so it can be longer. The limit
   * holds for it too: it is what is stored, and it must parse again. */
  {
    size_t written = written_size(c);
    if (written == (size_t)-1) {
      gcu_allocator_free(alloc_default(), c);
      return GDEFCORE_ERR_OOM;
    }
    if (written > GDEFCORE_CONDITION_MAX_BYTES) {
      set_error(out_error, len, kMsgWritten);
      gcu_allocator_free(alloc_default(), c);
      return GDEFCORE_ERR_INVALID;
    }
  }
  if (out_condition != NULL) {
    *out_condition = c;
  } else {
    gcu_allocator_free(alloc_default(), c);
  }
  return GDEFCORE_OK;
}

void gdefcore_condition_free(GDEFCORE_Condition * condition) {
  gcu_allocator_free(alloc_default(), condition);
}

unsigned gdefcore_condition_uses(const GDEFCORE_Condition * condition) {
  return condition == NULL ? 0u : condition->uses;
}

/* Whether the node holds only for entities of some stated type. A comparison
 * or a list that has `type` as an operand does; `and` does when any operand
 * does; `or` only when every operand does. `not` never does: excluding one
 * type leaves every other. */
static int node_constrains_type(const GDEFCORE_Condition * c, int idx) {
  const CNode * node = &c->nodes[idx];
  size_t k;
  switch (node->kind) {
    case kCmp:
    case kIn:
      if (node->kind == kCmp && node->op != kEq) {
        return 0;
      }
      for (k = 0; k < node->count; k++) {
        if (c->nodes[c->kids[node->first + k]].kind == kType) {
          return 1;
        }
      }
      return 0;
    case kAnd:
      for (k = 0; k < node->count; k++) {
        if (node_constrains_type(c, c->kids[node->first + k])) {
          return 1;
        }
      }
      return 0;
    case kOr:
      if (node->count == 0) {
        return 0;
      }
      for (k = 0; k < node->count; k++) {
        if (!node_constrains_type(c, c->kids[node->first + k])) {
          return 0;
        }
      }
      return 1;
    default:
      return 0;
  }
}

int gdefcore_condition_constrains_type(const GDEFCORE_Condition * condition) {
  return condition != NULL && node_constrains_type(condition, condition->root);
}

int gdefcore_condition_tests_field(const GDEFCORE_Condition * condition,
    const char * field, size_t field_len) {
  size_t i;
  if (condition == NULL) {
    return 0;
  }
  for (i = 0; i < condition->nnodes; i++) {
    const CNode * node = &condition->nodes[i];
    if (node->kind != kField) {
      continue;
    }
    if (field == NULL) {
      return 1;
    }
    if (node->str_len == field_len &&
        memcmp(condition->pool + node->str, field, field_len) == 0) {
      return 1;
    }
  }
  return 0;
}

int gdefcore_condition_relation_at(const GDEFCORE_Condition * condition,
    size_t index, const char ** out_name, size_t * out_len) {
  size_t i;
  size_t seen = 0;
  if (condition == NULL || out_name == NULL || out_len == NULL) {
    return 0;
  }
  for (i = 0; i < condition->nnodes; i++) {
    const CNode * node = &condition->nodes[i];
    const CNode * name;
    size_t j;
    int dup = 0;
    if (node->kind != kRelated) {
      continue;
    }
    name = &condition->nodes[condition->kids[node->first]];
    /* In order of first use; a relation named twice is one relation. */
    for (j = 0; j < i; j++) {
      const CNode * other = &condition->nodes[j];
      if (other->kind == kRelated) {
        const CNode * on = &condition->nodes[condition->kids[other->first]];
        if (on->str_len == name->str_len &&
            memcmp(condition->pool + on->str, condition->pool + name->str,
                name->str_len) == 0) {
          dup = 1;
          break;
        }
      }
    }
    if (dup) {
      continue;
    }
    if (seen == index) {
      *out_name = condition->pool + name->str;
      *out_len = name->str_len;
      return 1;
    }
    seen += 1;
  }
  return 0;
}

/* ---- validation ------------------------------------------------------- */

/* 1 when the type has a non-personal field called name. */
static int field_usable(GDEFCORE_Catalog * catalog, const char * type,
    size_t type_len, const char * name, size_t name_len) {
  size_t count = 0;
  size_t i;
  if (gdefcore_type_field_count(catalog, type, type_len, &count) !=
      GDEFCORE_OK) {
    return 0;
  }
  for (i = 0; i < count; i++) {
    char * got = NULL;
    size_t got_len = 0;
    int required = 0;
    int many = 0;
    int match;
    if (gdefcore_type_field(catalog, type, type_len, i, &got, &got_len,
            &required, &many) != GDEFCORE_OK) {
      return 0;
    }
    match = got_len == name_len && memcmp(got, name, name_len) == 0;
    gdefcore_text_free(catalog, got);
    if (match) {
      int personal = 0;
      if (gdefcore_type_field_personal(catalog, type, type_len, i,
              &personal) != GDEFCORE_OK) {
        return 0;
      }
      return personal == 0;
    }
  }
  return 0;
}

static int state_name_ok(const char * s, size_t n) {
  return word_is(s, n, "published") || word_is(s, n, "draft");
}

/* Whether an operand can be what a relation column holds. */
static int operand_suits(const GDEFCORE_Condition * c, const CNode * node,
    int kind) {
  char canon[GDEFCORE_PUBLIC_ID_LEN + 1];
  int64_t v;
  switch (node->kind) {
    case kAny:
    case kField:
      return 1;
    case kPrincipal:
    case kCreator:
    case kRevCreator:
      return kind == GDEFCORE_RELATION_ENTITY || kind == GDEFCORE_RELATION_TEXT;
    case kNow:
    case kInt:
      return kind == GDEFCORE_RELATION_INTEGER || kind == GDEFCORE_RELATION_TEXT;
    case kType:
    case kState:
      return kind == GDEFCORE_RELATION_TEXT;
    case kText:
      if (kind == GDEFCORE_RELATION_TEXT) {
        return 1;
      }
      if (kind == GDEFCORE_RELATION_ENTITY) {
        return node->str_len == GDEFCORE_PUBLIC_ID_LEN &&
               gdefcore_id_canonical(c->pool + node->str, node->str_len,
                   canon) == GDEFCORE_OK &&
               memcmp(canon, c->pool + node->str, node->str_len) == 0;
      }
      return cond_parse_int(c->pool + node->str, node->str_len, &v) &&
             node->str_len < 20;
    default:
      return 0;
  }
}

static GDEFCORE_Result check_related(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Condition * condition, const CNode * node,
    const GDEFCORE_Changeset * projection, GDEFCORE_Condition_Error * out_error) {
  const CNode * name = &condition->nodes[condition->kids[node->first]];
  GDEFCORE_Host * host = gdefcore_catalog_host(catalog);
  const GDEFCORE_Module_Declared_Relation ** items = NULL;
  size_t nitems = 0;
  size_t i;
  size_t k;
  const GDEFCORE_Module_Declared_Relation * found = NULL;
  const uint8_t * tenant;
  size_t tenant_len = 0;
  GDEFCORE_Result rc;
  GDEFCORE_Result out = GDEFCORE_OK;
  if (host == NULL) {
    set_error(out_error, node->pos, kMsgNoRelation);
    return GDEFCORE_ERR_INVALID;
  }
  tenant = gdefcore_catalog_tenant(catalog, &tenant_len);
  rc = gdefcore_module_relations(host, tenant, tenant_len, projection, &items,
      &nitems);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  for (i = 0; i < nitems; i++) {
    if (items[i]->name_len == name->str_len &&
        memcmp(items[i]->name, condition->pool + name->str, name->str_len) == 0) {
      found = items[i];
      break;
    }
  }
  if (found == NULL) {
    set_error(out_error, node->pos, kMsgNoRelation);
    out = GDEFCORE_ERR_INVALID;
  } else if ((size_t)node->count - 1 != found->ncolumns) {
    set_error(out_error, node->pos, kMsgRelArity);
    out = GDEFCORE_ERR_INVALID;
  } else {
    for (k = 1; k < node->count; k++) {
      const CNode * operand = &condition->nodes[condition->kids[node->first + k]];
      if (!operand_suits(condition, operand, found->columns[k - 1].kind)) {
        set_error(out_error, operand->pos, kMsgRelOperand);
        out = GDEFCORE_ERR_INVALID;
        break;
      }
    }
  }
  gdefcore_module_declared_free(host, items);
  return out;
}

GDEFCORE_Result gdefcore_condition_validate(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Condition * condition, const char * type_name,
    size_t type_name_len, GDEFCORE_Condition_Error * out_error) {
  return gdefcore_condition_validate_in(catalog, condition, type_name,
      type_name_len, NULL, out_error);
}

GDEFCORE_Result gdefcore_condition_validate_in(GDEFCORE_Catalog * catalog,
    const GDEFCORE_Condition * condition, const char * type_name,
    size_t type_name_len, const GDEFCORE_Changeset * projection,
    GDEFCORE_Condition_Error * out_error) {
  size_t i;
  if (catalog == NULL || condition == NULL) {
    set_error(out_error, 0, kMsgExpr);
    return GDEFCORE_ERR_INVALID;
  }
  for (i = 0; i < condition->nnodes; i++) {
    const CNode * node = &condition->nodes[i];
    if (node->kind == kRelated) {
      GDEFCORE_Result rc = check_related(catalog, condition, node, projection,
          out_error);
      if (rc != GDEFCORE_OK) {
        return rc;
      }
      continue;
    }
    if (node->kind == kField) {
      if (type_name == NULL ||
          !field_usable(catalog, type_name, type_name_len,
              condition->pool + node->str, node->str_len)) {
        /* Absent and personal read alike (AD-19). */
        set_error(out_error, node->pos, kMsgNoField);
        return GDEFCORE_ERR_INVALID;
      }
    }
    if ((node->kind == kCmp && (node->op == kEq || node->op == kNe)) ||
        node->kind == kIn) {
      const CNode * first = &condition->nodes[condition->kids[node->first]];
      const CNode * second = node->kind == kCmp
                                 ? &condition->nodes[condition->kids[node->first + 1]]
                                 : NULL;
      int is_type = first->kind == kType ||
                    (second != NULL && second->kind == kType);
      int is_state = first->kind == kState ||
                     (second != NULL && second->kind == kState);
      size_t k;
      if (!is_type && !is_state) {
        continue;
      }
      for (k = 0; k < node->count; k++) {
        const CNode * c = &condition->nodes[condition->kids[node->first + k]];
        if (c->kind != kText) {
          continue;
        }
        if (is_type) {
          int kind = 0;
          if (c->str_len == 0 ||
              gdefcore_type_kind(catalog, condition->pool + c->str,
                  c->str_len, &kind) != GDEFCORE_OK) {
            set_error(out_error, c->pos, kMsgNoType);
            return GDEFCORE_ERR_INVALID;
          }
        } else if (!state_name_ok(condition->pool + c->str, c->str_len)) {
          set_error(out_error, c->pos, kMsgNoState);
          return GDEFCORE_ERR_INVALID;
        }
      }
    }
  }
  return GDEFCORE_OK;
}

/* ---- text buffers ----------------------------------------------------- */

typedef struct Buf {
  char * p;
  size_t n;
  size_t cap;
  int oom;
} Buf;

static void buf_add(Buf * b, const char * s, size_t n) {
  if (b->oom) {
    return;
  }
  if (b->n + n + 1 > b->cap) {
    size_t cap = b->cap == 0 ? 64 : b->cap;
    char * next;
    while (cap < b->n + n + 1) {
      cap *= 2;
    }
    next = (char *)gcu_allocator_realloc(alloc_default(), b->p, cap);
    if (next == NULL) {
      b->oom = 1;
      return;
    }
    b->p = next;
    b->cap = cap;
  }
  if (n > 0) {
    memcpy(b->p + b->n, s, n);
  }
  b->n += n;
  b->p[b->n] = '\0';
}

static void buf_str(Buf * b, const char * s) {
  buf_add(b, s, strlen(s));
}

static void buf_quoted(Buf * b, const char * s, size_t n) {
  size_t i;
  buf_add(b, "\"", 1);
  for (i = 0; i < n; i++) {
    switch (s[i]) {
      case '"':
        buf_add(b, "\\\"", 2);
        break;
      case '\\':
        buf_add(b, "\\\\", 2);
        break;
      case '\n':
        buf_add(b, "\\n", 2);
        break;
      case '\t':
        buf_add(b, "\\t", 2);
        break;
      default:
        buf_add(b, s + i, 1);
        break;
    }
  }
  buf_add(b, "\"", 1);
}

void gdefcore_condition_text_free(char * text) {
  gcu_allocator_free(alloc_default(), text);
}

/* ---- canonical text --------------------------------------------------- */

typedef struct Piece {
  char * p;
  size_t n;
} Piece;

typedef struct Pieces {
  Piece * v;
  size_t n;
  size_t cap;
  int oom;
} Pieces;

static void pieces_free(Pieces * ps) {
  size_t i;
  for (i = 0; i < ps->n; i++) {
    gcu_allocator_free(alloc_default(), ps->v[i].p);
  }
  gcu_allocator_free(alloc_default(), ps->v);
  memset(ps, 0, sizeof *ps);
}

static void pieces_add(Pieces * ps, Buf * b) {
  if (ps->oom || b->oom) {
    ps->oom = 1;
    gcu_allocator_free(alloc_default(), b->p);
    return;
  }
  if (ps->n >= ps->cap) {
    size_t cap = ps->cap == 0 ? 8 : ps->cap * 2;
    Piece * next = (Piece *)gcu_allocator_realloc(alloc_default(), ps->v,
        cap * sizeof *next);
    if (next == NULL) {
      ps->oom = 1;
      gcu_allocator_free(alloc_default(), b->p);
      return;
    }
    ps->v = next;
    ps->cap = cap;
  }
  if (b->p == NULL) {
    /* An empty rendering cannot happen; keep the array well formed. */
    b->p = (char *)gcu_allocator_calloc(alloc_default(), 1, 1);
    if (b->p == NULL) {
      ps->oom = 1;
      return;
    }
  }
  ps->v[ps->n].p = b->p;
  ps->v[ps->n].n = b->n;
  ps->n += 1;
}

static int cmp_piece(const void * a, const void * b) {
  const Piece * x = (const Piece *)a;
  const Piece * y = (const Piece *)b;
  size_t m = x->n < y->n ? x->n : y->n;
  int r = memcmp(x->p, y->p, m);
  if (r != 0) {
    return r;
  }
  return x->n < y->n ? -1 : (x->n > y->n ? 1 : 0);
}

/* Sort and drop repeats. */
static void pieces_normalize(Pieces * ps) {
  size_t i;
  size_t w = 0;
  if (ps->n > 1) {
    qsort(ps->v, ps->n, sizeof *ps->v, cmp_piece);
  }
  for (i = 0; i < ps->n; i++) {
    if (w > 0 && cmp_piece(&ps->v[w - 1], &ps->v[i]) == 0) {
      gcu_allocator_free(alloc_default(), ps->v[i].p);
      continue;
    }
    ps->v[w++] = ps->v[i];
  }
  ps->n = w;
}

static void render(const GDEFCORE_Condition * c, int idx, Buf * out);

static void collect(const GDEFCORE_Condition * c, int idx, int kind,
    Pieces * ps) {
  const CNode * node = &c->nodes[idx];
  size_t k;
  for (k = 0; k < node->count; k++) {
    int child = c->kids[node->first + k];
    if (c->nodes[child].kind == kind) {
      collect(c, child, kind, ps);
    } else {
      Buf b;
      memset(&b, 0, sizeof b);
      render(c, child, &b);
      pieces_add(ps, &b);
    }
  }
}

static void render(const GDEFCORE_Condition * c, int idx, Buf * out) {
  const CNode * node = &c->nodes[idx];
  switch (node->kind) {
    case kTrue:
      buf_str(out, "true");
      break;
    case kFalse:
      buf_str(out, "false");
      break;
    case kType:
      buf_str(out, "type");
      break;
    case kState:
      buf_str(out, "state");
      break;
    case kRevCreator:
      buf_str(out, "revision.creator");
      break;
    case kCreator:
      buf_str(out, "creator");
      break;
    case kPrincipal:
      buf_str(out, "principal");
      break;
    case kNow:
      buf_str(out, "now");
      break;
    case kField:
      buf_str(out, "field.");
      buf_add(out, c->pool + node->str, node->str_len);
      break;
    case kText:
      buf_quoted(out, c->pool + node->str, node->str_len);
      break;
    case kInt:
      buf_add(out, c->pool + node->str, node->str_len);
      break;
    case kAny:
      buf_str(out, "_");
      break;
    case kRelated: {
      size_t k;
      buf_str(out, "(related ");
      render(c, c->kids[node->first], out);
      buf_str(out, " (");
      for (k = 1; k < node->count; k++) {
        if (k > 1) {
          buf_str(out, " ");
        }
        render(c, c->kids[node->first + k], out);
      }
      buf_str(out, "))");
      break;
    }
    case kNot:
      buf_str(out, "(not ");
      render(c, c->kids[node->first], out);
      buf_str(out, ")");
      break;
    case kCmp: {
      static const char * const names[] = {"", "=", "!=", "<", "<=", ">", ">="};
      buf_str(out, "(");
      buf_str(out, names[node->op]);
      buf_str(out, " ");
      render(c, c->kids[node->first], out);
      buf_str(out, " ");
      render(c, c->kids[node->first + 1], out);
      buf_str(out, ")");
      break;
    }
    case kIn: {
      Pieces ps;
      size_t k;
      memset(&ps, 0, sizeof ps);
      for (k = 1; k < node->count; k++) {
        Buf b;
        memset(&b, 0, sizeof b);
        render(c, c->kids[node->first + k], &b);
        pieces_add(&ps, &b);
      }
      pieces_normalize(&ps);
      buf_str(out, "(in ");
      render(c, c->kids[node->first], out);
      buf_str(out, " (");
      for (k = 0; k < ps.n; k++) {
        if (k > 0) {
          buf_str(out, " ");
        }
        buf_add(out, ps.v[k].p, ps.v[k].n);
      }
      buf_str(out, "))");
      if (ps.oom) {
        out->oom = 1;
      }
      pieces_free(&ps);
      break;
    }
    case kAnd:
    case kOr: {
      Pieces ps;
      size_t k;
      memset(&ps, 0, sizeof ps);
      collect(c, idx, node->kind, &ps);
      pieces_normalize(&ps);
      if (ps.oom || ps.n == 0) {
        out->oom = 1;
      } else if (ps.n == 1) {
        buf_add(out, ps.v[0].p, ps.v[0].n);
      } else {
        buf_str(out, node->kind == kAnd ? "(and" : "(or");
        for (k = 0; k < ps.n; k++) {
          buf_str(out, " ");
          buf_add(out, ps.v[k].p, ps.v[k].n);
        }
        buf_str(out, ")");
      }
      pieces_free(&ps);
      break;
    }
    default:
      out->oom = 1;
      break;
  }
}

static size_t written_size(const GDEFCORE_Condition * c) {
  Buf b;
  size_t n;
  memset(&b, 0, sizeof b);
  render(c, c->root, &b);
  n = b.oom ? (size_t)-1 : b.n;
  gcu_allocator_free(alloc_default(), b.p);
  return n;
}

GDEFCORE_Result gdefcore_condition_canonical(
    const GDEFCORE_Condition * condition, char ** out_text, size_t * out_len) {
  Buf b;
  int pass;
  if (condition == NULL || out_text == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_text = NULL;
  if (out_len != NULL) {
    *out_len = 0;
  }
  memset(&b, 0, sizeof b);
  render(condition, condition->root, &b);
  if (b.oom) {
    gcu_allocator_free(alloc_default(), b.p);
    return GDEFCORE_ERR_OOM;
  }
  /* A pass can leave a nested and inside an and (an or that shrank to one
   * operand). Parse and render again until the text stops changing. Each
   * pass that changes it removes a node, so this ends. */
  for (pass = 0; pass < kMaxPasses; pass++) {
    GDEFCORE_Condition * again = NULL;
    Buf next;
    int same;
    if (gdefcore_condition_parse(b.p, b.n, &again, NULL) != GDEFCORE_OK) {
      gcu_allocator_free(alloc_default(), b.p);
      return GDEFCORE_ERR_INTERNAL;
    }
    memset(&next, 0, sizeof next);
    render(again, again->root, &next);
    gdefcore_condition_free(again);
    if (next.oom) {
      gcu_allocator_free(alloc_default(), next.p);
      gcu_allocator_free(alloc_default(), b.p);
      return GDEFCORE_ERR_OOM;
    }
    same = next.n == b.n && memcmp(next.p, b.p, b.n) == 0;
    gcu_allocator_free(alloc_default(), b.p);
    b = next;
    if (same) {
      *out_text = b.p;
      if (out_len != NULL) {
        *out_len = b.n;
      }
      return GDEFCORE_OK;
    }
  }
  gcu_allocator_free(alloc_default(), b.p);
  return GDEFCORE_ERR_INTERNAL;
}

GDEFCORE_Result gdefcore_condition_hash(const char * text, size_t len,
    char out_hash[GDEFCORE_CONDITION_HASH_LEN + 1],
    GDEFCORE_Condition_Error * out_error) {
  GDEFCORE_Condition * c = NULL;
  char * canon = NULL;
  size_t canon_len = 0;
  GSEC_Sha256 ctx;
  uint8_t dig[GSEC_SHA256_DIGEST_LEN];
  static const char hexd[] = "0123456789abcdef";
  size_t i;
  GDEFCORE_Result rc;
  if (out_hash == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  rc = gdefcore_condition_parse(text, len, &c, out_error);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_condition_canonical(c, &canon, &canon_len);
  gdefcore_condition_free(c);
  if (rc != GDEFCORE_OK) {
    set_error(out_error, 0, kMsgInternal);
    return rc;
  }
  if (gsec_sha256_init(&ctx) != GSEC_OK ||
      gsec_sha256_update(&ctx, canon, canon_len) != GSEC_OK ||
      gsec_sha256_final(&ctx, dig) != GSEC_OK) {
    gdefcore_condition_text_free(canon);
    return GDEFCORE_ERR_INTERNAL;
  }
  gdefcore_condition_text_free(canon);
  for (i = 0; i < GSEC_SHA256_DIGEST_LEN; i++) {
    out_hash[i * 2] = hexd[dig[i] >> 4];
    out_hash[i * 2 + 1] = hexd[dig[i] & 0x0fu];
  }
  out_hash[GDEFCORE_CONDITION_HASH_LEN] = '\0';
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_condition_builtin(int builtin, const char * type_name,
    size_t type_name_len, char ** out_text, size_t * out_len) {
  Buf raw;
  GDEFCORE_Condition * c = NULL;
  GDEFCORE_Result rc;
  if (out_text == NULL || type_name == NULL || type_name_len == 0 ||
      (builtin != GDEFCORE_CONDITION_BUILTIN_ANY &&
          builtin != GDEFCORE_CONDITION_BUILTIN_OWN)) {
    return GDEFCORE_ERR_INVALID;
  }
  memset(&raw, 0, sizeof raw);
  if (builtin == GDEFCORE_CONDITION_BUILTIN_OWN) {
    buf_str(&raw, "(and ");
  }
  buf_str(&raw, "(= type ");
  buf_quoted(&raw, type_name, type_name_len);
  buf_str(&raw, ")");
  if (builtin == GDEFCORE_CONDITION_BUILTIN_OWN) {
    buf_str(&raw, " (= creator principal))");
  }
  if (raw.oom) {
    gcu_allocator_free(alloc_default(), raw.p);
    return GDEFCORE_ERR_OOM;
  }
  rc = gdefcore_condition_parse(raw.p, raw.n, &c, NULL);
  gcu_allocator_free(alloc_default(), raw.p);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_condition_canonical(c, out_text, out_len);
  gdefcore_condition_free(c);
  return rc;
}

/* ---- editions --------------------------------------------------------- */

/*
 * Edition 1 called the operand that names who wrote the entity's content
 * `actor`. Edition 2 splits it in two: `creator` is who created the entity
 * (immutable, and what `own` means) and `revision.creator` is who wrote the
 * revision that is now active. A stored edition 1 `actor` means the second,
 * which is what it read, so the upcaster is a rename of that one atom outside
 * text constants. Text that is already edition 2 contains no bare `actor` (the
 * parser refuses it), so the upcast is the identity on it: a stored condition
 * need not say which edition it is.
 */
GDEFCORE_Result gdefcore_condition_upcast(const char * text, size_t len,
    int from_edition, char ** out_text, size_t * out_len) {
  static const char kOld[] = "actor";
  static const char kNew[] = "revision.creator";
  Buf b;
  size_t i = 0;
  if (out_text == NULL || (text == NULL && len != 0) ||
      (from_edition != 1 && from_edition != 2 && from_edition != 3)) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_text = NULL;
  if (out_len != NULL) {
    *out_len = 0;
  }
  memset(&b, 0, sizeof b);
  while (i < len) {
    unsigned char ch = (unsigned char)text[i];
    if (ch == '"') {
      /* A text constant: copied whole, its escapes included. */
      size_t j = i + 1;
      while (j < len && text[j] != '"') {
        j += text[j] == '\\' && j + 1 < len ? 2 : 1;
      }
      j = j < len ? j + 1 : len;
      buf_add(&b, text + i, j - i);
      i = j;
    } else if (is_delim(ch)) {
      buf_add(&b, text + i, 1);
      i += 1;
    } else {
      size_t j = i;
      while (j < len && !is_delim((unsigned char)text[j]) && text[j] != '"') {
        j += 1;
      }
      if (from_edition == 1 && j - i == sizeof kOld - 1 &&
          memcmp(text + i, kOld, sizeof kOld - 1) == 0) {
        buf_add(&b, kNew, sizeof kNew - 1);
      } else {
        buf_add(&b, text + i, j - i);
      }
      i = j;
    }
  }
  if (b.oom) {
    gcu_allocator_free(alloc_default(), b.p);
    return GDEFCORE_ERR_OOM;
  }
  if (b.p == NULL) {
    b.p = (char *)gcu_allocator_malloc(alloc_default(), 1);
    if (b.p == NULL) {
      return GDEFCORE_ERR_OOM;
    }
    b.p[0] = '\0';
  }
  *out_text = b.p;
  if (out_len != NULL) {
    *out_len = b.n;
  }
  return GDEFCORE_OK;
}

GDEFCORE_Result gdefcore_condition_parse_stored(const char * text, size_t len,
    GDEFCORE_Condition ** out_condition, GDEFCORE_Condition_Error * out_error) {
  char * up = NULL;
  size_t up_len = 0;
  GDEFCORE_Result rc = gdefcore_condition_upcast(text, len, 1, &up, &up_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_condition_parse(up, up_len, out_condition, out_error);
  gcu_allocator_free(alloc_default(), up);
  return rc;
}

/* ---- plain English ---------------------------------------------------- */

static int plain_word(const char * s, size_t n) {
  size_t i;
  if (n == 0) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    char ch = s[i];
    if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-')) {
      return 0;
    }
  }
  return 1;
}

static void say_operand(const GDEFCORE_Condition * c, int idx, Buf * out) {
  const CNode * node = &c->nodes[idx];
  switch (node->kind) {
    case kType:
      buf_str(out, "the type");
      break;
    case kState:
      buf_str(out, "the state");
      break;
    case kRevCreator:
      buf_str(out, "the author of the revision");
      break;
    case kCreator:
      buf_str(out, "the creator");
      break;
    case kPrincipal:
      buf_str(out, "the person");
      break;
    case kNow:
      buf_str(out, "the current time");
      break;
    case kField:
      buf_str(out, "the ");
      buf_add(out, c->pool + node->str, node->str_len);
      buf_str(out, " field");
      break;
    case kInt:
      buf_add(out, c->pool + node->str, node->str_len);
      break;
    case kAny:
      buf_str(out, "anything");
      break;
    default:
      if (plain_word(c->pool + node->str, node->str_len)) {
        buf_add(out, c->pool + node->str, node->str_len);
      } else {
        buf_quoted(out, c->pool + node->str, node->str_len);
      }
      break;
  }
}

static void say(const GDEFCORE_Condition * c, int idx, Buf * out, int parent) {
  const CNode * node = &c->nodes[idx];
  size_t k;
  switch (node->kind) {
    case kTrue:
      buf_str(out, "always");
      break;
    case kFalse:
      buf_str(out, "never");
      break;
    case kNot:
      buf_str(out, "not (");
      say(c, c->kids[node->first], out, kNot);
      buf_str(out, ")");
      break;
    case kAnd:
    case kOr: {
      int wrap = parent == kAnd || parent == kOr;
      if (wrap) {
        buf_str(out, "(");
      }
      for (k = 0; k < node->count; k++) {
        if (k > 0) {
          buf_str(out, node->kind == kAnd ? " and " : " or ");
        }
        say(c, c->kids[node->first + k], out, node->kind);
      }
      if (wrap) {
        buf_str(out, ")");
      }
      break;
    }
    case kCmp: {
      static const char * const verbs[] = {"", " is ", " is not ",
          " is less than ", " is at most ", " is greater than ",
          " is at least "};
      say_operand(c, c->kids[node->first], out);
      buf_str(out, verbs[node->op]);
      say_operand(c, c->kids[node->first + 1], out);
      break;
    }
    case kRelated: {
      const CNode * name = &c->nodes[c->kids[node->first]];
      buf_str(out, "there is a row of ");
      buf_add(out, c->pool + name->str, name->str_len);
      buf_str(out, " listing ");
      for (k = 1; k < node->count; k++) {
        if (k > 1) {
          buf_str(out, k + 1 == node->count ? " and " : ", ");
        }
        say_operand(c, c->kids[node->first + k], out);
      }
      break;
    }
    case kIn:
      say_operand(c, c->kids[node->first], out);
      buf_str(out, " is one of: ");
      for (k = 1; k < node->count; k++) {
        if (k > 1) {
          buf_str(out, ", ");
        }
        say_operand(c, c->kids[node->first + k], out);
      }
      break;
    default:
      out->oom = 1;
      break;
  }
}

GDEFCORE_Result gdefcore_condition_explain(
    const GDEFCORE_Condition * condition, char ** out_text, size_t * out_len) {
  char * canon = NULL;
  size_t canon_len = 0;
  GDEFCORE_Condition * c = NULL;
  Buf b;
  GDEFCORE_Result rc;
  if (condition == NULL || out_text == NULL) {
    return GDEFCORE_ERR_INVALID;
  }
  *out_text = NULL;
  if (out_len != NULL) {
    *out_len = 0;
  }
  rc = gdefcore_condition_canonical(condition, &canon, &canon_len);
  if (rc != GDEFCORE_OK) {
    return rc;
  }
  rc = gdefcore_condition_parse(canon, canon_len, &c, NULL);
  gdefcore_condition_text_free(canon);
  if (rc != GDEFCORE_OK) {
    return rc == GDEFCORE_ERR_OOM ? rc : GDEFCORE_ERR_INTERNAL;
  }
  memset(&b, 0, sizeof b);
  say(c, c->root, &b, 0);
  gdefcore_condition_free(c);
  if (b.oom) {
    gcu_allocator_free(alloc_default(), b.p);
    return GDEFCORE_ERR_OOM;
  }
  *out_text = b.p;
  if (out_len != NULL) {
    *out_len = b.n;
  }
  return GDEFCORE_OK;
}
