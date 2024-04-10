/* vim: set et ts=2 sw=2: */
#include <assert.h>
#include <stddef.h>
#include <string.h>
#ifdef __SSE4_2__
#ifdef _MSC_VER
#include <nmmintrin.h>
#else
#include <x86intrin.h>
#endif
#endif
#include "picohttpparser.h"

#ifndef __ANNOTATE_LOOP
#define __ANNOTATE_LOOP(x)
#endif

static const char *get_token_to_eol(const char *buf, const char *buf_end,
                                    const char **token, size_t *token_len,
                                    int *ret) {
  const char *token_start = buf;
  char non_printable_flag = 0;
  char found_flag = 0;
  /* unrolled version of the loop */
  __ANNOTATE_LOOP(16)
  while ((buf_end - buf >= 8)) {
    const char *b0 = buf + 0;
    const char *b1 = buf + 1;
    const char *b2 = buf + 2;
    const char *b3 = buf + 3;
    const char *b4 = buf + 4;
    const char *b5 = buf + 5;
    const char *b6 = buf + 6;
    const char *b7 = buf + 7;

    if (!((unsigned char)(*b0) - 040u < 0137u)) {
      buf = b0;
      non_printable_flag = 1;
    } else if(!((unsigned char)(*b1) - 040u < 0137u)) {
      buf = b1;
      non_printable_flag = 1;
    } else if(!((unsigned char)(*b2) - 040u < 0137u)) {
      buf = b2;
      non_printable_flag = 1;
    } else if(!((unsigned char)(*b3) - 040u < 0137u)) {
      buf = b3;
      non_printable_flag = 1;
    } else if(!((unsigned char)(*b4) - 040u < 0137u)) {
      buf = b4;
      non_printable_flag = 1;
    } else if(!((unsigned char)(*b5) - 040u < 0137u)) {
      buf = b5;
      non_printable_flag = 1;
    } else if(!((unsigned char)(*b6) - 040u < 0137u)) {
      buf = b6;
      non_printable_flag = 1;
    } else if(!((unsigned char)(*b7) - 040u < 0137u)) {
      buf = b7;
      non_printable_flag = 1;
    } else {
      buf = b7 + 1;
    }

    if (non_printable_flag) {
      if ((((unsigned char)*buf < '\040') && (*buf != '\011')) ||
          (*buf == '\177')) {
        /* goto FOUND_CTL; */
        found_flag = 1;
        break;
      }
      ++buf;
    }
  }

  /* Check what ever is not divisable to groups of 8 (non-unrolled version) */
  __ANNOTATE_LOOP(8)
  while (!found_flag) {
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
    if ((!((unsigned char)(*buf) - 040u < 0137u))) {
      if ((((unsigned char)*buf < '\040') && (*buf != '\011')) ||
          (*buf == '\177')) {
        /* goto FOUND_CTL; */
        found_flag = 1;
        break;
      }
    }
    ++buf;
  }

/* FOUND_CTL: */
  if ((*buf == '\015')) {
    ++buf;
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
    if (*buf != '\012') {
      *ret = -1;
      return NULL;
    };
    buf++;
    *token_len = buf - 2 - token_start;
  } else if (*buf == '\012') {
    *token_len = buf - token_start;
    ++buf;
  } else {
    *ret = -1;
    return NULL;
  }
  *token = token_start;

  return buf;
}

static const char *is_complete(const char *buf, const char *buf_end,
                               size_t last_len, int *ret) {
  int ret_cnt = 0;
  buf = last_len < 3 ? buf : buf + last_len - 3;

  __ANNOTATE_LOOP(4)
  while (1) {
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
    if (*buf == '\015') {
      ++buf;
      if (buf == buf_end) {
        *ret = -2;
        return NULL;
      };
      if (buf == buf_end) {
        *ret = -2;
        return NULL;
      };
      if (*buf != '\012') {
        *ret = -1;
        return NULL;
      };
      buf++;
      ++ret_cnt;
    } else if (*buf == '\012') {
      ++buf;
      ++ret_cnt;
    } else {
      ++buf;
      ret_cnt = 0;
    }
    if (ret_cnt == 2) {
      return buf;
    }
  }

  *ret = -2;
  return NULL;
}
static const char *parse_token(const char *buf, const char *buf_end,
                               const char **token, size_t *token_len,
                               char next_char, int *ret) {

  static const char *token_char_map = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\0\1\1\1\1\1\0\0\1\1\0\1\1\0\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\1\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  const char *buf_start = buf;
  if (buf == buf_end) {
    *ret = -2;
    return NULL;
  };
  __ANNOTATE_LOOP(16)
  while (1) {
    if (*buf == next_char) {
      break;
    } else if (!token_char_map[(unsigned char)*buf]) {
      *ret = -1;
      return NULL;
    }
    ++buf;
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
  }
  *token = buf_start;
  *token_len = buf - buf_start;
  return buf;
}

static const char *parse_http_version(const char *buf, const char *buf_end,
                                      int *minor_version, int *ret) {

  if (buf_end - buf < 9) {
    *ret = -2;
    return NULL;
  }
  if (*buf != 'H') {
    *ret = -1;
    return NULL;
  }
  buf++;
  if (*buf != 'T') {
    *ret = -1;
    return NULL;
  }
  buf++;
  if (*buf != 'T') {
    *ret = -1;
    return NULL;
  }
  buf++;
  if (*buf != 'P') {
    *ret = -1;
    return NULL;
  }
  buf++;
  if (*buf != '/') {
    *ret = -1;
    return NULL;
  }
  buf++;
  if (*buf != '1') {
    *ret = -1;
    return NULL;
  }
  buf++;
  if (*buf != '.') {
    *ret = -1;
    return NULL;
  }
  buf++;
  if (*buf < '0' || '9' < *buf) {
    buf++;
    *ret = -1;
    return NULL;
  }
  *(minor_version) = (1) * (*buf - '0');
  buf++;
  return buf;
}

static const char *parse_headers(const char *buf, const char *buf_end,
                                 struct phr_header *headers,
                                 size_t *num_headers, size_t max_headers,
                                 int *ret) {
  __ANNOTATE_LOOP(4)
  while(1) {
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
    if (*buf == '\015') {
      ++buf;
      if (buf == buf_end) {
        *ret = -2;
        return NULL;
      };
      if (*buf != '\012') {
        *ret = -1;
        return NULL;
      }
      buf++;
      break;
    } else if (*buf == '\012') {
      ++buf;
      break;
    }
    if (*num_headers == max_headers) {
      *ret = -1;
      return NULL;
    }
    if (!(*num_headers != 0 && (*buf == ' ' || *buf == '\t'))) {
      buf = parse_token(buf, buf_end, &headers[*num_headers].name,
          &headers[*num_headers].name_len, ':', ret);
      if (buf == NULL) {
        return NULL;
      }
      if (headers[*num_headers].name_len == 0) {
        *ret = -1;
        return NULL;
      }
      ++buf;
      __ANNOTATE_LOOP(32)
      while(1) {
        if (buf == buf_end) {
          *ret = -2;
          return NULL;
        };
        if (!(*buf == ' ' || *buf == '\t')) {
          break;
        }
        ++buf;
      }
    } else {
      headers[*num_headers].name = NULL;
      headers[*num_headers].name_len = 0;
    }
    const char *value;
    size_t value_len;
    buf = get_token_to_eol(buf, buf_end, &value, &value_len, ret);
    if (buf == NULL) {
      return NULL;
    }

    const char *value_end = value + value_len;
    __ANNOTATE_LOOP(3)
    while(1) {
      if (value_end == value)
        break;
      const char c = *(value_end - 1);
      if (!(c == ' ' || c == '\t')) {
        break;
      }
      --value_end;
    }
    headers[*num_headers].value = value;
    headers[*num_headers].value_len = value_end - value;

    ++*num_headers;
  }
  return buf;
}

static const char *parse_request(const char *buf, const char *buf_end,
                                 const char **method, size_t *method_len,
                                 const char **path, size_t *path_len,
                                 int *minor_version, struct phr_header *headers,
                                 size_t *num_headers, size_t max_headers,
                                 int *ret) {

  if (buf == buf_end) {
    *ret = -2;
    return NULL;
  };
  if (*buf == '\015') {
    ++buf;
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
    if (*buf != '\012') {
      *ret = -1;
      return NULL;
    };
    buf++;
  } else if (*buf == '\012') {
    ++buf;
  }
  buf = parse_token(buf, buf_end, method, method_len, ' ', ret);
  if (buf == NULL) {
    return NULL;
  }
  __ANNOTATE_LOOP(2)
  do {
    ++buf;
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
  } while (*buf == ' ');
  const char *tok_start = buf;
  if (buf == buf_end) {
    *ret = -2;
    return NULL;
  };
  __ANNOTATE_LOOP(56)
  while (1) {
    if (*buf == ' ') {
      break;
    } else if ((!((unsigned char)(*buf) - 040u < 0137u))) {
      if ((unsigned char)*buf < '\040' || *buf == '\177') {
        *ret = -1;
        return NULL;
      }
    }
    ++buf;
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
  }
  *path = tok_start;
  *path_len = buf - tok_start;
  __ANNOTATE_LOOP(2)
  do {
    ++buf;
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
  } while (*buf == ' ');
  if (*method_len == 0 || *path_len == 0) {
    *ret = -1;
    return NULL;
  }

  buf = parse_http_version(buf, buf_end, minor_version, ret);
  if (buf == NULL) {
    return NULL;
  }
  if (*buf == '\015') {
    ++buf;
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
    if (*buf != '\012') {
      *ret = -1;
      return NULL;
    };
    ++buf;
  } else if (*buf == '\012') {
    ++buf;
  } else {
    *ret = -1;
    return NULL;
  }

  return parse_headers(buf, buf_end, headers, num_headers, max_headers, ret);
}

int phr_parse_request(const char *buf_start, size_t len, const char **method,
                      size_t *method_len, const char **path, size_t *path_len,
                      int *minor_version, struct phr_header *headers,
                      size_t *num_headers, size_t last_len) {
  const char *buf = buf_start;
  const char *buf_end = buf_start + len;
  size_t max_headers = *num_headers;
  int r = -1;

  *method = NULL;
  *method_len = 0;
  *path = NULL;
  *path_len = 0;
  *minor_version = -1;
  *num_headers = 0;

  if (last_len != 0) {
    const char *tmp = is_complete(buf, buf_end, last_len, &r);
    if (tmp == NULL) {
      return r;
    }
  }

  buf = parse_request(buf, buf_end, method, method_len, path, path_len,
      minor_version, headers, num_headers, max_headers, &r);
  if (buf == NULL) {
    return r;
  }

  return (int)(buf - buf_start);
}

static const char *parse_response(const char *buf, const char *buf_end,
                                  int *minor_version, int *status,
                                  const char **msg, size_t *msg_len,
                                  struct phr_header *headers,
                                  size_t *num_headers, size_t max_headers,
                                  int *ret) {

  if ((buf = parse_http_version(buf, buf_end, minor_version, ret)) == NULL) {
    return NULL;
  }

  if (*buf != ' ') {
    *ret = -1;
    return NULL;
  }
  __ANNOTATE_LOOP(64)
  do {
    ++buf;
    if (buf == buf_end) {
      *ret = -2;
      return NULL;
    };
  } while (*buf == ' ');

  if (buf_end - buf < 4) {
    *ret = -2;
    return NULL;
  }
  int res_ = 0;
  if (*buf < '0' || '9' < *buf) {
    buf++;
    *ret = -1;
    return NULL;
  }
  *(&res_) = (100) * (*buf - '0');
  ++buf;
  *status = res_;
  if (*buf < '0' || '9' < *buf) {
    buf++;
    *ret = -1;
    return NULL;
  }
  *(&res_) = (10) * (*buf - '0');
  ++buf;
  *status += res_;
  if (*buf < '0' || '9' < *buf) {
    buf++;
    *ret = -1;
    return NULL;
  }
  *(&res_) = (1) * (*buf - '0');
  ++buf;
  *status += res_;

  buf = get_token_to_eol(buf, buf_end, msg, msg_len, ret);
  if (buf == NULL) {
    return NULL;
  }
  if (*msg_len == 0) {

  } else if (**msg == ' ') {
    __ANNOTATE_LOOP(64)
    do {
      ++*msg;
      --*msg_len;
    } while (**msg == ' ');
  } else {

    *ret = -1;
    return NULL;
  }

  return parse_headers(buf, buf_end, headers, num_headers, max_headers, ret);
}

int phr_parse_response(const char *buf_start, size_t len, int *minor_version,
                       int *status, const char **msg, size_t *msg_len,
                       struct phr_header *headers, size_t *num_headers,
                       size_t last_len) {
  const char *buf = buf_start, *buf_end = buf + len;
  size_t max_headers = *num_headers;
  int r;

  *minor_version = -1;
  *status = 0;
  *msg = NULL;
  *msg_len = 0;
  *num_headers = 0;

  if (last_len != 0 && is_complete(buf, buf_end, last_len, &r) == NULL) {
    return r;
  }

  if ((buf = parse_response(buf, buf_end, minor_version, status, msg, msg_len,
                            headers, num_headers, max_headers, &r)) == NULL) {
    return r;
  }

  return (int)(buf - buf_start);
}

int phr_parse_headers(const char *buf_start, size_t len,
                      struct phr_header *headers, size_t *num_headers,
                      size_t last_len) {
  const char *buf = buf_start, *buf_end = buf + len;
  size_t max_headers = *num_headers;
  int r;

  *num_headers = 0;

  if (last_len != 0 && is_complete(buf, buf_end, last_len, &r) == NULL) {
    return r;
  }
  buf = parse_headers(buf, buf_end, headers, num_headers, max_headers, &r);
  if (buf == NULL) {
    return r;
  }

  return (int)(buf - buf_start);
}

enum {
  CHUNKED_IN_CHUNK_SIZE,
  CHUNKED_IN_CHUNK_EXT,
  CHUNKED_IN_CHUNK_DATA,
  CHUNKED_IN_CHUNK_CRLF,
  CHUNKED_IN_TRAILERS_LINE_HEAD,
  CHUNKED_IN_TRAILERS_LINE_MIDDLE
};

static int decode_hex(int ch) {
  if ('0' <= ch && ch <= '9') {
    return ch - '0';
  } else if ('A' <= ch && ch <= 'F') {
    return ch - 'A' + 0xa;
  } else if ('a' <= ch && ch <= 'f') {
    return ch - 'a' + 0xa;
  } else {
    return -1;
  }
}

ssize_t phr_decode_chunked(struct phr_chunked_decoder *decoder, char *buf,
                           size_t *_bufsz) {
  size_t dst = 0, src = 0, bufsz = *_bufsz;
  ssize_t ret = -2;

  decoder->_total_read += bufsz;

  __ANNOTATE_LOOP(128)
  while (1) {
    switch (decoder->_state) {
    case CHUNKED_IN_CHUNK_SIZE:
      __ANNOTATE_LOOP(128)
      while (1) {
        int v;
        if (src == bufsz)
          goto Exit;
        v = decode_hex(buf[src]);
        if (v == -1) {
          if (decoder->_hex_count == 0) {
            ret = -1;
            goto Exit;
          }

          switch (buf[src]) {
          case ' ':
          case '\011':
          case ';':
          case '\012':
          case '\015':
            break;
          default:
            ret = -1;
            goto Exit;
          }
          break;
        }
        if (decoder->_hex_count == sizeof(size_t) * 2) {
          ret = -1;
          goto Exit;
        }
        decoder->bytes_left_in_chunk = decoder->bytes_left_in_chunk * 16 + v;
        ++decoder->_hex_count;
        ++src;
      }
      decoder->_hex_count = 0;
      decoder->_state = CHUNKED_IN_CHUNK_EXT;

    case CHUNKED_IN_CHUNK_EXT:
      __ANNOTATE_LOOP(128)
      while(1) {
        if (src == bufsz)
          goto Exit;
        if (buf[src] == '\012')
          break;
        ++src;
      }
      ++src;
      if (decoder->bytes_left_in_chunk == 0) {
        if (decoder->consume_trailer) {
          decoder->_state = CHUNKED_IN_TRAILERS_LINE_HEAD;
          break;
        } else {
          goto Complete;
        }
      }
      decoder->_state = CHUNKED_IN_CHUNK_DATA;

    case CHUNKED_IN_CHUNK_DATA: {
      size_t avail = bufsz - src;
      if (avail < decoder->bytes_left_in_chunk) {
        if (dst != src)
          memmove(buf + dst, buf + src, avail);
        src += avail;
        dst += avail;
        decoder->bytes_left_in_chunk -= avail;
        goto Exit;
      }
      if (dst != src)
        memmove(buf + dst, buf + src, decoder->bytes_left_in_chunk);
      src += decoder->bytes_left_in_chunk;
      dst += decoder->bytes_left_in_chunk;
      decoder->bytes_left_in_chunk = 0;
      decoder->_state = CHUNKED_IN_CHUNK_CRLF;
    }

    case CHUNKED_IN_CHUNK_CRLF:
      __ANNOTATE_LOOP(128)
      while(1) {
        if (src == bufsz)
          goto Exit;
        if (buf[src] != '\015')
          break;
        ++src;
      }
      if (buf[src] != '\012') {
        ret = -1;
        goto Exit;
      }
      ++src;
      decoder->_state = CHUNKED_IN_CHUNK_SIZE;
      break;
    case CHUNKED_IN_TRAILERS_LINE_HEAD:
      __ANNOTATE_LOOP(128)
      while(1) {
        if (src == bufsz)
          goto Exit;
        if (buf[src] != '\015')
          break;
        ++src;
      }
      if (buf[src++] == '\012')
        goto Complete;
      decoder->_state = CHUNKED_IN_TRAILERS_LINE_MIDDLE;

    case CHUNKED_IN_TRAILERS_LINE_MIDDLE:
      __ANNOTATE_LOOP(128)
      while (1) {
        if (src == bufsz)
          goto Exit;
        if (buf[src] == '\012')
          break;
        ++src;
      }
      ++src;
      decoder->_state = CHUNKED_IN_TRAILERS_LINE_HEAD;
      break;
    default:
      assert(!"decoder is corrupt");
    }
  }

Complete:
  ret = bufsz - src;
Exit:
  if (dst != src)
    memmove(buf + dst, buf + src, bufsz - src);
  *_bufsz = dst;

  if (ret == -2) {
    decoder->_total_overhead += bufsz - dst;
    if (decoder->_total_overhead >= 100 * 1024 &&
        decoder->_total_read - decoder->_total_overhead <
            decoder->_total_read / 4)
      ret = -1;
  }
  return ret;
}

int phr_decode_chunked_is_in_data(struct phr_chunked_decoder *decoder) {
  return decoder->_state == CHUNKED_IN_CHUNK_DATA;
}
