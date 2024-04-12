#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "libs/picohttpparser.h"
#include "limits.h"

#ifndef __ANNOTATE_LOOP
#define __ANNOTATE_LOOP(x)
#endif

#ifndef __u32
typedef unsigned long long int __u64;
typedef unsigned int           __u32;
typedef unsigned short         __u16;
typedef unsigned char          __u8 ;
#endif

struct parsed_data {
	char *method;
	__u16 method_len;
	char *path;
	__u16 path_len;
	int minor_version;
	struct phr_header headers[MAX_NUM_HDR];
	__u16 num_headers;
};

struct per_conn_state {
	__u8 is_old;
	__u16 parsed_off;
	struct parsed_data preq;
};

/*
 * Check if server expects a new request on the connection. If so, initialize
 * the state.
 * */
void _check_new_req(struct per_conn_state *state)
{
	if (!state->is_old) {
		state->is_old = 1;
		state->parsed_off = 0;
		memset(&state->preq, 0, sizeof(struct parsed_data));
	}
}

/* Entry function */
void loop(struct per_conn_state state)
{
	int ret;
	int fd;
	char *buf;
	__u16 size;
	struct parsed_data *preq;

	_check_new_req(&state);
	preq = &state.preq;

	size = read(fd, buf, 0);
	ret = phr_parse_request(buf, size, &preq->method, &preq->method_len,
			&preq->path, &preq->path_len, &preq->minor_version,
			preq->headers, &preq->num_headers, state.parsed_off);
	if (ret < 0) {
		if (ret == -1) {
			/* Failed to parse the request */
			return;
		} else if (ret == -2) {
			/* Partial data */
			state.parsed_off += size;
			return;
		}
	}
	/* Finish parsing the HTTP/1.1 */
	state.parsed_off = 0;
	char path[128];
	memset(path, 0, 128);
	__ANNOTATE_LOOP(127);
	strncpy(path, preq->path, preq->path_len);
	path[preq->path_len] = 0;
	printk("path: %s", path);
}
