#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "libs/picohttpparser.h"
#include "limits.h"

struct parsed_data {
	char *method;
	size_t method_len;
	char *path;
	size_t path_len;
	int minor_version;
	struct phr_header headers[MAX_NUM_HDR];
	size_t num_headers;
};

/* Entry function */
void loop(void)
{
	int ret = 0;
	int fd = 0;
	char *buf = NULL;
	size_t size = 0;
	struct parsed_data preq;
	memset(&preq, 0, sizeof(preq));

	size = read(fd, buf, 0);

	printk("hello");
	/* ret = phr_parse_request(buf, size, ) */
}
