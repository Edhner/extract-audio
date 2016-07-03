#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>
#include <evhtp.h>
#include <event2/dns.h>


struct event_base *base;

static void
terminate(int sig, short why, void *data)
{
	event_base_loopexit(base, NULL);
}

static void
request_finished(evhtp_request_t *req, void *arg)
{
	event_base_loopexit(base, NULL);
}

static evhtp_res
dump_data(evhtp_request_t *req, evbuf_t *buf, void *arg)
{
	size_t length = evbuffer_get_length(buf);

	if (req->status != EVHTP_RES_OK) {
		event_base_loopexit(base, NULL);
		return -1;
	}

	void *data = malloc(length);
	if (data == NULL) {
		fprintf(stderr, "Fatal error! Could not allocate memory!\n");
		return EVHTP_RES_FATAL;
	}
	if (evbuffer_remove(buf, data, length) == -1) {
		fprintf(stderr, "Fatal error!\n");
		return EVHTP_RES_FATAL;
	}
	if (write(1, data, length) == -1) {
		fprintf(stderr, "Fatal error!\n");
		return EVHTP_RES_FATAL;
	}

	free(data);
	return EVHTP_RES_OK;
}

static void usage()
{
	fprintf(stderr,
		"Usage: extract-audio -h <host> -n <port> -p <path>\n");
}

int
main(int argc, char **argv)
{
	evhtp_connection_t *conn;
	evhtp_request_t *request;
	struct evdns_base *dns_base;
	struct event *ev_sigterm;
	struct event *ev_sigint;
	char *host = NULL;
	char *path = NULL;
	int port = 80;
	int c;

	while ((c = getopt(argc, argv, "h:p:n:")) != -1) {
		switch(c) {
		case 'h':
			host = optarg;
			break;
		case 'n':
			port = strtol(optarg, NULL, 10);
			if (port == 0) {
				/* strtol returns 0 on failure... */
				fprintf(stderr,
					"Invalid port %s\n", optarg);
				return -1;
			}
			break;
		case 'p':
			path = optarg;
			break;
		case '?':
			usage();
			return -1;
		}
	}

	if (host == NULL) {
		fprintf(stderr, "No host specified!\n");
		usage();
		return -1;
	}
	if (path == NULL) {
		fprintf(stderr, "No path specified!\n");
		usage();
		return -1;
	}

	base = event_base_new();

	dns_base = evdns_base_new(base, 1);
	conn = evhtp_connection_new_dns(base, dns_base, host, port);

	request = evhtp_request_new(request_finished, base);
	evhtp_set_hook(&request->hooks, evhtp_hook_on_read, dump_data, NULL);


	evhtp_headers_add_header(request->headers_out,
				 evhtp_header_new("Host", host, 0, 0));
	evhtp_headers_add_header(request->headers_out,
				 evhtp_header_new("Connection", "close", 0, 0));
	evhtp_headers_add_header(request->headers_out,
				 evhtp_header_new("User-Agent", "extract-audio",
						  0, 0));

	evhtp_make_request(conn, request, htp_method_GET, path);

	/* Add SIGTERM and SIGINT to base */
	ev_sigterm = evsignal_new(base, SIGTERM, terminate, NULL);
	ev_sigint = evsignal_new(base, SIGINT, terminate, NULL);

	event_base_loop(base, 0);

	event_base_free(base);
	free(ev_sigint);
	free(ev_sigterm);

	return 0;
}
