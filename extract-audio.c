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
#include <arpa/inet.h>

#include "extract-audio.h"

static void download_data(int start_point, int size);

struct event_base *base;

/* State variables:
 *
 * Since only one file is handled we only need to store one state which makes
 * file global varialbes easiest (it is also possible to store state in user
 * data that is added to the evhtp request, but that is not needed here)
 */

evhtp_connection_t *conn;
char *path;
char *host;

void *moov;
int moov_size;
struct generic_box *moov_box;
int offset;

struct chunk_data *chunks;
int chunk;
int nbr_of_chunks;

int mp4_file_verified;

static void*
get_box(void *data, char *box_name, uint32_t box_size, int box_no)
{
	void *tmp = data;
	struct box_header *sub_box = tmp;
	int bytes_left = box_size;
	int found_boxes = 0;

	while (bytes_left > 0) {
		if (strncmp(sub_box->name, box_name, 4) == 0) {
			found_boxes++;
			if (found_boxes == box_no) {
				return tmp;
			}
		}

		bytes_left -= ntohl(sub_box->size);
		tmp += ntohl(sub_box->size);
		sub_box = tmp;
	}
	return NULL;
}

static void
free_exit()
{
	event_base_loopexit(base, NULL);
}

static void
terminate(int sig, short why, void *data)
{
	free_exit();
}

static int
track_is_audio(struct generic_box *trak)
{
	struct generic_box *mdia = get_box(trak->data, "mdia",
					   ntohl(trak->header.size), 1);
	struct generic_box *minf = get_box(mdia->data, "minf",
					   ntohl(trak->header.size), 1);
	struct generic_box *stbl = get_box(minf->data, "stbl",
					   ntohl(minf->header.size), 1);
	struct stsd_box *stsd = get_box(stbl->data, "stsd",
					ntohl(stbl->header.size), 1);

	if (strncmp(stsd->sample_entry.header.name, "mp4a", 4) == 0) {
		return 1;
	} else {
		return 0;
	}
}

static int
get_audio_chunks()
{
	int track_no = 1;
	int i;
	int smp = 0;
	struct generic_box *trak = get_box(moov_box->data, "trak",
					   ntohl(moov_box->header.size),
					   track_no);
	while (!track_is_audio(trak)) {
		track_no++;
		trak = get_box(moov_box->data, "trak",
			       ntohl(moov_box->header.size), track_no);
		if (trak == NULL) {
			/* Can not find any more tracks */
			fprintf(stderr, "Could not find any audio tracks!");
			return -1;
		}
	}

	struct generic_box *mdia = get_box(trak->data, "mdia",
					   ntohl(trak->header.size), 1);
	struct generic_box *minf = get_box(mdia->data, "minf",
					   ntohl(trak->header.size), 1);
	struct generic_box *stbl = get_box(minf->data, "stbl",
					   ntohl(minf->header.size), 1);

	struct stco_box *stco = get_box(stbl->data, "stco",
					ntohl(stbl->header.size), 1);
	struct stsc_box *stsc = get_box(stbl->data, "stsc",
					ntohl(stbl->header.size), 1);
	struct stsz_box *stsz = get_box(stbl->data, "stsz",
					ntohl(stbl->header.size), 1);

	nbr_of_chunks = ntohl(stco->entry_count);
	chunks = calloc(nbr_of_chunks, sizeof(struct chunk_data));

	uint32_t *p = &stco->chunk_offset;
	for (i = 0; i < nbr_of_chunks; ++i) {
		chunks[i].samples = -1;
		chunks[i].position = ntohl(*p);
		p++;
	}

	uint32_t *p_first_chunk = &stsc->first_chunk;
	uint32_t *p_samples_per_chunk = &stsc->samples_per_chunk;
	for (i = 0; i < ntohl(stsc->entry_count); ++i) {
		chunks[ntohl(*p_first_chunk) - 1].samples = ntohl(*p_samples_per_chunk);

		p_first_chunk += 3;
		p_samples_per_chunk += 3;
	}

	for (i = 0; i < nbr_of_chunks; ++i) {
		if (chunks[i].samples != -1) {
			smp = chunks[i].samples;
		} else {
			chunks[i].samples = smp;
		}
	}

	uint32_t *p_entry_size = &stsz->entry_size;
	if (stsz->sample_size != 0) {
		for (i = 0; i < nbr_of_chunks; ++i) {
			chunks[i].size = ntohl(stsz->sample_size) * chunks[i].samples;
		}
	} else {
		int j;
		for (i = 0; i < nbr_of_chunks; ++i) {
			for (j = 0; j < chunks[i].samples; ++j) {
				chunks[i].size += ntohl(*p_entry_size);
				p_entry_size++;
			}
		}
	}
	return 0;
}

static void
request_finished(evhtp_request_t *req, void *arg)
{
	if (moov_box == NULL) {
		moov_box = get_box(moov, "moov", moov_size, 1);
		if (moov_box == NULL) {
			struct box_header *box = moov;
			offset += ntohl(box->size);
			download_data(offset, 8);
			free(moov);
			return;
		}
		/* We have the moov header, now we download the entire box */
		download_data(offset, ntohl(moov_box->header.size));

		void *p;
		p = realloc(moov, ntohl(moov_box->header.size));
		if (p == NULL) {
			fprintf(stderr,
				"Fatal error! Could not allocate memory!\n");
			free_exit();
		}
		moov = p;
		return;
	} else if (moov_box != NULL && chunks == NULL) {
		moov_box = get_box(moov, "moov", moov_size, 1);
		if (get_audio_chunks() == -1) {
			event_base_loopexit(base, NULL);
		}
	}
	if (chunks != NULL && chunk < nbr_of_chunks) {
		download_data(chunks[chunk].position, chunks[chunk].size);
		chunk++;
	} else if (chunk >= nbr_of_chunks) {
		free_exit();
	}
}

static evhtp_res
dump_data(evhtp_request_t *req, evbuf_t *buf, void *arg)
{
	size_t length = evbuffer_get_length(buf);

	if (req->status != EVHTP_RES_OK) {
		event_base_loopexit(base, NULL);
		return -1;
	}

	if (chunks == NULL) {
		if (evbuffer_remove(buf, moov + moov_size, length) == -1) {
			fprintf(stderr, "Fatal error!\n");
			return EVHTP_RES_FATAL;
		}
		moov_size += length;
		if (!mp4_file_verified) {
			struct box_header *box = moov;
			if (strncmp(box->name, "ftyp", 4) != 0) {
				fprintf(stderr, "Invalid mp4 file!\n");
				free_exit();
				return EVHTP_RES_FATAL;
			}
			mp4_file_verified = 1;
		}
	} else {
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
	}

	return EVHTP_RES_OK;
}

static void usage()
{
	fprintf(stderr,
		"Usage: extract-audio -h <host> -n <port> -p <path>\n");
}

static void
download_data(int start_point, int size)
{
	evhtp_request_t *request;

	int end_point = start_point + size;
	char range_string[100];

	sprintf(range_string, "bytes=%d-%d", start_point, end_point);

	request = evhtp_request_new(request_finished, base);
	evhtp_set_hook(&request->hooks, evhtp_hook_on_read, dump_data, NULL);


	evhtp_headers_add_header(request->headers_out,
				 evhtp_header_new("Host", host, 0, 0));
	evhtp_headers_add_header(request->headers_out,
				 evhtp_header_new("Connection", "keep-alive",
						  0, 0));
	evhtp_headers_add_header(request->headers_out,
				 evhtp_header_new("User-Agent", "extract-audio",
						  0, 0));
	evhtp_headers_add_header(request->headers_out,
				 evhtp_header_new("Range", range_string,
						  0, 0));

	evhtp_make_request(conn, request, htp_method_GET, path);

	moov_size = 0;
}

int
main(int argc, char **argv)
{
	struct evdns_base *dns_base;
	struct event *ev_sigterm;
	struct event *ev_sigint;
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

	moov = malloc(8);
	if (moov == NULL) {
		fprintf(stderr, "Fatal error! Could not allocate memory!\n");
		return -1;
	}

	base = event_base_new();

	dns_base = evdns_base_new(base, 1);
	conn = evhtp_connection_new_dns(base, dns_base, host, port);

	download_data(0, 8);

	/* Add SIGTERM and SIGINT to base */
	ev_sigterm = evsignal_new(base, SIGTERM, terminate, NULL);
	ev_sigint = evsignal_new(base, SIGINT, terminate, NULL);

	event_base_loop(base, 0);

	event_base_free(base);
	free(ev_sigint);
	free(ev_sigterm);

	if (moov != NULL) {
		free(moov);
	}
	if (chunks != NULL) {
		free(chunks);
	}
	return 0;
}
