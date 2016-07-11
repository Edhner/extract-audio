#ifndef EXTRACT_AUDIO_H
#define EXTRACT_AUDIO_H

struct box_header {
	uint32_t size;
	char name[4];
};

struct full_box_header {
	uint32_t size;
	char box_name[4];
	uint8_t version;
	uint8_t flags[3];
};

struct generic_box {
	struct box_header header;
	uint8_t data[1];
};

struct generic_full_box {
	struct full_box_header header;
	uint8_t data[1];
};

struct stsd_box {
	struct box_header header;
	uint32_t i;
	uint32_t entry_count;
	struct generic_box sample_entry;
};

struct stsz_box {
	struct full_box_header header;
	uint32_t sample_size;
	uint32_t sample_count;
	uint32_t entry_size;
};

struct stsc_box {
	struct full_box_header header;
	uint32_t entry_count;
	uint32_t first_chunk;
	uint32_t samples_per_chunk;
	uint32_t sample_description_index;
};

struct stco_box {
	struct full_box_header header;
	uint32_t entry_count;
	uint32_t chunk_offset;
};

struct chunk_data {
	uint32_t position;
	uint32_t size;
	int samples;
};

#endif
