CC      ?= gcc
CFLAGS  ?= -std=c99 -Wall -Wextra -O3 -flto -fomit-frame-pointer
LDFLAGS ?= -lm

OBJS = rangecoder.o lzp.o crc32.o container.o decode.o crypto.o encode.o \
       alz.o alz_state.o alz_core.o alz_bm.o alz_match.o alz_side.o \
       alz_cm.o alz_score.o alz_arena2d.o alz_arena_c4.o alz_d2score.o \
       alz_block.o alz_parse_score.o alz_tables.o alz_lm.o filter.o \
       alz_esc_line.o alz_est414630.o \
       ppm.o ppm_core.o ppm_fenwick.o ppm_kernel.o ppm_mm.o ppm_model.o \
       ppm_update.o ppm_maint.o ppm_records.o ppm_mf.o ppm_predict.o \
       ppm_rw1.o ppm_rw2.o ppm_d390.o ppm_c550.o ppm_bc1.o ppm_post.o \
       ppm_tables.o ppm_cascade.o ppm_encode.o ppm_detr_inv.o ppm_detr_fwd.o \
       ppm_legacy_cost.o ppm_blocklen.o ppm_blk_cost.o frontier.o selclk.o

.PHONY: all clean test

all: uharc

uharc: uharc.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o uharc

test: uharc
	./uharc --selftest
