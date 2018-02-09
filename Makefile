# --------------------------------------------------------------------
CC              = gcc
CFLAGS          = -Wall -Wextra -O3 -funroll-loops -fno-stack-protector -mfpu=neon -marm
CFLAGS          += -D NUM_SHARES=$(NUM_SHARES) -D NUM_BLOCKS=$(NUM_BLOCKS)

# NUM_SHARES selects the masking order
# NUM_BLOCKS selects the number of blocks that are processed in parallel
# Possible combinations: 1x4, 2x4, 1x8
NUM_SHARES      ?= 4
NUM_BLOCKS      ?= 2

# --------------------------------------------------------------------
SOURCES			= aes_shared_$(NUM_BLOCKS)x$(NUM_SHARES)s.s common.c cpucycles.c
TARGETS			= analysis benchmark

analysis: CFLAGS += -Wa,--defsym,ANALYSIS=1

# --------------------------------------------------------------------
.PHONY: all clean

all: $(TARGETS)

$(TARGETS): %:%.c $(SOURCES)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(TARGETS)

