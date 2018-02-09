#include <stdint.h>
#include <stdio.h>

typedef uint16_t bint16_t[NUM_SHARES];

int compare(const void *a, const void *b);
void share_secret(bint16_t r, const uint16_t a, FILE * random);
void share_public(bint16_t r, const uint16_t a);
uint16_t recombine_share(bint16_t a);
uint16_t recombine_share_key(bint16_t a, bint16_t b);
void printdata(const bint16_t data, const unsigned int numblocks);

extern long long cpucycles_cortex(void);
