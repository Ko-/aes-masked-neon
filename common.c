#include <stdint.h>
#include <stdio.h>
#include "common.h"

int compare(const void *a, const void *b) {
    return *(unsigned long long *)a - *(unsigned long long *)b;
}

void share_secret(bint16_t r, const uint16_t a, FILE * random) {
    unsigned int i;

    r[0] = a;
    fread(r+1, sizeof(uint16_t), NUM_SHARES-1, random);
    for (i = 1; i < NUM_SHARES; i++) {
        r[0] ^= r[i];
    }
    return;
}

void share_public(bint16_t r, const uint16_t a) {
    unsigned int i;

    r[0] = a;
    for (i = 1; i < NUM_SHARES; i++) {
        r[i] = 0;
    }
    return;
}

uint16_t recombine_share(bint16_t a) {
    uint16_t r;
    unsigned int i;

    r = a[0];
    for (i = 1; i < NUM_SHARES; i++) {
        r ^= a[i];
    }
    return r;
}

uint16_t recombine_share_key(bint16_t a, bint16_t b) {
    uint16_t r;
    int i;

    r = 0;
    for (i = 0; i < NUM_SHARES; i += 2) r ^= a[i];
    for (i = 0; i < NUM_SHARES; i += 2) r ^= b[i];
    return r;
}

void printdata(const uint16_t * data, const unsigned int numblocks) {
    unsigned int i;

    for (i = 0; i < 8 * numblocks; i++) {
        printf("%04x", data[i]);
    }
    printf("\n");
}

