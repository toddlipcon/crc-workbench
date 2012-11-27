#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "bulk_crc32.h"

#define PACKET_SIZE (64*1024)
#define CHUNK_SIZE 512
#define CRC_ALGO CRC32C_POLYNOMIAL
//#define CRC_ALGO CRC32_ZLIB_POLYNOMIAL

__inline__ uint64_t rdtsc(void) {
  uint32_t lo, hi;
  __asm__ __volatile__ (      // serialize
  "xorl %%eax,%%eax \n        cpuid"
  ::: "%rax", "%rbx", "%rcx", "%rdx");
  /* We cannot use "=A", since this would use %rax on x86_64 and return only the lower 32bits of the TSC */
  __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
  return (uint64_t)hi << 32 | lo;
}

int get_misalignment() {
  char *s = getenv("MISALIGNMENT");
  if (s == NULL) {
    return 0;
  }

  int result = atoi(s);
  if (result < 0 || result >= 16) {
    fprintf(stderr, "misalignment %s must be between 0 and 16", s);
    exit(1);
  }
}

int main(int argc, char **argv) {
  int i;
  size_t verified = 0;
  uint8_t *buf = malloc(PACKET_SIZE + 16);
  assert(buf & 7 == 0 && "malloc results should be 8-byte aligned");

  buf += get_misalignment();

  int num_chunks = PACKET_SIZE / CHUNK_SIZE;
  uint32_t *sums = (uint32_t *)malloc(num_chunks * 4);

  memset(buf, 0x7f, PACKET_SIZE);
  bulk_calculate_crc(buf, PACKET_SIZE, sums, CRC_ALGO, CHUNK_SIZE);

  struct timespec time_before;
  clock_gettime(CLOCK_MONOTONIC, &time_before);
  uint64_t tc_before = rdtsc();  
  for (i = 0; i < 500000; i++) {
    int rc = bulk_verify_crc(buf, PACKET_SIZE, sums, CRC_ALGO, CHUNK_SIZE, NULL);
    if (rc != 0) {
      fprintf(stderr, "failed!\n");
      return 1;
    }
    verified += PACKET_SIZE;
  }
  uint64_t tc_after = rdtsc();
  struct timespec time_after;
  clock_gettime(CLOCK_MONOTONIC, &time_after);

  double elapsed_sec = (time_after.tv_sec - time_before.tv_sec) +
       (time_after.tv_nsec - time_before.tv_nsec)/1000000000.0;
  double rate = ((double)(tc_after - tc_before)/verified);
  double rate_mb = ((double)verified)/1024.0/1024.0/elapsed_sec;
  printf("processed %f MB, rate: %.2f cycles/byte  %.1f MB/sec\n",
     ((double)verified)/1024/1024, rate, rate_mb);

  return 0;
}
