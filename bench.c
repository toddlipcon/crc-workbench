#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "bulk_crc32.h"

#define PACKET_SIZE (4*1024*1024)
#define CHUNK_SIZE PACKET_SIZE/6
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

int main(int argc, char **argv) {
  int i;
  size_t verified = 0;
  uint8_t *buf = malloc(PACKET_SIZE);
  int num_chunks = PACKET_SIZE / CHUNK_SIZE;
  uint32_t *sums = (uint32_t *)malloc(num_chunks * 4);

  memset(buf, 0x7f, PACKET_SIZE);
  bulk_calculate_crc(buf, PACKET_SIZE, sums, CRC_ALGO, CHUNK_SIZE);

  uint64_t tc_before = rdtsc();  
  for (i = 0; i < 50000; i++) {
    int rc = bulk_verify_crc(buf, PACKET_SIZE, sums, CRC_ALGO, CHUNK_SIZE, NULL);
    if (rc != 0) {
      fprintf(stderr, "failed!\n");
      return 1;
    }
    verified += PACKET_SIZE;
  }
  uint64_t tc_after = rdtsc();
  double rate = ((double)(tc_after - tc_before)/verified);
  printf("processed %f MB, rate: %.2f cycles/byte\n",
     ((double)verified)/1024/1024, rate);

  return 0;
}
