// Copyright (C) 2017, 2018 Verizon, Inc. All rights reserved.
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if _POSIX_C_SOURCE >= 199309L
#include <time.h>   // for nanosleep
#else
#include <unistd.h> // for usleep
#endif
#if _POSIX_C_SOURCE < 200809L
#include <sys/time.h>
#endif

// TODO - post compile-time warning if not a unix system

#include "ts_platform.h"
#define MOCANA_ENTROPY_BYTES (64)
static void ts_initialize();
static void ts_printf(const char *, ...);
static void ts_vprintf(const char *, va_list);
static uint64_t ts_time();
static void ts_sleep(uint32_t);
static void ts_random(uint32_t*);
static void * ts_malloc(size_t);
static void ts_free(void *, size_t);
static void ts_assertion(const char *, const char *, int);
static void _addExternalEntropy();


static TsPlatformVtable_t ts_platform_unix = {
    .initialize = ts_initialize,
    .printf = ts_printf,
    .vprintf = ts_vprintf,
    .time = ts_time,
    .sleep = ts_sleep,
    .random = ts_random,
    .malloc = ts_malloc,
    .free = ts_free,
    .assertion = ts_assertion,
};
const TsPlatformVtable_t * ts_platform = &ts_platform_unix;

static void ts_initialize() {
    // Add some entropy to Mocana via the HW RNG
	_addExternalEntropy();
}

static void ts_printf(const char * format, ...) {
    va_list argp;
	va_start(argp, format);
    vprintf(format, argp);
	va_end(argp);
    fflush(stdout);
}

static void ts_vprintf(const char * format, va_list argp) {
    vprintf(format, argp);
    fflush(stdout);
}

// TODO - does this work the same on linux vs mac? monotonic increasing time?
static uint64_t ts_time() {
    uint64_t microseconds;
#if _POSIX_C_SOURCE >= 200809L
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    microseconds = (uint64_t)(spec.tv_sec) * TS_TIME_SEC_TO_USEC + (uint64_t)(spec.tv_nsec) / TS_TIME_USEC_TO_NSEC;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    microseconds = (uint64_t)(tv.tv_sec) * TS_TIME_SEC_TO_USEC + (uint64_t)(tv.tv_usec);
#endif
    return microseconds;
}

static void ts_sleep(uint32_t microseconds) {
#if _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = microseconds / TS_TIME_SEC_TO_USEC;
    ts.tv_nsec = (microseconds % TS_TIME_SEC_TO_USEC) * TS_TIME_USEC_TO_NSEC;
    nanosleep(&ts, NULL);
#else
    usleep(microseconds);
#endif
}

static bool seeded = false;
static int randomFile;

static void ts_random(uint32_t * number) {
	if (!seeded) {
		randomFile = open("/dev/hwrng", O_RDONLY);
		if (randomFile < 0)
		{
			ts_assertion("Can open HW Random number generator - driver installed?", __FILE__, __LINE__);
			seeded = true;
		}
		char myRandomData[4];
		ssize_t result = read(randomFile, myRandomData, sizeof myRandomData);
		if (result < 0)
		{
			ts_assertion("Can read HW Random number generator - driver installed?", __FILE__, __LINE__);
		}
		memcpy(number, &myRandomData[0],4);

	}
}

static void * ts_malloc(size_t size) {
    return malloc( size );
}

static void ts_free(void * pointer, size_t size) {
    return free( pointer );
}

static void ts_assertion(const char *msg, const char *file, int line) {
    printf("assertion failed, '%s' at %s:%d\n", msg, file, line);
    fflush(stdout);
    exit(0);
}


// Add some entropy to Mocana from the HW rng
static void _addExternalEntropy ()
{
    int		fd=-1, rval=-1, bytes_read=0, done=0;
    uint32_t	randVal=0;


    while (!done)
    {

        randVal=0;
        ts_random(&randVal);

        // Mocana says 512 bits works
        if (MOCANA_ENTROPY_BYTES >= bytes_read)
        {
            MOCANA_addEntropy32Bits(randVal);

        }
        else
        {
            break;
        }

        bytes_read += sizeof(randVal);
        done = ((MOCANA_ENTROPY_BYTES <= bytes_read));
    }


}

