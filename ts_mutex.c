// Copyright (C) 2017, 2018 Verizon, Inc. All rights reserved.
#if defined(TS_MUTEX_CUSTOM)
#include <pthread.h>
#include <memory.h>

#include "ts_platform.h"
#include "ts_mutex.h"

static TsStatus_t ts_create(TsMutexRef_t *);
static TsStatus_t ts_destroy(TsMutexRef_t);
static TsStatus_t ts_lock(TsMutexRef_t);
static TsStatus_t ts_unlock(TsMutexRef_t);

static TsMutexVtable_t ts_mutex_unix = {
	.create = ts_create,
	.destroy = ts_destroy,
	.lock = ts_lock,
	.unlock = ts_unlock,
};
const TsMutexVtable_t * ts_mutex = &(ts_mutex_unix);

static TsStatus_t ts_create(TsMutexRef_t * mutex ) {

	pthread_mutex_t * pthread_mutex;
	pthread_mutex = (pthread_mutex_t*)(ts_platform_malloc(sizeof(pthread_mutex_t)));
	memset( pthread_mutex, 0x00, sizeof(pthread_mutex_t));

	if( pthread_mutex_init( pthread_mutex, NULL ) < 0 ) {
		ts_platform_free(pthread_mutex, sizeof(pthread_mutex_t));
		*mutex = NULL;
		return TsStatusErrorInternalServerError;
	}
	*mutex = (TsMutexRef_t)pthread_mutex;
	return TsStatusOk;
}

static TsStatus_t ts_destroy(TsMutexRef_t mutex) {

	pthread_mutex_t * pthread_mutex = (pthread_mutex_t*)mutex;
	ts_platform_free( pthread_mutex, sizeof(pthread_mutex_t));

	return TsStatusOk;
}

static TsStatus_t ts_lock(TsMutexRef_t mutex) {

	pthread_mutex_t * pthread_mutex = (pthread_mutex_t*)mutex;
	pthread_mutex_lock( pthread_mutex );

	return TsStatusOk;
}

static TsStatus_t ts_unlock(TsMutexRef_t mutex) {

	pthread_mutex_t * pthread_mutex = (pthread_mutex_t*)mutex;
	pthread_mutex_unlock( pthread_mutex );

	return TsStatusOk;
}
#endif // TS_MUTEX_CUSTOM
