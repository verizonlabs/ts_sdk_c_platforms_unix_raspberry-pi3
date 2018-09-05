/*
 * ts_file.c
 *
 *  Created on: Jun 28, 2018
 *      Author: Admin
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

// Linux header
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>


#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mrtos.h"


//#include "ts_platform.h"
#include "ts_status.h"
#include "ts_platform.h"
#include "ts_cert.h"

typedef struct fx_errors_description
{
    uint32_t error_code;
    TsStatus_t ts_error;

}fx_error_codes;

const     fx_error_codes fx_error_codes_array[] =
{
#warning "boil this down"
    // First column is native error code, 2nd column is TS error mapped to
    {0x00, TsStatusOk},
    //{0x01, TsStatusErrorBootError},
    {EIO, TsStatusErrorMediaInvalid},
    {EBADF, TsStatusErrorFatReadError},
    {ENOENT , TsStatusErrorNotFound},
    {0x05, TsStatusErrorNotAFile},
    {EACCES, TsStatusErrorAccessError},
    {EBADF, TsStatusErrorNotOpen},
    {EDESTADDRREQ , TsStatusErrorFileCorrupt},
    {EDQUOT , TsStatusErrorNoMoreSpace},
    {EFBIG , TsStatusErrorNoMoreSpace},
    {EOVERFLOW , TsStatusErrorNoMoreSpace},
    {EDESTADDRREQ , TsStatusErrorNoMoreSpace},
    {EEXIST , TsStatusErrorAlreadyCreated},
    {EINVAL , TsStatusErrorInvalidName},
    {ESPIPE , TsStatusErrorInvalidName},
    {EFAULT , TsStatusErrorInvalidPath},
    {ENOTDIR, TsStatusErrorNotDirectory},
    {EPERM, TsStatusErrorNotDirectory},
    {ENOSPC , TsStatusErrorNoMoreEntries},
    {ENFILE, TsStatusErrorNoMoreEntries },
    {EBUSY, TsStatusErrorDirNotEmpty},
    {EPERM , TsStatusErrorDirNotEmpty},
    {EACCES, TsStatusErrorDirNotEmpty},
    {EEXIST , TsStatusErrorDirNotEmpty},
    {EISDIR , TsStatusErrorDirNotEmpty},
    {ENOTEMPTY, TsStatusErrorDirNotEmpty},
    //{0x11, TsStatusErrorMediaNotOpened},
    {ELOOP  , TsStatusErrorPtrError},
    {EMLINK , TsStatusErrorPtrError},
    {EFAULT , TsStatusErrorPtrError},
    {ENOTDIR, TsStatusErrorInvalidAttr},
    //{0x20, TsStatusErrorCallerError},
    {ERANGE, TsStatusErrorBufferError},
    {EFAULT, TsStatusErrorBufferError},
    {ENAMETOOLONG, TsStatusErrorBufferError},
    {EBADF, TsStatusErrorNotImplemented},
    {0x23, TsStatusErrorWriteProtect},
    {0x24, TsStatusErrorInvalidOption},
    {0x89, TsStatusErrorSectorInvalid},
    {ENOTDIR, TsStatusErrorIo_Error},
    {ENOMEM , TsStatusErrorNotEnoughMemory},
    //{0x92, TsStatusErrorErrorFixed},
    //{0x93, TsStatusErrorErrorNotFixed},
    {ENOSR, TsStatusErrorNotAvailable},
    //{0x95, TsStatusErrorInvalidChecksum},
    {EROFS  , TsStatusErrorReadContinue},
    {ETXTBSY, TsStatusErrorInvalidState},
    {EWOULDBLOCK, TsStatusErrorInvalidState},
    {EAGAIN , TsStatusErrorInvalidState},

	// Keep this flag last
    {0xFFFF, 0xFF},

};

static void             ts_initialize();
static TsStatus_t ts_scep_enroll(TsScepConfigRef_t ptrScepConfig){


static void             ts_assertion(const char *msg, const char *file, int line);


static TsFileVtable_t ts_platform_file = {
	.initialize = ts_initialize,
	.enroll = ts_enroll,
    .assertion = ts_assertion
};

const TsFileVtable_t * ts_file = &ts_platform_scep;

/**
 * Initialize the storage device (flash) and the file system
 */
static void ts_initialize (TsScepRef_t obj)
{


}

static TsStatus_t ts_map_error(uint32_t scepError)
{
	TsStatus_t ret = TsStatusError ;
	uint16_t index =0;

	while (fx_error_codes_array[index].error_code != 0XFFFF)
	{
		if (fx_error_codes_array[index].error_code == osError)
		{
			ret = fx_error_codes_array[index].ts_error;
			break;
		}
		else
		{
			index++;
		}
	}

	return ret;

}


static TsStatus_t ts_scep_enroll(TsScepConfigRef_t ptrScepConfig){
	
}

 static void ts_assertion(const char *msg, const char *file, int line) {
	 //ts_printf("assertion failed, '%s' at %s:%d\n", msg, file, line);
	 while(1) {}
 }



