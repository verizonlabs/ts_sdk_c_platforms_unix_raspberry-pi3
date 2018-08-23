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


#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mrtos.h"


//#include "ts_platform.h"
#include "ts_file.h"
#include "ts_status.h"
#include "bsp_api.h"
#include "r_crypto_api.h"
#include "fx_api.h"
#include "ts_platform.h"

// The FileX media - QSPI device for TS
extern FX_MEDIA g_fx_media0;

typedef struct fx_errors_description
{
    UINT error_code;
    TsStatus_t ts_error;

}fx_error_codes;

const     fx_error_codes fx_error_codes_array[] =
{
    {0x00, TsStatusOk},
    {0x01, TsStatusErrorBootError},
    {0x02, TsStatusErrorMediaInvalid},
    {0x03, TsStatusErrorFatReadError},
    {0x04, TsStatusErrorNotFound},
    {0x05, TsStatusErrorNotAFile},
    {0x06, TsStatusErrorAccessError},
    {0x07, TsStatusErrorNotOpen},
    {0x08, TsStatusErrorFileCorrupt},
    {0x09, TsStatusErrorEndOfFile },
    {0x0A, TsStatusErrorNoMoreSpace},
    {0x0B, TsStatusErrorAlreadyCreated},
    {0x0C, TsStatusErrorInvalidName},
    {0x0D, TsStatusErrorInvalidPath},
    {0x0E, TsStatusErrorNotDirectory},
    {0x0F, TsStatusErrorNoMoreEntries},
    {0x10, TsStatusErrorDirNotEmpty},
    {0x11, TsStatusErrorMediaNotOpened},
    {0x18, TsStatusErrorPtrError},
    {0x19, TsStatusErrorInvalidAttr},
    {0x20, TsStatusErrorCallerError},
    {0x21, TsStatusErrorBufferError},
    {0x22, TsStatusErrorNotImplemented},
    {0x23, TsStatusErrorWriteProtect},
    {0x24, TsStatusErrorInvalidOption},
    {0x89, TsStatusErrorSectorInvalid},
    {0x90, TsStatusErrorIo_Error},
    {0x91, TsStatusErrorNotEnoughMemory},
    {0x92, TsStatusErrorErrorFixed},
    {0x93, TsStatusErrorErrorNotFixed},
    {0x94, TsStatusErrorNotAvailable},
    {0x95, TsStatusErrorInvalidChecksum},
    {0x96, TsStatusErrorReadContinue},
    {0x97, TsStatusErrorInvalidState},
};

static void             ts_initialize();
static TsStatus_t 		ts_directory_create (char* directory_name);
static TsStatus_t 		ts_directory_default_get(char** returned_path);
static TsStatus_t 		ts_directory_default_set (char* directory_name);
static TsStatus_t		ts_directory_delete(char* directory);
static TsStatus_t		ts_close(ts_file_handle*);
static TsStatus_t		ts_delete(char* file_name);
static TsStatus_t		ts_create(char* file_name);
static TsStatus_t		ts_open(ts_file_handle *handle,  char *file, uint32_t open_type);
static TsStatus_t		ts_read(ts_file_handle *handle_ptr, void* buffer, uint32_t size, uint32_t* act_size);
static TsStatus_t		ts_seek(ts_file_handle *handle_ptr,  uint32_t offset);
static TsStatus_t		ts_write(ts_file_handle *handle_ptr, void* buffer, uint32_t size);
static void             ts_assertion(const char *msg, const char *file, int line);


static TsFileVtable_t ts_platform_file = {
	.initialize = ts_initialize,
    .directory_create = ts_directory_create,
    .directory_default_get = ts_directory_default_get,
    .directory_default_set = ts_directory_default_set,
    .directory_delete = ts_directory_delete,
    .close = ts_close,
    .delete = ts_delete,
    .open = ts_open,
    .read = ts_read,
    .seek = ts_seek,
    .write = ts_write,
	.create = ts_create,
	.assertion = ts_assertion
};

const TsFileVtable_t * ts_file = &ts_platform_file;

/**
 * Initialize the storage device (flash) and the file system
 */
static void ts_initialize (TsFileRef_t obj)
{
    // FileX is brought up in the qpi int.
	// If we want to init FileX time, etc, do it here


}

static TsStatus_t ts_map_error(uint32_t fileXerror)
{
	TsStatus_t ret = TsStatusError ;
	uint16_t index =0;

	while (fx_error_codes_array[index].error_code != 0X97)
	{
		if (fx_error_codes_array[index].error_code == fileXerror)
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
/**
 * Create a directory on the file system
 */
static TsStatus_t 		ts_directory_create (char * directory_name)
{
	TsStatus_t ret = TsStatusOk;
	UINT status;

    status = fx_directory_create(&g_fx_media0, directory_name);
    if(FX_SUCCESS != status)
    {
        ret = ts_map_error(status);
    }
    fx_media_flush(&g_fx_media0);
	return ret;

}


/**
 * Get the current default directory in the file system.
 */
static TsStatus_t 		ts_directory_default_get(char ** returned_path)
{
	TsStatus_t ret = TsStatusOk;
	UINT status;

    status = fx_directory_default_get(&g_fx_media0, returned_path);
    if(FX_SUCCESS != status)
    {
        ret = ts_map_error(status);
    }
    fx_media_flush(&g_fx_media0);
	return ret;

}


/**
 * Set the current default directory ib the file system
 */
static TsStatus_t 		ts_directory_default_set (char * directory_name)
{
	TsStatus_t ret = TsStatusOk;
	UINT status;

    status = fx_directory_default_set(&g_fx_media0, directory_name);
    if(FX_SUCCESS != status)
    {
        ret = ts_map_error(status);
    }
    fx_media_flush(&g_fx_media0);
	return ret;

}

/**
 * Delete a directory in the file system
 */
static TsStatus_t		ts_directory_delete(char * directory)
{
	TsStatus_t ret = TsStatusOk;
	UINT status;

    status = fx_directory_delete(&g_fx_media0, directory);
    if(FX_SUCCESS != status)
    {
        ret = ts_map_error(status);
    }
    fx_media_flush(&g_fx_media0);
	return ret;

}

/**
 * Close a file.
 */
static TsStatus_t		ts_close(ts_file_handle* handle)
{
	TsStatus_t ret = TsStatusOk;
	UINT status;

    status = fx_file_close((FX_FILE *)handle);
    if(FX_SUCCESS != status)
    {
        ret = ts_map_error(status);
    }
    fx_media_flush(&g_fx_media0);
	return ret;

}
/**
 * Delete a file from the file system
 */
static TsStatus_t		ts_delete(char* file_name)
{
	TsStatus_t ret = TsStatusOk;
	UINT status;

    status = fx_file_delete(&g_fx_media0, file_name);
    if(FX_SUCCESS != status)
    {
        ret = ts_map_error(status);
    }
    fx_media_flush(&g_fx_media0);
	return ret;

}

/**
 * Create a file on the file system
 */
static TsStatus_t		ts_create(char* file_name)
{
	TsStatus_t ret = TsStatusOk;
	UINT status;

    status = fx_file_create(&g_fx_media0, file_name);
    if(FX_SUCCESS != status)
    {
        ret = ts_map_error(status);
    }
    fx_media_flush(&g_fx_media0);
	return ret;

}
/**
 * Open a file on the file system
 */
 static TsStatus_t		ts_open(ts_file_handle *handle,  char *file, uint32_t open_type)
 {
 	TsStatus_t ret = TsStatusOk;
 	UINT status;

 	 status = fx_file_open(&g_fx_media0, (FX_FILE *)handle, file, open_type);
     if(FX_SUCCESS != status)
     {
         ret = ts_map_error(status);
     }
     fx_media_flush(&g_fx_media0);
 	return ret;

 }


/**
 * Read a file from the file system
 */
 static TsStatus_t		ts_read(ts_file_handle *handle_ptr, void* buffer, uint32_t size, uint32_t* act_size)
 {
 	TsStatus_t ret = TsStatusOk;
 	UINT status;

     status = fx_file_read((FX_FILE*)handle_ptr, buffer, size, act_size);

     if(FX_SUCCESS != status)
     {
         ret = ts_map_error(status);
     }
     fx_media_flush(&g_fx_media0);
 	return ret;

 }
/**
 * Seek to a position in a file
 */
 static TsStatus_t		ts_seek(ts_file_handle *handle_ptr,  unsigned long offset)
 {
 	TsStatus_t ret = TsStatusOk;
 	UINT status;

 	status = fx_file_seek((FX_FILE*)handle_ptr, offset);

     if(FX_SUCCESS != status)
     {
         ret = ts_map_error(status);
     }
     fx_media_flush(&g_fx_media0);
 	return ret;

 }
/**
 * Write to a file in the file system.
 */
 static TsStatus_t		ts_write(ts_file_handle *handle_ptr, void* buffer, uint32_t size)
 {
 	TsStatus_t ret = TsStatusOk;
 	UINT status;

     status = fx_file_write((FX_FILE*)handle_ptr, buffer, size);

     if(FX_SUCCESS != status)
     {
         ret = ts_map_error(status);
     }
     fx_media_flush(&g_fx_media0);
 	return ret;

 }
/**
 * Handle any assertion, i.e., this function doesnt perform the check, it simply performs the effect, e.g.,
 * display the given message and halt, etc.
 */


 static void ts_assertion(const char *msg, const char *file, int line) {
	 //ts_printf("assertion failed, '%s' at %s:%d\n", msg, file, line);
	 while(1) {}
 }



