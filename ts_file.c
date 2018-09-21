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

struct stat st = {0};

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mrtos.h"


//#include "ts_platform.h"
#include "ts_file.h"
#include "ts_status.h"
#include "ts_platform.h"


typedef struct fx_errors_description
{
    uint32_t error_code;
    TsStatus_t ts_error;

}fx_error_codes;

const     fx_error_codes fx_error_codes_array[] =
{
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
static TsStatus_t		ts_readline(ts_file_handle *handle_ptr, void* buffer, uint32_t size);
static TsStatus_t		ts_size(ts_file_handle *handle_ptr,  uint32_t* size);
static TsStatus_t		ts_writeline(ts_file_handle *handle_ptr, char* buffer);

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
    .readline = ts_readline,
    .size = ts_size,
    .writeline = ts_writeline,
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
    // For OSes like Linux nothing needs to be done.

}

static TsStatus_t ts_map_error(uint32_t osError)
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
/**
 * Create a directory on the file system
 */
static TsStatus_t 		ts_directory_create (char * directory_name)
{
	TsStatus_t ret = TsStatusOk;
	uint32_t status;
	struct stat st = {0};

	// Do nothing if it already exists
	if (stat(directory_name, &st) == -1) {
		// +read/write/search permissions for owner and group, and with read/search permissions for others.
		status = mkdir(directory_name, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

		if(0 != status)
		{
			ret = ts_map_error(errno);
		}
	}
	return ret;

}


/**
 * Get the current default directory in the file system.
 */
static TsStatus_t 		ts_directory_default_get(char ** returned_path)
{
	TsStatus_t ret = TsStatusOk;
	uint32_t status;

	// User provides the buffer

	if (getcwd(*returned_path, strlen(*returned_path)) == NULL) {
		ret = ts_map_error(status);
	}

	return ret;

}


/**
 * Set the current default directory in the file system
 */
static TsStatus_t 		ts_directory_default_set(char * directory_name)
{
	TsStatus_t ret = TsStatusOk;
	uint32_t status;

	status = chdir(directory_name);

	if (0 != status)
	{
		ret = ts_map_error(errno);
	}

	return ret;

}

/**
 * Delete a directory in the file system
 */
static TsStatus_t		ts_directory_delete(char * directory)
{
	TsStatus_t ret = TsStatusOk;
	uint32_t status;

	status = rmdir(directory);

	if (0 != status)
	{
		ret = ts_map_error(errno);
	}

	return ret;
}

/**
 * Close a file.
 */
static TsStatus_t		ts_close(ts_file_handle* handle)
{
	TsStatus_t ret = TsStatusOk;
	uint32_t status;

    status = close(handle->data[0]);  // This should be the linux fd as an in
    if(0 != status)
    {
        ret = ts_map_error(status);
    }
	return ret;

}
/**
 * Delete a file from the file system
 */
static TsStatus_t		ts_delete(char* file_name)
{
	TsStatus_t ret = TsStatusOk;
	uint32_t status;

	status = unlink(file_name);

	if (0 != status)
	{
		ret = ts_map_error(errno);
	}

	return ret;

}

/**
 * Create a file on the file system
 */
static TsStatus_t		ts_create(char* file_name)
{
	TsStatus_t ret = TsStatusOk;
	uint32_t status;

	int fd;

	// Open the file and close it if it was OK
	fd = open(file_name, O_RDWR | O_CREAT, S_IRWXU | S_IRGRP | S_IROTH);
	if (fd != -1) {
	    // use file descriptor
	    close(fd);
	}
	else
	{
		ret = ts_map_error(errno);
	}

	return ret;


}
/**
 * Open a file on the file system
 */
static TsStatus_t		ts_open(ts_file_handle *handle,  char *file, uint32_t open_type)
{
	TsStatus_t ret = TsStatusOk;
	int fd;
	// Open the file and close it if it was OK
	if (open_type == TS_FILE_OPEN_FOR_READ)
	{
		fd = open(file, O_RDONLY , S_IRUSR | S_IRGRP | S_IROTH);
	}
	
	else if (open_type == TS_FILE_OPEN_FOR_WRITE)
	{
		fd = open(file, O_WRONLY|O_CREAT , S_IRWXU | S_IRGRP | S_IROTH);
	}
	else
	{
		ret = TsStatusErrorInvalidAttr;
		goto exit;
	}

	if (fd != -1) {
		// Save the nandle for the user
		handle->data[0] = fd;
	}
	else
	{
		ret = ts_map_error(errno);
	}
exit:
	return ret;

}


/**
 * Read a file from the file system.
 */
 static TsStatus_t		ts_read(ts_file_handle *handle_ptr, void* buffer, uint32_t size, uint32_t* act_size)
 {
 	TsStatus_t ret = TsStatusOk;
 	uint32_t status;
 	int read_bytes;

 	// Read into supplied buffer
     status = read((int)handle_ptr->data[0], buffer, size);

     if(-1 != status)
     {
    	 // Return bytes read
         *act_size = status;
     }
 	else
 	{
 		ret = ts_map_error(errno);
 	}
 	return ret;

 }
/**
 * Seek to a position in a file
 */
 static TsStatus_t		ts_seek(ts_file_handle *handle_ptr,  uint32_t offset)
 {
 	TsStatus_t ret = TsStatusOk;
 	uint32_t status;

 	status = lseek((int)handle_ptr->data[0], offset, SEEK_SET);

     if(-1 == status)
     {
         ret = ts_map_error(status);
     }

 	return ret;

 }
/**
 * Write to a file in the file system.
 */
 static TsStatus_t		ts_write(ts_file_handle *handle_ptr, void* buffer, uint32_t size)
 {
 	TsStatus_t ret = TsStatusOk;
 	uint32_t status;

     status = write((int)handle_ptr->data[0], buffer, size);

     if(-1 == status)
     {
         ret = ts_map_error(status);
     }
     fsync((int)handle_ptr->data[0]);
 	return ret;

 }


 /**
  * Read a file from the file system.
  */
 static TsStatus_t		ts_readline(ts_file_handle *handle_ptr, void* vbuffer, uint32_t size)
 {
	 TsStatus_t ret = TsStatusOk;
	 uint32_t status;
	 int read_bytes;
	 char c;
	 int pos = 0;
	 int file = (int)handle_ptr->data[0];
         char* buffer = (char*)vbuffer;

	 if (file && size>1 ) {
		 // Read each byte, looking for the newline or EOF. Newline DOES go into return string
		 // Don't go pass the end of the users buffer length, and leave space for the NULL at the end
		 do {
			 status = read(file,&c,1);
                         if(status<0)
                         {
                             // EOF or error 
                             ret = ts_map_error(status);
                             goto error;
                         }
                         else if(status==0) {
                            // EOF
                            ret = TsStatusErrorNoMoreEntries;
                            goto error;
                         }
                         // Make sure it fits
			 if ((pos < (size-1)) ) {
				 buffer[pos++]=c;
			 }

		 } while ((c != '\n') && (status==1));
                 // End of string for the returned line
		 buffer[pos]='\0';
	 }
	 else
         // Bad params
	 {
		 ret = TsStatusErrorNotOpen;
		 goto error;
	 }


	 error:
	 return ret;

 }
 /**
  * Returns the size of a file - must be opened
  */
  static TsStatus_t		ts_size(ts_file_handle *handle_ptr,  uint32_t* size)
  {
  	TsStatus_t ret = TsStatusOk;
  	uint32_t status;
        uint32_t save_pos;

  	save_pos = lseek((int)handle_ptr->data[0], 0L, SEEK_CUR);
  	status = lseek((int)handle_ptr->data[0], 0L, SEEK_END);

      if(-1 == status)
      {
          ret = ts_map_error(status);
      }
      else
      {
    	  *size=status;                          
          // Back to where we were
  	  save_pos = lseek((int)handle_ptr->data[0], save_pos, SEEK_SET);
      }


  	return ret;

  }
 /**
  * Write to a line to a file in the file system.
  */
  static TsStatus_t		ts_writeline(ts_file_handle *handle_ptr, char* buffer)
  {
  	TsStatus_t ret = TsStatusOk;
  	uint32_t status;
        char eol = '\n';
        char* sbuffer = (char*) buffer;

      status = write((int)handle_ptr->data[0], sbuffer, strlen(sbuffer));
      //status = write((int)handle_ptr->data[0], &eol, 1);
      fsync((int)handle_ptr->data[0]);

      if(-1 == status)
      {
          ret = ts_map_error(status);
      }
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



