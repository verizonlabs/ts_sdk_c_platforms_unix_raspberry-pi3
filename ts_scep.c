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

#include "ts_status.h"
#include "ts_platform.h"
#include "ts_cert.h"
#include "ts_scep.h"


static void   ts_initialize();
static TsStatus_t ts_enroll(TsScepConfigRef_t config, scepOpType op);


static void    ts_assertion(const char *msg, const char *file, int line);


static TsScepVtable_t ts_platform_scep = {
	.initialize = ts_initialize,
	.scep_op = ts_enroll,
    .assertion = ts_assertion
};

const TsScepVtable_t * ts_scep = &ts_platform_scep;

/**
 * Initialize the SCEP client 
 */
static void ts_initialize ()
{


}

static TsStatus_t ts_enroll(TsScepConfigRef_t config, scepOpType op)
{
int status;
status =  SCEP_CLIENT_Verizon(config, op);
}

 static void ts_assertion(const char *msg, const char *file, int line) {
	 //ts_printf("assertion failed, '%s' at %s:%d\n", msg, file, line);
	 while(1) {}
 }



