// Copyright (C) 2018 Verizon, Inc. All rights reserved.

#include "ts_cert.h"
#include "ts_platform.h"
#include "ts_status.h"
#include "ts_util.h"
#include "ts_file.h"
#include "ts_log.h"
#include "ts_scep.h"

#define OP_CERT_PATH "/var/lib/thingspace/certs"
#define OP_CERT_FILE "opcert.pem"

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "ts_log.h"
#include "ts_scep.h"

// Mocana includes for AES Keywrap RFC

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/mocana.h"
#include "crypto/hw_accel.h"

#include "common/mdefs.h"
#include "common/merrors.h"
#include "common/mrtos.h"
#include "common/mstdlib.h"
#include "common/debug_console.h"
#include "crypto/aesalgo.h"
#include "crypto/aes.h"
#include "crypto/aes_ecb.h"
#include "crypto/aes_keywrap.h"


extern bool cert;
extern bool g_reboot_now;
extern bool g_useOpCert;
TsStatus_t enroll(TsScepConfigRef_t *pConfig);
TsLogConfigRef_t log_g = NULL;
TsStatus_t _ts_scep_create( TsScepConfigRef_t, int);
static TsStatus_t _ts_handle_get( TsMessageRef_t fields );
static TsStatus_t _ts_handle_set( TsScepConfigRef_t scepconfig, TsMessageRef_t fields );
static TsStatus_t _ts_set_log( TsLogConfigRef_t log );


#if 1
static TsStatus_t _log_scep( TsLogLevel_t level, char *message );
#define SCEP_LOG(level, ...) {char log_string_scep[LOG_MESSAGE_MAX_LENGTH]; snprintf(log_string_scep, LOG_MESSAGE_MAX_LENGTH, __VA_ARGS__); _log_scep(level, log_string_scep);}
#endif
int A2X(char* ascii, char* hex, int len);
int X2A(char* hex,  char* ascii, int len);

/**
 * Create a scep configuration object.
 * @param scepconfig
 * [on/out] Pointer to a TsScepConfigRef_t in which the new config will be stored.
 * @return
 * The return status (TsStatus_t) of the function, see ts_status.h for more information.
 * - TsStatusOk
 * - TsStatusError[Code]
 */
TsStatus_t ts_scepconfig_create(TsScepConfigRef_t *scepconfig, TsStatus_t (*messageCallback)(TsMessageRef_t, char *)) {
	ts_status_debug("ts_scepconfig_create");
	ts_platform_assert(scepconfig != NULL);
	*scepconfig = (TsScepConfigRef_t)ts_platform_malloc(sizeof(TsScepConfig_t));
	(*scepconfig)->_enabled = false;
	(*scepconfig)->_certExpiresAfter = false;
	(*scepconfig)->_generateNewPrivateKey = false;  //added
	(*scepconfig)->_certEnrollmentType = false;
	(*scepconfig)->_numDaysBeforeAutoRenew = 0;
	(*scepconfig)->_encryptionAlgorithm = "RSA";
	(*scepconfig)->_hashFunction = "";
	(*scepconfig)->_retries = 0;
	(*scepconfig)->_retryDelayInSeconds = 1000;
	(*scepconfig)->_keySize = 15;
	(*scepconfig)->_keyUsage = 0;
	(*scepconfig)->_keyAlgorithm = 0;
	(*scepconfig)->_keyAlgorithmStrength = 0;
	(*scepconfig)->_caInstance = 1;
	(*scepconfig)->_challengeType = 0;
	(*scepconfig)->_challengeUsername = "user";
	(*scepconfig)->_challengePassword = "psswd";
	(*scepconfig)->_caCertFingerprint = "FingerPrint";
	(*scepconfig)->_certSubject = "subject";
	(*scepconfig)->_getCaCertUrl = "myurl";
	(*scepconfig)->_getPkcsRequestUrl = 15;
	(*scepconfig)->_getCertInitialUrl = 0;
	(*scepconfig)->_messageCallback = messageCallback;

	// Allocate some space for messages
	_ts_scep_create(*scepconfig, 15);

#ifdef TEST_CONFIG
	(*scepconfig)->_enabled = true;
#endif

	return TsStatusOk;
}

TsStatus_t _ts_scep_create(TsScepConfigRef_t scep, int new_max_entries) {
	return TsStatusOk;
}

/**
 * Handle a cert config message.
 * @param message
 * [in] The configuration message to be handled.
 * @return
 * The return status (TsStatus_t) of the function, see ts_status.h for more information.
 * - TsStatusOk
 * - TsStatusError[Code]
 */
TsStatus_t ts_scepconfig_handle(TsScepConfigRef_t scepconfig, TsMessageRef_t message) {

	ts_status_debug("ts_scepconfig_handle");
	ts_platform_assert(message != NULL);

	TsStatus_t status;
	char * kind;
	status = ts_message_get_string(message, "kind", &kind);
	if ((status == TsStatusOk) && (strcmp(kind, "ts.event.credential") == 0)) {

		char * action;
		status = ts_message_get_string(message, "action", &action);
		if (status == TsStatusOk) {

			TsMessageRef_t fields;
			status = ts_message_get_message(message, "fields", &fields);
			if (status == TsStatusOk) {

				if (strcmp(action, "set") == 0) {

					// set or update a scep configuration
					ts_status_debug(
							"ts_cert_handle: delegate to set handler\n");
					status = _ts_handle_set(scepconfig, fields);
					ts_status_debug(
							"ts_cert_handle: save the scepconfig structure\n");
					status = ts_scepconfig_save(scepconfig, "/var/lib/thingspace/","scepconfig");
					//enroll(scepconfig);
					return status;

				} else if (strcmp(action, "get") == 0) {

					// get the cert information
					ts_status_debug(
							"ts_cert_handle: delegate to get handler\n");
					status = _ts_handle_get(fields);

				} else {

					ts_status_info(
							"ts_cert_handle: message missing valid action.\n");
					status = TsStatusErrorBadRequest;
				}
			} else {

				ts_status_info("ts_cert_handle: message missing fields.\n");
				status = TsStatusErrorBadRequest;
			}
		} else {

			ts_status_info("ts_cert_handle: message missing action.\n");
			status = TsStatusErrorBadRequest;
		}
	} else {

		ts_status_info("ts_cert_handle: message missing correct kind.\n");
		status = TsStatusErrorBadRequest;
	}
	return status;
}

TsStatus_t enroll(TsScepConfigRef_t *pConfig)
{

        // SCEP
        ts_scep_initialize();
//	scpe_revoke, scep_crl, scep_publishcrl} scepOpType;
        ts_scep_enroll(pConfig, scep_ca);
        ts_scep_enroll(pConfig, scep_renew);
        ts_scep_enroll(pConfig, scep_rekey);


// OPS Available (2nd param) scep_ops {scep_enroll, scep_renew, scep_rekey, 
// scep_ca, scep_cacertchain, scep_cacaps, scpe_revoke, 
// scep_crl, scep_publishcrl} scepOpType;

//        ts_scep_assert(0);
}

// Loads a crypto object into memory from a files. Sizes the file and malloc needed memory
// Certificate storage and keys - base credentials

static TsStatus_t loadFileIntoRam(char* directory, char* file_name, uint8_t** buffer, uint32_t* loaded_size)
{
  	TsStatus_t iret = TsStatusOk;
	ts_file_handle handle;
	uint32_t actual_size, size;
	uint8_t* addr;

	// Set the default directory, then open and size the file. Malloc some ram and read it all it.


	iret = ts_file_directory_default_set(directory);
	if (TsStatusOk != iret)
		goto error;


	iret =  ts_file_open(&handle, file_name, TS_FILE_OPEN_FOR_READ);
	if (TsStatusOk != iret)
		goto error;

	iret = ts_file_size(&handle, &size);
	if (TsStatusOk != iret)
		goto error;

	addr = ts_platform_malloc( size);
	if (addr==0)
		goto error;

    *buffer = addr;
	iret = ts_file_read(&handle,addr, size, &actual_size);
	// Make sure we got the whole thing
	if (TsStatusOk != iret || size!=actual_size) {
		ts_platform_free(addr, size);
		goto error;
	}
	// The actual size of the object.  Users generall need to know how big it is
    *loaded_size = size;
	ts_file_close(&handle);


	error:
	return iret;

}

TsStatus_t ts_cert_make_update( TsMessageRef_t *new ) {

	char *opcert;
	ts_file_handle handle;
	TsStatus_t iret = TsStatusOk;
	static uint32_t size_cacert_buf;

	// Read certs and keys into memory - Fatal is can't read them
	iret = loadFileIntoRam(OP_CERT_PATH, OP_CERT_FILE, &opcert, &size_cacert_buf);
	if( iret != TsStatusOk ) {
		ts_status_debug("simple: failed to read CA Cert file %s\n", ts_status_string(iret));
		ts_platform_assert(0);
	}
	ts_status_trace("ts_cert_make_update");
	TsStatus_t status = ts_message_create(new);
	if (status != TsStatusOk) {
		return status;
	}
	char uuid[UUID_SIZE];
	ts_uuid(uuid);
	ts_message_set_string(*new, "transactionid", uuid);
	ts_message_set_string(*new, "kind", "ts.event.cert");
	ts_message_set_string(*new, "action", "update");
	TsMessageRef_t fields;
	status = ts_message_create_message(*new, "fields", &fields);
	if (status != TsStatusOk) {
		ts_message_destroy(*new);
		return status;
	}
#if 1
	ts_message_set_string(fields, "cert", opcert);
#else
	ts_message_set_string(fields, "cert", "-----BEGIN CERTIFICATE-----\n\
MIIEODCCAyCgAwIBAgIUPZurKDWZxuyTcr7U80TaA9VggzwwDQYJKoZIhvcNAQEL\n\
BQAwZzELMAkGA1UEBhMCVVMxGTAXBgNVBAoMEFZlcml6b24gV2lyZWxlc3MxFDAS\n\
BgNVBAsMC0RldmVsb3BtZW50MScwJQYDVQQDDB5UUyBEZXYgQ3VzdG9tZXIgT3Bl\n\
cmF0aW9uYWwgQ0EwHhcNMTgwODEzMTcxODI3WhcNMTgxMTEzMTcxODI3WjCBkTEL\n\
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5KMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2Nv\n\
MRAwDgYDVQQKDAdWZXJpem9uMRQwEgYDVQQLDAtEZXZlbG9wbWVudDE1MDMGA1UE\n\
AwwsVmVyaXpvbl82YjM0MDJlNS03Zjg5LTRlNGMtYWZlNy03ODEzNzI0ZjBiMDUw\n\
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDX/U7rPMLZaIzMJBTlcdWn\n\
CNxsgh9a9DxYxfwRhE28mlgVuu0cwsI4vWMTKII/uzxB+5asuhGk+GziScrqWIjL\n\
T0TeeTItibheQ/6iBbm3kJupiaktRKABJSzMwoVsGKJnIEgKQNSzEiEan1DCDa5x\n\
5ZK0BdsDmcB9DZuVZy8miMVbgaQPKccj+DMs3MGycn29ZUeF2meQXPcAud7uUZaX\n\
wGL/laGLxLhKGVSsHkyIYxff9fPnjqFquPR5z6aaOOGljNUy6ZD0Punm61W3eE4w\n\
fPrg+z9Ia0YR6uv+MRrx63X8mkMcRTJHdn8OJjkdPPIlRWq35llD1PxZkTIiWBVd\n\
AgMBAAGjgbAwga0wCQYDVR0TBAIwADA7BggrBgEFBQcBAQQvMC0wKwYIKwYBBQUH\n\
MAGGH2h0dHA6Ly9pb3Qtb2NzcC1wb2MudmVyaXpvbi5jb20wDgYDVR0PAQH/BAQD\n\
AgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFFsf8e6UOVK78Mmn\n\
5kTcIi2sQydKMB0GA1UdDgQWBBQgIIVhRwCbe0EJTp6qmK7v/qP48jANBgkqhkiG\n\
9w0BAQsFAAOCAQEAE9PSUscIMY3sN+BV8xAc4hypiR8QcL8lP8GJawpCYK6oH70U\n\
/0tFL5k+9gOi18xenIw8LCnhhF1yQQnaVlyENisKMD8Jbyj8sWVGqJxvqWjO6+8q\n\
pXWrjx8yXURCRQLADZlDs7Mr3uS9GwEIs4tK55oO5nRqXtZEwpvfM4uSWGtwQ9nq\n\
UM8R9+M3AALH3XDBrj5zoTYx8rObKihZ1hLxYa5ZNvF3qCmw4WDEEqIBtem4GLuy\n\
Zud+wYVMPWq2noul+uhrZBTMa6M5gE704lYeEyMM4O9ZlPg3gKLg1g2EF3ZTOMJD\n\
TmXwK20y7b2AuemWHSz0lyZXJPn+9RubywqraA==\n\
-----END CERTIFICATE-----");
#endif
	ts_status_trace("ts_cert_make_update successful\n");
	return TsStatusOk;
}

static TsStatus_t _ts_handle_get( TsMessageRef_t fields ) {
	TsMessageRef_t contents;
	if (ts_message_has(fields, "cert", &contents) == TsStatusOk) {
		ts_status_debug("_ts_handle_get: get cert\n");
	}
	return TsStatusOk;
}

TsStatus_t ts_handle_certack( TsMessageRef_t fields ) {
	char *retcert, *ack;
	ts_status_debug("ts_handle_certack: ack is recved\n");
	//if( ts_message_get_message( fields, "cert", &object ) == TsStatusOk ) {
	if (ts_message_get_string(fields, "ack", &ack) == TsStatusOk) {
				ts_status_debug("_ts_handle_certack: cert accepted: %s\n", ack);

			}
	TsMessageRef_t contents;
	if (ts_message_get_message(fields, "fields", &contents) == TsStatusOk) {
		ts_status_debug("_ts_handle_certack: cert ack\n");
		if (ts_message_has(contents, "accepted", &fields) == TsStatusOk) {
			ts_status_debug("_ts_handle_certack: cert accepted\n");
		}
		else{
			ts_status_debug("_ts_handle_certack: cert accepted\n");
		}
		ts_status_debug("_ts_handle_certack: filed end\n");
	}
	g_useOpCert = true;
	g_reboot_now = true;
	ts_status_debug("_ts_handle_certack: completed processing\n");
	return TsStatusOk;
}

TsStatus_t ts_certrenew_handle( TsMessageRef_t fields ) {
	char *retcert, *ack;
	ts_status_debug("ts_handle_certrenew: ack is recved\n");
	if (ts_message_get_string(fields, "ack", &ack) == TsStatusOk) {
				ts_status_debug("_ts_handle_certrenew: cert renew: %s\n", ack);

			}
	TsMessageRef_t contents;
	if (ts_message_get_message(fields, "fields", &contents) == TsStatusOk) {
		ts_status_debug("_ts_handle_certrenew: cert renew\n");
		if (ts_message_has(contents, "forcerenew", &fields) == TsStatusOk) {
			ts_status_debug("_ts_handle_certrenew: cert renew requested \n");
		}
		else{
			ts_status_debug("_ts_handle_certrenew: cert renew requested\n");
		}
		ts_status_debug("_ts_handle_certrenew: cert renew field ends\n");
	}
	ts_status_debug("_ts_handle_certrenew: completed processing\n");
	cert = true;
	return TsStatusOk;
}

TsStatus_t ts_certrewoke_handle( TsMessageRef_t fields ) {
	char *retcert, *ack;
	ts_status_debug("ts_handle_certrewoke: rewoke is recved\n");
	if (ts_message_get_string(fields, "reowke", &ack) == TsStatusOk) {
				ts_status_debug("_ts_handle_certrewoke: cert rewoke: %s\n", ack);

			}
	TsMessageRef_t contents;
	if (ts_message_get_message(fields, "fields", &contents) == TsStatusOk) {
		ts_status_debug("_ts_handle_certrewoke: cert rewoke\n");
		if (ts_message_has(contents, "forcerenew", &fields) == TsStatusOk) {
			ts_status_debug("_ts_handle_certrewoke: cert rewoke requested \n");
		}
		else{
			ts_status_debug("_ts_handle_certrewoke: cert rewoke requested\n");
		}
		ts_status_debug("_ts_handle_certrewoke: cert rewoke field ends\n");
	}
	ts_status_debug("_ts_handle_certrewoke: completed processing\n");
	return TsStatusOk;
}

static TsStatus_t _ts_handle_set( TsScepConfigRef_t scepconfig, TsMessageRef_t fields ) {
	ts_status_debug("_ts_handle_set: setting scepconfig\n");
	SCEP_LOG(TsLogLevelAlert, "Scep Config is set\n");
	TsMessageRef_t object;
	if( ts_message_get_message( fields, "credential", &object ) == TsStatusOk ) {
		ts_status_debug("_ts_handle_set: getting credential\n");
		if( ts_message_get_string( object, "getCaCertUrl", &(scepconfig->_getCaCertUrl)) == TsStatusOk ) {
			if( strcmp( scepconfig->_getCaCertUrl, "url" ) == 0 ) {
				ts_status_debug("_ts_handle_set: setting url correctly = %s\n", scepconfig->_getCaCertUrl);
			}
		}
		if (ts_message_get_bool(object, "enable", &(scepconfig->_enabled))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: enabled = %d\n", scepconfig->_enabled);
		}
		if (ts_message_get_bool(object, "generateNewPrivateKey", &(scepconfig->_generateNewPrivateKey))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: generateNewPrivateKey = %d\n", scepconfig->_generateNewPrivateKey);
		}
		if (ts_message_get_string(object, "certExpiresAfter", &(scepconfig->_certExpiresAfter))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: certExpiresAfter = %s\n", scepconfig->_certExpiresAfter);
		}
		if( ts_message_get_string( object, "keyAlgorithm", &(scepconfig->_keyAlgorithm))
				== TsStatusOk ) {
			ts_status_debug("_ts_handle_set: keyAlgorithm = %s\n", scepconfig->_keyAlgorithm);
		}
		if( ts_message_get_string( object, "keyAlgorithmStrength", &(scepconfig->_keyAlgorithmStrength))
				== TsStatusOk ) {
			ts_status_debug("_ts_handle_set: keyAlgorithmStrength = %s\n", scepconfig->_keyAlgorithmStrength);
		}
		if( ts_message_get_int( object, "keySize", &(scepconfig->_keySize)) == TsStatusOk ) {
			ts_status_debug("_ts_handle_set: keySize = %d\n", scepconfig->_keySize);
		}
		if (ts_message_get_string(object, "certEnrollmentType", &(scepconfig->_certEnrollmentType))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: certEnrollmentType = %s\n", scepconfig->_certEnrollmentType);
		}
		if (ts_message_get_int(object, "numDaysBeforeAutoRenew", &(scepconfig->_numDaysBeforeAutoRenew))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: numDaysBeforeAutoRenew = %d\n", scepconfig->_numDaysBeforeAutoRenew);
		}
		if (ts_message_get_int(object, "retryDelayInSeconds", &(scepconfig->_retryDelayInSeconds))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: retryDelayInSeconds = %d\n", scepconfig->_retryDelayInSeconds);
		}
		if (ts_message_get_string(object, "encryptionAlgorithm", &(scepconfig->_encryptionAlgorithm))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: encryptionAlgorithm = %s\n", scepconfig->_encryptionAlgorithm);
		}
		if (ts_message_get_string(object, "certSubject", &(scepconfig->_certSubject))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: certSubject = %s\n", scepconfig->_certSubject);
		}
		if (ts_message_get_string(object, "password", &(scepconfig->_challengePassword))
						== TsStatusOk) {
			ts_status_debug("_ts_handle_set: challengePassword = XXX\n");
		}
		if (ts_message_get_string(object, "username", &(scepconfig->_challengeUsername))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: challengeUsername = %s\n", scepconfig->_challengeUsername);
		}
		if (ts_message_get_string(object, "keyUsage", &(scepconfig->_keyUsage))
				== TsStatusOk) {
			ts_status_debug("_ts_handle_set: keyUsage = %s\n", scepconfig->_keyUsage);
		}
		if( ts_message_get_string( object, "hashFunction", &(scepconfig->_hashFunction)) == TsStatusOk ) {
			if( strcmp( scepconfig->_hashFunction, "SHA-256" ) == 0 ) {
				ts_status_debug("_ts_handle_set: hashFunction = %s\n", scepconfig->_hashFunction);
			}
		}
	}
	cert = true;
	return TsStatusOk;
}

// See what interface this comes up with
 TsStatus_t getMAC(char* mac) {
	 TsStatus_t iret = TsStatusOk;

	 struct ifreq ifr;
	 struct ifconf ifc;
	 char buf[1024];
	 int success = 0;

	 int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	 if (sock == -1) {
		 return TsStatusError; // fix this
	 };

	 ifc.ifc_len = sizeof(buf);
	 ifc.ifc_buf = buf;
	 if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
		 return TsStatusError; // fix this
	 }

	 struct ifreq* it = ifc.ifc_req;
	 const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	 for (; it != end; ++it) {
		 strcpy(ifr.ifr_name, it->ifr_name);
		 if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			 if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
				 if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					 success = 1;
					 break;
				 }
			 }
		 }
		 else {
			 return TsStatusError; // fix this
		 }
	 }


	 if (success) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	 return iret;
 }


// Get cpu serial number 64 bit from Ras Pi cpu
 TsStatus_t getSerial(uint64_t* serial)
{

 	TsStatus_t iret = TsStatusOk;


   FILE *filp;
   char buf[512];
   char term;

   filp = fopen ("/proc/cpuinfo", "r");

   if (filp != NULL)
   {
      while (fgets(buf, sizeof(buf), filp) != NULL)
      {
         if (!strncasecmp("serial\t\t:", buf, 9))
         {
            sscanf(buf+9, "%Lx", serial);
         }
      }

      fclose(filp);
   }
    else
   	iret = TsStatusError;

   return iret;
}

static TsStatus_t makeKey256(uint8_t* key256)
{
	 hwAccelDescr    hwAccelCtx;
	 ubyte*          pRetData = NULL;
	 TsStatus_t  iret = TsStatusOk;
	 uint8_t mac[6];
	 uint64_t serial;

	 // Form a 256 bit key from the MAC address and the RaspPi serial number
	 iret = getMAC(&mac[0]);
	 if (iret!=TsStatusOk)
		 goto error;

	 iret = getSerial(&serial);
	 if (iret!=TsStatusOk)
		 goto error;

	 // Create the key
	 memset(key256,0,32);
	 memcpy(key256, &mac[0],6); // 48 bits
	 memcpy(key256+6, &serial, 8); // 64 bits 112 bits
	error:
	return iret;

}

/**
 * Save a scep configuration object to a file

 */
TsStatus_t ts_scepconfig_save( TsScepConfig_t* pConfig, char* path, char* filename)
{
 	TsStatus_t iret = TsStatusOk;
 	ts_file_handle handle;
 	uint32_t actual_size, size;
 	uint8_t* addr;
 	char text_line[600];

	ts_status_debug("ts_scepconfig_save: save the scepconfig structure\n");

 	// Set the default directory, then open and size the file. Malloc some ram and read it all it.

	 	iret = ts_file_directory_default_set(path);
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Remove the old file and create a new one
	 	iret = ts_file_delete(filename);
	 	iret = ts_file_create(filename);
	 	// Open the specifid config file in the given directory
	 	iret =  ts_file_open(&handle, filename, TS_FILE_OPEN_FOR_WRITE);
	 	if (TsStatusOk != iret) {
			ts_status_debug("ts_scepconfig_save: Error in opening the the file %s\n", filename);
	 		goto error;
		}

	 	// Write the signature line at the beginning
	 	ts_file_writeline(&handle,SCEP_CONFIG_REV"\n");

	 	snprintf(text_line, sizeof(text_line),  "%d\n", pConfig->_enabled);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing enabled to file\n");
	 		goto error;
		}

	 	snprintf(text_line,sizeof(text_line), "%d\n",pConfig->_generateNewPrivateKey);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing generateNewPrivateKey to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_certExpiresAfter);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing certExpiresAfter to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_certEnrollmentType);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing certEnrollment to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_numDaysBeforeAutoRenew);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing numDaysBeforeAutoRenew to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_encryptionAlgorithm);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing encryptionAlgorithm to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_hashFunction);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing hashFunction to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_retries);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing retries to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_retryDelayInSeconds);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing retryDelayInSeconds to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_keySize);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing keySize to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_keyUsage);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing keyUsage to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_keyAlgorithm);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing keyAlgorithm to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_keyAlgorithmStrength);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing keyAlgorithmStrength to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_caInstance);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing challengeType to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_challengeType);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing challengeType to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_challengeUsername);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing challengeUsername to file\n");
	 		goto error;
		}
	 	// Password (Shared secret)
#define KEYWRAP
#ifdef NO_ENCRYPTION
	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_challengePassword);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing challengePassword to file\n");
	 		goto error;
		}
#endif
#ifdef LIGHT_ENCRYPTION
        char toAscii[200];
        X2A(pConfig->_challengePassword, toAscii, strlen(pConfig->_challengePassword));
	 	snprintf(text_line, sizeof(toAscii), "%s\n", toAscii);

	 	iret = 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing challengePassword to file\n");
	 		goto error;
		}

#endif
#ifdef KEYWRAP
	 	// Encrypt the password aes256 ECB per the keywrap RFC
	 	char passwordCt[256]; // 8 longer than input is mandatory for IV
        char toAscii[500];
        uint8_t aes256key[32];
        uint32_t sizeCt = 0;

        // Create the AES 256 bit key (32 bytes)
        iret = makeKey256(&aes256key[0]);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig: Bad keygen during save encrypt\n");
	 		goto error;
		}

	 	// Wrap the key in RFC 5649 mode to handle buffers not multiple of 8
	 	 MSTATUS ret = AESKWRAP_encrypt5649( MOC_SYM(hwAccelCtx) &aes256key[0],
	 				 256/8 , &pConfig->_challengePassword[0],  strlen(pConfig->_challengePassword),
	 				 passwordCt, sizeof(passwordCt), &sizeCt);

        // Now convert the password binary to text (ie 0x0CFACE3D becomes "0CFACE2D")
        X2A(passwordCt, toAscii, sizeof(passwordCt));  // CT up to 15 longer than PT, and this will be 2* origig
	 	snprintf(text_line, sizeof(text_line), "%s\n", toAscii);
	 	iret = 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing caCertFingerprint to file\n");
	 		goto error;
		}
#endif
	 	// Fingerprint
	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_caCertFingerprint);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing caCertFingerprint to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_certSubject);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing certSubject to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%s\n",pConfig->_getCaCertUrl);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing getCaCertUrl to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_getPkcsRequestUrl);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing getPkcsRequestUrl to file\n");
	 		goto error;
		}

	 	snprintf(text_line, sizeof(text_line), "%d\n",pConfig->_getCertInitialUrl);
	 	iret = 	 	ts_file_writeline(&handle,text_line);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig_save: Error in writing getCertInitialUrl to file\n");
	 		goto error;
		}


	 	error:
		ts_status_debug("ts_scepconfig_save: Closing the file\n");
		ts_file_close(&handle);
		return iret;
}

 /**
  * Restore a scep configuration object from a file

  */
 TsStatus_t ts_scepconfig_restore(TsScepConfig_t* pConfig, char* path, char* filename)
  {
	 	TsStatus_t iret = TsStatusOk;
	 	ts_file_handle handle;
	 	uint32_t actual_size, size;
	 	uint8_t* addr;
	 	char text_line[256];
	 	// These are all used to whold string in the passed struct ptr - the are returned via ptr so need statics
		static char bfr_certExpiresAfter[30];
		static char bfr_certEnrollmentType[30];
	 	static char bfr_encryptionAlgorithm[100];
	 	static char bfr_hashFunction[16];
	 	static char bfr_keyUsage[30];
	 	static char bfr_keyAlgorithm[100];
	 	static char bfr_keyAlgorithmStrength[10];
	 	static char bfr_urlBuffer[100];
	 	static char bfr_challengeUsername[30];
		static char bfr_challengePassword[30];
		static char bfr_caCertFingerprint[100];
		static char bfr_certSubject[100];
		static char bfr_getCaCertUrl[100];


	 	// Set the default directory, then open and size the file. Malloc some ram and read it all it.

	 	iret = ts_file_directory_default_set(path);
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Open the specific config file in the given directory
	 	iret =  ts_file_open(&handle, filename, TS_FILE_OPEN_FOR_READ);
	 	if (TsStatusOk != iret)
	 		goto error;


	   // Read each line in the config, storing the data, but first verify the format written is compatible with this
	   // version of the code

	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Go the REV = check it - error if no match
	 	if (strcmp(text_line,SCEP_CONFIG_REV ) !=0)
	 	{
	 		iret = TsStatusErrorMediaInvalid;
	 		goto error;

	 	}

	 	// Auto Renew
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_enabled = (strcmp(text_line,"1")==0)?true:false;

	 	// Generate private key
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_generateNewPrivateKey = (strcmp(text_line,"1")==0)?true:false;

	 	// _certExpiresAfter
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_certExpiresAfter = bfr_certExpiresAfter;
	 	strncpy(bfr_certExpiresAfter, text_line,sizeof(bfr_certExpiresAfter));

	    // _certEnrollmentType
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_certEnrollmentType = bfr_certEnrollmentType;
	 	strncpy(bfr_certEnrollmentType, text_line,sizeof(bfr_certEnrollmentType));

        // _numDaysBeforeAutoRenew
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_numDaysBeforeAutoRenew));

	    // _encryptionAlgorithm
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_encryptionAlgorithm = bfr_encryptionAlgorithm;
	 	strncpy(bfr_encryptionAlgorithm, text_line,sizeof(bfr_encryptionAlgorithm));

	 	// _hashFunction
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_hashFunction = bfr_hashFunction;
	 	strncpy(bfr_hashFunction, text_line,sizeof(bfr_hashFunction));


	 	// _retries
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_retries));

	    // _retryDelayInSeconds
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_retryDelayInSeconds));

	    // _keySize
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_keySize));

	    // _keyUsage
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyUsage= bfr_keyUsage;
	 	strncpy(bfr_keyUsage, text_line,sizeof(bfr_keyUsage));

	 	// _keyAlgorithm
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyAlgorithm = bfr_keyAlgorithm;
	 	strncpy(bfr_keyAlgorithm, text_line,sizeof(bfr_keyAlgorithm));

	 	// _keyAlgorithmStrength
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyAlgorithmStrength = bfr_keyAlgorithmStrength;
	 	strncpy(bfr_keyAlgorithmStrength, text_line,sizeof(bfr_keyAlgorithmStrength));

	 	// _caInstance
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_caInstance));

	 	// _challengeType
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_challengeType));

	    // _challengeUsername
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_challengeUsername = bfr_challengeUsername;
	 	strncpy(bfr_challengeUsername, text_line,sizeof(bfr_challengeUsername));

#define KEYWRAP
#ifdef NO_ENCRYPTION
	 	// _challengePassword
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_challengePassword = bfr_challengePassword;
	 	strncpy(bfr_challengePassword, text_line,sizeof(bfr_challengePassword));
#endif
#ifdef LIGHT_ENCRYPTION
        char toHex[200];
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
        A2X(text_line, toHex, strlen(text_line));
        toHex[strlen(text_line)/2]='\0';
	 	pConfig->_challengePassword = bfr_challengePassword;
	 	strncpy(bfr_challengePassword, toHex, strlen(toHex));


#endif
#ifdef KEYWRAP
	 	// Encrypt the password aes256 ECB per the keywrap RFC

        char toHex[128];
	 	char passwordPt[256]; // 8 longer than input is mandatory for IV
        char toAscii[500];
        uint8_t aes256key[32];
        uint32_t ptLength;

	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;

        // Take the CT ascii password and convert it to binary CT for to prep for decryption
	 	A2X(text_line, toHex, strlen(text_line));  // new lenght in binary should be 1/2 original string
        int ctLen = strlen(text_line)/2;

        // Create the AES 256 bit key (32 bytes)
        iret = makeKey256(&aes256key[0]);
	 	if (iret!=TsStatusOk) {
			ts_status_debug("ts_scepconfig: Bad keygen during save encrypt\n");
	 		goto error;
		}

	 	// Wrap the key in RFC 5649 mode to handle buffers not multiple of 8
	 	MSTATUS ret = AESKWRAP_decrypt5649( MOC_SYM(hwAccelCtx) &aes256key[0],
	 			256/8, toHex, ctLen, &passwordPt[0], sizeof(passwordPt), &ptLength);
        passwordPt[ptLength]='\0'; // end the buffer as a string

        // Save the decrypted password
	 	pConfig->_challengePassword = bfr_challengePassword;
	 	strncpy(bfr_challengePassword, passwordPt, strlen(passwordPt));
#endif
	 	//


	 	// _caCertFingerprint
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_caCertFingerprint = bfr_caCertFingerprint;
	 	strncpy(bfr_caCertFingerprint, text_line,sizeof(bfr_caCertFingerprint));


	 	// _certSubject
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_certSubject = bfr_certSubject;
	 	strncpy(bfr_certSubject, text_line,sizeof(bfr_certSubject));


	 	// _getCaCertUrl
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_getCaCertUrl = bfr_getCaCertUrl;
	 	strncpy(bfr_getCaCertUrl, text_line,sizeof(bfr_getCaCertUrl));

	    // _getPkcsRequestUrl
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_getPkcsRequestUrl));

	    // _getCertInitialUrl
		    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
		 	if (TsStatusOk != iret)
		 		goto error;
		    sscanf( text_line, "%d", &(pConfig->_getCertInitialUrl));

	 	error:
	 	ts_file_close(&handle);

	 	return iret;

  }

#if 1
static TsStatus_t _log_scep( TsLogLevel_t level, char *message ) {
	if ( log_g == NULL ) {
		return TsStatusErrorPreconditionFailed;
	}

	return ts_log( log_g, level, TsCategoryCredential, message );
}
#endif

//static TsStatus_t _ts_set_log( TsLogConfigRef_t log ) {
TsStatus_t ts_scep_set_log( TsLogConfigRef_t log ) {
	log_g = log;
	return TsStatusOk;
}

/**
 * Check the availability of operation certificates.
 * @param NA
 * @return
 * The return true/false (bool)) of the function
 */
bool ts_check_opcert_available()
{

  	TsStatus_t iret = TsStatusOk;
	ts_file_handle handle;

	iret = ts_file_directory_default_set(OP_CERT_PATH);
	if (TsStatusOk != iret)
		return false;

	iret =  ts_file_open(&handle, "opcert.der", TS_FILE_OPEN_FOR_READ);
	if (TsStatusOk != iret)
		return false;

	ts_file_close(&handle);
	return true;
}


int A2X(char* ascii, char* hex, int len)
{
	int i;
    unsigned int conv;
	for (i=0; i<len; i+=2)
	{
		sscanf(&ascii[i],"%2X",&conv );
		hex[i/2]=conv;
	}
    return 0;
}

// in 0xDEAD1F23 out "DEAD1F3A"
int X2A(char* hex,  char* ascii, int len)
{
	int i;
        char three[3];

	for (i=0; i<len; i++)
	{
		snprintf(&three[0],3,"%02X",hex[i]);
                memcpy(&ascii[i*2],&three[0],2);
	}
        ascii[(len*2)]=0; // null on the end
    return 0;
}

// Test code generator - future FIPS140-2 use
TsStatus_t ts_scepconfig_setup(TsScepConfig_t* pConfig, char* path, char* filename)
  {
	 	TsStatus_t iret = TsStatusOk;
	 	ts_file_handle handle;
	 	uint32_t actual_size, size;
	 	uint8_t* addr;
	 	char text_line[120];
	 	// These are all used to whold string in the passed struct ptr - the are returned via ptr so need statics
		static char bfr_certExpiresAfter[30];
		static char bfr_certEnrollmentType[30];
	 	static char bfr_encryptionAlgorithm[100];
	 	static char bfr_hashFunction[16];
	 	static char bfr_keyUsage[30];
	 	static char bfr_keyAlgorithm[100];
	 	static char bfr_keyAlgorithmStrength[10];
	 	static char bfr_urlBuffer[100];
	 	static char bfr_challengeUsername[30];
		static char bfr_challengePassword[30];
		static char bfr_caCertFingerprint[100];
		static char bfr_certSubject[100];
		static char bfr_getCaCertUrl[100];


	 	// Set the default directory, then open and size the file. Malloc some ram and read it all it.

	 	iret = ts_file_directory_default_set(path);
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Open the specific config file in the given directory
	 	iret =  ts_file_open(&handle, filename, TS_FILE_OPEN_FOR_READ);
	 	if (TsStatusOk != iret)
	 		goto error;


	   // Read each line in the config, storing the data, but first verify the format written is compatible with this
	   // version of the code

	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Go the REV = check it - error if no match
	 	if (strcmp(text_line,SCEP_CONFIG_REV ) !=0)
	 	{
	 		iret = TsStatusErrorMediaInvalid;
	 		goto error;

	 	}

	 	// Auto Renew
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_enabled = (strcmp(text_line,"1")==0)?true:false;

	 	// Generate private key
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_generateNewPrivateKey = (strcmp(text_line,"1")==0)?true:false;

	 	// _certExpiresAfter
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_certExpiresAfter = bfr_certExpiresAfter;
	 	strncpy(bfr_certExpiresAfter, text_line,sizeof(bfr_certExpiresAfter));

	    // _certEnrollmentType
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_certEnrollmentType = bfr_certEnrollmentType;
	 	strncpy(bfr_certEnrollmentType, text_line,sizeof(bfr_certEnrollmentType));

        // _numDaysBeforeAutoRenew
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_numDaysBeforeAutoRenew));

	    // _encryptionAlgorithm
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_encryptionAlgorithm = bfr_encryptionAlgorithm;
	 	strncpy(bfr_encryptionAlgorithm, text_line,sizeof(bfr_encryptionAlgorithm));

	 	// _hashFunction
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_hashFunction = bfr_hashFunction;
	 	strncpy(bfr_hashFunction, text_line,sizeof(bfr_hashFunction));


	 	// _retries
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_retries));

	    // _retryDelayInSeconds
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_retryDelayInSeconds));

	    // _keySize
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_keySize));

	    // _keyUsage
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyUsage= bfr_keyUsage;
	 	strncpy(bfr_keyUsage, text_line,sizeof(bfr_keyUsage));

	 	// _keyAlgorithm
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyAlgorithm = bfr_keyAlgorithm;
	 	strncpy(bfr_keyAlgorithm, text_line,sizeof(bfr_keyAlgorithm));

	 	// _keyAlgorithmStrength
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyAlgorithmStrength = bfr_keyAlgorithmStrength;
	 	strncpy(bfr_keyAlgorithmStrength, text_line,sizeof(bfr_keyAlgorithmStrength));

	 	// _caInstance
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_caInstance));

	 	// _challengeType
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_challengeType));

	    // _challengeUsername
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_challengeUsername = bfr_challengeUsername;
	 	strncpy(bfr_challengeUsername, text_line,sizeof(bfr_challengeUsername));

#define XXX
#ifdef XXX
	 	// _challengePassword
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_challengePassword = bfr_challengePassword;
	 	strncpy(bfr_challengePassword, text_line,sizeof(bfr_challengePassword));
#endif
#ifdef LIGHT_ENCRYPTION
        char toHex[200];
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
        A2X(text_line, toHex, strlen(text_line));
        toHex[strlen(text_line)/2]='\0';
	 	pConfig->_challengePassword = bfr_challengePassword;
	 	strncpy(bfr_challengePassword, toHex, strlen(toHex));


#endif

	 	//


	 	// _caCertFingerprint
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_caCertFingerprint = bfr_caCertFingerprint;
	 	strncpy(bfr_caCertFingerprint, text_line,sizeof(bfr_caCertFingerprint));


	 	// _certSubject
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_certSubject = bfr_certSubject;
	 	strncpy(bfr_certSubject, text_line,sizeof(bfr_certSubject));


	 	// _getCaCertUrl
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_getCaCertUrl = bfr_getCaCertUrl;
	 	strncpy(bfr_getCaCertUrl, text_line,sizeof(bfr_getCaCertUrl));

	    // _getPkcsRequestUrl
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", &(pConfig->_getPkcsRequestUrl));

	    // _getCertInitialUrl
		    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
		 	if (TsStatusOk != iret)
		 		goto error;
		    sscanf( text_line, "%d", &(pConfig->_getCertInitialUrl));

	 	error:
	 	ts_file_close(&handle);

	 	return iret;

  }

