// Copyright (C) 2018 Verizon, Inc. All rights reserved.

#include "ts_cert.h"
#include "ts_platform.h"
#include "ts_util.h"
#include "ts_file.h"

TsStatus_t _ts_scep_create( TsScepConfigRef_t, int);
static TsStatus_t _ts_handle_get( TsMessageRef_t fields );
static TsStatus_t _ts_handle_set( TsScepConfigRef_t scepconfig, TsMessageRef_t fields );

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
	(*scepconfig)->_certEnrollmentType = false;
	(*scepconfig)->_numDaysBeforeAutoRenew = 0;
	(*scepconfig)->_encryptionAlgorithm = 1000;
	(*scepconfig)->_hashFunction = 15;
	(*scepconfig)->_retries = 0;
	(*scepconfig)->_retryDelayInSeconds = 1000;
	(*scepconfig)->_keySize = 15;
	(*scepconfig)->_keyUsage = 0;
	(*scepconfig)->_keyAlgorithm = 1;
	(*scepconfig)->_keyAlgorithmStrength = 0;
	(*scepconfig)->_caInstance = 1;
	(*scepconfig)->_challengeType = 0;
	(*scepconfig)->_challengeUsername = 1000;
	(*scepconfig)->_challengePassword = 15;
	(*scepconfig)->_caCertFingerprint = 0;
	(*scepconfig)->_certSubject = 1;
	(*scepconfig)->_getCaCertUrl = 1000;
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

TsStatus_t ts_cert_make_update( TsMessageRef_t *new ) {

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
	ts_status_debug("_ts_handle_set: setting scepconfig PUSHPENDRAS\n");
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
		if( ts_message_get_string( fields, "keyAlgorithm", &(scepconfig->_keyAlgorithm)) == TsStatusOk ) {
			ts_status_debug("_ts_handle_set: keyAlgorithm = %s\n", scepconfig->_keyAlgorithm);
		}
		if( ts_message_get_string( fields, "keyAlgorithmStrength", &(scepconfig)->_keyAlgorithmStrength) == TsStatusOk ) {
			ts_status_debug("_ts_handle_set: keyAlgorithmStrength = %s\n", scepconfig->_keyAlgorithmStrength);
		}
		if( ts_message_get_int( fields, "keySize", &(scepconfig->_keySize)) == TsStatusOk ) {
			ts_status_debug("_ts_handle_set: keySize = %d\n", scepconfig->_keySize);
		}
		if (ts_message_get_int(object, "certEnrollmentType", &(scepconfig->_certEnrollmentType))
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
			ts_status_debug("_ts_handle_set: challengePassword = %s\n", scepconfig->_challengePassword);
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
	return TsStatusOk;
}

/**
 * Save a scep configuration object to a file

 */
TsStatus_t ts_scepconfig_save( TsScepConfigRef_t pConfig, char* path, char* filename)
{

}

 /**
  * Restore a scep configuration object from a file

  */
#define SCEP_CONFIG_REV "083018-1"
 TsStatus_t ts_scepconfig_restore(TsScepConfigRef_t pConfig, char* path, char* filename)
  {
	 	TsStatus_t iret = TsStatusOk;
	 	ts_file_handle handle;
	 	uint32_t actual_size, size;
	 	uint8_t* addr;
	 	char text_line[120];
	 	// These are all used to whold string in the passed struct ptr - the are returned via ptr so need statics
	 	static char bfr_encryptionAlgorithm[100];
	 	static char bfr_hashFunction[16];
	 	static char bfr_keyUsage[10];
	 	static char bfr_keyAlgorithm[100];
	 	static char bfr_keyAlgorithmStrength[10];
	 	static char bfr_urlBuffer[100];
	 	static char bfr_challengeUsername[20];
		static char bfr_challengePassword[20];
		static char bfr_caCertFingerprint[100];
		static char bfr_certSubject[100];
		static char bfr_getCaCertUrl[100];


	 	// Set the default directory, then open and size the file. Malloc some ram and read it all it.

	 	iret = ts_file_directory_default_set(path);
	 	if (TsStatusOk != iret)
	 		goto error;

	 	// Open the specifid config file in the given directory
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
	    sscanf( text_line, "%d", pConfig->_certExpiresAfter);

	    // _certEnrollmentType
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_certEnrollmentType);

        // _numDaysBeforeAutoRenew
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_numDaysBeforeAutoRenew);

	    // _encryptionAlgorithm
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_encryptionAlgorithm = &bfr_encryptionAlgorithm;
	 	strncpy(bfr_encryptionAlgorithm, text_line,sizeof(bfr_encryptionAlgorithm));

	 	// _hashFunction
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_hashFunction = &bfr_hashFunction;
	 	strncpy(bfr_hashFunction, text_line,sizeof(bfr_hashFunction));


	 	// _retries
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_retries);

	    // _retryDelayInSeconds
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d",pConfig->_retryDelayInSeconds);

	    // _keySize
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_keySize);

	    // _keyUsage
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyUsage= &bfr_keyUsage;
	 	strncpy(bfr_keyUsage, text_line,sizeof(bfr_keyUsage));

	 	// _keyAlgorithm
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyAlgorithm = &bfr_keyAlgorithm;
	 	strncpy(bfr_keyAlgorithm, text_line,sizeof(bfr_keyAlgorithm));

	 	// _keyAlgorithmStrength
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_keyAlgorithmStrength = &bfr_keyAlgorithmStrength;
	 	strncpy(bfr_keyAlgorithmStrength, text_line,sizeof(bfr_keyAlgorithmStrength));

	 	// _caInstance
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_caInstance);

	 	// _challengeType
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_challengeType);

	    // _challengeUsername
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_challengeUsername = &bfr_challengeUsername;
	 	strncpy(bfr_challengeUsername, text_line,sizeof(bfr_challengeUsername));


	 	// _challengePassword
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_challengePassword = &bfr_challengePassword;
	 	strncpy(bfr_challengePassword, text_line,sizeof(bfr_challengePassword));


	 	// _caCertFingerprint
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_caCertFingerprint = &bfr_caCertFingerprint;
	 	strncpy(bfr_caCertFingerprint, text_line,sizeof(bfr_caCertFingerprint));


	 	// _certSubject
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_certSubject = &bfr_certSubject;
	 	strncpy(bfr_certSubject, text_line,sizeof(bfr_certSubject));


	 	// _getCaCertUrl
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	 	pConfig->_getCaCertUrl = &bfr_getCaCertUrl;
	 	strncpy(bfr_getCaCertUrl, text_line,sizeof(bfr_getCaCertUrl));

	    // _getCertInitialUrl
	    iret = ts_file_readline(&handle, text_line, sizeof(text_line));
	 	if (TsStatusOk != iret)
	 		goto error;
	    sscanf( text_line, "%d", pConfig->_getCertInitialUrl);


	 	error:
	 	ts_file_close(&handle);

	 	return iret;

  }

#warning "\n\nDELETE BEFORE MERGE\n\n\n"
#if 0
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


	// Delete a directory that doesn't exist - ERROR
	iret = ts_file_directory_delete(TDIR_NAME);
	printf("dir delete retruns error %d\n\r", iret);

	// Create  a directory - TEST
	iret = ts_file_directory_create(TDIR_NAME);
	printf("dir create returns error %d\n\r", iret);

#ifdef DELETE_TDIR
	// Delete the directory just created
	iret = ts_file_directory_delete(TDIR_NAME);
	printf("dir delete retruns error %d\n\r", iret);
#endif
	// Get the current default directory
	iret = ts_file_directory_default_set(TDIR_NAME);
	printf("dir default SET returns  error %d\n\r", iret);



#if 0
	// Get the current default directory
	strcpy(name,"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
	iret = ts_file_directory_default_get(&namePtr);
	printf("dir default get returns  error %d \n\r", iret);

#endif
	// Delete the test file in case its there
	iret = ts_file_delete(TFILE_NAME);
	printf("DELETE test file before write  error %d - Current default dir is now...\n\r", iret);


	// Create a test file
	iret =  ts_file_create(TFILE_NAME);
	printf("Create file  returns  error %d..\n\r", iret);



	// Open a file for writing
	iret =  ts_file_open(&handle, TFILE_NAME, TS_FILE_OPEN_FOR_WRITE);
	printf("Open file  returns  error %d..\n\r", iret);


	// Write some lines
	iret = ts_file_write(&handle,"12345678\n\r", 10);
	printf("WRITE 1 file  returns  error %d..\n\r", iret);



	iret = ts_file_write(&handle,"abcdefgh\n\r", 10);
	printf("WRITE 2 file  returns  error %d..\n\r", iret);


	iret = ts_file_close(&handle);
	printf("First CLOSE  error %d..\n\r", iret);


	iret = ts_file_close(&handle);
	printf("SECOND CLOSE  error %d..\n\r", iret);


	// Open the file for reading
	iret =  ts_file_open(&handle, TFILE_NAME, TS_FILE_OPEN_FOR_READ);
	printf("Open file  for READ error %d..\n\r", iret);

	// Size the file
	actualRead=0;
	iret = ts_file_size(&handle, &actualRead);
	printf("SIZE 1 file  returns  error %d  LENGTH size %d..\n\r", iret, actualRead);
	// Read a couple of line from it
	actualRead=0;
	iret = ts_file_read(&handle,readbuf, 100, &actualRead);
	printf("READ 1 file  returns  error %d  LENGTH read %d..\n\r", iret, actualRead);
	readbuf[actualRead+1]=0; // end of string in case binara
	printf("READ data >>%s<<\n\r", readbuf);



	// Seek pack to 0
	iret = ts_file_seek(&handle,0);
	printf("SEEK error %d..\n\r", iret);

	// Read the first line again
	iret = ts_file_read(&handle,readbuf, 10, &actualRead);

	printf("READ after seek file  returns  error %d  LENGTH read %d..\n\r", iret, actualRead);
	readbuf[actualRead+1]=0; // end of string in case binara

	printf("READ data after seek >>%s<<\n\r", readbuf);


    // Read an existing file by line
	iret = ts_file_close(&handle);

   ts_file_directory_default_set("..");  // up from subdir
	iret =  ts_file_open(&handle, "line.txt", TS_FILE_OPEN_FOR_READ);

    iret = TsStatusOk;
    char text_line[3];
    while(iret==TsStatusOk) {

      iret = ts_file_readline(&handle,text_line, sizeof(text_line));
      printf("Line read status %d len %d>>>%s<\n",iret, strlen(text_line),text_line);
    sleep(1);

    }



     // Close the file

	iret = ts_file_close(&handle);


     // Writeline test
	iret =  ts_file_create("newline.txt");
	printf("Create file  returns  error %d..\n\r", iret);
	iret =  ts_file_open(&handle, "newline.txt", TS_FILE_OPEN_FOR_WRITE);
      iret = ts_file_writeline(&handle,"Line 1\n");
      iret = ts_file_writeline(&handle,"Line 222222\n");
      iret = ts_file_writeline(&handle,"Line 3\n");
	iret = ts_file_close(&handle);







	ts_file_assert(0);
	/* Program should not reach beyond the assert(0). */





	return 0;
}

#endif
