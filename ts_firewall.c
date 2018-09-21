// Copyright (C) 2017, 2018 Verizon, Inc. All rights reserved.
#if defined(TS_FIREWALL_CUSTOM)
#include <stdio.h>
#include <string.h>
#include "wall/mfw_internal.h"
#include "wall/mfirewall.h"

#include "ts_platform.h"
#include "ts_firewall.h"
#include "ts_status.h"
#include "ts_util.h"
#include "ts_log.h"
#include "ts_file.h"

static TsStatus_t ts_create(TsFirewallRef_t *,  TsStatus_t (*alert_callback) (TsMessageRef_t, char *) );
static TsStatus_t ts_destroy(TsFirewallRef_t);
static TsStatus_t ts_tick(TsFirewallRef_t, uint32_t);
static TsStatus_t ts_handle(TsFirewallRef_t, TsMessageRef_t);
static TsStatus_t ts_set_log( TsLogConfigRef_t );
static TsMessageRef_t ts_stats();
static TsStatus_t ts_set_suspended(TsFirewallRef_t, bool);
static bool ts_suspended(TsFirewallRef_t);

static TsStatus_t _ts_handle_set(TsFirewallRef_t, TsMessageRef_t);
static TsStatus_t _ts_handle_update(TsFirewallRef_t, TsMessageRef_t);
static TsStatus_t _ts_handle_get(TsFirewallRef_t, TsMessageRef_t);
static TsStatus_t _ts_handle_delete(TsFirewallRef_t, TsMessageRef_t);

static TsStatus_t _mf_handle_get_eval( TsFirewallRef_t );
static TsStatus_t _mf_insert_custom_rule( TsMessageRef_t, unsigned int* );
static TsStatus_t _mf_set_enabled( TsFirewallRef_t );
static TsStatus_t _mf_set_default_policy( TsMessageRef_t policy );
static TsStatus_t _mf_set_default_rules( TsFirewallRef_t );
static TsStatus_t _mf_set_custom_domains( TsFirewallRef_t );
static TsStatus_t _mf_set_default_domains( TsFirewallRef_t );
static TsStatus_t _mf_delete( char * sense, int id );
static TsStatus_t _mf_save( TsMessageRef_t);
static TsStatus_t _mf_restore(TsFirewallRef_t );


static TsStatus_t _ts_refresh_array( TsMessageRef_t * );

static void _ts_make_rejection_alert( TsMessageRef_t *, TsMessageRef_t *, TsMessageRef_t *, int, char *, PMFIREWALL_DecisionInfo);
static char * _ip_to_string( ubyte4, char *, size_t );
static char * _mac_to_string( ubyte mac[6], char * string, size_t string_size );
static ubyte4 _string_to_ip( char * string );
static void _string_to_mac( char * string, ubyte mac[6] );


static TsStatus_t _log( TsLogLevel_t level, char *message );

#define FIREWALL_LOG(level, ...) {char log_string[LOG_MESSAGE_MAX_LENGTH]; snprintf(log_string, LOG_MESSAGE_MAX_LENGTH, __VA_ARGS__); _log(level, log_string);}

// TODO - these should be part of the (custom) firewall object
#define TS_FIREWALL_MAX_RULES 7
// NOTE - today we're just storing 7 inbound and 7 outbound
//        this limitation is due to ts_message array size
//        ts_message.h, TS_MESSAGE_MAX_BRANCHES
static MFIREWALL_RuleEntry _inbound[ TS_FIREWALL_MAX_RULES ];
static MFIREWALL_RuleEntry _outbound[ TS_FIREWALL_MAX_RULES ];

// TODO - this should be a member of firewall
static TsMessageRef_t _statistics;
static TsMessageRef_t _policy;
static MFIREWALL_Statistics last_reported_statistics;
static bool fw_save_state;

static TsFirewallVtable_t ts_firewall_mocana = {
	.create = ts_create,
	.destroy = ts_destroy,
	.tick = ts_tick,
	.handle = ts_handle,
	.set_log = ts_set_log,
	.stats = ts_stats,
	.set_suspended = ts_set_suspended,
	.suspended = ts_suspended,
};
const TsFirewallVtable_t * ts_firewall = &(ts_firewall_mocana);

static TsCallbackContext_t ts_callback_context = {
	.alerts_enabled = FALSE,
	.alert_in_progress = FALSE,
	.alert_to_send = NULL,
	.alert_threshold_inbound = 0,
	.alert_threshold_outbound = 0,
	.inbound_rejections = 0,
	.outbound_rejections = 0,
	.alert_callback = NULL,
	.log = NULL,
};

static void _ts_decision_callback (void *context, PMFIREWALL_DecisionInfo pDecisionInfo);

//hardcode for now
#define STATISTICS_REPORTING_INTERVAL 10000
#define xTEST_CONFIG_WALL
#define xGENERATE_TEST_EVENTS
#define xTEST_DOMAIN_FILTER

/**
 * Allocate and initialize a new firewall object.
 *
 * @param firewall
 * [on/out] The pointer to a pre-existing TsFirewallRef_t, which will be initialized with the firewall state.
 *
 * @param alert_callback
 * [in] Pointer to a function that will send an alert message.
 *
 * @return
 * The return status (TsStatus_t) of the function, see ts_status.h for more information.
 * - TsStatusOk
 * - TsStatusError[Code]
 */
static TsStatus_t ts_create( TsFirewallRef_t * firewall, TsStatus_t (*alert_callback) (TsMessageRef_t, char *) ) {

	ts_status_trace( "ts_firewall_create\n" );
	TsStatus_t status = TsStatusOk;

	// intialize firewall system
	if( MFIREWALL_initialize() != OK ) {
		ts_status_alarm("ts_firewall_create: firewall initialize failed\n" );
		return TsStatusErrorInternalServerError;
	}

	// We want to save the FW rules afer update
	fw_save_state = true;

	MFIREWALL_registerDecisionCallback(&ts_callback_context, _ts_decision_callback);
	ts_callback_context.alert_callback = alert_callback;

	// initialize firewall object
	*firewall = (TsFirewallRef_t)ts_platform_malloc( sizeof( TsFirewall_t ) );
	if( *firewall == NULL ) {
		ts_status_alarm( "ts_firewall_create: malloc failed\n" );
		return TsStatusErrorInternalServerError;
	}
	memset( *firewall, sizeof( TsFirewall_t ), 0x00 );

	_ts_refresh_array( &((*firewall)->_default_domains) );
	_ts_refresh_array( &((*firewall)->_default_rules ) );
	_ts_refresh_array( &((*firewall)->_domains ) );
	_ts_refresh_array( &((*firewall)->_rules ) );

	(*firewall)->_statistics_reporting_interval = STATISTICS_REPORTING_INTERVAL; //hardcode for now
	(*firewall)->_last_report_time = 0;

	// TODO - should be part of custom firewall object
	ts_message_create( &_policy );
	ts_message_create( &_statistics );

	ts_suspend_set_firewall( *firewall );

	(*firewall)->_enabled = FALSE;

#ifdef TEST_DOMAIN_FILTER
	ts_message_set_string_at( (*firewall)->_domains, 0, "google.com");
	ts_message_set_string_at( (*firewall)->_domains, 1, "thingspace.verizon.com");
	_mf_set_custom_domains(*firewall);

	TsMessageRef_t domainMessage;
	unsigned int index = 0;
	ts_message_create(&domainMessage);
	ts_message_set_bool(domainMessage, "domain", true);
	ts_message_set_string(domainMessage, "action", "drop");
	ts_message_set_string(domainMessage, "sense", "outbound");
	_mf_insert_custom_rule(domainMessage, &index);
	ts_message_destroy(domainMessage);
	index++;

	(*firewall)->_enabled = true;
	_mf_set_enabled(*firewall);
#endif /* TEST_DOMAIN_FILTER */

#ifdef TEST_CONFIG_WALL
	(*firewall)->_enabled = true;
	int n_rules = 0;
	unsigned int inboundIndex = 0;
	unsigned int outboundIndex = 0;

	_mf_set_enabled(*firewall);

	ts_callback_context.alerts_enabled = true;
	ts_callback_context.alert_threshold_inbound = 2;
	ts_callback_context.alert_threshold_outbound = 2;

	TsMessageRef_t rejectMessage, whitelistMessage, source;

	ts_message_create(&whitelistMessage);
	ts_message_create(&source);
	ts_message_set_string(source, "address", "63.98.10.34");
	ts_message_set_string(source, "netmask", "255.255.255.255");
	ts_message_set_string(source, "port", "8883");
	ts_message_set_message(whitelistMessage, "destination", source);
	ts_message_set_string(whitelistMessage, "action", "accept");
	ts_message_set_string(whitelistMessage, "sense", "outbound");
	ts_message_set_string(whitelistMessage, "protocol", "tcp");
	_mf_insert_custom_rule(whitelistMessage, &outboundIndex);
	ts_status_debug("outbound_index:%d\n", (int)outboundIndex);
	outboundIndex++;

	ts_message_create(&whitelistMessage);
	ts_message_create(&source);
	ts_message_set_string(source, "address", "63.98.10.34");
	ts_message_set_string(source, "netmask", "255.255.255.255");
	ts_message_set_string(source, "port", "8883");
	ts_message_set_message(whitelistMessage, "source", source);
	ts_message_set_string(whitelistMessage, "action", "accept");
	ts_message_set_string(whitelistMessage, "sense", "inbound");
	ts_message_set_string(whitelistMessage, "protocol", "tcp");
	_mf_insert_custom_rule(whitelistMessage, &inboundIndex);
	ts_status_debug("outbound_index:%d\n", (int)inboundIndex);
	inboundIndex++;


	ts_message_create(&whitelistMessage);
	ts_message_create(&source);
	ts_message_set_string(source, "address", "192.168.1.206");
	ts_message_set_string(source, "netmask", "255.255.255.255");
	ts_message_set_message(whitelistMessage, "source", source);
	ts_message_set_string(whitelistMessage, "action", "accept");
	ts_message_set_string(whitelistMessage, "sense", "inbound");
	ts_message_set_string(whitelistMessage, "protocol", "icmp");
	_mf_insert_custom_rule(whitelistMessage, &inboundIndex);
	inboundIndex++;

	ts_message_create(&whitelistMessage);
	ts_message_create(&source);
	ts_message_set_string(source, "address", "192.168.1.206");
	ts_message_set_string(source, "netmask", "255.255.255.255");
	ts_message_set_message(whitelistMessage, "destination", source);
	ts_message_set_string(whitelistMessage, "action", "accept");
	ts_message_set_string(whitelistMessage, "sense", "outbound");
	ts_message_set_string(whitelistMessage, "protocol", "icmp");
	_mf_insert_custom_rule(whitelistMessage, &outboundIndex);
	outboundIndex++;


	ts_message_create(&rejectMessage);
	ts_message_set_string(rejectMessage, "action", "drop");
	ts_message_set_string(rejectMessage, "sense", "outbound");
	ts_message_set_string(rejectMessage, "protocol", "tcp");
	_mf_insert_custom_rule(rejectMessage, &outboundIndex);
	ts_message_destroy(rejectMessage);
	outboundIndex++;



	ts_message_create(&rejectMessage);
	ts_message_set_string(rejectMessage, "action", "drop");
	ts_message_set_string(rejectMessage, "sense", "outbound");
	ts_message_set_string(rejectMessage, "protocol", "udp");
	ts_message_destroy(rejectMessage);
	_mf_insert_custom_rule(rejectMessage, &outboundIndex);
	outboundIndex++;

	ts_message_create(&rejectMessage);
	ts_message_set_string(rejectMessage, "action", "drop");
	ts_message_set_string(rejectMessage, "sense", "outbound");
	ts_message_set_string(rejectMessage, "protocol", "icmp");
	ts_message_destroy(rejectMessage);
	_mf_insert_custom_rule(rejectMessage, &outboundIndex);
	outboundIndex++;

	ts_message_create(&rejectMessage);
	ts_message_set_string(rejectMessage, "action", "drop");
	ts_message_set_string(rejectMessage, "sense", "inbound");
	ts_message_set_string(rejectMessage, "protocol", "tcp");
	ts_message_destroy(rejectMessage);
	_mf_insert_custom_rule(rejectMessage, &inboundIndex);
	inboundIndex++;

	ts_message_create(&rejectMessage);
	ts_message_set_string(rejectMessage, "action", "drop");
	ts_message_set_string(rejectMessage, "sense", "inbound");
	ts_message_set_string(rejectMessage, "protocol", "udp");
	ts_message_destroy(rejectMessage);
	_mf_insert_custom_rule(rejectMessage, &inboundIndex);
	inboundIndex++;



	ts_message_create(&rejectMessage);
	ts_message_set_string(rejectMessage, "action", "drop");
	ts_message_set_string(rejectMessage, "sense", "inbound");
	ts_message_set_string(rejectMessage, "protocol", "icmp");
	ts_message_destroy(rejectMessage);
	_mf_insert_custom_rule(rejectMessage, &inboundIndex);
	inboundIndex++;


	n_rules++;


	ts_status_debug("done inserting firewall rules\n");

	ts_message_destroy(rejectMessage);

	ts_message_destroy(whitelistMessage);

	FIREWALL_LOG(TsLogLevelInfo, "Test config firewall rules installed; number of rules = %d\n", n_rules);
#endif // TEST_CONFIG

	// See if there are persistent firewall rules to restore - ignore status
	// It's not fatal if no rules to restore
    _mf_restore(*firewall);

	return status;
}

static void _ts_decision_callback (void *contextArg, PMFIREWALL_DecisionInfo pDecisionInfo) {
	TsCallbackContext_t *context = (TsCallbackContext_t *)contextArg;
	if (pDecisionInfo->action == MFIREWALL_ACTION_DROP) {
		FIREWALL_LOG(TsLogLevelAlert, "Packet rejected, sense = %s\n", (pDecisionInfo->ruleListIndex == MFIREWALL_RULE_LIST_INBOUND ? "inbound" : "outbound"));
		switch(pDecisionInfo->ruleListIndex) {
		case MFIREWALL_RULE_LIST_INBOUND:
			context->inbound_rejections++;
			break;
		case MFIREWALL_RULE_LIST_OUTBOUND:
			context->outbound_rejections++;
			break;
		}
		if (context->alerts_enabled && !(context->alert_in_progress)) {
			if (context->alert_threshold_inbound > 0
					&& context->inbound_rejections
							>= context->alert_threshold_inbound) {
				context->alert_in_progress = TRUE;
				// send rejection alert
				TsMessageRef_t alert, source, dest;
				_ts_make_rejection_alert(&alert, &source, &dest,
						context->inbound_rejections, "inbound", pDecisionInfo);

				context->alert_to_send = alert;

				ts_message_destroy(source);
				ts_message_destroy(dest);

				context->inbound_rejections = 0;
			}
			if (context->alert_threshold_outbound > 0
					&& context->outbound_rejections
							>= context->alert_threshold_outbound) {
				context->alert_in_progress = TRUE;
				// send rejection alert
				TsMessageRef_t alert, source, dest;
				_ts_make_rejection_alert(&alert, &source, &dest,
						context->outbound_rejections, "outbound",
						pDecisionInfo);

				context->alert_to_send = alert;

				ts_message_destroy(source);
				ts_message_destroy(dest);

				context->outbound_rejections = 0;
			}
		}
	}
}

#define PROTOCOL_HEADER(p) ((ubyte *)p) + (p->versionAndHeaderLength & 0xF) * 4

static void _ts_make_rejection_alert( TsMessageRef_t *alert, TsMessageRef_t *source, TsMessageRef_t *dest, int packets, char *sense, PMFIREWALL_DecisionInfo pDecisionInfo) {

	PM_IPV4_HEADER mfw_ip_header = pDecisionInfo->pIpHeader;
	PM_ETHERNET_HEADER mfw_eth_header = pDecisionInfo->pEthernetHeader;
	PM_TCP_HEADER mfw_tcp_header;
	PM_UDP_HEADER mfw_udp_header;
	char tmp [ 25 ];
	TsMessageRef_t fields;
	const char *protocol = NULL;

	char transactionid[UUID_SIZE];

	ts_message_create( alert ); // the alert
	ts_message_create( &fields ); // the alert

	ts_message_create( source ); // Filter object representing the source
	ts_message_create( dest ); // Filter object representing the destination

	ts_uuid(transactionid);

	ts_message_set_string( *alert, "transactionid", transactionid);
	ts_message_set_string( *alert, "kind", "ts.event.firewall.alert");
	ts_message_set_string( *alert, "action", "update");
	ts_message_set_int( fields, "time", (int)ts_platform_time());
	ts_message_set_int( fields, "packets", packets);
	ts_message_set_string( fields, "sense", sense);

	ts_message_set_string( fields, "interface", "lan"); // TODO: make this responsive; for now, it's always going to be Ethernet

	switch(mfw_ip_header->protocol) {
	case M_IP_PROTOCOL_ICMP:
		protocol = "icmp";
		break;
	case M_IP_PROTOCOL_TCP:
		protocol = "tcp";
		mfw_tcp_header = (PM_TCP_HEADER)PROTOCOL_HEADER(mfw_ip_header);
		ts_message_set_int( *source, "port", mfw_tcp_header->sourcePort);
		ts_message_set_int( *dest, "port", mfw_tcp_header->destinationPort);
		break;
	case M_IP_PROTOCOL_UDP:
		protocol = "udp";
		mfw_udp_header = (PM_UDP_HEADER)PROTOCOL_HEADER(mfw_ip_header);
		ts_message_set_int( *source, "port", mfw_udp_header->sourcePort);
		ts_message_set_int( *dest, "port", mfw_udp_header->destinationPort);
		break;
	}
	if (protocol != NULL) {
		ts_message_set_string( fields, "protocol", (char *)protocol);
	}

	ts_message_set_string( *source, "address", _ip_to_string( mfw_ip_header->sourceAddress, tmp, 25) );
	ts_message_set_string( *dest, "address", _ip_to_string( mfw_ip_header->destinationAddress, tmp, 25) );
	ts_message_set_string( *source, "mac", _mac_to_string( mfw_eth_header->sourceAddress, tmp, 25) );
	ts_message_set_string( *dest, "mac", _mac_to_string( mfw_eth_header->destinationAddress, tmp, 25) );


	ts_message_set_message( fields, "source", *source );
	ts_message_set_message( fields, "destination", *dest );

	ts_message_set_message( *alert, "fields", fields );

	ts_message_destroy(fields);
}

/**
 * Deallocate the given firewall object.
 *
 * @param firewall
 * [in] The firewall state.
 *
 * @return
 * The return status (TsStatus_t) of the function, see ts_status.h for more information.
 * - TsStatusOk
 * - TsStatusError[Code]
 */
static TsStatus_t ts_destroy( TsFirewallRef_t firewall ) {

	ts_status_trace( "ts_firewall_destroy\n" );
	ts_platform_assert( firewall != NULL );

	MFIREWALL_shutdown();

	ts_message_destroy( firewall->_default_domains );
	ts_message_destroy( firewall->_default_rules );
	ts_message_destroy( firewall->_domains );
	ts_message_destroy( firewall->_rules );
	ts_message_destroy( _policy );
	ts_message_destroy( _statistics );

	ts_platform_free( firewall, sizeof( TsFirewall_t ) );

	return TsStatusOk;
}

#ifdef GENERATE_TEST_EVENTS
static int count = 0;
#endif

/*
 * Provide the given firewall processing time according to the given budget "recommendation".
 * This function is typically called from ts_service.
 *
 * @param firewall
 * [in] The firewall state.
 *
 * @param budget
 * [in] The recommended time in microseconds budgeted for the function
 *
 * @return
 * The return status (TsStatus_t) of the function, see ts_status.h for more information.
 * - TsStatusOk
 * - TsStatusError[Code]
 */
static TsStatus_t ts_tick( TsFirewallRef_t firewall, uint32_t budget ) {

	ts_status_trace( "ts_firewall_tick\n" );

	uint64_t time = ts_platform_time();
	if (firewall && firewall->_enabled && !(firewall->_suspended)
			&& firewall->_statistics_reporting_interval > 0
			&& (time - firewall->_last_report_time
					>= firewall->_statistics_reporting_interval)) {
		TsMessageRef_t stats = ts_firewall_stats();
		ts_callback_context.alert_callback(stats, "ts.event.firewall.statistics");
		ts_message_destroy(stats);

		firewall->_last_report_time = ts_platform_time();
	}

#ifdef GENERATE_TEST_EVENTS
	// Generate a fake packet rejection, if the firewall is operating

	if (firewall && firewall->_enabled && !(firewall->_suspended)) {
		count++;
		if (count >= 5) {
			count = 0;
			MFIREWALL_DecisionInfo info;
			info.ruleListIndex = MFIREWALL_RULE_LIST_INBOUND;
			info.action = MFIREWALL_ACTION_DROP;

			M_IPV4_HEADER ipHeader;
			ipHeader.protocol = M_IP_PROTOCOL_ICMP; // for simplicity (don't need the extra header info for tcp/udp)
			ipHeader.sourceAddress = _string_to_ip("128.0.0.1");
			ipHeader.destinationAddress = _string_to_ip("129.0.0.1");
			info.pIpHeader = &ipHeader;

			M_ETHERNET_HEADER ethernetHeader;
			_string_to_mac("01:23:45:67:89:ab", ethernetHeader.sourceAddress);
			_string_to_mac("cd:ef:01:23:45:67", ethernetHeader.destinationAddress);
			info.pEthernetHeader = &ethernetHeader;

			_ts_decision_callback (&ts_callback_context, (PMFIREWALL_DecisionInfo)&info);
		}
	}

#endif /* GENERATE_TEST_EVENTS */

	if (ts_callback_context.alert_in_progress && ts_callback_context.alert_to_send != NULL) {
		ts_message_dump(ts_callback_context.alert_to_send);
		ts_callback_context.alert_callback(ts_callback_context.alert_to_send, "ts.event.firewall.alert");
		ts_message_destroy(ts_callback_context.alert_to_send);
		ts_callback_context.alert_to_send = NULL;
		ts_callback_context.alert_in_progress = FALSE;
	}

	return TsStatusOk;
}

/**
 * Process the given firewall message.
 *
 * @return
 * The return status (TsStatus_t) of the function, see ts_status.h for more information.
 * - TsStatusOk
 * - TsStatusError[Code]
 */
static TsStatus_t ts_handle(TsFirewallRef_t firewall, TsMessageRef_t message ) {

	ts_status_trace( "ts_firewall_handle\n" );
	TsStatus_t status;

	char * kind;
	status = ts_message_get_string( message, "kind", &kind );
	if( ( status == TsStatusOk ) && ( strcmp( kind, "ts.event.firewall" ) == 0 ) ) {

		char * action;
		status = ts_message_get_string( message, "action", &action );
		if( status == TsStatusOk ) {

			TsMessageRef_t fields;
			status = ts_message_get_message( message, "fields", &fields );
			if( status == TsStatusOk ) {

				if( strcmp( action, "set" ) == 0 ) {

					// set or update a rule or domain
					ts_status_debug("ts_firewall_nano: delegate to set handler\n" );
					status = _ts_handle_set( firewall, fields );
					// If it was set ok, then save the rules so they are persistent (unless being restored)
					if (status == TsStatusOk)  {
						if (fw_save_state)
						   ts_status_trace( "Saving firewall rules {n" );
						   status = _mf_save(message);
					}

				} else if( strcmp( action, "update" ) == 0 ) {

					// get a rule or list of rules
					ts_status_debug("ts_firewall_nano: delegate to update handler\n" );
					status = _ts_handle_update( firewall, fields );

				} else if( strcmp( action, "get" ) == 0 ) {

					// get a rule or list of rules
					ts_status_debug("ts_firewall_nano: delegate to get handler\n" );
					status = _ts_handle_get( firewall, fields );

				} else if( strcmp( action, "delete" ) == 0 ) {

					// delete a rule
					ts_status_debug("ts_firewall_nano: delegate to delete handler\n" );
					status = _ts_handle_delete( firewall, fields );

				} else {

					ts_status_info( "ts_firewall_handle: message missing valid action.\n" );
					status = TsStatusErrorBadRequest;
				}
			} else {

				ts_status_info( "ts_firewall_handle: message missing fields.\n" );
				status = TsStatusErrorBadRequest;
			}
		} else {

			ts_status_info( "ts_firewall_handle: message missing action.\n" );
			status = TsStatusErrorBadRequest;
		}
	} else {

		ts_status_info( "ts_firewall_handle: message missing correct kind.\n");
		status = TsStatusErrorBadRequest;
	}
	return status;
}

static TsStatus_t _ts_handle_set( TsFirewallRef_t firewall, TsMessageRef_t fields ) {

	// refresh local copy of mf rules
	_mf_handle_get_eval( firewall );

	// update configuration
	TsMessageRef_t array;
	TsMessageRef_t contents;
	TsMessageRef_t object;
	TsMessageRef_t rejectMessage;
	unsigned int inbound_index = 0;
	unsigned int outbound_index = 0;
	char* string = NULL;
	if( ts_message_get_message( fields, "firewall", &object ) == TsStatusOk ) {

		if( ts_message_get_message( object, "configuration", &contents ) == TsStatusOk ) {

			// override configuration setting if one or more exist in the message
			ts_status_debug( "ts_firewall_nano: set configuration\n" );
			if( ts_message_get_bool( contents, "enable", &(firewall->_enabled ) ) == TsStatusOk ) {

				ts_status_info( "_ts_firewall_set: enabled, %d\n", firewall->_enabled );
				FIREWALL_LOG(TsLogLevelInfo, "Firewall enabled = %s\n", firewall->_enabled ? "true" : "false");
				_mf_set_enabled( firewall );
			}
			// TODO - Default policy should be part of the firewall structure
			if( ts_message_has( contents, "default_policy", &array ) == TsStatusOk ) {

				ts_status_info( "_ts_firewall_set: default-policy\n" );
				FIREWALL_LOG(TsLogLevelInfo, "Default policy set\n");
				ts_message_destroy( _policy );
				ts_message_create_copy( array, &_policy );
				_mf_set_default_policy( _policy );
			}

			if( ts_message_has( contents, "default_domains", &array ) == TsStatusOk ) {

				ts_message_destroy( firewall->_default_domains );
				ts_message_create_copy( array, &(firewall->_default_domains) );
				FIREWALL_LOG(TsLogLevelInfo, "Default domains set\n");
				// TODO
				_mf_set_default_domains( firewall );
			}

			// alert settings
			if( ts_message_get_bool( contents, "alert_enabled", &(ts_callback_context.alerts_enabled) ) == TsStatusOk ) {
				FIREWALL_LOG(TsLogLevelInfo, "alerts enabled: %s \n", ts_callback_context.alerts_enabled ? "true" : "false");
				ts_status_info( "_ts_firewall_set: alerts_enabled, %d\n", ts_callback_context.alerts_enabled );
			}
			if( ts_message_get_int( contents, "alert_threshold_inbound", &(ts_callback_context.alert_threshold_inbound) ) == TsStatusOk ) {
				FIREWALL_LOG(TsLogLevelInfo, "Inbound alert threshold set to %d\n", ts_callback_context.alert_threshold_inbound);
				ts_status_info( "_ts_firewall_set: alert_threshold_inbound, %d\n", ts_callback_context.alert_threshold_inbound );
			}
			if( ts_message_get_int( contents, "alert_threshold_outbound", &(ts_callback_context.alert_threshold_outbound) ) == TsStatusOk ) {
				FIREWALL_LOG(TsLogLevelInfo, "Outbound alert threshold set to %d\n", ts_callback_context.alert_threshold_outbound);
				ts_status_info( "_ts_firewall_set: alert_threshold_outbound, %d\n", ts_callback_context.alert_threshold_outbound );
			}
			//  compensate for platform/provider typo
			if( ts_message_get_int( contents, "alert_threshold_outboun", &(ts_callback_context.alert_threshold_outbound) ) == TsStatusOk ) {
				FIREWALL_LOG(TsLogLevelInfo, "Outbound alert threshold set to %d\n", ts_callback_context.alert_threshold_outbound);
				ts_status_info( "_ts_firewall_set: alert_threshold_outbound, %d\n", ts_callback_context.alert_threshold_outbound );
			}
		}

		// update rules
		// note that the array can only be 15 items long (limitation of ts_message)
		if( ts_message_get_array( object, "rules", &contents ) == TsStatusOk ) {

			ts_status_debug( "ts_firewall: set rules\n" );
			size_t length;
			ts_message_get_size( contents, &length );
			ts_status_debug( "length is: %d\n", length );
			for( size_t i = 0; i < length; i++ ) {

				// set by id, or add to back w/o id ("set" or "update")
				TsMessageRef_t current = contents->value._xfields[ i ];
				unsigned int id = 0;
				int id_int = 0;

				if( ts_message_get_int( current, "id", &id_int ) == TsStatusOk ) {
					id = id_int;
					// TODO - _zz_update( current, id );

					FIREWALL_LOG(TsLogLevelInfo, "Inserting firewall rule: index = %d\n", id);

					_mf_insert_custom_rule( current, &id );
					ts_status_debug("Adding at idx: %d\n", id);

				} else {
					if( ts_message_get_string( current, "sense", &string ) == TsStatusOk ) {

						if(0 == strcmp(string, "inbound")){
							_mf_insert_custom_rule( current, &inbound_index );
							inbound_index++;
						}
						if(0 == strcmp(string, "outbound")){
							_mf_insert_custom_rule( current, &outbound_index );
							outbound_index++;
						}
					}
				}
			}
		}
		if( ts_message_has( object, "default_rules", &contents ) == TsStatusOk ) {

			ts_message_destroy( firewall->_default_rules );
			ts_message_create_copy( array, &( firewall->_default_rules ));
			ts_status_debug( "ts_firewall_nano: setting default rules\n" );
			size_t length;
			ts_message_get_size( contents, &length );
			ts_status_debug( "length is: %d\n", length );
			for( size_t i = 0; i < length; i++ ) {

				// set by id, or add to back w/o id ("set" or "update")
				TsMessageRef_t current = contents->value._xfields[ i ];
				unsigned int id = 0;
				int id_int = 0;

				if( ts_message_get_int( current, "id", &id_int ) == TsStatusOk ) {
					id = id_int;
					// TODO - _zz_update( current, id );

					FIREWALL_LOG(TsLogLevelInfo, "Inserting firewall rule: index = %d\n", id);

					_mf_insert_custom_rule( current, &id );
					ts_status_debug("Adding at idx: %d\n", id);

				} else {
					if( ts_message_get_string( current, "sense", &string ) == TsStatusOk ) {

						if(0 == strcmp(string, "inbound")){
							_mf_insert_custom_rule( current, &inbound_index );
							inbound_index++;
						}
						if(0 == strcmp(string, "outbound")){
							_mf_insert_custom_rule( current, &outbound_index );
							outbound_index++;
						}
					}
				}
			}
			FIREWALL_LOG(TsLogLevelInfo, "Default rules set\n");
			_mf_set_default_rules( firewall );
		}

		// update domains
		// note that the array can only be 15 items long (limitation of ts_message)
		if( ts_message_has( object, "domains", &array ) == TsStatusOk ) {

			FIREWALL_LOG(TsLogLevelInfo, "Updating firewall domains\n");
			ts_message_destroy( firewall->_domains );
			ts_message_create_copy( array, &(firewall->_domains) );
			// TODO
			_mf_set_custom_domains( firewall );
		}
	}

	return TsStatusOk;
}

static TsStatus_t _ts_handle_update( TsFirewallRef_t firewall, TsMessageRef_t fields ) {

	// TODO - reset firewall rules in kernel module, like set (but append becomes insert-at)
	return TsStatusErrorNotImplemented;
}

static TsStatus_t _ts_handle_get( TsFirewallRef_t firewall, TsMessageRef_t fields ) {

	// refresh firewall rules from kernel module
	_mf_handle_get_eval( firewall );

	TsMessageRef_t contents;
	if( ts_message_has( fields, "configuration", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_nano: get configuration\n" );
		ts_message_create_message( fields, "configuration", &contents );
		ts_message_set_bool( contents, "enabled", firewall->_enabled );
		// TODO - should we copy?
		ts_message_set_message( contents, "default_policy", _policy );
		ts_message_set_array( contents, "default_rules", firewall->_default_rules );
		ts_message_set_array( contents, "default_domains", firewall->_default_domains );
	}
	if( ts_message_has( fields, "rules", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_nano: get rules\n" );
		// TODO - should we copy?
		ts_message_set_array( fields, "rules", firewall->_rules );
	}
	if( ts_message_has( fields, "domains", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_nano: get domains\n" );
		// TODO - should we copy?
		ts_message_set_array( fields, "domains", firewall->_domains );
	}
	if( ts_message_has( fields, "statistics", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_nano: get statistics\n" );
		// TODO - this should be a member of firewall
		// TODO - should we copy?
		ts_message_set_message( fields, "fields", _statistics );
	}

	return TsStatusOk;
}

static TsStatus_t _ts_handle_delete( TsFirewallRef_t firewall, TsMessageRef_t fields ) {

	TsStatus_t status = TsStatusOk;
	TsMessageRef_t contents;
	if( ts_message_get_array( fields, "rules", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_nano: delete rule by id\n" );
		size_t length;
		ts_message_get_size( contents, &length );
		for( size_t i = 0; i < length; i++ ) {

			// delete by id
			TsMessageRef_t current = contents->value._xfields[ i ];
			int id = 0;
			if( ts_message_get_int( current, "id", &id ) == TsStatusOk ) {

				char * sense = "inbound";
				ts_message_get_string( current, "sense", &sense );

				ts_status_debug( "ts_firewall_nano: delete %s, %d\n", sense, id );
				FIREWALL_LOG(TsLogLevelInfo, "Deleting firewall rule %d\n", id);
				status = _mf_delete( sense, id );

			} else {

				ts_status_debug( "ts_firewall_nano: delete, id not found, ignoring,...\n" );
			}
		}
	}
	return status;
}

static TsStatus_t _ts_refresh_array( TsMessageRef_t * xarray ) {
	if( *xarray != NULL ) {
		ts_message_destroy( *xarray );
	}
	ts_message_create( xarray );
	(*xarray)->type = TsTypeArray;
	return TsStatusOk;
}

/**
 * Private Mini-firewall Section
 */

static char * _mac_to_string( ubyte mac[6], char * string, size_t string_size ) {
	snprintf( string, string_size, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
	return string;
}

static char * _ip_to_string( ubyte4 ip, char * string, size_t string_size ) {
	ubyte xip[4];
	xip[0] = (ubyte)(ip>>24);
	xip[1] = (ubyte)(ip>>16);
	xip[2] = (ubyte)(ip>>8);
	xip[3] = (ubyte)(ip);
	snprintf( string, string_size, "%u.%u.%u.%u", xip[3], xip[2], xip[1], xip[0] );
	return string;
}

static char * _port_to_string( ubyte2 port, char * string, size_t string_size ) {
	snprintf( string, string_size, "%u", port );
	return string;
}

static void _string_to_mac( char * string, ubyte mac[6] ) {
	unsigned int mac_int[6];
	sscanf( string, "%02x:%02x:%02x:%02x:%02x:%02x", mac_int, mac_int+1, mac_int+2, mac_int+3, mac_int+4, mac_int+5 );
	int i;
	for (i = 0; i < 6; i++) {
		mac[i] = (ubyte)mac_int[i];
	}
}

static ubyte4 _string_to_ip( char * string ) {
	ubyte4 ip;
	unsigned int xip[4];
	sscanf( string, "%u.%u.%u.%u", xip, xip+1, xip+2, xip+3 );
	ip = ((ubyte)xip[3])<<24;
	ip = ip | ((ubyte)xip[2])<<16;
	ip = ip | ((ubyte)xip[1])<<8;
	ip = ip | ((ubyte)xip[0]);
	return ip;
}

static ubyte2 _string_to_port( char * string ) {
	ubyte2 port;
	unsigned int portint;
	sscanf( string, "%u", &portint );
	port = (ubyte2) portint;
	return port;
}

static TsMessageRef_t _mf_to_ts_rule( char * sense, int id, MFIREWALL_RuleEntry mf_rule ) {

	TsMessageRef_t ts_rule;
	ts_message_create( &ts_rule );
	ts_message_set_int( ts_rule, "id", id );
	ts_message_set_string( ts_rule, "sense", sense );

	// convert match-flags
	char * match = "unknown";
	if( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_PROTOCOL ) {
		match = "protocol";
	} else if( ( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_SRC_IP_ADDR ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_SRC_IP_ADDR ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_SRC_PORT ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_SRC_MAC ) ) {
		match = "source";
	} else if( ( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DST_IP_ADDR ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DST_IP_ADDR ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DST_PORT ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DST_MAC ) ) {
		match = "destination";
	} else if( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DOMAIN_FILTER ) {
		match = "domain";
	}
	ts_message_set_string( ts_rule, "match", match );

	// convert action setting
	char * action = "drop";
	if( mf_rule.action == MFIREWALL_ACTION_ACCEPT ) {
		action = "accept";
	}
	ts_message_set_string( ts_rule, "action", action );

	// convert protocol setting
	// see wall/mfirewall.h for "magic" numbers, TCP(6), UDP(17) and ICMP(1)
	char * protocol;
	switch( mf_rule.protocol ) {
	case 6:
		protocol = "tcp";
		break;
	case 17:
		protocol = "udp";
		break;
	case 1:
		protocol = "icmp";
		break;
	default:
		protocol = "unknown";
		break;
	}
	ts_message_set_string( ts_rule, "protocol", protocol );

	// convert network interface name
	char * interface;
	switch( mf_rule.networkInterfaces ) {
	case MFIREWALL_RULE_IF_LAN:
		interface = "lan";
		break;
	case MFIREWALL_RULE_IF_WAN:
		interface = "wan";
		break;
	case MFIREWALL_RULE_IF_WIFI:
		interface = "wifi";
		break;
	case MFIREWALL_RULE_IF_PPP:
		interface = "ppp";
		break;
	case MFIREWALL_RULE_IF_CELL:
		interface = "cell";
		break;
	default:
		interface = "unknown";
		break;
	}
	ts_message_set_string( ts_rule, "interface", interface );

	if ( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DOMAIN_FILTER ) {
		ts_message_set_bool( ts_rule, "domain", true );
	}

	// convert source
	if( ( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_SRC_IP_ADDR ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_SRC_IP_ADDR ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_SRC_PORT ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_SRC_MAC ) ) {
		TsMessageRef_t source;
		char string[ 24 ];
		ts_message_create_message( ts_rule, "source", &source );
		ts_message_set_string( source, "mac", _mac_to_string( mf_rule.sourceMacAddress, string, 24 ) );
		ts_message_set_string( source, "address", _ip_to_string( mf_rule.ipSource.address, string, 24 ) );
		ts_message_set_string( source, "netmask", _ip_to_string( mf_rule.ipSource.netmask, string, 24 ) );
		ts_message_set_string( source, "port", _port_to_string( mf_rule.ipSource.port, string, 24 ) );
	}

	// convert destination
	if( ( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DST_IP_ADDR ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DST_IP_ADDR ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DST_PORT ) ||
			( mf_rule.matchFlags & MFIREWALL_RULE_MATCH_DST_MAC ) ) {
		TsMessageRef_t destination;
		char string[ 24 ];
		ts_message_create_message( ts_rule, "destination", &destination );
		ts_message_set_string( destination, "mac", _mac_to_string( mf_rule.sourceMacAddress, string, 24 ) );
		ts_message_set_string( destination, "address", _ip_to_string( mf_rule.ipSource.address, string, 24 ) );
		ts_message_set_string( destination, "netmask", _ip_to_string( mf_rule.ipSource.netmask, string, 24 ) );
		ts_message_set_string( destination, "port", _port_to_string( mf_rule.ipSource.port, string, 24 ) );
	}

	return ts_rule;
}

static MFIREWALL_RuleEntry _ts_to_mf_rule( TsMessageRef_t ts_rule ) {

	MFIREWALL_RuleEntry mf_rule;
	memset( &mf_rule, sizeof( MFIREWALL_RuleEntry ), 0x00 );

	ubyte matchFlags = 0x00;
	char * string;
	bool match_domains;

	// convert action
	mf_rule.action = MFIREWALL_ACTION_ACCEPT;
	if( ts_message_get_string( ts_rule, "action", &string ) == TsStatusOk ) {
		if( strcmp( string, "drop" ) == 0 ) {
			mf_rule.action = MFIREWALL_ACTION_DROP;
		}
	}

	// convert domain-matching flag
	if ( ts_message_get_bool( ts_rule, "domain", &match_domains ) == TsStatusOk ) {
		if ( match_domains ) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_DOMAIN_FILTER;
		}
	}

	// convert protocol (and implicit match-flags)
	// see wall/mfirewall.h for "magic" numbers, TCP(6), UDP(17) and ICMP(1)
	mf_rule.protocol = 6;
	if( ts_message_get_string( ts_rule, "protocol", &string ) == TsStatusOk ) {
		matchFlags = matchFlags | MFIREWALL_RULE_MATCH_PROTOCOL;
		if( strcmp( string, "udp" ) == 0 ) {
			mf_rule.protocol = 17;
		} else if( strcmp( string, "icmp" ) == 0 ) {
			mf_rule.protocol = 1;
		}
	}

	// convert network interface name
	mf_rule.networkInterfaces = 0; // there's no match flag here--Mocana uses zero value
	if( ts_message_get_string( ts_rule, "interface", &string ) == TsStatusOk ) {
		if ( strcmp( string, "wan" ) == 0 ) {
			mf_rule.networkInterfaces = MFIREWALL_RULE_IF_WAN;
		} else if ( strcmp( string, "lan" )  == 0 ) {
			mf_rule.networkInterfaces = MFIREWALL_RULE_IF_LAN;
		} else if( strcmp( string, "wifi" ) == 0 ) {
			mf_rule.networkInterfaces = MFIREWALL_RULE_IF_WIFI;
		} else if ( strcmp( string, "ppp" )  == 0 ) {
			mf_rule.networkInterfaces = MFIREWALL_RULE_IF_PPP;
		} else if( strcmp( string, "cell" ) == 0 ) {
			mf_rule.networkInterfaces = MFIREWALL_RULE_IF_CELL;
		}
	}

	// convert source (and implicit match-flags)
	TsMessageRef_t source;
	//ts_status_debug("about to call ts_message_has for source\n");
	if( ts_message_has( ts_rule, "source", &source ) == TsStatusOk ) {
		//ts_status_debug("getting stuff from source\n");
		if( ts_message_get_string( source, "mac", &string ) == TsStatusOk && (1 < strlen(string))) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_SRC_MAC;
			_string_to_mac( string, mf_rule.sourceMacAddress );
		}
		if( ts_message_get_string( source, "address", &string ) == TsStatusOk ) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_SRC_IP_ADDR;
			mf_rule.ipSource.address = _string_to_ip( string );
			//ts_status_debug("address = %s\n", string);
		}
		if( ts_message_get_string( source, "netmask", &string ) == TsStatusOk ) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_SRC_IP_ADDR;
			mf_rule.ipSource.netmask = _string_to_ip( string );
		}
		if( ts_message_get_string( source, "port", &string ) == TsStatusOk  && 1 < strlen(string)) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_SRC_PORT;
			mf_rule.ipSource.port = MOC_htons(_string_to_port( string ));
			//ts_status_debug("port = %s\n", string);
		}
		int number;
		if( ts_message_get_int( source, "port", &number) == TsStatusOk && (0 != number )  ) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_SRC_PORT;
			mf_rule.ipSource.port = MOC_htons(number);
		}
		float point;
		if( ts_message_get_float( source, "port", &point)== TsStatusOk  && (0 != point) ) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_SRC_PORT;
			mf_rule.ipSource.port = MOC_htons((int)point);
		}
	}

	// convert destination (and implicit match-flags)
	TsMessageRef_t destination;
	//ts_status_debug("about to call ts_message_has for destination\n");
	if( ts_message_has( ts_rule, "destination", &destination ) == TsStatusOk ) {
		//ts_status_debug("getting stuff from destination\n");
		if( ts_message_get_string( destination, "mac", &string ) == TsStatusOk && (1 < strlen(string))) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_DST_MAC;
			_string_to_mac( string, mf_rule.destinationMacAddress );
		}
		if( ts_message_get_string( destination, "address", &string ) == TsStatusOk ) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_DST_IP_ADDR;
			mf_rule.ipDestination.address = _string_to_ip( string );
			//ts_status_debug("address = %s\n", string);
		}
		if( ts_message_get_string( destination, "netmask", &string ) == TsStatusOk ) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_DST_IP_ADDR;
			mf_rule.ipDestination.netmask = _string_to_ip( string );
			//ts_status_debug("netmask = %s\n", string);
		}
		if( ts_message_get_string( destination, "port", &string ) == TsStatusOk && 1 < strlen(string)) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_DST_PORT;
			mf_rule.ipDestination.port = MOC_htons(_string_to_port( string ));
		}
		int number;
		if( ts_message_get_int( destination, "port", &number ) == TsStatusOk && (0 != number )) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_DST_PORT;
			mf_rule.ipDestination.port = MOC_htons(number);
		}
		float point;
		if( ts_message_get_float( destination, "port", &point ) == TsStatusOk && (0 != number )) {
			matchFlags = matchFlags | MFIREWALL_RULE_MATCH_DST_PORT;
			mf_rule.ipDestination.port = MOC_htons((int)point);
		}
	}

	// set match flags
	// this happens last, after we've determined what the user set
	mf_rule.matchFlags = matchFlags;

	return mf_rule;
}

static TsStatus_t ts_set_log( TsLogConfigRef_t log ) {
	ts_callback_context.log = log;
	return TsStatusOk;
}

static TsMessageRef_t ts_stats() {
	TsMessageRef_t stats;
	ts_message_create( &stats );
	MFIREWALL_Statistics statistics;
	MFIREWALL_getStatistics( &statistics );

	ubyte4 inbound = statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].totalPackets -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].totalPackets;
	ubyte4 inbound_tcp = statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].tcpPacketsTotal -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].tcpPacketsTotal;
	ubyte4 inbound_udp  = statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].udpPacketsTotal -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].udpPacketsTotal;
	ubyte4 inbound_icmp = statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].icmpPacketsTotal -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].icmpPacketsTotal;
	ubyte4 inbound_blocked = statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].droppedPackets -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].droppedPackets;
	ubyte4 inbound_blocked_tcp = statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].tcpPacketsDropped -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].tcpPacketsDropped;
	ubyte4 inbound_blocked_udp = statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].udpPacketsDropped -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].udpPacketsDropped;
	ubyte4 inbound_blocked_icmp = statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].icmpPacketsDropped -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_INBOUND ].icmpPacketsDropped;

	ts_status_debug("inbound = %d\n", inbound);
	ts_message_set_int( stats, "inbound", inbound );
	ts_status_debug("inbound_tcp = %d\n", inbound_tcp);
	ts_message_set_int( stats, "inbound_tcp", inbound_tcp );
	ts_status_debug("inbound_udp = %d\n", inbound_udp);
	ts_message_set_int( stats, "inbound_udp", inbound_udp );
	ts_status_debug("inbound_icmp = %d\n", inbound_icmp);
	ts_message_set_int( stats, "inbound_icmp", inbound_icmp );
	ts_status_debug("inbound_blocked = %d\n", inbound_blocked);
	ts_message_set_int( stats, "inbound_blocked", inbound_blocked );
	ts_status_debug("inbound_blocked_tcp = %d\n", inbound_blocked_tcp);
	ts_message_set_int( stats, "inbound_blocked_tcp", inbound_blocked_tcp );
	ts_status_debug("inbound_blocked_udp = %d\n", inbound_blocked_udp);
	ts_message_set_int( stats, "inbound_blocked_udp", inbound_blocked_udp );
	ts_status_debug("inbound_blocked_icmp = %d\n", inbound_blocked_icmp);
	ts_message_set_int( stats, "inbound_blocked_icmp", inbound_blocked_icmp );
	ts_message_set_int( stats, "time", (int)ts_platform_time());

	ubyte4 outbound = statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].totalPackets -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].totalPackets;
	ubyte4 outbound_tcp = statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].tcpPacketsTotal -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].tcpPacketsTotal;
	ubyte4 outbound_udp  = statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].udpPacketsTotal -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].udpPacketsTotal;
	ubyte4 outbound_icmp = statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].icmpPacketsTotal -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].icmpPacketsTotal;
	ubyte4 outbound_blocked = statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].droppedPackets -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].droppedPackets;
	ubyte4 outbound_blocked_tcp = statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].tcpPacketsDropped -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].tcpPacketsDropped;
	ubyte4 outbound_blocked_udp = statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].udpPacketsDropped -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].udpPacketsDropped;
	ubyte4 outbound_blocked_icmp = statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].icmpPacketsDropped -
			last_reported_statistics.ruleList[ MFIREWALL_RULE_LIST_OUTBOUND ].icmpPacketsDropped;


	ts_status_debug("outbound = %d\n", outbound);
	ts_message_set_int( stats, "outbound", outbound );
	ts_status_debug("outbound_tcp = %d\n", outbound_tcp);
	ts_message_set_int( stats, "outbound_tcp", outbound_tcp );
	ts_status_debug("outbound_udp = %d\n", outbound_udp);
	ts_message_set_int( stats, "outbound_udp", outbound_udp );
	ts_status_debug("outbound_icmp = %d\n", outbound_icmp);
	ts_message_set_int( stats, "outbound_icmp", outbound_icmp );
	ts_status_debug("outbound_blocked = %d\n", outbound_blocked);
	ts_message_set_int( stats, "outbound_blocked", outbound_blocked );
	ts_status_debug("outbound_blocked_tcp = %d\n", outbound_blocked_tcp);
	ts_message_set_int( stats, "outbound_blocked_tcp", outbound_blocked_tcp );
	ts_status_debug("outbound_blocked_udp = %d\n", outbound_blocked_udp);
	ts_message_set_int( stats, "outbound_blocked_udp", outbound_blocked_udp );
	ts_status_debug("outbound_blocked_icmp = %d\n", outbound_blocked_icmp);
	ts_message_set_int( stats, "outbound_blocked_icmp", outbound_blocked_icmp );


	memcpy(&last_reported_statistics, &statistics, sizeof(MFIREWALL_Statistics));	//+jv

	return stats;
}

static TsStatus_t ts_set_suspended( TsFirewallRef_t firewall, bool suspended ) {
	firewall->_suspended = suspended;
	_mf_set_enabled(firewall);
	return TsStatusOk;
}

static bool ts_suspended( TsFirewallRef_t firewall ) {
	return firewall->_suspended;
}

static TsStatus_t _log( TsLogLevel_t level, char *message ) {
	if ( ts_callback_context.log == NULL ) {
		return TsStatusErrorPreconditionFailed;
	}

	return ts_log( ts_callback_context.log, level, TsCategoryFirewall, message );
}

/**
 * Refresh the given firewall object from the rules that currently exist on the firewall
 * @param firewall
 * @return
 */
static TsStatus_t _mf_handle_get_eval( TsFirewallRef_t firewall ) {

	ts_status_trace( "_ts_handle_get_eval\n" );

	// get firewall default policy
	MFIREWALL_DefaultPolicy policy;
	MFIREWALL_getDefaultPolicy( &policy );
	char * dpi = policy.defaultAction[ MFIREWALL_RULE_LIST_INBOUND ] == MFIREWALL_ACTION_DROP ? "drop" : "accept";
	char * dpo = policy.defaultAction[ MFIREWALL_RULE_LIST_OUTBOUND ] == MFIREWALL_ACTION_DROP ? "drop" : "accept";
	ts_message_set_string( _policy, "default_policy_inbound", dpi );
	ts_message_set_string( _policy, "default_policy_outbound", dpo );

	// get firewall default rules and domains
	// TODO - ignores default rules and domains for the moment

	// get rules
	_ts_refresh_array( &(firewall->_rules) );

	MFIREWALL_RuleEntry * rules = _inbound;
	size_t rules_size = sizeof( rules );
	ubyte4 number_of_rules = TS_FIREWALL_MAX_RULES;
	MSTATUS mstatus = MFIREWALL_getRules( MFIREWALL_RULE_LIST_INBOUND, rules, &rules_size, &number_of_rules );
	if( mstatus == OK ) {

		for( int index = 0; index < number_of_rules; index++ ) {
			firewall->_rules->value._xfields[ index ] = _mf_to_ts_rule( "inbound", index, rules[ index ] );
		}

	} else {
		ts_status_alarm( "_mf_handle_get_eval: failed to get rules, %d, ignoring,...\n", mstatus );
	}

	rules = _outbound;
	rules_size = sizeof( rules );
	number_of_rules = TS_FIREWALL_MAX_RULES;
	mstatus = MFIREWALL_getRules( MFIREWALL_RULE_LIST_INBOUND, rules, &rules_size, &number_of_rules );
	if( mstatus == OK ) {

		for( int index = 0; index < number_of_rules; index++ ) {
			firewall->_rules->value._xfields[ index ] = _mf_to_ts_rule( "outbound", index, rules[ index ] );
		}

	} else {
		ts_status_alarm( "_mf_handle_get_eval: failed to get rules, %d, ignoring,...\n", mstatus );
	}

	// get domains
	_ts_refresh_array( &(firewall->_domains) );

	char * domains = NULL; // MFIREWALL_getDomainList();
	ubyte4 domains_size = 0; // MFIREWALL_getDomainListLength( domains );
	int index = 0;
	for( int i = 0; i < domains_size; i++ ) {

		if( domains[ i ] == 0x00 ) {

			ts_message_set_string_at( firewall->_domains, index, domains );
			domains = &(domains[ i + 1 ]);
			index = index + 1;
			if( ( domains[ 0 ] == 0x00 ) || ( index >= TS_MESSAGE_MAX_BRANCHES ) ) {
				break;
			}
		}
	}

	// get statistics
	_statistics = ts_stats();

	return TsStatusOk;
}

static TsStatus_t _mf_insert_custom_rule( TsMessageRef_t rule, unsigned int* id ) {

	MFIREWALL_RuleEntry mf_rule = _ts_to_mf_rule( rule );
	MFIREWALL_RuleListIndex rli = MFIREWALL_RULE_LIST_INBOUND;
	char * sense;
	if( ( ts_message_get_string( rule, "sense", &sense ) == TsStatusOk ) && ( strcmp( sense, "outbound" ) == 0 ) ) {
		rli = MFIREWALL_RULE_LIST_OUTBOUND;
	}
	MFIREWALL_insertRule( rli, id, &mf_rule );

	return TsStatusOk;
}

static TsStatus_t _mf_set_custom_domains( TsFirewallRef_t firewall ) {

	MFIREWALL_DomainList domains[ 1024 ];
	size_t domains_size = sizeof( domains );
	memset( domains, domains_size, 0x00 );

	int index = 0;
	size_t size;
	ts_message_get_size( firewall->_domains, &size );
	for( int i = 0; i < (int)size; i++ ) {

		TsMessageRef_t item;
		ts_message_get_at( firewall->_domains, i, &item );
		char * domain = item->value._xstring;

		size_t domain_size = strlen( domain );
		if( index + domain_size + 2 > domains_size ) {
			ts_status_alarm( "_mf_set_custom_domains: could not fit all of the given domains\n" );
			break;
		}

		snprintf( (char *)(domains + index), domains_size - index, "%s", domain );
		index = index + domain_size + 1;
	}

	// this function performs a memcpy
	MFIREWALL_setDomains( domains );

	return TsStatusOk;
}

static TsStatus_t _mf_set_default_rules( TsFirewallRef_t firewall ) {

	// TODO - ignore default rules for now
	return TsStatusOk;
}

static TsStatus_t _mf_set_default_domains( TsFirewallRef_t firewall ) {

	// TODO - ignored default domains for now
	return TsStatusOk;
}

static TsStatus_t _mf_set_default_policy( TsMessageRef_t policy ) {

	MFIREWALL_DefaultPolicy default_policy;
	char * dpi;
	if( ts_message_get_string( policy, "default_policy_inbound", &dpi ) == TsStatusOk ) {
		if( strcmp( dpi, "drop" ) == 0 ) {
			default_policy.defaultAction[ MFIREWALL_RULE_LIST_INBOUND ] = MFIREWALL_ACTION_DROP;
		} else {
			default_policy.defaultAction[ MFIREWALL_RULE_LIST_INBOUND ] = MFIREWALL_ACTION_ACCEPT;
		}
	}
	char * dpo;
	if( ts_message_get_string( policy, "default_policy_inbound", &dpo ) == TsStatusOk ) {
		if( strcmp( dpo, "drop" ) == 0 ) {
			default_policy.defaultAction[ MFIREWALL_RULE_LIST_OUTBOUND ] = MFIREWALL_ACTION_DROP;
		} else {
			default_policy.defaultAction[ MFIREWALL_RULE_LIST_OUTBOUND ] = MFIREWALL_ACTION_ACCEPT;
		}
	}
	MFIREWALL_setDefaultPolicy( &default_policy );
	return TsStatusOk;
}

static TsStatus_t _mf_set_enabled( TsFirewallRef_t firewall ) {

	// The underlying enabled state depends on both the enabled flag (set through firewall's handler)
	// and the suspended flag (set through the ODS suspension object's handler).
	// So we will call this whenever either of them changes.

	bool mf_enabled = (firewall->_enabled && !(firewall->_suspended));
	if( mf_enabled && !MFIREWALL_isEnabled() ) {
		MSTATUS mstatus = MFIREWALL_enable();
		if( mstatus != OK ) {
			ts_status_info( "_mf_set_enabled: failed to enable, %d\n", mstatus );
		}
	} else if( !mf_enabled && MFIREWALL_isEnabled() ) {
		MSTATUS mstatus = MFIREWALL_disable();
		if( mstatus != OK ) {
			ts_status_info( "_mf_set_enabled: failed to disable, %d\n", mstatus );
		}
	}
	return TsStatusOk;
}

static TsStatus_t _mf_delete( char * sense, int id ) {

	MFIREWALL_RuleListIndex rli = MFIREWALL_RULE_LIST_INBOUND;
	if( strcmp( sense, "outbound" ) == 0 ) {
		rli = MFIREWALL_RULE_LIST_OUTBOUND;
	}
	MFIREWALL_deleteRule( rli, id );

	return TsStatusOk;
}


#define FW_DIRECTORY "/var/lib/thingspace/firewall"
//#define FW_DIRECTORY "/"
#define FW_VERSION_FILE "fw_version_file"
#define FW_RULES_FILE "fw_rules_file"
static uint8_t cbor_Buffer[2048];
// DO NOT change the length of next string - only the contents.
#define FW_STORAGE_VERSION "FW-001"

static TsStatus_t _mf_save( TsMessageRef_t dataToSave) {
	ts_status_trace( "ts_firewall saving rules\n" );

	// Create the directory for saving firewall rules - it may already be present
  	TsStatus_t iret = TsStatusOk;
  	TsStatus_t iret1 = TsStatusOk;
	ts_file_handle handle;
	uint32_t  buffer_size;

	// Get to the directory - may need to create it
	iret = ts_file_directory_default_set(FW_DIRECTORY);
	if (TsStatusOk != iret) {
		iret = ts_file_directory_create(FW_DIRECTORY);
		if (TsStatusOk != iret) {
			ts_status_trace( "ts_firewall Can't create default director\n" );
			goto error;
		}

		ts_status_trace( "ts_firewall Default directory created\n" );
		goto error;
	}

	iret = ts_file_directory_default_set(FW_DIRECTORY);
	if (TsStatusOk != iret) {
		ts_status_trace( "ts_firewall can't change directory\n" );
		goto error;
	}

	// Write the FW SW version string for this version of the firewall
	iret = ts_file_delete(FW_VERSION_FILE);
	iret = ts_file_create(FW_VERSION_FILE);
	iret =  ts_file_open(&handle, FW_VERSION_FILE, TS_FILE_OPEN_FOR_WRITE);
	if (TsStatusOk != iret) {
		ts_status_trace( "ts_firewall can't open version file\n" );
		goto error;
	}

	iret = ts_file_write(&handle,FW_STORAGE_VERSION, sizeof(FW_STORAGE_VERSION));
	ts_file_close(&handle);

	if (TsStatusOk != iret) {
		ts_status_trace( "ts_firewall can't write version file\n" );
		goto error;
	}

	// Serialize the rules back into a CBOR message, and write out the entire buffer
	// in one chunk.
	// Pre-pend a 4 byte size to the front of the file so we know how big to read it back
	buffer_size=sizeof(cbor_Buffer);
	iret = ts_message_encode( dataToSave, TsEncoderTsCbor, cbor_Buffer, &buffer_size );
	if (TsStatusOk != iret) {
		ts_status_trace( "ts_firewall can't encode rules to cbor format\n" );
		goto error;
	}


	// Delete existing file, create new empty one, write length and cbor data
	iret = ts_file_delete(FW_RULES_FILE);
	iret =  ts_file_create(FW_RULES_FILE);
	if (TsStatusOk != iret) {
		ts_status_trace( "ts_firewall can't create a firewall rules file\n" );
		goto error;
	}

	iret =  ts_file_open(&handle, FW_RULES_FILE, TS_FILE_OPEN_FOR_WRITE);
	if (TsStatusOk != iret) {
		ts_status_trace( "ts_firewall can't open a firewall rules file\n" );
		goto error;
	}

	// Write the size then the buffer.
	iret = ts_file_write(&handle, &buffer_size, sizeof(buffer_size));
	iret1 = ts_file_write(&handle, cbor_Buffer, buffer_size);
    if (TsStatusOk != iret || TsStatusOk != iret1) {
		ts_status_trace( "ts_firewall can't write a firewall rules file\n" );
		ts_file_close(&handle);
		goto error;
    }
	ts_status_trace( "ts_firewall rules saved SUCCESS\n" );

    ts_file_close(&handle);
error:
	return TsStatusOk;
}


static TsStatus_t _mf_restore(TsFirewallRef_t firewallPtr) {
	  ts_status_trace( "ts_firewall restoring rules\n" );

	  // Create the directory for saving firewall rules - it may already be present
	  TsStatus_t iret = TsStatusOk;
	  ts_file_handle handle;
	  uint32_t actualRead, buffer_size;
	  uint8_t readbuf[sizeof(FW_STORAGE_VERSION)];

	  ts_status_trace( "ts_firewall trying to restoring rules\n" );

	  // Change to directory where the FW rules are stored
	  iret = ts_file_directory_default_set(FW_DIRECTORY);
	  if (TsStatusOk != iret) {
		  ts_status_trace( "ts_firewall can't change directory - no rules saved\n" );
		  goto error;
	  }

		// Read the version string file and see if it matches
		iret =  ts_file_open(&handle, FW_VERSION_FILE, TS_FILE_OPEN_FOR_READ);
		if (TsStatusOk != iret) {
			ts_status_trace( "ts_firewall can't open version file\n" );
			goto error;
		}

		iret = ts_file_read(&handle,readbuf, sizeof(FW_STORAGE_VERSION), &actualRead);
		ts_file_close(&handle);

		if (TsStatusOk != iret || actualRead!=sizeof(FW_STORAGE_VERSION)) {
			ts_status_trace( "ts_firewall can't read version file or bad read\n" );
			goto error;
		}


		// Check that the version matches - cant continue of rules not written by compatible code
		if (strncmp(readbuf, FW_STORAGE_VERSION, sizeof(FW_STORAGE_VERSION))!=0) {
			ts_status_trace( "ts_firewall version mismatch cant read fw persisntent rulesn" );
			goto error;
		}
		// Open the rules file
		// Convert CBOR to  a message
		iret =  ts_file_open(&handle, FW_RULES_FILE, TS_FILE_OPEN_FOR_READ);
		if (TsStatusOk != iret) {
			ts_status_trace( "ts_firewall can't open a firewall rules file\n" );
			goto error;
		}

		// Read the size then the buffer.
		iret = ts_file_read(&handle, &buffer_size, sizeof(buffer_size), &actualRead);
	    if (TsStatusOk != iret || actualRead!=sizeof(buffer_size) ) {
			ts_status_trace( "ts_firewall can't read of fw rules file buffer  length\n" );
			ts_file_close(&handle);
			goto error;
	    }
	    // Read the actual size of the cbor message into the buffer
		iret = ts_file_read(&handle, cbor_Buffer, buffer_size, &actualRead);

	    if (TsStatusOk != iret || actualRead!=buffer_size) {
			ts_status_trace( "ts_firewall can't read rules back in\n" );
		    ts_file_close(&handle);
			goto error;
	    }
	    ts_file_close(&handle);

	    // We have the cbor rules. Convert CBOR saved rilesto a message send to firewall handler

	    TsMessageRef_t message;
		ts_message_create( &message );
		iret = ts_message_decode( message, TsEncoderTsCbor, cbor_Buffer, buffer_size );
	    if (TsStatusOk != iret ) {
			ts_status_trace( "ts_firewall cant decode cbor FW rulesn" );
			ts_message_destroy(message);
			goto error;
	    }

	    //Send to FW processor
	    // Tell the message handler it doesn't need to save these rules.
		fw_save_state = false;
		iret = ts_firewall_handle( firewallPtr, message);
	    if (TsStatusOk != iret ) {
    		ts_status_trace( "ts_firewall rules restored BAD ***\n" );
	    }
	    else {
    		ts_status_trace( "ts_firewall rules restored SUCCESS ***\n" );
	    }
		fw_save_state = true;

		ts_message_destroy(message);

	    ts_file_close(&handle);

	error:
	  return iret;
  }

#ifdef WANT_TEST
int fw_test() {

	TsStatus_t status;
	ts_status_set_level( TsStatusLevelTrace );




	// create new firewall
	TsFirewallRef_t firewall;
	//ts_status_debug( "test_firewall: create firewall, %s\n", ts_status_string( ts_firewall_create( &firewall , NULL ) ) );

#if 0	// test simple configuration setting
	char * xmessage =
		"{\"transactionid\":\"00000000-0000-0000-0000-000000000001\","
		"\"kind\":\"ts.event.firewall\","
		"\"action\":\"set\","
		"\"fields\":{"
		"\"configuration\":{"
			"\"enabled\":true,"
			"\"default_domains\":[\"google.com\",\"verizon.com\",\"amazon.com\"],"
			"\"default_rules\":[{\"sense\":\"outbound\",\"action\":\"drop\",\"destination\":{\"address\":\"35.194.94.155\"}},"
				"{\"sense\":\"outbound\",\"action\":\"drop\",\"destination\":{\"address\":\"35.194.94.156\"}}]"
		"}}}";
			"}}";
#endif



    TsMessageRef_t rejectMessage, whitelistMessage, source;
	//ts_message_create(&whitelistMessage);
	ts_message_create(&source);
	ts_message_set_string(source, "kind", "ts.event.firewall");
	ts_message_set_string(source, "action", "set");
    //_mf_save( source);
    //_mf_restore();
	//ts_handle( firewall, whitelistMessage );
	return 0;
#if 0
	// test decoding to message from json
	TsMessageRef_t from_json;
	ts_status_debug( "test_firewall: create message from_json, %s\n", ts_status_string( ts_message_create( &from_json ) ) );
	ts_status_debug( "test_firewall: decode json, %s\n", ts_status_string( ts_message_decode( from_json, TsEncoderJson, (uint8_t*)xmessage, strlen(xmessage) ) ) );
	ts_status_debug( "test_firewall: encode debug, %s\n", ts_status_string( ts_message_encode( from_json, TsEncoderDebug, NULL, 0 ) ) );

	// test encoding to ts-cbor from message
	uint8_t buffer[ 2048 ];
	size_t buffer_size = sizeof( buffer );
	ts_status_debug( "test_firewall: encode ts-cbor, %s\n", ts_status_string( ts_message_encode( from_json, TsEncoderTsCbor, buffer, &buffer_size ) ) );
	for( int i = 0; i < buffer_size; i++ ) {
		ts_platform_printf( "%02x ", buffer[i] );
	}
	ts_platform_printf( "\n" );
	ts_status_debug( "test_firewall: destroy from_json, %s\n", ts_status_string( ts_message_destroy( from_json ) ) );

	// test decoding from ts-cbor to message
	TsMessageRef_t from_cbor;
	ts_status_debug( "test_firewall: create new message from_cbor, %s\n", ts_status_string( ts_message_create( &from_cbor ) ) );
	ts_status_debug( "test_firewall: decode ts-cbor, %s\n", ts_status_string( ts_message_decode( from_cbor, TsEncoderTsCbor, buffer, buffer_size ) ) );
	ts_status_debug( "test_firewall: encode debug, %s\n", ts_status_string( ts_message_encode( from_cbor, TsEncoderDebug, NULL, 0 ) ) );
	ts_status_debug( "test_firewall: destroy from_cbor, %s\n", ts_status_string( ts_message_destroy( from_cbor ) ) );

	// test firewall handler, set
	TsMessageRef_t message;
	ts_status_debug( "test_firewall: create firewall message, %s\n", ts_status_string( ts_message_create( &message ) ) );
	ts_status_debug( "test_firewall: decode json, %s\n", ts_status_string( ts_message_decode( message, TsEncoderJson, (uint8_t*)xmessage, strlen(xmessage) ) ) );
	ts_status_debug( "test_firewall: handle set firewall message, %s\n", ts_status_string( ts_firewall_handle( firewall, message ) ) );
	ts_status_debug( "test_firewall: destroy firewall message, %s\n", ts_status_string( ts_message_destroy( message ) ) );

	// test firewall handler, get
	ts_status_debug( "test_firewall: create firewall message, %s\n", ts_status_string( ts_message_create( &message ) ) );
	ts_status_debug( "test_firewall: decode json, %s\n", ts_status_string( ts_message_decode( message, TsEncoderJson, (uint8_t*)ymessage, strlen(ymessage) ) ) );
	ts_status_debug( "test_firewall: handle get firewall message, %s\n", ts_status_string( ts_firewall_handle( firewall, message ) ) );
	ts_status_debug( "test_firewall: result, %s\n", ts_status_string( ts_message_encode( message, TsEncoderDebug, NULL, 0 ) ) );
	ts_status_debug( "test_firewall: destroy firewall message, %s\n", ts_status_string( ts_message_destroy( message ) ) );


	// clean up
	ts_status_debug( "test_firewall: destroy firewall, %s\n", ts_status_string( ts_firewall_destroy( firewall ) ) );
#endif
	}
#endif


#endif // TS_FIREWALL_CUSTOM
