// Copyright (C) 2017, 2018 Verizon, Inc. All rights reserved.
#if defined(TS_FIREWALL_CUSTOM)
#include "ts_platform.h"
#include "ts_firewall.h"

static TsStatus_t ts_create(TsFirewallRef_t *, TsStatus_t (*alertCallback)(TsMessageRef_t, char *));
static TsStatus_t ts_destroy(TsFirewallRef_t);
static TsStatus_t ts_tick(TsFirewallRef_t, uint32_t);
static TsStatus_t ts_handle(TsFirewallRef_t, TsMessageRef_t);
static TsStatus_t _ts_handle_set(TsFirewallRef_t, TsMessageRef_t);
static TsStatus_t _ts_handle_update(TsFirewallRef_t, TsMessageRef_t);
static TsStatus_t _ts_handle_get(TsFirewallRef_t, TsMessageRef_t);
static TsStatus_t _ts_handle_delete(TsFirewallRef_t, TsMessageRef_t);
static TsStatus_t _ts_handle_set_eval( TsFirewallRef_t );
static TsStatus_t _ts_handle_get_eval( TsFirewallRef_t );

static TsFirewallVtable_t ts_firewall_unix = {
	.create = ts_create,
	.destroy = ts_destroy,
	.tick = ts_tick,
	.handle = ts_handle,
};
const TsFirewallVtable_t * ts_firewall = &(ts_firewall_unix);

static void _mf_clear();
static void _mf_read();
static void _mf_write();
static void _mf_delete( int );
static void _mf_copy_ts( TsFirewallRef_t );
static void _ts_insert( TsMessageRef_t, int );

/**
 * Allocate and initialize a new firewall object.
 *
 * @param firewall
 * [on/out] The pointer to a pre-existing TsFirewallRef_t, which will be initialized with the firewall state.
 *
 * @return
 * The return status (TsStatus_t) of the function, see ts_status.h for more information.
 * - TsStatusOk
 * - TsStatusError[Code]
 */
static TsStatus_t ts_create( TsFirewallRef_t * firewall, TsStatus_t (*alertCallback)(TsMessageRef_t, char *) ) {

	ts_status_trace( "ts_firewall_create\n" );
	TsStatus_t status = TsStatusOk;

	// check for kernel module
	FILE * fp = fopen("/proc/miniFirewall", "r");
	if( fp == NULL ) {
		ts_status_alarm( "ts_firewall_create: mini-firewall kernel module not found, check installation\n" );
		status = TsStatusErrorNotImplemented;
	}
	fclose(fp);

	// initialize firewall object
	*firewall = (TsFirewallRef_t)ts_platform_malloc( sizeof( TsFirewall_t ) );
	if( *firewall == NULL ) {
		return TsStatusErrorInternalServerError;
	}

	ts_message_create( &((*firewall)->_default_domains) );
	ts_message_create( &((*firewall)->_default_rules ) );
	ts_message_create( &((*firewall)->_domains ) );
	ts_message_create( &((*firewall)->_rules ) );

	(*firewall)->_default_domains->type = TsTypeArray;
	(*firewall)->_default_rules->type = TsTypeArray;
	(*firewall)->_domains->type = TsTypeArray;
	(*firewall)->_rules->type = TsTypeArray;
	(*firewall)->_enabled = false;

	_mf_clear();

	ts_status_debug( "ts_firewall_create: mini-firewall kernel module found! firewall now READY.\n" );
	return status;
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

	ts_message_destroy( firewall->_default_domains );
	ts_message_destroy( firewall->_default_rules );
	ts_message_destroy( firewall->_domains );
	ts_message_destroy( firewall->_rules );

	ts_platform_free( firewall, sizeof( TsFirewall_t ) );

	return TsStatusOk;
}

/**
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

	// do nothing

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
					ts_status_debug("ts_firewall_unix: delegate to set handler\n" );
					status = _ts_handle_set( firewall, fields );

				} else if( strcmp( action, "update" ) == 0 ) {

					// get a rule or list of rules
					ts_status_debug("ts_firewall_unix: delegate to update handler\n" );
					status = _ts_handle_update( firewall, fields );

				} else if( strcmp( action, "get" ) == 0 ) {

					// get a rule or list of rules
					ts_status_debug("ts_firewall_unix: delegate to get handler\n" );
					status = _ts_handle_get( firewall, fields );

				} else if( strcmp( action, "delete" ) == 0 ) {

					// delete a rule
					ts_status_debug("ts_firewall_unix: delegate to delete handler\n" );
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
	_ts_handle_get_eval( firewall );

	// update configuration
	TsMessageRef_t array;
	TsMessageRef_t contents;
	if( ts_message_get_message( fields, "configuration", &contents ) == TsStatusOk ) {

		// override configuration setting if one or more exist in the message
		ts_status_debug( "ts_firewall_unix: set configuration\n" );
		ts_message_get_bool( contents, "enabled", &(firewall->_enabled ) );
		if( ts_message_has( contents, "default_rules", &array ) == TsStatusOk ) {

			ts_message_destroy( firewall->_default_rules );
			ts_message_create_copy( array, &( firewall->_default_rules ));

			// TODO - this is additive, should not overwrite instead
			size_t length;
			ts_message_get_size( array, &length );
			for( size_t i = 0; i < length; i++ ) {
				TsMessageRef_t current = array->value._xfields[ i ];
				_ts_insert( current, 0 );
			}
		}
		if( ts_message_has( contents, "default_domains", &array ) == TsStatusOk ) {

			ts_message_destroy( firewall->_default_domains );
			ts_message_create_copy( array, &(firewall->_default_domains) );
		}
	}

	// update rules
	// note that the array can only be 15 items long (limitation of ts_message)
	if( ts_message_get_array( fields, "rules", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_unix: set rules\n" );
		size_t length;
		ts_message_get_size( contents, &length );
		for( size_t i = 0; i < length; i++ ) {

			// set by id, or add to back w/o id ("set" or "update")
			TsMessageRef_t current = contents->value._xfields[ i ];
			int id = 0;
			if( ts_message_get_int( current, "id", &id ) == TsStatusOk ) {

				// TODO - _zz_update( current, id );
				_ts_insert( current, id );

			} else {

				// TODO - _zz_append( current );
				_ts_insert( current, 0 );
			}
		}
	}

	// update domains
	// note that the array can only be 15 items long (limitation of ts_message)
	if( ts_message_has( fields, "domains", &array ) == TsStatusOk ) {
		ts_message_destroy( firewall->_domains );
		ts_message_create_copy( array, &(firewall->_domains) );
	}

	return _ts_handle_set_eval( firewall );
}

static TsStatus_t _ts_handle_update( TsFirewallRef_t firewall, TsMessageRef_t fields ) {

	// TODO - synce with set
	ts_platform_assert(0);

	TsMessageRef_t contents;
	if( ts_message_get_message( fields, "configuration", &contents ) == TsStatusOk ) {

		// override configuration setting if one or more exist in the message
		ts_status_debug( "ts_firewall_unix: set configuration\n" );
		ts_message_get_bool( contents, "enabled", &(firewall->_enabled ) );
		// TODO - potential memory leak, need to check (i.e., set rules on top of rules already set)
		ts_message_get_array( contents, "default_rules", &(firewall->_default_rules) );
		ts_message_get_array( contents, "default_domains", &(firewall->_default_domains) );
	}

	// note that the array can only be 15 items long (limitation of ts_message)
	if( ts_message_get_array( fields, "rules", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_unix: update rules\n" );
		size_t length;
		ts_message_get_size( contents, &length );
		for( size_t i = 0; i < length; i++ ) {

			// insert-before (using "update") by id, or add to back w/o id ("set" or "update")
			TsMessageRef_t current = contents->value._xfields[ i ];
			int id = 0;
			if( ts_message_get_int( current, "id", &id ) == TsStatusOk ) {

				// TODO - _zz_insert( current, id );
				_ts_insert( current, id );

			} else {

				// TODO - _zz_append( current );
				_ts_insert( current, 0 );
			}
		}
	}

	// override configuration setting
	// note that the array can only be 15 items long (limitation of ts_message)
	// TODO - potential memory leak, need to check (i.e., set rules on top of rules already set)
	ts_message_get_array( fields, "domains", &(firewall->_domains) );

	// reset firewall rules in kernel module
	return _ts_handle_set_eval( firewall );
}

static TsStatus_t _ts_handle_get( TsFirewallRef_t firewall, TsMessageRef_t fields ) {

	TsMessageRef_t contents;
	if( ts_message_has( fields, "configuration", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_unix: get configuration\n" );

		ts_message_create_message( fields, "configuration", &contents );
		ts_message_set_bool( contents, "enabled", firewall->_enabled );
		ts_message_set_array( contents, "default_rules", firewall->_default_rules );
		ts_message_set_array( contents, "default_domains", firewall->_default_domains );
	}
	if( ts_message_has( fields, "rules", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_unix: get rules\n" );

		// refresh firewall rules from kernel module
		_ts_handle_get_eval( firewall );

		// refresh message
		ts_message_set_array( fields, "rules", firewall->_rules );
	}
	if( ts_message_has( fields, "domains", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_unix: get domains\n" );

		ts_message_set_message( fields, "domains", firewall->_domains );
	}

	return TsStatusOk;
}

static TsStatus_t _ts_handle_delete( TsFirewallRef_t firewall, TsMessageRef_t fields ) {

	TsStatus_t status = TsStatusOk;
	TsMessageRef_t contents;
	if( ts_message_get_array( fields, "rules", &contents ) == TsStatusOk ) {

		ts_status_debug( "ts_firewall_unix: delete rule by id\n" );
		size_t length;
		ts_message_get_size( contents, &length );
		for( size_t i = 0; i < length; i++ ) {

			// delete by id
			TsMessageRef_t current = contents->value._xfields[ i ];
			int id = 0;
			if( ts_message_get_int( current, "id", &id ) == TsStatusOk ) {

				ts_status_debug( "ts_firewall_unix: delete %d\n", id );

				// delete the rule from the kernel module
				_mf_delete( id );

			} else {

				ts_status_debug( "ts_firewall_unix: delete, id not found, ignoring,...\n" );
			}
		}
	}
	return status;
}

// ////////////////////////////////////////////////////////////////////////////
// mini-firewall utilities

struct mf_rule_struct {
	unsigned int src_ip;
	unsigned int dest_ip;
	unsigned int src_port;
	unsigned int dest_port;
	int in_out;                 // IN->1, OUT->2
	char src_netmask;
	char dest_netmask;
	char proto;                 // TCP->1, UDP->2, ALL->3
	char action;                // LOG->0， BLOCK->1
};

struct mf_rule_link {
	int id;
	bool assigned;
	struct mf_rule_link * next;
	struct mf_rule_link * prev;
	struct mf_rule_struct rule;
};

/**
 * User copy of the kernel firewall module rules
 */
#define TS_FIREWALL_MAX_RULES 256
static struct mf_rule_link * _mf_root = NULL;
static struct mf_rule_link _mf_rule_pool[ TS_FIREWALL_MAX_RULES ];

/**
 * Find first unassigned rule in pool
 * @return
 */
static struct mf_rule_link * _get_unassigned_rule() {

	for( int i = 0; i < TS_FIREWALL_MAX_RULES; i++ ) {

		if( _mf_rule_pool[i].assigned == false ) {
			_mf_rule_pool[i].assigned = true;
			_mf_rule_pool[i].next = NULL;
			_mf_rule_pool[i].prev = NULL;
			return &(_mf_rule_pool[i]);
		}
	}
	return NULL;
}

static unsigned int _ip_str_to_hl(char *ip_str) {

	unsigned int ip_array[4];
	unsigned int ip = 0;
	if (ip_str==NULL) {
		return 0;
	}

	sscanf(ip_str, "%u.%u.%u.%u", ip_array, ip_array+1, ip_array+2, ip_array+3);
	for (int i=0; i<4; i++) {
		ts_platform_assert((ip_array[i] <= 255) && "Wrong ip format");
	}
	ip = (ip_array[0] << 24);
	ip = (ip | (ip_array[1] << 16));
	ip = (ip | (ip_array[2] << 8));
	ip = (ip | ip_array[3]);

	return ip;
}

static void _ip_hl_to_str(unsigned int ip, char *ip_str) {

	unsigned char ip_array[4];
	memset(ip_array, 0, 4);

	ip_array[0] = (ip_array[0] | (ip >> 24));
	ip_array[1] = (ip_array[1] | (ip >> 16));
	ip_array[2] = (ip_array[2] | (ip >> 8));
	ip_array[3] = (ip_array[3] | ip);
	sprintf(ip_str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2], ip_array[3]);
}

/**
 * Convert a rule to a message (rule)
 * @param rule
 * @return
 */
static TsMessageRef_t _convert_mf( struct mf_rule_link * link ) {

	//	unsigned int src_ip;
	//	unsigned int dest_ip;
	//	unsigned int src_port;
	//	unsigned int dest_port;
	//	int in_out;                 // IN->1, OUT->2
	//	char src_netmask;
	//	char dest_netmask;
	//	char proto;                 // TCP->1, UDP->2, ALL->3
	//	char action;                // LOG->0， BLOCK->1

	char xsource[16], xdestination[16];
	_ip_hl_to_str( link->rule.src_ip, xsource );
	_ip_hl_to_str( link->rule.dest_ip, xdestination );

	TsMessageRef_t xrule, source, destination;
	ts_message_create( &xrule );
	ts_message_set_int( xrule, "id", link->id );
	ts_message_set_string( xrule, "sense", link->rule.in_out == 1 ? "inbound" : "outbound" );
	ts_message_set_string( xrule, "match", "all" );
	ts_message_set_string( xrule, "action", link->rule.action == 1 ? "drop" : "accept" );
	ts_message_set_string( xrule, "protocol", link->rule.proto == 1 ? "tcp" : "udp" );
	ts_message_set_string( xrule, "interface", "eth0" );

	ts_message_create_message( xrule, "source", &source );
	ts_message_set_string( source, "address", xsource );
	ts_message_set_string( source, "netmask", "255.255.255.0" );
	ts_message_set_int( source, "port", link->rule.src_port );

	ts_message_create_message( xrule, "destination", &destination );
	ts_message_set_string( destination, "address", xdestination );
	ts_message_set_string( destination, "netmask", "255.255.255.0" );
	ts_message_set_int( destination, "port", link->rule.dest_port );

	return xrule;
}

/**
 * Convert a message (rule) to a kernel rule
 * @param rule
 * @return
 */
static struct mf_rule_link * _convert_ts( TsMessageRef_t rule ) {

	ts_platform_assert( rule != NULL );

	//	unsigned int src_ip;
	//	unsigned int dest_ip;
	//	unsigned int src_port;
	//	unsigned int dest_port;
	//	int in_out;                 // IN->1, OUT->2
	//	char src_netmask;
	//	char dest_netmask;
	//	char proto;                 // TCP->1, UDP->2, ALL->3
	//	char action;                // LOG->0， BLOCK->1

	char * temp;
	int port;
	struct mf_rule_link * link = _get_unassigned_rule();
	if( link != NULL ) {

		ts_message_get_int( rule, "id", &(link->id) );
		ts_message_get_string( rule, "sense", &temp );
		if( temp != NULL ) link->rule.in_out = strcmp( temp, "inbound" ) == 0 ? 1 : 2;
		ts_message_get_string( rule, "action", &temp );
		if( temp != NULL ) link->rule.action = (char)( strcmp( temp, "drop" ) == 0 ? 1 : 0 );
		ts_message_get_string( rule, "protocol", &temp);
		if( temp != NULL ) link->rule.proto = (char)( strcmp( temp, "tcp" ) == 0 ? 1 : 2 );

		TsMessageRef_t filter;
		if( ts_message_get_message( rule, "source", &filter ) == TsStatusOk ) {
			link->rule.src_netmask = 24;
			ts_message_get_string( filter, "address", &temp );
			if( temp != NULL ) link->rule.src_ip = _ip_str_to_hl( temp );
			ts_message_get_int( filter, "port", &port );
			link->rule.src_port = (unsigned int)port;
		}
		if( ts_message_get_message( rule, "destination", &filter ) == TsStatusOk ) {
			link->rule.dest_netmask = 24;
			ts_message_get_string( filter, "address", &temp );
			if( temp != NULL ) link->rule.dest_ip = _ip_str_to_hl( temp );
			ts_message_get_int( filter, "port", &port );
			link->rule.dest_port = (unsigned int)port;
		}
	}

	return link;
}

/**
 * Copy the rules held by this firewall instance to the firewall
 * this includes default and additional rules
 * TODO - currently ignores domains
 * @param firewall
 * @return
 */
static TsStatus_t _ts_handle_set_eval( TsFirewallRef_t firewall ) {

	ts_status_trace( "_ts_handle_set_eval\n" );

	// the user rules list has been modified before this call
	// do not get all mf rules - i.e., _mf_read();

	// TODO - not correct, but a quick way to sync the user and kernel, demo code only,...
	// delete all mf rules
	struct mf_rule_link * current = _mf_root;
	while( current != NULL ) {

		_mf_delete( 1 );
		current = current->next;
	}

	// TODO - missing default rules
	// fill mf rules from ts, if enabled
	if( firewall->_enabled ) {

		// set mf rules from ts
		_mf_write();
	}

	return TsStatusOk;
}

/**
 * Refresh the given firewall object from the rules that currently exist on the firewall
 * @param firewall
 * @return
 */
static TsStatus_t _ts_handle_get_eval( TsFirewallRef_t firewall ) {

	ts_status_trace( "_ts_handle_get_eval\n" );

	// get mf rules (note, this wipes out any local changes)
	_mf_read();

	// set ts rules from mf
	// TODO - notice this wont filter the default rules, they will be repeated (which is correct?)
	_mf_copy_ts( firewall );

	return TsStatusOk;
}

/**
 * Clear the user copy of the rule-set, any changes are lost
 */
static void _mf_clear() {

	ts_status_trace( "_mf_clear\n" );

	// initialize static firewall rules
	for( int i = 0; i < TS_FIREWALL_MAX_RULES; i++ ) {
		_mf_rule_pool[ i ].assigned = false;
	}

	// remove root
	_mf_root = NULL;
}

/**
 * Refresh the user copy of the rule-set from the kernel
 */
static void _mf_read() {

	ts_status_trace( "_mf_read\n" );

	// clear local
	_mf_clear();

	// open firewall module
	FILE * fd = fopen("/proc/miniFirewall", "r");
	if( fd == NULL ) {
		ts_status_alarm("_mf_read: fopen failed\n");
		return;
	}

	// fill local
	int index = 0;
	struct mf_rule_link * prev = NULL;
	struct mf_rule_link current;
	while( fread( &(current.rule), sizeof(struct mf_rule_struct), 1, fd ) > 0 && index < TS_FIREWALL_MAX_RULES ) {

		// update previous next pointer (including root)
		if( prev != NULL ) {
			ts_status_debug( "_mf_read: prev(%d)->next = %d\n", prev->id, index );
			prev->next = &(_mf_rule_pool[ index ]);
		} else {
			ts_status_debug( "_mf_read: root = %d\n", index );
			_mf_root = &(_mf_rule_pool[ index ]);
		}

		// update current with the data held by the firewall
		_mf_rule_pool[ index ].id = index;
		_mf_rule_pool[ index ].assigned = true;
		_mf_rule_pool[ index ].prev = prev;
		_mf_rule_pool[ index ].next = NULL;
		_mf_rule_pool[ index ].rule = current.rule;

		// update next previous pointer
		prev = &(_mf_rule_pool[ index ]);
		index = index + 1;
	}

	// close and return
	fclose( fd );
}

/**
 * Refresh the kernel copy of the rule-set from the user
 */
static void _mf_write() {

	ts_status_trace( "_mf_write\n" );
	if( _mf_root == NULL ) {
		ts_status_debug( "_mf_write: nothing to do, leaving,...\n" );
		return;
	}

	// open firewall module
	FILE * fd = fopen( "/proc/miniFirewall", "w" );
	if( fd == NULL ) {
		ts_status_alarm("_mf_write: fopen failed\n");
		return;
	}

	// write local copy of all rules to the firewall
	struct mf_rule_link * current = _mf_root;
	while( current != NULL ) {

		ts_status_debug( "_mf_write: writing, %d\n", current->id );

		fwrite( &(current->rule), sizeof(struct mf_rule_struct), 1, fd );
		fflush(fd);

		current = current->next;
	}

	// close and return
	fclose( fd );
}

/**
 * Delete a particular rule by id, after return the old indexes will be stale
 * @param id
 * The index of the particular rule to delete from the kernel
 */
static void _mf_delete( int id ) {

	ts_status_trace( "_mf_delete\n" );

	// open the kernel firewall
	FILE * fd = fopen("/proc/miniFirewall", "w");
	if( fd == NULL ) {
		ts_status_alarm("_mf_delete: fopen failed\n");
		return;
	}

	// write the index to delete
	fwrite( &id, sizeof(unsigned int), 1, fd );
	fflush(fd);

	// close and return
	fclose( fd );
}

/**
 * Copy rules from the user copy to the firewall object
 * @param firewall
 */
static void _mf_copy_ts( TsFirewallRef_t firewall ) {

	ts_status_trace( "_mf_copy_ts\n" );

	// create an empty array
	TsMessageRef_t rules;
	ts_message_create( &rules );
	rules->type = TsTypeArray;

	// prepare result
	if( firewall->_rules != NULL ) {
		ts_message_destroy( firewall->_rules );
	}
	firewall->_rules = rules;

	// TODO - check; it should show default rules first, then regular,...
	int index = 0;
	struct mf_rule_link * current = _mf_root;
	while( ( current != NULL ) && ( index < TS_MESSAGE_MAX_BRANCHES ) ) {

		ts_status_debug( "_mf_copy_ts: index, %d\n", index);
		firewall->_rules->value._xfields[ index ] = _convert_mf( current );
		current = current->next;
		index = index + 1;
	}
}

/**
 * Insert a rule into the user space list
 * @param rule
 * @param index
 */
static void _ts_insert( TsMessageRef_t rule, int index ) {

	ts_status_trace( "_ts_insert\n" );

	// copy rule to unassigned one in pool
	struct mf_rule_link * xassign = _convert_ts( rule );
	if( xassign == NULL ) {
		ts_status_alarm( "_ts_insert: rule pool empty\n");
		return;
	}

	// insert at top as index or linked-list determines
	if( index == 0 || _mf_root == NULL ) {

		ts_status_debug( "_ts_insert: insert at root\n" );

		if( _mf_root != NULL ) {
			xassign->next = _mf_root;
			_mf_root->prev = xassign;
		}
		xassign->prev = NULL;
		_mf_root = xassign;

		return;
	}

	// insert before as index or linked-list determines
	struct mf_rule_link * current = _mf_root;
	while( current != NULL) {

		if( index > current->id ) {

			if( current->prev == NULL ) {

				ts_status_debug( "_ts_insert: insert at root according to id\n" );

				xassign->next = current;
				xassign->prev = NULL;

				current->prev = xassign;
				_mf_root = xassign;
				return;

			} else {

				ts_status_debug( "_ts_insert: insert at id\n" );

				xassign->next = current;
				xassign->prev = current->prev;

				current->prev->next = xassign;
				current->prev = xassign;
				return;
			}
		}
		current = current->next;
	}
}

#endif // TS_FIREWALL_CUSTOM
