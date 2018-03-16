// Copyright (C) 2017, 2018 Verizon, Inc. All rights reserved.
#if defined(TS_FIREWALL_CUSTOM)
#include "ts_platform.h"
#include "ts_firewall.h"

static TsStatus_t ts_create(TsFirewallRef_t *);
static TsStatus_t ts_destroy(TsFirewallRef_t);
static TsStatus_t ts_tick(TsFirewallRef_t, uint32_t);
static TsStatus_t ts_handle(TsFirewallRef_t, TsMessageRef_t );

static TsFirewallVtable_t ts_firewall_unix = {
	.create = ts_create,
	.destroy = ts_destroy,
	.tick = ts_tick,
	.handle = ts_handle,
};
const TsFirewallVtable_t * ts_firewall = &(ts_firewall_unix);

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
static TsStatus_t ts_create( TsFirewallRef_t * firewall ) {

	ts_status_trace( "ts_firewall_create\n" );
	return TsStatusErrorNotImplemented;
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
	return TsStatusErrorNotImplemented;
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
	return TsStatusErrorNotImplemented;
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
	return TsStatusErrorNotImplemented;
}
#endif // TS_FIREWALL_CUSTOM