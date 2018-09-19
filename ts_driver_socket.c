// Copyright (C) 2017, 2018 Verizon, Inc. All rights reserved.
#if defined(TS_DRIVER_SOCKET)
#if defined(__unix__) || defined(__unix) || ( defined(__APPLE__) && defined(__MACH__))

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__APPLE__) && defined(__MACH__)

#include <sys/types.h>
#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <stdlib.h>

#endif

#include "ts_platform.h"
#include "ts_driver.h"

static uint8_t _hex_digits[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

static TsStatus_t ts_create( TsDriverRef_t * );
static TsStatus_t ts_destroy( TsDriverRef_t );
static TsStatus_t ts_tick( TsDriverRef_t, uint32_t );

static TsStatus_t ts_connect( TsDriverRef_t, TsAddress_t );
static TsStatus_t ts_disconnect( TsDriverRef_t );
static TsStatus_t ts_read( TsDriverRef_t, const uint8_t *, size_t *, uint32_t );
static TsStatus_t ts_reader( TsDriverRef_t, void *, TsDriverReader_t );
static TsStatus_t ts_write( TsDriverRef_t, const uint8_t *, size_t *, uint32_t );

static TsDriverVtable_t ts_driver_unix_socket = {
	.create = ts_create,
	.destroy = ts_destroy,
	.tick = ts_tick,

	.connect = ts_connect,
	.disconnect = ts_disconnect,
	.read = ts_read,
	.reader = ts_reader,
	.write = ts_write,
};
const TsDriverVtable_t * ts_driver = &ts_driver_unix_socket;

typedef struct TsDriverSocket * TsDriverSocketRef_t;
typedef struct TsDriverSocket {

	// inheritance by encapsulation; must be the first
	// attribute in order to treat this struct as a
	// TsDriver struct
	TsDriver_t _driver;

	int _fd;
	uint64_t _last_read_timestamp;

} TsDriverSocket_t;

static TsStatus_t ts_create( TsDriverRef_t * driver ) {

	ts_status_trace( "ts_driver_create: socket\n" );
	ts_platform_assert( driver != NULL );

	// TODO - init sockets?
	//sigignore(SIGHUP);
	//sigignore(SIGINT);
	//sigignore(SIGPIPE);
	//sigignore(SIGALRM);

	TsDriverSocketRef_t sock = (TsDriverSocketRef_t) ( ts_platform_malloc( sizeof( TsDriverSocket_t )));
	sock->_driver._address = "";
	sock->_driver._profile = NULL;
	sock->_driver._spec_budget = 60*TS_TIME_SEC_TO_USEC;
	sock->_driver._spec_mtu = 8192;
	// TODO - should provide mac address here? probably not
	// TODO - currently using my own mac-id - need to change this asap.
	snprintf((char *) ( sock->_driver._spec_id ), TS_DRIVER_MAX_ID_SIZE, "%s", "B827EBA15910" );
	sock->_fd = -1;

	*driver = (TsDriverRef_t) sock;

	return TsStatusOk;
}

static TsStatus_t ts_destroy( TsDriverRef_t driver ) {

	ts_status_trace( "ts_driver_destroy\n" );
	ts_platform_assert( driver != NULL );

	TsDriverSocketRef_t sock = (TsDriverSocketRef_t) ( driver );
	ts_platform->free( sock, sizeof( TsDriverSocket_t ));

	return TsStatusOk;
}

static TsStatus_t ts_tick( TsDriverRef_t driver, uint32_t budget ) {

	ts_status_trace( "ts_driver_tick\n" );
	ts_platform_assert( driver != NULL );

	// do nothing

	return TsStatusOk;
}

static TsStatus_t ts_connect( TsDriverRef_t driver, TsAddress_t address ) {

	ts_status_trace( "ts_driver_connect\n" );
	ts_platform_assert( driver != NULL );

	TsStatus_t status = TsStatusErrorNotFound;
	TsDriverSocketRef_t sock = (TsDriverSocketRef_t) ( driver );

	// TODO - should really pattern match to see if this is an IP or an FQDN
#if defined(TS_UNIX_SIMPLE_SOCKET)
	struct sockaddr_in server;
	sock->_fd = socket(AF_INET, SOCK_STREAM , 0);
	if( sock->_fd == -1 ) {
		return TsStatusErrorInternalServerError;
	}

	char host[256], port[8];
	ts_address_parse( address, host, port );

	server.sin_addr.s_addr = inet_addr( host );
	server.sin_family = AF_INET;
	server.sin_port = htons( atoi( port ) );

	if (connect( sock->_fd , (struct sockaddr *)&server , sizeof(server)) == 0) {

		if( fcntl( sock->_fd, F_SETFL, fcntl( sock->_fd, F_GETFL, 0 ) | O_NONBLOCK ) == -1 ) {

			status = TsStatusErrorInternalServerError;

		} else {

			status = TsStatusOk;
		}
	}
#else
	// init address hints
	struct addrinfo hints;
	memset( &hints, 0x00, sizeof( struct addrinfo ));
	hints.ai_family = AF_UNSPEC;
	// TODO - allow UDP
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// decode and resolve address
	char host[TS_ADDRESS_MAX_HOST_SIZE];
	char port[TS_ADDRESS_MAX_PORT_SIZE];
	if( ts_address_parse( address, host, port ) != TsStatusOk ) {
		return TsStatusErrorInternalServerError;
	}
	struct addrinfo * address_list;
	if( getaddrinfo( host, port, &hints, &address_list ) != 0 ) {
		return TsStatusErrorNotFound;
	}

	// find active listener
	struct addrinfo * current;
	for( current = address_list; current != NULL; current = current->ai_next ) {

		sock->_fd = (int) socket( current->ai_family, current->ai_socktype, current->ai_protocol );
		if( sock->_fd < 0 ) {
			status = TsStatusErrorNotFound;
			continue;
		}
		if( connect( sock->_fd, current->ai_addr, current->ai_addrlen ) == 0 ) {

			if( fcntl( sock->_fd, F_SETFL, fcntl( sock->_fd, F_GETFL, 0 ) | O_NONBLOCK ) == -1 ) {
				status = TsStatusErrorInternalServerError;
				close( sock->_fd );
				continue;
			}
			status = TsStatusOk;
			break;
		}
		status = TsStatusErrorBadGateway;
		ts_disconnect( driver );
	}
	freeaddrinfo( address_list );
#endif

	// return status
	return status;
}

static TsStatus_t ts_disconnect( TsDriverRef_t driver ) {

	ts_status_trace( "ts_driver_disconnect\n" );
	ts_platform_assert( driver != NULL );

	TsDriverSocketRef_t sock = (TsDriverSocketRef_t) ( driver );
	close( sock->_fd );

	return TsStatusOk;
}

/**
 * Read from the socket driver (non-blocking). Note that we dont use select() in order to emulate
 * the other channels better, e.g., uart and usb.
 *
 * @note
 * TsStatusOkReadPending has a very specific meaning, only return when the read
 * has returned pending and there isn't data in the buffer, in all other cases
 * return a valid status with the contents of the current buffer.
 *
 * @param driver
 * [in] The socket state
 *
 * @param buffer
 * [in] The pre-allocated buffer memory
 *
 * @param buffer_size
 * [in] The pre-allocated buffer memory size
 * [out] The actual number of byte read
 *
 * @param budget
 * [in] Recommended allotment of time in microseconds allowed wait for received bytes.
 *
 * @return
 * TsStatusOk, *buffer_size > 0 - Return the given amount of read data
 * TsStatusOk, *buffer_size = 0 - Usually indicates and end-of-file condition
 * TsStatusOkPendingRead        - Indicates a blocking condition exists (and avoided),
 *                                note, *buffer_size is guaranteed to be zero when this condition occurs.
 *                                TODO - currently, we dont wait for the budget to be exhausted, this may change later
 * TsStatusErrorConnectionReset - Indicates that the driver was broken
 * TsStatusError*               - Indicates an error has occurred, see ts_status.h for more information.
 */
static TsStatus_t ts_read( TsDriverRef_t driver, const uint8_t * buffer, size_t * buffer_size, uint32_t budget ) {

	ts_status_trace( "ts_driver_read\n" );
	ts_platform_assert( driver != NULL );
	ts_platform_assert( buffer != NULL );
	ts_platform_assert( buffer_size != NULL );
	ts_platform_assert( *buffer_size > 0 );

	TsDriverSocketRef_t sock = (TsDriverSocketRef_t) ( driver );

	// initialize timestamp for read timer budgeting
	uint64_t timestamp = ts_platform_time();

	// limit read to 1MHz call bandwidth
	// note that this doesnt limit the number of recv calls made below,
	// just the number of reattempts by the caller,...
	if( timestamp - sock->_last_read_timestamp == 0 ) {
		*buffer_size = 0;
		return TsStatusOkReadPending;
	}
	sock->_last_read_timestamp = timestamp;

	// perform read
	int flags = 0x00;
	bool reading = true;
	ssize_t index = 0;
	TsStatus_t status = TsStatusOk;
	do {

		// read from the socket
		ssize_t size = recv( sock->_fd, (void *) ( buffer + index ), ( *buffer_size ) - index, flags );
		if( size < 0 ) {

			// recv has indicated either non-block status
			// or an actual driver issue,...
			size = 0;
			reading = false;

			// establish the exit scenario for the caller
			if( errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR ) {
				if( index > 0 ) {
					status = TsStatusOk;
				} else {
					// TODO - allow the timer budget to be exhausted before returning?
					status = TsStatusOkReadPending;
				}
			} else if( errno == EPIPE || errno == ECONNRESET ) {
				status = TsStatusErrorConnectionReset;
			} else if( errno != 0 ) {
				ts_status_debug( "ts_driver_read: ignoring error, %d\n", errno );
				status = TsStatusErrorInternalServerError;
			}

		} else if( size == 0 ) {

			// first normal exit condition, non-block io read returns zero bytes
			reading = false;
			status = TsStatusOk;

		} else if( ts_platform_time() - timestamp > budget ) {

			// there is more to read than expected on this attempt,
			// give back control to caller
			ts_status_debug( "ts_driver_read: timer budget exceeded\n" );
			reading = false;

			if( index > 0 ) {
				status = TsStatusOk;
			} else {
				status = TsStatusOkReadPending;
			}
		}

		index = index + size;

		if( index >= *buffer_size ) {
			// second normal exit condition, the buffer is full
			reading = false;
			status = TsStatusOk;
		}

	} while( reading );

	// update read buffer size and return
	*buffer_size = (size_t) index;
	return status;
}

static TsStatus_t ts_reader( TsDriverRef_t driver, void * data, TsDriverReader_t reader ) {
	return TsStatusErrorNotImplemented;
}

static TsStatus_t ts_write( TsDriverRef_t driver, const uint8_t * buffer, size_t * buffer_size, uint32_t budget ) {

	ts_status_trace( "ts_driver_write\n" );
	ts_platform_assert( driver != NULL );
	ts_platform_assert( buffer != NULL );
	ts_platform_assert( buffer_size != NULL );
	ts_platform_assert( *buffer_size > 0 );

	TsDriverSocketRef_t sock = (TsDriverSocketRef_t) ( driver );

	// initialize timestamp for write timer budgeting
	uint64_t timestamp = ts_platform_time();

	// perform write
	int flags = 0x00;
	bool writing = true;
	ssize_t index = 0;
	TsStatus_t status = TsStatusOk;
	do {

		// write to the socket
		ssize_t size = send( sock->_fd, buffer + index, *buffer_size - index, flags );
		if( size < 0 ) {

			// send has indicated either non-block status
			// or an actual driver issue,...
			size = 0;
			writing = false;

			// establish exit scenarip for the caller
			if( errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR ) {
				if( index > 0 ) {
					status = TsStatusOk;
				} else {
					status = TsStatusOkWritePending;
				}
			} else if( errno == EPIPE || errno == ECONNRESET ) {
				status = TsStatusErrorConnectionReset;
			} else if( errno != 0 ) {
				ts_status_debug( "ts_driver_write: ignoring error, %d\n", errno );
				status = TsStatusErrorInternalServerError;
			}

		} else if( size == 0 ) {

			// unexpected non-blocking call returns zero bytes
			ts_status_info( "ts_driver_write: unexpected empty write occured\n" );
			writing = false;
			if( index > 0 ) {
				status = TsStatusOk;
			} else {
				status = TsStatusOkWritePending;
			}

		} else if( ts_platform_time() - timestamp > budget ) {

			// there is more to write, but dont give control back to the caller
			ts_status_debug( "ts_driver_write: ignoring timer budget exceeded\n" );
		}

		index = index + size;

		if( index >= *buffer_size ) {

			// second normal exit condition, the buffer is full
			writing = false;
			status = TsStatusOk;
		}

	} while( writing );

	// update write buffer size and return
	*buffer_size = (size_t) index;
	return status;
}

static TsStatus_t _ts_driver_initialize_id( TsDriverSocketRef_t sock ) {
//
//	if( status == TsStatusOk ) {
//
//#if defined(__APPLE__) && defined(__MACH__)
//		struct ifreq ifr;
//		struct ifconf ifc;
//		char buf[1024];
//		int success = 0;
//
//		ifc.ifc_len = sizeof( buf );
//		ifc.ifc_buf = buf;
//		if( ioctl( sock->_fd, SIOCGIFCONF, &ifc ) == -1 ) {
//			return status;
//		}
//		struct ifreq * it = ifc.ifc_req;
//		size_t count = ifc.ifc_len / sizeof( struct ifreq );
//		for( size_t index = 0; index < count; index++ ) {
//
//			strcpy( ifr.ifr_name, it->ifr_name );
//			it = it + 1;
//
//			if( ioctl( sock->_fd, SIOCGIFFLAGS, &ifr ) == 0 ) {
//
//				if( !( ifr.ifr_flags & IFF_LOOPBACK )) {
//
//					int mib[6];
//					size_t len = 6;
//
//					mib[ 0 ] = CTL_NET;
//					mib[ 1 ] = AF_ROUTE;
//					mib[ 2 ] = 0;
//					mib[ 3 ] = AF_LINK;
//					mib[ 4 ] = NET_RT_IFLIST;
//					if( ( mib[ 5 ] = if_nametoindex( ifr.ifr_name ) ) == 0 ) {
//						continue;
//					}
//					if( sysctl( mib, 6, buf, &len, NULL, 0 ) < 0 ) {
//						continue;
//					}
//					success = 1;
//					break;
//				}
//			} else {
//
//				return status;
//			}
//		}
//		if( success ) {
//
//			unsigned char * ptr;
//			struct if_msghdr * ifm;
//			struct sockaddr_dl * sdl;
//
//			ifm = (struct if_msghdr *) buf;
//			sdl = (struct sockaddr_dl *) ( ifm + 1 );
//			ptr = (unsigned char *) LLADDR( sdl );
//
//			memset( driver->_spec_id, 0x00, TS_DRIVER_MAX_ID_SIZE );
//			int index = 0;
//			for( int i = 0; i < 6; i++ ) {
//				driver->_spec_id[ index ] = _hex_digits[ ptr[i] >> 4 ];
//				driver->_spec_id[ index + 1 ] = _hex_digits[ ptr[i] & 0x0f ];
//				index = index + 2;
//				driver->_spec_id[ index ] = 0x00;
//			}
//			ts_status_debug( "ts_driver_socket: UUID( %s )\n", driver->_spec_id );
//		}
//#else
//		struct ifreq ifr;
//		struct ifconf ifc;
//		char buf[1024];
//		int success = 0;
//
//		ifc.ifc_len = sizeof( buf );
//		ifc.ifc_buf = buf;
//		if( ioctl( sock->_fd, SIOCGIFCONF, &ifc ) == -1 ) {
//			return status;
//		}
//
//		struct ifreq * it = ifc.ifc_req;
//		const struct ifreq * const end = it + ( ifc.ifc_len / sizeof( struct ifreq ));
//
//		for( ; it != end; ++it ) {
//
//			strcpy( ifr.ifr_name, it->ifr_name );
//			if( ioctl( sock->_fd, SIOCGIFFLAGS, &ifr ) == 0 ) {
//
//				if( !( ifr.ifr_flags & IFF_LOOPBACK )) {
//
//					if( ioctl( sock->_fd, SIOCGIFHWADDR, &ifr ) == 0 ) {
//
//						success = 1;
//						break;
//					}
//				}
//			} else {
//
//				return status;
//			}
//		}
//		if( success ) {
//
//			memset( driver->_spec_id, 0x00, TS_DRIVER_MAX_ID_SIZE );
//			int index = 0;
//			for( int i = 0; i < 6; i++ ) {
//				driver->_spec_id[ index ] = _hex_digits[ ifr.ifr_hwaddr.sa_data[i] >> 4 ];
//				driver->_spec_id[ index + 1 ] = _hex_digits[ ifr.ifr_hwaddr.sa_data[i] & 0x0f ];
//				index = index + 2;
//				driver->_spec_id[ index ] = 0x00;
//			}
//			ts_status_debug( "ts_driver_socket: UUID( %s )\n", driver->_spec_id );
//		}
//#endif
//	}
	return TsStatusErrorNotImplemented;
}

#endif // __unix__
#endif // TS_DRIVER_SOCKET
