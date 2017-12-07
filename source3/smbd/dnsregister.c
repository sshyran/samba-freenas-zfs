/*
   Unix SMB/CIFS implementation.
   DNS-SD registration
   Copyright (C) Rishi Srivatsavai 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <includes.h>
#include "smbd/smbd.h"

/* Uses DNS service discovery (libdns_sd) to
 * register the SMB service. SMB service is registered
 * on ".local" domain via Multicast DNS & any
 * other unicast DNS domains available.
 *
 * Users use the smbclient -B (Browse) option to
 * browse for advertised SMB services.
 */

#define DNS_REG_RETRY_INTERVAL (5*60)  /* in seconds */

#ifdef WITH_DNSSD_SUPPORT

#include <dns_sd.h>

struct dns_reg_state {
	int count;
	struct reg_state {
		DNSServiceRef srv_ref;
		TALLOC_CTX *mem_ctx;
		struct tevent_context *event_ctx;
		struct tevent_timer *te;
		struct tevent_fd *fde;
		uint16_t port;
		int if_index;
		int fd;
	} *drs;
};

static void dns_register_smbd_retry(struct tevent_context *ctx,
				    struct tevent_timer *te,
				    struct timeval now,
				    void *private_data);
static void dns_register_smbd_fde_handler(struct tevent_context *ev,
					  struct tevent_fd *fde,
					  uint16_t flags,
					  void *private_data);


static int reg_state_destructor(struct reg_state *state)
{
	if (state == NULL) {
		return -1;
	}

	if (state->srv_ref != NULL) {
		/* Close connection to the mDNS daemon */
		DNSServiceRefDeallocate(state->srv_ref);
		state->srv_ref = NULL;
	}

	/* Clear event handler */
	TALLOC_FREE(state->te);
	TALLOC_FREE(state->fde);
	state->fd = -1;

	return 0;
}


static bool dns_register_smbd_schedule(struct reg_state *state,
				       struct timeval tval)
{
	reg_state_destructor(state);

	state->te = tevent_add_timer(state->event_ctx,
					 state->mem_ctx,
					 tval,
					 dns_register_smbd_retry,
					 state);
	if (!state->te) {
		return false;
	}

	return true;
}

static void dns_register_smbd_callback(DNSServiceRef service,
				       DNSServiceFlags flags,
				       DNSServiceErrorType errorCode,
				       const char *name,
				       const char *type,
				       const char *domain,
				       void *context)
{
	if (errorCode != kDNSServiceErr_NoError) {
		DEBUG(6, ("error=%d\n", errorCode));
	} else {
		DEBUG(6, ("%-15s %s.%s%s\n", "REGISTER", name, type, domain));
	}
}

static void dns_register_smbd_retry(struct tevent_context *ctx,
				    struct tevent_timer *te,
				    struct timeval now,
				    void *private_data)
{
	struct reg_state *state = (struct reg_state *)private_data;
	DNSServiceErrorType err;

	reg_state_destructor(state);

	DEBUG(6, ("registering _smb._tcp service on port %d index %d\n",
		  state->port, state->if_index));

	/* Register service with DNS. Connects with the mDNS
	 * daemon running on the local system to perform DNS
	 * service registration.
	 */
	err = DNSServiceRegister(&state->srv_ref,
			0		/* flags */,
			state->if_index /* interface index */,
			NULL 		/* service name */,
			"_smb._tcp"	/* service type */,
			NULL		/* domain */,
			""		/* SRV target host name */,
			htons(state->port) /* port */, 
			0		/* TXT record len */,
			NULL		/* TXT record data */,
			dns_register_smbd_callback /* callback func */,
			NULL		/* callback context */);

	if (err != kDNSServiceErr_NoError) {
		/* Failed to register service. Schedule a re-try attempt.
		 */
		DEBUG(3, ("unable to register with mDNS (err %d)\n", err));
		goto retry;
	}

	state->fd = DNSServiceRefSockFD(state->srv_ref);
	if (state->fd == -1) {
		goto retry;
	}

	state->fde = tevent_add_fd(state->event_ctx,
				   state->mem_ctx,
				   state->fd,
				   TEVENT_FD_READ,
				   dns_register_smbd_fde_handler,
				   state);
	if (!state->fde) {
		goto retry;
	}

	return;
 retry:
	dns_register_smbd_schedule(state,
		timeval_current_ofs(DNS_REG_RETRY_INTERVAL, 0));
}

/* Processes reply from mDNS daemon. Returns true if a reply was received */
static void dns_register_smbd_fde_handler(struct tevent_context *ev,
					  struct tevent_fd *fde,
					  uint16_t flags,
					  void *private_data)
{
	struct reg_state *state = (struct reg_state *)private_data;
	DNSServiceErrorType err;

	err = DNSServiceProcessResult(state->srv_ref);
	if (err != kDNSServiceErr_NoError) {
		DEBUG(3, ("failed to process mDNS result (err %d), re-trying\n", err));
		goto retry;
	}

	return;

 retry:
	dns_register_smbd_schedule(state, timeval_zero());
}

static int dns_reg_state_destructor(struct dns_reg_state *state)
{
	if (state != NULL) {
		talloc_free(state);
	}
	return 0;
}


bool smbd_setup_mdns_registration(struct tevent_context *ev,
				  TALLOC_CTX *mem_ctx,
				  uint16_t port)
{
	struct dns_reg_state *dns_state;
	bool bind_all = true;
	int i;

	dns_state = talloc_zero(mem_ctx, struct dns_reg_state);
	if (dns_state == NULL)
		return false;

	if (lp_interfaces() && lp_bind_interfaces_only())
		bind_all = false;

	dns_state->count = iface_count();
	if (dns_state->count <= 0 || bind_all == true)
		dns_state->count = 1;

	dns_state->drs = talloc_array(mem_ctx, struct reg_state, dns_state->count);
	if (dns_state->drs == NULL) {
		talloc_free(dns_state);
		return false;
	}

	for (i = 0; i < dns_state->count; i++) {
		struct interface *iface = get_interface(i);
		struct reg_state *state = &dns_state->drs[i];

		state->mem_ctx = mem_ctx;
		state->srv_ref = NULL;
		state->event_ctx = ev;
		state->te = NULL;
		state->fde = NULL;
		state->port = port;
		state->fd = -1;

		state->if_index = bind_all ? kDNSServiceInterfaceIndexAny : iface->if_index;

		dns_register_smbd_schedule(&dns_state->drs[i], timeval_zero());
	}

	talloc_set_destructor(dns_state, dns_reg_state_destructor);
	return true;
}


#else /* WITH_DNSSD_SUPPORT */

bool smbd_setup_mdns_registration(struct tevent_context *ev,
				  TALLOC_CTX *mem_ctx,
				  uint16_t port)
{
	return true;
}

#endif /* WITH_DNSSD_SUPPORT */
