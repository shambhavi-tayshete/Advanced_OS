#include "ns.h"
#include <inc/syscall.h>
#include <inc/lib.h>

extern union Nsipc nsipcbuf;

void
output(envid_t ns_envid)
{
	binaryname = "ns_output";
	int r;
	// LAB 6: Your code here:
	// 	- read a packet from the network server
	//	- send the packet to the device driver
	while(true)
	{
		r = ipc_recv(&ns_envid, &nsipcbuf.pkt ,NULL);
		if(r == NSREQ_OUTPUT)
		{
			while((r = sys_e1000_transmit(nsipcbuf.pkt.jp_data, nsipcbuf.pkt.jp_len)) < 0)
				{;}
		}	
	}
}
