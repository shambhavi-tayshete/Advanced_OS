#include "ns.h"

extern union Nsipc nsipcbuf;
#define PKTBUFSIZE 2048 
void
input(envid_t ns_envid)
{
	binaryname = "ns_input";

	// LAB 6: Your code here:
	// 	- read a packet from the device driver
	//	- send it to the network server
	// Hint: When you IPC a page to the network server, it will be
	// reading from it for a while, so don't immediately receive
	// another packet in to the same physical page.
	int r, perm;
	perm = PTE_P|PTE_U|PTE_W;
	size_t length;
	char temppacket[PKTBUFSIZE];
	while(1)
	{
		while((r = sys_e1000_receive(temppacket, &length)) < 0)   //wait till you get a message.
		{
			;//cprintf("Stuck in loop  R:%e\n",r);
		}
		//i++;
		//cprintf("char buffer:%s",temppacket);
		if((r = sys_page_alloc(0, &nsipcbuf, perm)) < 0)
			panic("Not enough memory, error:%e",r);
		memmove(nsipcbuf.pkt.jp_data,temppacket,length);
		nsipcbuf.pkt.jp_len  = length;
		ipc_send(ns_envid, NSREQ_INPUT, (void *)&nsipcbuf, perm);
	}
}
