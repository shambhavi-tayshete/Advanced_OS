#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <kern/pci.h>
#include <kern/pmap.h>

#define NUMBERTXDESC 64
#define PKTBUFSIZE 2048 
#define NUMBERRXDESC 128


int attachE100(struct pci_func *pcif);
int e1000transmit(void * packet, size_t length);
int e1000receive(void * packet, size_t *);

struct tx_desc
{
	uint64_t addr;
	uint16_t length;
	uint8_t cso;
	uint8_t cmd;
	uint8_t status;
	uint8_t css;
	uint16_t special;
};


/* Receive Descriptor */
struct rx_desc {
    uint64_t addr; /* Address of the descriptor's data buffer */
    uint16_t length;     /* Length of data DMAed into data buffer */
    uint16_t csum;       /* Packet checksum */
    uint8_t status;      /* Descriptor status */
    uint8_t errors;      /* Descriptor Errors */
    uint16_t special;
};

struct pkt_buf
{
	char buf[PKTBUFSIZE];
};

#endif	// JOS_KERN_E1000_H
