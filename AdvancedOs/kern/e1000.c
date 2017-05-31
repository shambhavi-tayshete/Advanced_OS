#include <kern/e1000.h>
#include <kern/pmap.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/env.h>

#include <inc/string.h>
#include <inc/error.h>

// LAB 6: Your driver code here
#define E1000_TDBAL    0x03800/4
#define E1000_TDBAH    0x03804/4  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808/4  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810/4  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818/4  /* TX Descripotr Tail - RW */
#define E1000_TCTL     0x00400/4  /* TX Control - RW */
#define E1000_TIPG     0x00410/4  /* TX Inter-packet gap -RW */

#define E1000_RAL	   0x05400/4  /* Lower 32 bits of 48 bit MAC ADdress */
#define E1000_RAH      0x05404/4  /* higher 12 bits of 48 bit MAC ADdress */
#define E1000_MTA      0x05200/4  /* Multicast Table Array - RW Array */
#define E1000_RDBAL    0x02800/4  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804/4  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808/4  /* RX Descriptor Length - RW */
#define E1000_RDH 	   0x02810/4  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818/4  /* RX Descripotr Tail - RW */
#define E1000_RCTL     0x00100/4  /* RX Control - RW */
#define E1000_IMS_RXT0 0x00000080      /* rx timer intr */
#define E1000_IMS      0x000D0/4  /* Interrupt Mask Set - RW */
//Individual bits
/* Transmit Control */
#define E1000_TCTL_RST    0x00000001    /* software reset */
#define E1000_TCTL_EN     0x00000002    /* enable tx */
#define E1000_TCTL_BCE    0x00000004    /* busy check enable */
#define E1000_TCTL_PSP    0x00000008    /* pad short packets */
#define E1000_TCTL_CT     0x00000100    /* collision threshold */
#define E1000_TCTL_COLD   0x00040000    /* collision distance */
#define E1000_TCTL_SWXOFF 0x00400000    /* SW Xoff transmission */
#define E1000_TCTL_PBE    0x00800000    /* Packet Burst Enable */
#define E1000_TCTL_RTLC   0x01000000    /* Re-transmit on late collision */
#define E1000_TCTL_NRTU   0x02000000    /* No Re-transmit on underrun */
#define E1000_TCTL_MULR   0x10000000    /* Multiple request support */

/* Receive Control Bits */
#define E1000_RCTL_EN     0x00000002    /* enable */
#define E1000_RCTL_BAM    0x00008000    /* broadcast enable */
#define E1000_RCTL_SECRC  0x04000000    /* Strip Ethernet CRC */

#define E1000_TIPG_IPGT 0
#define E1000_TIPG_IPGR1 10
#define E1000_TIPG_IPGR2 20

// Transmission descriptor bits
#define E1000_TXD_DEXT	0x20 /* bit 5 in CMD section */
#define E1000_TXD_RS	0x8 /* bit 3 in CMD section */
#define E1000_TXD_DD	0x1 /* bit 0 in STATUS section */
#define E1000_TXD_EOP	0x1 /* bit 0 of CMD section */


#define E1000_RXD_STAT_DD       0x01    /* Descriptor Done */
#define E1000_RXD_STAT_EOP      0x02    /* End of Packet */
#define E1000_RXD_STAT_IXSM     0x04    /* Ignore checksum */
#define E1000_RXD_STAT_VP       0x08    /* IEEE VLAN Packet */
#define E1000_RXD_STAT_UDPCS    0x10    /* UDP xsum caculated */
#define E1000_RXD_STAT_TCPCS    0x20    /* TCP xsum calculated */
#define E1000_RXD_STAT_IPCS     0x40    /* IP xsum calculated */
#define E1000_RXD_STAT_PIF      0x80    /* passed in-exact filter */
#define E1000_RXD_STAT_IPIDV    0x200   /* IP identification valid */
#define E1000_RXD_STAT_UDPV     0x400   /* Valid UDP checksum */
#define E1000_RXD_STAT_ACK      0x8000  /* ACK Packet indication */
#define MTA_LEN 				128
volatile uint32_t *e1000;

static void
e1000w(int index, int value)
{
	e1000[index] = value;
	//lapic[ID];  // wait for write to finish, by reading
}

static uint32_t
e1000r(int index)
{
	return e1000[index];
	//lapic[ID];  // wait for write to finish, by reading
}

struct tx_desc tx_queue[NUMBERTXDESC] __attribute__ ((aligned (16)));
struct pkt_buf tx_pkt_buf[NUMBERTXDESC];

struct rx_desc rx_queue[NUMBERRXDESC] __attribute__((aligned(16)));
struct pkt_buf rx_pkt_buf[NUMBERRXDESC];


int attachE100(struct pci_func *pcif)
{
	pci_func_enable(pcif); //Enable the network device using the vendor id and the device id set in pci.c. 
							//looked these values from e1000 5.2
	
	e1000 = (uint32_t *)mmio_map_region((physaddr_t)pcif->reg_base[0], pcif->reg_size[0]); //Map the IO device to kernel memory 
																				//for the kernel to access it.
	cprintf("Settings:%x\n",e1000r(2));
	//Set the Transmit part of e1000 NIC
	e1000w(E1000_TDBAL, PADDR(tx_queue)); //write the base the transmitt descriptor to TDBAL register
	e1000w(E1000_TDBAH, 0x00000000);
	e1000w(E1000_TDLEN, sizeof(struct tx_desc)*NUMBERTXDESC); //write the size the "entire" transmitt descriptor to TDLEN register
	e1000w(E1000_TDT, 0x0);  //Set the head and tail to 0b as asked in the manual.
	e1000w(E1000_TDH, 0x0);
	e1000w(E1000_TCTL,0x0);
	//int temp = E1000_TCTL_EN | E1000_TCTL_PSP | E1000_TCTL_CT | E1000_TCTL_COLD
	e1000w(E1000_TCTL, E1000_TCTL_EN | E1000_TCTL_PSP | E1000_TCTL_CT | E1000_TCTL_COLD);
	
	//Table 13-77. TIPG Register Bit Description : 31 30   29 20   19 10   9 0
												//Reserved IPGR2   IPGR1   IPGT
	e1000w(E1000_TIPG, (0xC << E1000_TIPG_IPGR2) | (0x8 << E1000_TIPG_IPGR1) | (0xA << E1000_TIPG_IPGT));
	//int temp = (0xC << E1000_TIPG_IPGR2) | (0x8 << E1000_TIPG_IPGR1) | (0xA << E1000_TIPG_IPGT);
	
	memset(tx_queue, 0, sizeof(struct tx_desc) * NUMBERTXDESC); //set all the tx_desc array to 0.
	int i;
	for (i = 0; i < NUMBERTXDESC; i++) 
	{
		tx_queue[i].addr = PADDR(&tx_pkt_buf[i]); 	// set packet buffer to each addr

		//tx_queue[i].cmd &= ~E1000_TXD_DEXT;		// set legacy descriptor mode, asked by them

		tx_queue[i].cmd |= E1000_TXD_RS;			// set RS bit for the DD bit to be set by e1000
		
		tx_queue[i].status |= E1000_TXD_DD;		// all descriptors are initally free
	}

	//set the Receive part of the E1000 NIC.
	e1000w(E1000_RAL,0x12005452);     //52:54:00:12:34:56 RAL := 0x12005452;
	e1000w(E1000_RAH, 0x80005634);   //Be sure to be carefull about the byte order.
	for(i = 0; i < MTA_LEN; i++)
		e1000w(E1000_MTA+i, 0x00000000);   //Set the MTA to '0'.
	e1000w(E1000_RDBAL, PADDR(rx_queue));
	e1000w(E1000_RDBAH, 0x0);
	e1000w(E1000_RDLEN, sizeof(struct rx_desc) * NUMBERRXDESC);
	
	e1000w(E1000_RDH, 0x00000000);
	e1000w(E1000_RDT, NUMBERRXDESC-1); //Consider 128 as the value.

	//e1000w(E1000_IMS, E1000_IMS_RXT0);
	e1000w(E1000_RCTL, 0x00000000);
	e1000w(E1000_RCTL, E1000_RCTL_SECRC | E1000_RCTL_BAM | E1000_RCTL_EN);
	
	
	memset(rx_queue, 0, sizeof(struct rx_desc) * NUMBERRXDESC);


	for(i = 0;i<NUMBERRXDESC; i++)
	{
		rx_queue[i].addr = PADDR(&rx_pkt_buf[i]); 	// set packet buffer to each addr
		memset(&rx_pkt_buf[i],0,PKTBUFSIZE); 
	}
	return 0;
}

int e1000transmit(void * packet, size_t length)
{
	int pos = e1000r(E1000_TDT);

	//cprintf("Pos Value:%d\n",pos);

	if(length > PKTBUFSIZE)
		panic("e1000transmit:length more than buffer");
	
	if((tx_queue[pos].status & E1000_TXD_DD) != 1 )
		return -E_BUFFER_FULL;
	
	memmove((void *) &tx_pkt_buf[pos], (void *)packet, length); //overhead
	
	tx_queue[pos].status &= ~E1000_TXD_DD; //set the DD flag to zero.
	
	tx_queue[pos].cmd |= E1000_TXD_EOP; //Set the last packet for this desc
	
	tx_queue[pos].length = length;
		
	e1000w(E1000_TDT, (pos+1)%NUMBERTXDESC); //notifies E1000 that a new packet is in the TX descriptor queue.
	return 0;
}

int e1000receive(void * pkt, size_t * length)
{
	int i = e1000r(E1000_RDT); 
	int desc_id = (i+1) % NUMBERRXDESC;
	//cprintf("status: %x\n",rx_queue[desc_id].status);
	//cprintf("Desc_id:%d  pkt:%x  buf:%x\n",desc_id,pkt,&rx_pkt_buf[desc_id]);

	/*for(i = 0; i < NUMBERRXDESC; i++)
	{
		cprintf("status: %x for desc:%d\t",rx_queue[i].status,i);
	}*/

	if((rx_queue[desc_id].status & E1000_RXD_STAT_DD) == 0 )//&& (rx_queue[desc_id].status & E1000_RXD_STAT_EOP))
	{
		//cprintf("length:%d\n",rx_queue[desc_id].length);
		return -E_NO_PACKETS;
	}

	if((rx_queue[desc_id].status & E1000_RXD_STAT_EOP) == 0)
		panic("In receive. Not end of packet");	
	
	memmove((void *)pkt, (void *)&rx_pkt_buf[desc_id], rx_queue[desc_id].length);
	//rx_queue[desc_id].status = 0x0;
	rx_queue[desc_id].status &= ~E1000_RXD_STAT_DD;
	rx_queue[desc_id].status &= ~E1000_RXD_STAT_EOP;
	*length = rx_queue[desc_id].length;
	//cprintf("Value at desc_id %d: %.*s\n",desc_id,*length, (char *)pkt);
	e1000w(E1000_RDT, desc_id);
	//e1000w(E1000_RDT, (desc_id+1)%NUMBERRXDESC);
	return 0;
}