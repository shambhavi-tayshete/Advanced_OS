#include <kern/time.h>
#include <inc/assert.h>
#include <kern/cpu.h>

static unsigned int ticks[NCPU];

void
time_init(void)
{
	int i;
	for (i = 0; i < NCPU; ++i)
	{
		ticks[i] = 0;
	}
	//ticks = 0;
}

// This should be called once per timer interrupt.  A timer interrupt
// fires every 10 ms.
void
time_tick(int cpunum)
{
	ticks[cpunum]++;
	if (ticks[cpunum] * 10 < ticks[cpunum])
		panic("time_tick: time overflowed");
}

unsigned int
time_msec(cpunum)
{
	return ticks[cpunum] * 10;
}
