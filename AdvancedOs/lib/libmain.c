// Called from entry.S to get us going.
// entry.S already took care of defining envs, pages, uvpd, and uvpt.

#include <inc/lib.h>

extern void umain(int argc, char **argv);

const volatile struct Env *thisenv;
const char *binaryname = "<unknown>";

void
libmain(int argc, char **argv)
{
	// set thisenv to point at our Env structure in envs[].
	// LAB 3: Your code here.
	//thisenv = envs[sys_getenvid];
	//envid2env(sys_getenvid, &thisenv, 1);
	//((sys_getenvid) & (1024 - 1))
	int envid = sys_getenvid();
	int index = envid & (1023);
	//cprintf("Value of x:%x\n",index);
	thisenv = &envs[index];
	// save the name of the program so that panic() can use it
	if (argc > 0)
		binaryname = argv[0];
	cprintf("Binary Name:%s\n",binaryname);
	// call user main routine
	umain(argc, argv);

	// exit gracefully
	exit();
}

