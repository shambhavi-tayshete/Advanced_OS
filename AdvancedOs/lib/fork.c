// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800
#define CHECKWRITE 0x2

extern void _pgfault_upcall(void);

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	pte_t * pgtable = (pte_t *) UVPT;
	pte_t  pte = (pte_t )pgtable[PGNUM(addr)];
	if(!((err & CHECKWRITE) && (uvpt[PGNUM(addr)]&PTE_COW)))
		panic("The page fault was not a write page and on a COW page\n");
	
	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//cprintf("\nPasses the COW checks\n");
	if((r = sys_page_alloc(0, PFTEMP, PTE_P|PTE_U|PTE_W))<0)
		panic("Panic in pgfault in fork error:%e",r);
	
	memmove(PFTEMP, ROUNDDOWN(addr,PGSIZE),PGSIZE);
	
	if ((r = sys_page_map(0, PFTEMP, 0, ROUNDDOWN(addr,PGSIZE), PTE_P|PTE_U|PTE_W)) < 0)
		panic("sys_page_map: %e", r);
	
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;
	uint32_t addr = pn*PGSIZE;
	
	uint32_t pgnum = PGNUM(addr);
	if (uvpt[pn] & PTE_SHARE) 
	{
		if ((r = sys_page_map(0, (void *) addr, envid, (void *) addr, uvpt[pn] & PTE_SYSCALL)) < 0)
			panic("sys_page_map: %e\n", r);
	}
	else if(uvpt[pgnum] & PTE_W || uvpt[pgnum] & PTE_COW)
	{
		//cprintf("\nPage is COW and Write");
		if ((r = sys_page_map(0, (void *)addr, envid, (void *)addr, PTE_P|PTE_U|PTE_COW)) < 0)
			panic("sys_page_map: %e", r);
		if ((r = sys_page_map(0, (void *)addr, 0, (void *)addr, PTE_P|PTE_U|PTE_COW)) < 0)
			panic("sys_page_map: %e", r);
	}
	else
	{
		if ((r = sys_page_map(0, (void *)addr, envid, (void *)addr, PTE_P|PTE_U)) < 0)
			panic("sys_page_map: %e", r);
	}
	// LAB 4: Your code here.
	//panic("duppage not implemented");
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	int r;
	set_pgfault_handler(pgfault);
	envid_t envid = sys_exofork();
	if (envid < 0)
		panic("sys_exofork: %e", envid);
	if (envid == 0) {
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid (it refers to the parent!).
		// Fix it and return 0.
		//cprintf("\nIn child");
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	uint32_t pg;
	for(pg = 0; pg < PGNUM(UTOP-PGSIZE);pg++)
	{
		uint32_t pdx = ROUNDDOWN(pg, NPDENTRIES) / NPDENTRIES;
		if ((uvpd[pdx] & PTE_P) == PTE_P && ((uvpt[pg] & PTE_P) == PTE_P)) 
		//if((uvpd[PDX(pdx)] & PTE_P) && (uvpt[pg] & PTE_P))
		{
			duppage(envid, pg);
		}
	}

	if((r = sys_page_alloc(envid, (void *) (UXSTACKTOP - PGSIZE), PTE_P|PTE_U|PTE_W))<0)
		panic("Panic in pgfault in fork error:%e",r);

	if ((r = sys_env_set_pgfault_upcall(envid, _pgfault_upcall)) < 0)
		panic("sys_env_set_pgfault_upcall: %e\n", r);

	// Mark child environment as runnable
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e\n", r);

	return envid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
