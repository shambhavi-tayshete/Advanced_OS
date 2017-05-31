#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/spinlock.h>
#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>

void sched_halt(void);

// Choose a user environment to run and run it.
void
sched_yield(void)
{
	struct Env *idle;

	// Implement simple round-robin scheduling.
	//
	// Search through 'envs' for an ENV_RUNNABLE environment in
	// circular fashion starting just after the env this CPU was
	// last running.  Switch to the first such environment found.
	//
	// If no envs are runnable, but the environment previously
	// running on this CPU is still ENV_RUNNING, it's okay to
	// choose that environment.
	//
	// Never choose an environment that's currently running on
	// another CPU (env_status == ENV_RUNNING). If there are
	// no runnable environments, simply drop through to the code
	// below to halt the cpu.

	// LAB 4: Your code here.
	//cprintf("\n%x",thiscpu->cpu_env);

	int i =0;
	if(curenv == NULL)
	{
		
		for(i =0;i<NENV;i++)
		{
			if(envs[i].env_status == ENV_RUNNABLE)
			{
				//cprintf("\nValue of I:%d",i);
				env_run(&envs[i]);
			}
		}
	}
	else
	{
		envid_t id = curenv->env_id;
		int location = ENVX(id);
		int end = NENV;
		//cprintf("\nId in else:%d\n",location);
		i = location;
		//for(i=location;i<end;i++)
		while(i < end)
		{
			
			if(envs[i].env_status == ENV_RUNNABLE)
			{
				//cprintf("\nStatus of ENV 0: %d",envs[0].env_status);
				//cprintf("\nIn normal i:%d\n",i);
				env_run(&envs[i]);
			}
			if(i==NENV-1)
			{
				//cprintf("\nIn loop over,location=%d,i:%d",location,i);
				end = location;
				i=0;
				continue;
			}	
			i++;
		}

		//cprintf("\nIn else of scheduler");
	}
	if(curenv != NULL)
	{
		if(curenv->env_status == ENV_RUNNING)
		{
			env_run(curenv);
		}	
	}
	
	//int i = thiscpu->cpu_env->env_id;
	//cprintf("\nValue of i is:%d",i);
	// sched_halt never returns
	sched_halt();
}

// Halt this CPU when there is nothing to do. Wait until the
// timer interrupt wakes it up. This function never returns.
//
void
sched_halt(void)
{
	int i;

	// For debugging and testing purposes, if there are no runnable
	// environments in the system, then drop into the kernel monitor.
	for (i = 0; i < NENV; i++) {
		if ((envs[i].env_status == ENV_RUNNABLE ||
		     envs[i].env_status == ENV_RUNNING ||
		     envs[i].env_status == ENV_DYING))
			break;
	}
	if (i == NENV) {
		cprintf("No runnable environments in the system!\n");
		while (1)
			monitor(NULL);
	}

	// Mark that no environment is running on this CPU
	curenv = NULL;
	lcr3(PADDR(kern_pgdir));

	// Mark that this CPU is in the HALT state, so that when
	// timer interupts come in, we know we should re-acquire the
	// big kernel lock
	xchg(&thiscpu->cpu_status, CPU_HALTED);

	// Release the big kernel lock as if we were "leaving" the kernel
	unlock_kernel();

	// Reset stack pointer, enable interrupts and then halt.
	asm volatile (
		"movl $0, %%ebp\n"
		"movl %0, %%esp\n"
		"pushl $0\n"
		"pushl $0\n"
		"sti\n"
		"1:\n"
		"hlt\n"
		"jmp 1b\n"
	: : "a" (thiscpu->cpu_ts.ts_esp0));
}

