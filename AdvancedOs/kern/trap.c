#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>
#include <kern/time.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


void trap_Divide_error();
void trap_debug();
void trap_non_maskable_Interrupt();
void trap_breakpoint();
void trap_overflow();
void trap_bound_Range_Exceeded();
void trap_invalid_Opcode();
void trap_device_Not_Available();
void trap_double_Fault();
void trap_invalid_TSS();
void trap_segment_Not_Present();
void trap_stack_Fault();
void trap_general_Protection();
void trap_PG();
void trap_FPU();
void trap_alignment_Check();
void trap_machine_check();
void trap_simd_FPE();
void system_call();
void irq_0();
void irq_1();
void irq_2();
void irq_3();
void irq_4();
void irq_5();
void irq_6();
void irq_7();
void irq_8();
void irq_9();
void irq_10();
void irq_11();
void irq_12();
void irq_13();
void irq_14();
void irq_15();



static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	SETGATE(idt[T_DIVIDE], 0, GD_KT, trap_Divide_error, 0);
	SETGATE(idt[T_DEBUG], 0, GD_KT, trap_debug, 0);
	SETGATE(idt[T_NMI], 0, GD_KT, trap_non_maskable_Interrupt, 0);
	SETGATE(idt[T_BRKPT], 0, GD_KT, trap_breakpoint, 3);
	SETGATE(idt[T_OFLOW], 0, GD_KT, trap_overflow, 0);
	SETGATE(idt[T_BOUND], 0, GD_KT, trap_bound_Range_Exceeded, 0);
	SETGATE(idt[T_ILLOP], 0, GD_KT, trap_invalid_Opcode, 0);
	SETGATE(idt[T_DEVICE], 0, GD_KT, trap_device_Not_Available, 0);
	SETGATE(idt[T_DBLFLT], 0, GD_KT, trap_double_Fault, 0);
	SETGATE(idt[T_TSS], 0, GD_KT, trap_invalid_TSS, 0);
	SETGATE(idt[T_SEGNP], 0, GD_KT, trap_segment_Not_Present, 0);
	SETGATE(idt[T_STACK], 0, GD_KT, trap_stack_Fault, 0);
	SETGATE(idt[T_GPFLT], 0, GD_KT, trap_general_Protection, 0);
	SETGATE(idt[T_PGFLT], 0, GD_KT, trap_PG, 0);
	SETGATE(idt[T_FPERR], 0, GD_KT, trap_FPU, 0);
	SETGATE(idt[T_ALIGN], 0, GD_KT, trap_alignment_Check, 0);
	SETGATE(idt[T_MCHK], 0, GD_KT, trap_machine_check, 0);
	SETGATE(idt[T_SIMDERR], 0, GD_KT, trap_simd_FPE, 0);
	//sys call
	SETGATE(idt[T_SYSCALL], 0, GD_KT, system_call, 3);
	
	SETGATE(idt[IRQ_OFFSET+0], 0, GD_KT, irq_0, 0);
	SETGATE(idt[IRQ_OFFSET+1], 0, GD_KT, irq_1, 0);
	SETGATE(idt[IRQ_OFFSET+2], 0, GD_KT, irq_2, 0);
	SETGATE(idt[IRQ_OFFSET+3], 0, GD_KT, irq_3, 0);
	SETGATE(idt[IRQ_OFFSET+4], 0, GD_KT, irq_4, 0);
	SETGATE(idt[IRQ_OFFSET+5], 0, GD_KT, irq_5, 0);
	SETGATE(idt[IRQ_OFFSET+6], 0, GD_KT, irq_6, 0);
	SETGATE(idt[IRQ_OFFSET+7], 0, GD_KT, irq_7, 0);
	SETGATE(idt[IRQ_OFFSET+8], 0, GD_KT, irq_8, 0);
	SETGATE(idt[IRQ_OFFSET+9], 0, GD_KT, irq_9, 0);
	SETGATE(idt[IRQ_OFFSET+10], 0, GD_KT, irq_10, 0);
	SETGATE(idt[IRQ_OFFSET+11], 0, GD_KT, irq_11, 0);
	SETGATE(idt[IRQ_OFFSET+12], 0, GD_KT, irq_12, 0);
	SETGATE(idt[IRQ_OFFSET+13], 0, GD_KT, irq_13, 0);
	SETGATE(idt[IRQ_OFFSET+14], 0, GD_KT, irq_14, 0);
	SETGATE(idt[IRQ_OFFSET+15], 0, GD_KT, irq_15, 0);



	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:

	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - (cpunum() * (KSTKSIZE + KSTKGAP));
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	//ts.ts_esp0 = KSTACKTOP;
	//thiscpu->cpu_ts.ts_ss0 = GD_KD;

	// Initialize the TSS slot of the gdt.
	gdt[(GD_TSS0 >> 3) + cpunum()] = SEG16(STS_T32A, (uint32_t) (&thiscpu->cpu_ts),
					sizeof(struct Taskstate) - 1, 0);
	gdt[(GD_TSS0 >> 3) + cpunum()].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0 + (thiscpu->cpu_id << 3));

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) 
	{
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.


	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	uint32_t syscallNO, a1, a2, a3, a4, a5;
	switch(tf->tf_trapno)
	{
		case T_PGFLT:
			page_fault_handler(tf);
			break;
		case T_BRKPT:
			//print_trapframe(tf);
			monitor(NULL);
			break;
		case T_SYSCALL:
			
			
			syscallNO = tf->tf_regs.reg_eax;
			a1 = tf->tf_regs.reg_edx;
			a2 = tf->tf_regs.reg_ecx;
			a3 = tf->tf_regs.reg_ebx;
			a4 = tf->tf_regs.reg_edi;
			a5 = tf->tf_regs.reg_esi;
			tf->tf_regs.reg_eax = syscall(syscallNO, a1,a2,a3,a4,a5);
			break;
		// Handle clock interrupts. Don't forget to acknowledge the
		// interrupt using lapic_eoi() before calling the scheduler!
		// LAB 4: Your code here.
		// Add time tick increment to clock interrupts.
		// Be careful! In multiprocessors, clock interrupts are
		// triggered on every CPU.
		// LAB 6: Your code here.
		case IRQ_OFFSET+IRQ_TIMER:
			//cprintf("In timer interrupt case\n");
			lapic_eoi();
			time_tick(cpunum());
			sched_yield();
			break;
		// Handle keyboard and serial interrupts.
		// LAB 5: Your code here.
		case (IRQ_OFFSET+IRQ_KBD):
			//cprintf("in kbd");
			kbd_intr();
			break;
		case (IRQ_OFFSET+IRQ_SERIAL):
			//cprintf("in serial");
			serial_intr();
			break;
		default:
			cprintf("\nIn default trap case. The code should not reach here");
			print_trapframe(tf);
			if (tf->tf_cs == GD_KT)
				panic("unhandled trap in kernel");
			else 
			{
				env_destroy(curenv);
				return;
			}
	}	
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");


	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();

	///cprintf("Current ENV Status:%d\nRUNNING VALUE:%d\n",curenv->env_status,ENV_RUNNING);
	//print_trapframe(tf);
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));   // I have bypassed this assert by calling cli in the all traps function. 
										//Not sure how it will work otherwise.
										//Check..!! Check..!!

	
	
	//cprintf("Incoming TRAP frame at %p\n", tf);
	//print_trapframe(tf);
	

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		assert(curenv);
		lock_kernel();
		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);


	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();

	
	// Return to the current environment, which should be running.
	assert(curenv && curenv->env_status == ENV_RUNNING);
	env_run(curenv);

}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if ((tf->tf_cs & 3) == 0)
	{
		print_trapframe(tf);
		panic("Page Fault in kernel mode");
	}
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
	if(curenv->env_pgfault_upcall == NULL || tf->tf_esp > UXSTACKTOP || 
		(tf->tf_esp > USTACKTOP && tf->tf_esp < UXSTACKTOP - PGSIZE))
	{
		cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
		print_trapframe(tf);
		env_destroy(curenv);
	}

	uint32_t x_stacktop;

	if(tf->tf_esp < USTACKTOP) //First call to user pagefault. Need to change the stack from user stack to exception stack.
	{
		x_stacktop = UXSTACKTOP - sizeof(struct UTrapframe); // The minus denotes that the handler can use the stack once the kernel has
															 // put the Usertrapframe onto the UX stack.
	}
	else		//We are in recursive user pagefault. Allocate 1 word for scratch space as memtioned in the comments.
	{
		x_stacktop = tf->tf_esp - sizeof(struct UTrapframe) - 4;   //the 4 denotes the 1 word scratch space.
	}

	user_mem_assert(curenv, (void *) x_stacktop, PGSIZE, PTE_W | PTE_U);   //check for the x_stacktop for memory errors. Check for 1 page.

	struct UTrapframe *utp = (struct UTrapframe *)x_stacktop;

	utp->utf_fault_va = fault_va;
	utp->utf_err = tf->tf_err;
	utp->utf_regs = tf->tf_regs;
	utp->utf_eip = tf->tf_eip;
	utp->utf_eflags = tf->tf_eflags;
	utp->utf_esp = tf->tf_esp;


	//Change the stack and the eip of this trapframe and maybe run the upcall

	tf->tf_esp = (uintptr_t)x_stacktop;
	tf->tf_eip = (uintptr_t)curenv->env_pgfault_upcall;

	env_run(curenv);



	// Destroy the environment that caused the fault.
	/*cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);*/
}

