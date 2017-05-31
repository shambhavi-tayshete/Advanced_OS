/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
TRAPHANDLER_NOEC(trap_Divide_error, T_DIVIDE)
TRAPHANDLER_NOEC(trap_debug,T_DEBUG)
TRAPHANDLER_NOEC(trap_non_maskable_Interrupt,T_NMI)
TRAPHANDLER_NOEC(trap_breakpoint,T_BRKPT)
TRAPHANDLER_NOEC(trap_overflow,T_OFLOW)
TRAPHANDLER_NOEC(trap_bound_Range_Exceeded,T_BOUND)
TRAPHANDLER_NOEC(trap_invalid_Opcode,T_ILLOP)
TRAPHANDLER_NOEC(trap_device_Not_Available,T_DEVICE)
TRAPHANDLER_NOEC(trap_double_Fault,T_DBLFLT)
TRAPHANDLER(trap_invalid_TSS,T_TSS)
TRAPHANDLER(trap_segment_Not_Present,T_SEGNP)
TRAPHANDLER(trap_stack_Fault,T_STACK)
TRAPHANDLER(trap_general_Protection,T_GPFLT)
TRAPHANDLER(trap_PG, T_PGFLT)
TRAPHANDLER_NOEC(trap_FPU,T_FPERR)
TRAPHANDLER_NOEC(trap_alignment_Check,T_ALIGN)
TRAPHANDLER_NOEC(trap_machine_check,T_MCHK)
TRAPHANDLER_NOEC(trap_simd_FPE,T_SIMDERR)
//sys call
TRAPHANDLER_NOEC(system_call,T_SYSCALL)

TRAPHANDLER_NOEC(irq_0,IRQ_OFFSET+IRQ_TIMER)  //0
TRAPHANDLER_NOEC(irq_1,IRQ_OFFSET+IRQ_KBD)
TRAPHANDLER_NOEC(irq_2,IRQ_OFFSET+2)
TRAPHANDLER_NOEC(irq_3,IRQ_OFFSET+3)
TRAPHANDLER_NOEC(irq_4,IRQ_OFFSET+IRQ_SERIAL)
TRAPHANDLER_NOEC(irq_5,IRQ_OFFSET+5)
TRAPHANDLER_NOEC(irq_6,IRQ_OFFSET+6)
TRAPHANDLER_NOEC(irq_7,IRQ_OFFSET+IRQ_SPURIOUS)
TRAPHANDLER_NOEC(irq_8,IRQ_OFFSET+8)
TRAPHANDLER_NOEC(irq_9,IRQ_OFFSET+9)
TRAPHANDLER_NOEC(irq_10,IRQ_OFFSET+10)
TRAPHANDLER_NOEC(irq_11,IRQ_OFFSET+11)
TRAPHANDLER_NOEC(irq_12,IRQ_OFFSET+12)
TRAPHANDLER_NOEC(irq_13,IRQ_OFFSET+13)
TRAPHANDLER_NOEC(irq_14,IRQ_OFFSET+IRQ_IDE)
TRAPHANDLER_NOEC(irq_15,IRQ_OFFSET+15)






/*
 * Lab 3: Your code here for _alltraps
 */
 _alltraps:
 	pushl %ds
	pushl %es
	pushal
	
	movl $GD_KD, %eax
	movw %ax, %ds
	movw %ax, %es

	pushl %esp
	//cli				//Mostly this is wrong, 
					//but I do not know how the interrupts would be automatically disabled when in kernel mode.
	call trap
 
 
 

