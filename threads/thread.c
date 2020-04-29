#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/fixed_point.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210
//Nested depth_limit
#define DEPTH_MAX 8

#define NICE_INIT 0
#define RECENT_CPU_INIT 0
#define LOAD_AVG_INIT 0

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/*List of sleeping threads*/
static struct list sleeping_threads;

/*List of all process*/
static struct list process_list;


/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);
static int64_t next_awake_tick;

int load_avg;

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };


/*getter and setter for the next_awake_tick
*/
void set_next_awake_tick(int64_t new_next){
	if(new_next < next_awake_tick){
		next_awake_tick = new_next;
	}
}
int64_t get_next_awake_tick(void){
    return next_awake_tick;
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);
    list_init (&sleeping_threads);
    list_init (&process_list);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);
    load_avg = LOAD_AVG_INIT;
	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/*File descriptor part*/
	t->next_fd = 2;
	t->fd_table = palloc_get_page(0);
	if(t->fd_table ==NULL)
		return TID_ERROR;
	/*Child, parent Relationship */
	t->parent = thread_current();
	t->success_load = 0;
	t->process_exit = 0;

	sema_init(&(t->load_sema), 0);
	sema_init(&(t->exit_sema), 0);
	
	list_push_back(&thread_current()->child, &t->child_elem);



	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;



	/* Add to run queue. */
	thread_unblock (t);
    swap_working();
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

bool thread_compare_waketime(struct list_elem * x, struct list_elem * y, void *aux){
	struct thread * X_thread = list_entry(x, struct thread, elem);
	struct thread * Y_thread = list_entry(y, struct thread, elem);
	if(X_thread -> wake_time < Y_thread -> wake_time)
		return true;
	else if(X_thread -> wake_time == Y_thread -> wake_time){
		//compare the priority
		if(X_thread -> priority < Y_thread -> priority)
			return true;
		else
			return false;
	}
	else
		return false;
}
bool thread_compare_priority(struct list_elem *x, struct list_elem *y, void*aux){
    struct thread * X_thread = list_entry(x, struct thread, elem);
    struct thread * Y_thread = list_entry(y, struct thread, elem);
    if(X_thread->priority > Y_thread->priority)
        return true;
    else
        return false;
}
/* Puts the thread to be asleep until some point of tick.
 Input: The waking time tick
 */
void thread_sleep(int64_t waking_tick){
    //When putting the thread to sleep we want to disable interrupts so that it isn't bothered
    enum intr_level old = intr_get_level();
    struct thread * current_thread = thread_current();
	intr_set_level(INTR_OFF);
    ASSERT(current_thread != idle_thread);
    
    current_thread -> wake_time = waking_tick;
	set_next_awake_tick(waking_tick);
	//putting threads in the list in order
    list_insert_ordered(&sleeping_threads,&current_thread->elem,thread_compare_waketime,NULL);
    thread_block();
    intr_set_level(old);
}

/*Wakes the threads on the sleeping list that passed the signal_tick
 For example for each threads, if each 	threads have waking time of
 2,3,4, 43, 123
 and the signal_tick is 44, we unblock the 2,3,4, 43 thread
 */
void thread_awake(int64_t signal_tick){
    struct list_elem *e;
    //traverse the list
    for(e=list_begin(&sleeping_threads);e != list_end(&sleeping_threads);){
		struct thread * temp = list_entry(e,struct thread, elem);

		//If the signal_tick that is given is bigger or same than the current tick, then it should wake up.
		if(signal_tick >= (temp->wake_time)){
			e = list_remove(&temp->elem);
			thread_unblock(temp);
		}else{
			e = list_next(e);
			set_next_awake_tick(temp->wake_time);
		}
	}
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
    //should change the priority as soon as it is unblocked
    list_insert_ordered(&ready_list, &t->elem, thread_compare_priority,NULL);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	struct thread *t = thread_current();
    list_remove(&t->process_elem); /*clear the list of all process*/
	
	/* tell the process descriptor that the process is done*/
	t->process_exit = 1;
	/* now the parent process is done with waiting.*/
	sema_up(&t->exit_sema);
	
	
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
        list_insert_ordered(&ready_list, &curr->elem, thread_compare_priority, NULL);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/*Since the ready list is ordered in the order of the high priority -> low priority, compare current_thread and the ready thread and yield it if the ready priority is bigger than the current one.
*/
void swap_working(void){
    if(!list_empty(&ready_list)){
        struct list_elem * first = list_begin(&ready_list);
        struct thread * first_thread = list_entry(first, struct thread, elem);
        if(thread_current()->priority < first_thread-> priority)
            thread_yield();
    }
}
/* Sets the current thread's priority to NEW_PRIORITY.
   If the priority of the thread changes, we need to check if it is somewhat different from the original priority. After updating the priority, we should immediately check it with the locks currently waiting for the possessed lock. (priority might change) After we get the refreshed_prioity,
    If it smaller than the original one, check if other processes in the waiting queue has higher priority (preemptive)
    If bigger, give the other threads that posess the lock the priority changed inforamtion.
    If same, no other processes are needed.
    Should not work when mlfqs is present
 */
void
thread_set_priority (int new_priority) {
    if(!thread_mlfqs){
        struct thread * cur = thread_current();
        enum intr_level old = intr_get_level();
        intr_set_level(INTR_OFF);
        int orig_pri = cur->priority;
        cur->original_priority = new_priority;
        refresh_priority();
        if(orig_pri > cur->priority)
            swap_working();
        if(orig_pri<cur->priority)
            donate_priority();
        intr_set_level(old);
    }
    
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE.
        interrupts are disabled for nice/load_avg operations
 */
void
thread_set_nice (int nice ) {
    intr_disable();
    if(nice>20) nice=20;
    if(nice<-20) nice = -20;
    thread_current() -> nice = nice;
    intr_enable();
    mlfqs_recent_cpu(thread_current());
    mlfqs_priority(thread_current());
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
    intr_disable();
    int cur_nice = thread_current()->nice;
    intr_enable();
	return cur_nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	intr_disable();
    int cur_load_avg = FP_TO_INT_ROUND(MULT_FI(load_avg,100));
    intr_enable();
    return cur_load_avg;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	intr_disable();
    int cur_recent_cpu = FP_TO_INT_ROUND(MULT_FI(thread_current()->recent_cpu,100));
    intr_enable();
    return cur_recent_cpu;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);

	t->magic = THREAD_MAGIC;
    list_push_back(&process_list,&t->process_elem);

    t->priority = priority;
    t->original_priority = priority;
    
    t->want_lock = NULL;
    list_init(&t->donation);
    if(thread_mlfqs){
        /* Differ whether it is initial or not*/
        if(t==initial_thread){
            t->nice = NICE_INIT;
            t->recent_cpu = RECENT_CPU_INIT;
        }
        else{
            t->nice = thread_current()->nice;
            t->recent_cpu = thread_current()->recent_cpu;
        }
    }


	list_init(&t->child);


	
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			/* shouuld delete process descriptor */
			palloc_free_page(curr);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

void remove_lock(struct lock *lock){

    struct thread *t;
    struct list_elem *e;
    struct thread *cur = thread_current();
    for(e= list_begin(&cur->donation); e != list_end(&cur->donation);){
        t = list_entry(e,struct thread, donation_elem);
        if(t->want_lock == lock)
            e = list_remove(e);
        else
            e = list_next(e);
    }
}
/*
 After erasing the thread due to lock, or if there is a change in priority we should change the priority.
 If the priority of the other waiting thread is higher then we tend to change the priority to that value, else just let it be the original one.
 */
void refresh_priority(void){

    struct thread * cur = thread_current();
    struct thread * first;
    //change the priority to the original priority since the thread is erased.
    cur->priority = cur->original_priority;
    if(list_empty(&cur->donation))
        return;

    else{
        first = list_entry(list_begin(&cur->donation), struct thread, donation_elem);
        if(first->priority > cur->priority)
            cur->priority = first->priority;
    }
}

/*
 When donation happens, the current thread priority should be higher
 */
void donate_priority(void){

    int depth = 0;
    struct thread * cur = thread_current();
    struct lock * temp_lock = cur->want_lock;
    while(temp_lock != NULL && depth < DEPTH_MAX){
        depth++;
        //No lock holder
        if(temp_lock->holder == NULL) return;
        if(temp_lock->holder->priority >= cur->priority) return;
        temp_lock->holder->priority = cur->priority;
        temp_lock = temp_lock->holder->want_lock;
    }
}
/*
 Check if it is idle and going to get the priority
 priority = PRI_MAX - recent_cpu/4-nice*2
 */
void mlfqs_priority(struct thread *t){
    if(t==idle_thread) return;
    int m_priority = 0;
    int max_pri = INT_TO_FP(PRI_MAX);
    int recent_cpu_d4 = DIV_FI(t->recent_cpu,4);
    int nice_doubled = MULT_FI(INT_TO_FP(t->nice),2);
    
    m_priority = SUB_FP(max_pri,recent_cpu_d4);
    m_priority = SUB_FP(m_priority,nice_doubled);
    if(m_priority>max_pri) m_priority = max_pri;
    if(m_priority<PRI_MIN) m_priority = PRI_MIN;
    t->priority = m_priority;
}
/*
 Check if it is idle and do the calc. recent_cpu = 2*load_avg/(2*load_avg+1) * recent_cpu +nice
 */
void mlfqs_recent_cpu(struct thread *t){
    if(t==idle_thread) return;
    int m_recent_cpu=0;
    int load_avg_doubled = MULT_FI(load_avg,2);
    int load_avg_doubled_plus_one = ADD_FI(load_avg_doubled, 1);
    int temp_recent_cpu = t->recent_cpu;
    int m_nice = INT_TO_FP(t->nice);
    int former = DIV_FP(load_avg_doubled,load_avg_doubled_plus_one);
    former = MULT_FP(former, temp_recent_cpu);
    m_recent_cpu = ADD_FP(former,m_nice);
    t->recent_cpu = m_recent_cpu;
}
/*
 Calculate the load average by the calc 59/60 * load_avg+1/60*ready_threads
 should be bigger than zero. SHould be initialized at system boot
 */
void mlfqs_load_avg(void){
    int coeff_former= DIV_FP(INT_TO_FP(59), INT_TO_FP(60));
    int before_lavg = load_avg;
    int coeff_ladder = DIV_FP(INT_TO_FP(1), INT_TO_FP(60));
    int ready_threads_count = INT_TO_FP(count_ready_threads());
    int former = MULT_FP(coeff_former,before_lavg);
    int ladder = MULT_FP(coeff_ladder,ready_threads_count);
    load_avg = ADD_FP(former,ladder);
    if(load_avg<0) load_avg = 0;
}
/*
 Also idle thread test needed +should increment recent_cpu value by 1
 */
void mlfqs_increment(void){
    if(thread_current()==idle_thread) return;
    thread_current()->recent_cpu = ADD_FI(thread_current()->recent_cpu, 1);
}

/*
 recalculate all the priiority and the recent_cpu value'
 It seems that I need a list of all scheduled processes.
 */
void mlfqs_recalc(void){
    struct list_elem *e;
    mlfqs_load_avg();
    for (e = list_begin(&process_list); e!=list_end(&process_list); e = list_next(e)){
        struct thread *thread_each = list_entry(e,struct thread, process_elem);
        mlfqs_recent_cpu(thread_each);
        mlfqs_priority(thread_each);
    }
}


int count_ready_threads(void){
   int cnt = list_size(&ready_list);
    if(thread_current() != idle_thread) cnt++;
    return cnt;
}
