#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "child.h"
#include "debug.h"
#include "ftrace.h"
#include "log.h"
#include "params.h"
#include "pids.h"
#include "post-mortem.h"
#include "random.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"

static void handle_child(int childno, pid_t childpid, int childstatus);

static unsigned long hiscore = 0;

/*
 * Make sure various entries in the shm look sensible.
 * We use this to make sure that random syscalls haven't corrupted it.
 *
 * also check the pids for sanity.
 */
static int shm_is_corrupt(void)
{
	unsigned int i;

	if (shm->stats.op_count < shm->stats.previous_op_count) {
		output(0, "Execcount went backwards! (old:%ld new:%ld):\n",
			shm->stats.previous_op_count, shm->stats.op_count);
		panic(EXIT_SHM_CORRUPTION);
		return TRUE;
	}
	shm->stats.previous_op_count = shm->stats.op_count;

	for_each_child(i) {
		struct childdata *child;
		pid_t pid;

		child = shm->children[i];
		pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (pid_is_valid(pid) == FALSE) {
			static bool once = FALSE;

			if (once != FALSE)
				return TRUE;

			output(0, "Sanity check failed! Found pid %u at pidslot %u!\n", pid, i);

			dump_childnos();

			if (shm->exit_reason == STILL_RUNNING)
				panic(EXIT_PID_OUT_OF_RANGE);
			dump_childdata(child);
			once = TRUE;
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * reap_child: Remove all references to a running child.
 *
 * This can get called from two possible places.
 * 1. From reap_dead_kids if it finds reference to a pid that no longer exists.
 * 2. From handle_child() if it gets a SIGBUS or SIGSTOP from the child,
 *    or if it dies from natural causes.
 *
 * The reaper lock protects against these happening at the same time.
 */
void reap_child(struct childdata *child)
{
	/* Don't reap a child again */
	if( pids[child->num] == EMPTY_PIDSLOT )
		return;
	child->tp = (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };
	unlock(&child->syscall.lock);
	shm->running_childs--;
	pids[child->num] = EMPTY_PIDSLOT;
}

/* Make sure there's no dead kids lying around.
 * We need to do this in case the oom killer has been killing them,
 * otherwise we end up stuck with no child processes.
 */
static void reap_dead_kids(void)
{
	unsigned int i;
	unsigned int reaped = 0;

	for_each_child(i) {
		pid_t pid;
		int childstatus;

		pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		/* if we find corruption, just skip over it. */
		if (pid_is_valid(pid) == FALSE)
			continue;

		if (pid_alive(pid) == FALSE) {
			/* If it disappeared, reap it. */
			if (errno == ESRCH) {
				output(0, "pid %u has disappeared. Reaping.\n", pid);
				reap_child(shm->children[i]);
				reaped++;
			} else {
				output(0, "problem checking on pid %u (%d:%s)\n", pid, errno, strerror(errno));
			}
		}

		pid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		handle_child(i, pid, childstatus);

		if (shm->running_childs == 0)
			return;
	}

	if (reaped != 0)
		output(0, "Reaped %d dead children\n", reaped);
}

static void kill_all_kids(void)
{
	unsigned int i;
	int children_seen = 0;

	shm->spawn_no_more = TRUE;

	reap_dead_kids();

	if (shm->running_childs == 0)
		return;

	/* Ok, some kids are still alive. 'help' them along with a SIGKILL */
	for_each_child(i) {
		pid_t pid;

		pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		/* if we find corruption, just skip over it. */
		if (pid_is_valid(pid) == FALSE)
			continue;

		if (pid_alive(pid) == TRUE) {
			kill_pid(pid);
			children_seen++;
		} else {
			/* check we don't have anything stale in the pidlist */
			if (errno == ESRCH)
				reap_child(shm->children[i]);
		}
	}

	if (children_seen == 0)
		shm->running_childs = 0;

	/* Check that no dead children hold locks. */
	while (check_all_locks() == TRUE)
		reap_dead_kids();
}


/* if the first arg was an fd, find out which one it was.
 * Call with syscallrecord lock held. */
unsigned int check_if_fd(struct childdata *child, struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int fd;

	entry = get_syscall_entry(rec->nr, rec->do32bit);

	if ((entry->arg1type != ARG_FD) &&
	    (entry->arg1type != ARG_SOCKETINFO))
	    return FALSE;

	/* in the SOCKETINFO case, post syscall, a1 is actually the fd,
	 * not the socketinfo.  In ARG_FD a1=fd.
	 */
	fd = rec->a1;

	/* if it's out of range, it's not going to be valid. */
	if (fd > 1024)
		return FALSE;

	if (logging == LOGGING_FILES) {
		if (child->logfile == NULL)
			return FALSE;

		if (fd <= (unsigned int) fileno(child->logfile))
			return FALSE;
	}

	return TRUE;
}

/*
 * This is only ever used by the main process, so we cache the FILE ptr
 * for each child there, to save having to constantly reopen it.
 */
static FILE * open_child_pidstat(pid_t target)
{
	FILE *fp;
	char filename[80];

	sprintf(filename, "/proc/%d/stat", target);

	fp = fopen(filename, "r");

	return fp;
}

static char get_pid_state(struct childdata *child)
{
	size_t n = 0;
	char *line = NULL;
	pid_t pid;
	char state = '?';
	char *procname = zmalloc(100);

	if (getpid() != mainpid)
		BUG("get_pid_state can only be called from main!\n");

	fseek(child->pidstatfile, 0L, SEEK_SET);
	fflush(child->pidstatfile);

	if (getline(&line, &n, child->pidstatfile) != -1)
		sscanf(line, "%d %s %c", &pid, procname, &state);

	free(line);
	free(procname);
	return state;
}

static void dump_pid_stack(int pid)
{
	FILE *fp;
	char filename[80];

	sprintf(filename, "/proc/%d/stack", pid);

	fp = fopen(filename, "r");
	if (fp == NULL) {
		output(0, "Couldn't dump stack info for pid %d: %s\n", pid, strerror(errno));
		return;
	}

	while (!(feof(fp))) {
		size_t n = 0;
		char *line = NULL;
		if (getline(&line, &n, fp) != -1) {
			output(0, "pid %d stack: %s", pid, line);
			free(line);
			line = NULL;
			n = 0;
		} else {
			if (errno != EAGAIN)
				output(0, "Error reading /proc/%d/stack :%s\n", pid, strerror(errno));
			return;
		}
	}
	output(0, "------------------------------------------------\n");

	fclose(fp);
}

static void stuck_syscall_info(struct childdata *child)
{
	struct syscallrecord *rec;
	unsigned int callno;
	char fdstr[20];
	pid_t pid;
	bool do32;
	char state;

	pid = pids[child->num];

	if (shm->debug == FALSE)
		return;

	rec = &child->syscall;

	if (trylock(&rec->lock) == FALSE)
		return;

	do32 = rec->do32bit;
	callno = rec->nr;

	memset(fdstr, 0, sizeof(fdstr));

	state = rec->state;

	/* we can only be 'stuck' if we're still doing the syscall. */
	if (state == BEFORE) {
		if (check_if_fd(child, rec) == TRUE) {
			sprintf(fdstr, "(fd = %u)", (unsigned int) rec->a1);
			shm->fd_lifetime = 0;
			//close(rec->a1);
			//TODO: Remove the fd from the object list.
		}
	}

	unlock(&rec->lock);

	output(0, "child %d (pid %u. state:%d) Stuck in syscall %d:%s%s%s.\n",
		child->num, pid, state, callno,
		print_syscall_name(callno, do32),
		do32 ? " (32bit)" : "",
		fdstr);
	if (state >= BEFORE)
		dump_pid_stack(pid);
}

enum childprogress {
	/**
	 * @brief Child is not making progress
	 * 
	 */
	NO_PROGRESS = 0,
	/**
	 * @brief Empty slot, not forked yet
	 * 
	 */
	EMPTY_SLOT,
	/**
	 * @brief The syscall record is locked by the child
	 * 
	 */
	CANNOT_LOCK,
	/**
	 * @brief The state of the syscall record < BEFORE
	 * 
	 */
	BEFORE_BEFORE,
	/**
	 * @brief The child has a 0 timestamp
	 * 
	 */
	ZERO_TIMESTAMP,
	/**
	 * @brief The syscall is just called for no more than 30 seconds
	 * 
	 */
	NOT_YET_30_SEC,
	/**
	 * @brief Sentinel
	 * 
	 */
	MAX_PROGRESS,
};

/*
 * Check that a child is making forward progress by comparing the timestamps it
 * recorded before making its last syscall.
 * If no progress is being made, send SIGKILLs to it.
 */
static enum childprogress is_child_making_progress(struct childdata *child)
{
	struct syscallrecord *rec;
	struct timespec tp;
	time_t diff, old, now;
	pid_t pid;
	char state;

	pid = pids[child->num];

	if (pid == EMPTY_PIDSLOT)
		return EMPTY_SLOT;
	// bail if we've not done a syscall yet, we probably just haven't
	// been scheduled due to other pids hogging the cpu
	rec = &child->syscall;
	if (trylock(&rec->lock) == FALSE)
		return CANNOT_LOCK;

	if (rec->state < BEFORE) {
		unlock(&rec->lock);
		return BEFORE_BEFORE;
	}
	unlock(&rec->lock);

	old = child->tp.tv_sec;

	/* haven't done anything yet. */
	if (old == 0)
		return ZERO_TIMESTAMP;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	now = tp.tv_sec;

	if (old > now)
		diff = old - now;
	else
		diff = now - old;

	/* hopefully the common case. */
	if (diff < 30)
		return NOT_YET_30_SEC;

	/* if we're blocked in uninteruptible sleep, SIGKILL won't help. */
	state = get_pid_state(child);
	if (state == 'D') {
		//debugf("child %d (pid %u) is blocked in D state\n", child->num, pid);
		return NO_PROGRESS;
	}

	/* After 30 seconds of no progress, send a kill signal. */
	if (diff == 30) {
		stuck_syscall_info(child);
		debugf("child %d (pid %u) hasn't made progress in 30 seconds! Sending SIGKILL\n",
				child->num, pid);
		child->kill_count++;
		kill_pid(pid);
	}

	/* if we're still around after 40s, repeatedly send SIGKILLs every second. */
	if (diff < 40)
		return NO_PROGRESS;

	debugf("sending another SIGKILL to child %u (pid:%u). [kill count:%u] [diff:%lu]\n",
		child->num, pid, child->kill_count, diff);
	child->kill_count++;
	kill_pid(pid);

	return NO_PROGRESS;
}

/*
 * If we call this, all children are stalled. Randomly kill a few.
 */
static void stall_genocide(void)
{
	unsigned int killed = 0;
	unsigned int i;

	for_each_child(i) {
		pid_t pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (RAND_BOOL()) {
			if (pid_alive(pid) == TRUE) {
				kill_pid(pid);
				killed++;
			}
		}
		if (killed == (max_children / 4))
			break;
	}
}

static bool spawn_child(int childno)
{
	struct childdata *child = shm->children[childno];
	int pid = 0;

	/* a new child means a new seed, or the new child
	 * will do the same syscalls as the one in the child it's replacing.
	 * (special case startup, or we reseed unnecessarily)
	 */
	if (shm->ready == TRUE)
		reseed();

	/* Wipe out any state left from a previous child running in this slot. */
	clean_childdata(child);

	fflush(stdout);
	pid = fork();

	if (pid == 0) {
		child_process(child, childno);
		_exit(EXIT_SUCCESS);
	} else {
		if (pid == -1) {
			debugf("Couldn't fork a new child in pidslot %d. errno:%s\n",
					childno, strerror(errno));
			return FALSE;
		}
	}

	/* Child won't get out of init_child until we write the pid */
	pids[childno] = pid;
	int nr_fds = get_num_fds();
	if ((max_files_rlimit.rlim_cur - nr_fds) < 3)
	{
		// child->pidstatfile may be NULL below if fd limition is reached.
		outputerr("current number of fd: %d, please consider ulimit -n xxx to increase fd limition\n", nr_fds);
		panic(EXIT_NO_FDS);
	}
	child->pidstatfile = open_child_pidstat(pid);
	shm->running_childs++;

	debugf("Created child %d (pid:%d) [total:%d/%d]\n",
		childno, pid, shm->running_childs, max_children);
	return TRUE;
}

static void replace_child(int childno)
{
	if (shm->exit_reason != STILL_RUNNING)
		return;

	while (spawn_child(childno) == FALSE);
}

/* Generate children*/
static void fork_children(void)
{
	while (shm->running_childs < max_children) {
		int childno;

		if (shm->spawn_no_more == TRUE)
			return;

		/* Find a space for it in the pid map */
		childno = find_childno(EMPTY_PIDSLOT);
		if (childno == CHILD_NOT_FOUND) {
			outputerr("## Pid map was full!\n");
			dump_childnos();
			exit(EXIT_FAILURE);
		}

		if (spawn_child(childno) == FALSE) {
			outputerr("Couldn't fork initial children!\n");
			panic(EXIT_FORK_FAILURE);
			exit(EXIT_FAILURE);
		}

		if (shm->exit_reason != STILL_RUNNING)
			return;
	}
	shm->ready = TRUE;
}

static void handle_childsig(int childno, int childstatus, bool stop)
{
	struct childdata *child;
	int __sig;
	pid_t pid = pids[childno];

	child = shm->children[childno];

	if (stop == TRUE)
		__sig = WSTOPSIG(childstatus);
	else
		__sig = WTERMSIG(childstatus);

	switch (__sig) {
	case SIGSTOP:
		if (stop != TRUE)
			return;
		debugf("Sending PTRACE_DETACH (and then KILL)\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		kill_pid(pid);
		//FIXME: Won't we create a zombie here?
		reap_child(shm->children[childno]);
		replace_child(childno);
		return;

	case SIGALRM:
		debugf("got a alarm signal from child %d (pid %d)\n", childno, pid);
		break;
	case SIGFPE:
	case SIGSEGV:
	case SIGKILL:
	case SIGPIPE:
	case SIGABRT:
	case SIGBUS:
	case SIGILL:
		if (stop == TRUE)
			debugf("Child %d (pid %d) was stopped by %s\n",
					childno, pid, strsignal(WSTOPSIG(childstatus)));
		else {
			debugf("got a signal from child %d (pid %d) (%s)\n",
					childno, pid, strsignal(WTERMSIG(childstatus)));
		}
		reap_child(shm->children[childno]);
		if (child->pidstatfile)
			fclose(child->pidstatfile);
		child->pidstatfile = NULL;

		replace_child(childno);
		return;

	default:
		if (__sig >= SIGRTMIN) {
			debugf("Child %d got RT signal (%d). Ignoring.\n", pid, __sig);
			return;
		}

		if (stop == TRUE)
			debugf("Child %d was stopped by unhandled signal (%s).\n", pid, strsignal(WSTOPSIG(childstatus)));
		else
			debugf("** Child got an unhandled signal (%d)\n", WTERMSIG(childstatus));
		return;
	}
}

static void handle_child(int childno, pid_t childpid, int childstatus)
{
	switch (childpid) {
	case 0:
		//debugf("Nothing changed. children:%d\n", shm->running_childs);
		break;

	case -1:
		break;

	default:
		if (WIFEXITED(childstatus)) {
			struct childdata *child = shm->children[childno];

			debugf("Child %d (pid:%u) exited after %ld operations.\n",
				childno, childpid, child->op_nr);
			reap_child(shm->children[childno]);
			if (child->pidstatfile != NULL)
				fclose(child->pidstatfile);
			child->pidstatfile = NULL;

			replace_child(childno);
			break;

		} else if (WIFSIGNALED(childstatus)) {
			handle_childsig(childno, childstatus, FALSE);
		} else if (WIFSTOPPED(childstatus)) {
			handle_childsig(childno, childstatus, TRUE);
		} else if (WIFCONTINUED(childstatus)) {
			break;
		}
	}
}

static void handle_children(void)
{
	unsigned int i;
	sigset_t mask;
	sigset_t orig_mask;
	struct timespec timeout = { .tv_sec = 1 };
	int ret;

	if (shm->running_childs == 0)
		return;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0) {
		perror ("sigprocmask");
		return;
	}

	ret = sigtimedwait(&mask, NULL, &timeout);
	if (ret < 0) {
		// timeout, go do something else.
		if (errno == EAGAIN) {
			return;
		}
	}

	/* If we get this far, we either got EINTR, a SIGCHLD, or some other signal.
	 * in either case, let's see if the children have anything going on
	 */
	for_each_child(i) {
		int childstatus;
		pid_t pid;

		pid = pids[i];

		if (pid == EMPTY_PIDSLOT)
			continue;

		pid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		handle_child(i, pid, childstatus);
	}
}

/* Progress checking */
static unsigned int progress_counts[MAX_PROGRESS] = {
	[NO_PROGRESS] = 0,
	[EMPTY_SLOT] = 0,
	[CANNOT_LOCK] = 0,
	[BEFORE_BEFORE] = 0,
	[ZERO_TIMESTAMP] = 0,
	[NOT_YET_30_SEC] = 0
};
#define stall_count (progress_counts[NO_PROGRESS])
/* The ops report control (don't want duplicated checking) */

static void check_children_progressing(void)
{
	unsigned int i;

	stall_count = 0;
	progress_counts[EMPTY_SLOT] = 0;
	progress_counts[CANNOT_LOCK] = 0;
	progress_counts[BEFORE_BEFORE] = 0;
	progress_counts[ZERO_TIMESTAMP] = 0;
	progress_counts[NOT_YET_30_SEC] = 0;

	bool all_stalled = FALSE;

	for_each_child(i) {
		struct childdata *child = shm->children[i];

		enum childprogress prog = is_child_making_progress(child);
		if (prog < 0 || prog >= MAX_PROGRESS)
			panic(EXIT_IMPOSSIBLE);
		progress_counts[prog]++;

		if (child->op_nr > hiscore)
			hiscore = child->op_nr;
	}

	if (stall_count == shm->running_childs) {
		output(0, "All children are stalled. Randomly kill a few.\n");
		all_stalled = TRUE;
		stall_genocide();
	}

  /* Ops-based stall checking (because the code above may still miss some
	unknown cases) */
	static unsigned long lastcount = 0;
	static time_t lasttime = 0;
	struct timespec tp;
#ifdef CLOCK_MONOTONIC_COARSE
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tp);
#else
	clock_gettime(CLOCK_MONOTONIC, &tp);
#endif

	time_t time_diff = tp.tv_sec - lasttime;  // Time since last progress made
	if (shm->stats.op_count != lastcount) {
		// Good, at least it is changing
		// Save this checkpoint
		lastcount = shm->stats.op_count;
		lasttime = tp.tv_sec;
	} else if (time_diff >= 60 && all_stalled == FALSE) {
		// Indeed stalled for 60s, but `is_child_making_progress` said no
		// This is likely a bug of Trinity, or we trigerred some kernel bug
		output(0, "Children is making 0 progress for 60 seconds, "
			"but we only have %u stalled process(es), and\n"
			"  %u empty slot(s)\n"
			"  %u process(es) that can't be locked\n"
			"  %u process(es) that not yet reached BEFORE state\n"
			"  %u process(es) reporting 0 timestamp(s)\n"
			"  %u process(es) magically said to have just issued a syscall for "
			"less then 30 seconds\n", progress_counts[NO_PROGRESS],
			progress_counts[EMPTY_SLOT],
			progress_counts[CANNOT_LOCK],
			progress_counts[BEFORE_BEFORE],
			progress_counts[ZERO_TIMESTAMP],
			progress_counts[NOT_YET_30_SEC]);
		panic(EXIT_POSSIBLE_BUG);
	}
	/* Otherwise, 0 new ops but 1) not yet 60 seconds, or 2) stall is detected by
	`is_child_making_progress` normally, do nothing */
}

static void print_stats(void)
{
	if (shm->stats.op_count > 1) {
		static unsigned long lastcount = 0;
		static time_t lastreport = 0;  // Last report time in seconds
		struct timespec tp;
#ifdef CLOCK_MONOTONIC_COARSE
		clock_gettime(CLOCK_MONOTONIC_COARSE, &tp);
#else
		clock_gettime(CLOCK_MONOTONIC, &tp);
#endif

		unsigned long newops = shm->stats.op_count - lastcount;
		if (newops > 10000 || \
				/* Report at least once per 60s, but keep silent if little progress */
				(newops > 30 && tp.tv_sec - lastreport > 60)) {
			char stalltxt[]=" STALLED:XXXX";

			if (stall_count > 0 && stall_count < 10000)
				sprintf(stalltxt, " STALLED:%u", stall_count);
			output(0, "[%llu.%u] %ld iterations. [F:%ld S:%ld HI:%ld%s]\n",
				tp.tv_sec, tp.tv_nsec,
				shm->stats.op_count,
				shm->stats.failures, shm->stats.successes,
				hiscore,
				stall_count ? stalltxt : "");
			lastcount = shm->stats.op_count;
			lastreport = tp.tv_sec;
		}
	}
}

static bool handled_taint = FALSE;

static void taint_check(void)
{
	if (handled_taint == TRUE)
		return;

	if (is_tainted() == TRUE) {
		stop_ftrace();
		tainted_postmortem();
		handled_taint = TRUE;
	}
}

void main_loop(void)
{
	fork_children();

	while (shm->exit_reason == STILL_RUNNING) {

		handle_children();

		taint_check();

		if (shm_is_corrupt() == TRUE)
			goto corrupt;

		while (check_all_locks() == TRUE) {
			reap_dead_kids();
			if (shm->exit_reason == EXIT_REACHED_COUNT)
				kill_all_kids();
		}

		if (syscalls_todo && (shm->stats.op_count >= syscalls_todo)) {
			output(0, "Reached limit %lu. Telling children to exit.\n", syscalls_todo);
			panic(EXIT_REACHED_COUNT);
		}

		check_children_progressing();

		print_stats();

		/* This should never happen, but just to catch corner cases, like if
		 * fork() failed when we tried to replace a child.
		 */
		if (shm->running_childs < max_children)
			fork_children();
	}

	/* if the pid map is corrupt, we can't trust that we'll
	 * ever successfully finish pidmap_empty, so skip it */
	if ((shm->exit_reason == EXIT_LOST_CHILD) ||
	    (shm->exit_reason == EXIT_SHM_CORRUPTION))
		goto dont_wait;

	handle_children();

	/* Are there still children running ? */
	while (pidmap_empty() == FALSE) {
		static unsigned int last = 0;

		if (last != shm->running_childs) {
			last = shm->running_childs;

			output(0, "exit_reason=%d, but %d children still running.\n",
				shm->exit_reason, shm->running_childs);
		}

		/* Wait for all the children to exit. */
		while (shm->running_childs > 0) {
			taint_check();

			handle_children();
			kill_all_kids();
			/* Give children a chance to exit before retrying. */
			sleep(1);
		}
		reap_dead_kids();
	}

corrupt:
	kill_all_kids();

dont_wait:
	output(0, "Bailing main loop because %s.\n", decode_exit(shm->exit_reason));
}


/*
 * Something potentially bad happened. Alert all processes by setting appropriate shm vars.
 * (not always 'bad', reaching max count for eg is one example).
 */
void panic(int reason)
{
	shm->spawn_no_more = TRUE;
	shm->exit_reason = reason;
}
