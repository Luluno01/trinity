#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>  // struct in_addr
#include "kcov.h"
#include "types.h"
#include "locks.h"


#define CHECK_SEND_LOCK 1

int kcovfd;
/**
 * Dump coverage to a file on disk
 */
int kcovDumpFd;

unsigned long *cover;
#if CHECK_SEND_LOCK
/**
 * One coverage server connection is supposed to be bound to only one thread,
 * (and Trinity use one thread in one child process, right?) but sometimes the
 * thread behaves really weird - the sending cursor shifts back and forth by 4
 * or 1 bytes, resulting in wrong PC values like 0xffff81001156 (an extra byte
 * `0x56`), 0xffff810011ff (an extra byte `0xff`, or 1 lower byte skipped)
 * 0x8100112281002233 (4 higher bytes `0xffffffff` skipped after sending the
 * lower bytes `0x81002233`), or 0x81001122ffffffff (4 lower bytes in previous
 * PC value skipped)
 * 
 * The true reason is still unknown, but let's use this to detect and abort on
 * any violation of our assumption
 * 
 * And, one more thing, the implementation of this lock is not a true lock but
 * still kind of works in this case
 */
lock_t send_lock = {
	.lock = UNLOCKED,
	.owner = 0
};
#endif
unsigned long last_cover_count = 0;
/**
 * Not really a guard, but hopefully when we see this in the coverage, we know
 * there was an underflow
 */
unsigned long guard = 0xdeadbeaf;
unsigned long last_cover[COVER_SIZE];
bool enabled = FALSE;

struct sockaddr_in cov_server = { sin_family: AF_INET };
int cov_server_sock = -1;

/* Private function */
void send_cov(void);

void init_kcov(void)
{
	/* A single fd descriptor allows coverage collection on a single
	 * thread.
	 */
	kcovfd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kcovfd == -1) {
		printf("Failed to open kcov file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
		return;
	}

	/* Setup trace mode and trace size. */
	if (ioctl(kcovfd, KCOV_INIT_TRACE, COVER_SIZE)) {
		printf("Failed to init kcov: %s\n", strerror(errno));
		goto fail;
	}
	/* Mmap buffer shared between kernel- and user-space. */
	cover = (unsigned long*)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
				     PROT_READ | PROT_WRITE, MAP_SHARED, kcovfd, 0);
	if ((void*)cover == MAP_FAILED) {
		printf("Failed to mmap kcov buffer: %s\n", strerror(errno));
		goto fail;
	}
	printf("kcov buffer: %p\n", cover);
	
	return;

fail:
	close(kcovfd);
	kcovfd = -1;
	exit(EXIT_FAILURE);
	return;
}

void enable_kcov(void)
{
	/* Enable coverage collection on the current thread. */
	if (ioctl(kcovfd, KCOV_ENABLE, 0))
		printf("Error enabling kcov: %s\n", strerror(errno));

	/* Reset coverage from the tail of the ioctl() call. */
	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
	enabled = TRUE;
}

void reset_kcov(void)
{
	/* Reset coverage from the tail of the ioctl() call. */
	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
}

void dump_kcov_buffer(void)
{
	unsigned long n, i;

	/* Read number of PCs collected. */
	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
	for (i = 0; i < n; i++)
		printf("0x%lx\n", cover[i + 1]);
}

void disable_kcov(void)
{
	if (!enabled) return;
	/* Disable coverage collection for the current thread. After this call
	 * coverage can be enabled for a different thread.
	 */
	if (ioctl(kcovfd, KCOV_DISABLE, 0))
		printf("Failed to disable kcov: %s\n", strerror(errno));
	enabled = FALSE;
}

/**
 * Enable KCOV if it is disabled, or reset the buffer if it is already enabled
 */
void start_kcov(void) {
	if (enabled) {
		reset_kcov();
	} else {
		enable_kcov();
	}
}

/**
 * Make a copy of current coverage, disable KCOV and send collected coverage if it is enabled
 */
void stop_kcov(void) {
	if (enabled) {
		/* Read number of PCs collected. */
		last_cover_count = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
		memcpy(last_cover, cover + 1, last_cover_count * sizeof(unsigned long));
		disable_kcov();
		send_cov();
	}
}

void shutdown_kcov(void)
{
	if (kcovfd == -1)
		return;

	if (munmap(cover, COVER_SIZE * sizeof(unsigned long)))
		printf("Couldn't munmap kcov buffer : %s\n", strerror(errno));

	cover = NULL;

	if (close(kcovfd))
		printf("Couldn't close kcov fd (%d) : %s\n", kcovfd, strerror(errno));
	kcovfd = -1;
}

/**
 * Connect to coverage server
 */
void connect_cov_server(void) {
	if (cov_server_sock != -1) return;
	if ((cov_server_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("Cannot create socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
		return;
	}
	printf("Coverage server socket: %d\n", cov_server_sock);
	if (connect(cov_server_sock, &cov_server, sizeof(cov_server)) != 0) {
		printf("Cannot connect to coverage server %s:%hu: %s\n", inet_ntoa(cov_server.sin_addr), ntohs(cov_server.sin_port), strerror(errno));
		exit(EXIT_FAILURE);
		return;
	}
}

/**
 * Disconnect from coverage server
 */
void disconnect_cov_server(void) {
	if (cov_server_sock == -1) return;
	close(cov_server_sock);
	cov_server_sock = -1;
}

void send_all(int socket, void *buffer, size_t length) {
	char *ptr = (char*) buffer;
	while (length > 0) {
		int i = send(socket, ptr, length, 0);
		if (i < 1) {
			printf("Cannot send coverage data via the socket: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		};
		ptr += i;
		length -= i;
	}
}

/**
 * Send last coverage
 */
void send_cov(void) {
	if (cov_server_sock == -1) {
		printf("Coverage server is not connected\n");
		exit(EXIT_FAILURE);
		return;
	}
#if CHECK_SEND_LOCK
	if (!trylock(&send_lock)) {
		printf("send_cov: send_lock is unexpectedly locked! This pid=%d, owner=%d\n", getpid(), send_lock.owner);
		exit(EXIT_FAILURE);
	};
#endif
	if (last_cover_count <= 0) return;
	send_all(cov_server_sock, (void *) last_cover, last_cover_count * sizeof(unsigned long));
	last_cover_count = 0;
#if CHECK_SEND_LOCK
	unlock(&send_lock);
#endif
}
