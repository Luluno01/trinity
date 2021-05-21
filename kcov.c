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


int kcovfd;
/**
 * Dump coverage to a file on disk
 */
int kcovDumpFd;

unsigned long *cover;
unsigned long last_cover_count = 0;
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
		_exit(EXIT_FAILURE);
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
	}
	if (connect(cov_server_sock, &cov_server, sizeof(cov_server)) != 0) {
		printf("Cannot connect to coverage server %s:%hu: %s\n", inet_ntoa(cov_server.sin_addr), ntohs(cov_server.sin_port), strerror(errno));
		exit(EXIT_FAILURE);
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

/**
 * Send last coverage
 */
void send_cov(void) {
	char *cursor, *eof;
	if (cov_server_sock == -1) {
		printf("Coverage server is not connected\n");
		exit(EXIT_FAILURE);
	}
	if (last_cover_count <= 0) return;
	cursor = (char*) last_cover;
	eof = (char*) (last_cover + last_cover_count);
	while ((cursor += write(cov_server_sock, cursor, eof - cursor)) < eof);
	last_cover_count = 0;
}
