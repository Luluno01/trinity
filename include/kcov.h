#pragma once

#include <sys/ioctl.h>
#define KCOV_INIT_TRACE	_IOR('c', 1, unsigned long)
#define KCOV_ENABLE	_IO('c', 100)
#define KCOV_DISABLE	_IO('c', 101)
#define COVER_SIZE	(64<<10)

void init_kcov(void);
void enable_kcov(void);
void reset_kcov(void);
void dump_kcov_buffer(void);
void disable_kcov(void);
void start_kcov(void);
void stop_kcov(void);
void shutdown_kcov(void);

void connect_cov_server(void);
void disconnect_cov_server(void);

extern int kcovfd;
extern unsigned long last_cover_count;
extern unsigned long last_cover[];

extern struct sockaddr_in cov_server;
extern int cov_server_sock;
