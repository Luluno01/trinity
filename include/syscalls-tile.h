#pragma once

/*
 * Derived from linux/arch/tile/include/asm/unistd.h
 */

#include "sanitise.h"
#include "syscall.h"
#include "syscalls/syscalls.h"

struct syscalltable syscalls_tile[] = {
/* 0 */                { .entry = &syscall_io_setup },
/* 1 */                { .entry = &syscall_io_destroy },
/* 2 */                { .entry = &syscall_io_submit },
/* 3 */                { .entry = &syscall_io_cancel },
/* 4 */                { .entry = &syscall_io_getevents },
/* 5 */                { .entry = &syscall_setxattr },
/* 6 */                { .entry = &syscall_lsetxattr },
/* 7 */                { .entry = &syscall_fsetxattr },
/* 8 */                { .entry = &syscall_getxattr },
/* 9 */                { .entry = &syscall_lgetxattr },
/* 10 */       { .entry = &syscall_fgetxattr },
/* 11 */       { .entry = &syscall_listxattr },
/* 12 */       { .entry = &syscall_llistxattr },
/* 13 */       { .entry = &syscall_flistxattr },
/* 14 */       { .entry = &syscall_removexattr },
/* 15 */       { .entry = &syscall_lremovexattr },
/* 16 */       { .entry = &syscall_fremovexattr },
/* 17 */       { .entry = &syscall_getcwd },
/* 18 */       { .entry = &syscall_lookup_dcookie },
/* 19 */       { .entry = &syscall_eventfd2 },
/* 20 */       { .entry = &syscall_epoll_create1 },
/* 21 */       { .entry = &syscall_epoll_ctl },
/* 22 */       { .entry = &syscall_epoll_pwait },
/* 23 */       { .entry = &syscall_dup },
/* 24 */       { .entry = &syscall_dup3 },
/* 25 */       { .entry = &syscall_fcntl },
/* 26 */       { .entry = &syscall_inotify_init1 },
/* 27 */       { .entry = &syscall_inotify_add_watch },
/* 28 */       { .entry = &syscall_inotify_rm_watch },
/* 29 */       { .entry = &syscall_ioctl },
/* 30 */       { .entry = &syscall_ioprio_set },
/* 31 */       { .entry = &syscall_ioprio_get },
/* 32 */       { .entry = &syscall_flock },
/* 33 */       { .entry = &syscall_mknodat },
/* 34 */       { .entry = &syscall_mkdirat },
/* 35 */       { .entry = &syscall_unlinkat },
/* 36 */       { .entry = &syscall_symlinkat },
/* 37 */       { .entry = &syscall_linkat },
/* 38 */       { .entry = &syscall_renameat },
/* 39 */       { .entry = &syscall_umount },
/* 40 */       { .entry = &syscall_mount },
/* 41 */       { .entry = &syscall_pivot_root },
/* 42 */       { .entry = &syscall_ni_syscall },
/* 43 */       { .entry = &syscall_statfs },
/* 44 */       { .entry = &syscall_fstatfs },
/* 45 */       { .entry = &syscall_truncate },
/* 46 */       { .entry = &syscall_ftruncate },
/* 47 */       { .entry = &syscall_fallocate },
/* 48 */       { .entry = &syscall_faccessat },
/* 49 */       { .entry = &syscall_chdir },
/* 50 */       { .entry = &syscall_fchdir },
/* 51 */       { .entry = &syscall_chroot },
/* 52 */       { .entry = &syscall_fchmod },
/* 53 */       { .entry = &syscall_fchmodat },
/* 54 */       { .entry = &syscall_fchownat },
/* 55 */       { .entry = &syscall_fchown },
/* 56 */       { .entry = &syscall_openat },
/* 57 */       { .entry = &syscall_close },
/* 58 */       { .entry = &syscall_vhangup },
/* 59 */       { .entry = &syscall_pipe2 },
/* 60 */       { .entry = &syscall_quotactl },
/* 61 */       { .entry = &syscall_getdents64 },
/* 62 */       { .entry = &syscall_lseek },
/* 63 */       { .entry = &syscall_read },
/* 64 */       { .entry = &syscall_write },
/* 65 */       { .entry = &syscall_readv },
/* 66 */       { .entry = &syscall_writev },
/* 67 */       { .entry = &syscall_pread64 },
/* 68 */       { .entry = &syscall_pwrite64 },
/* 69 */       { .entry = &syscall_preadv },
/* 70 */       { .entry = &syscall_pwritev },
/* 71 */       { .entry = &syscall_sendfile64 },
/* 72 */       { .entry = &syscall_pselect6 },
/* 73 */       { .entry = &syscall_ppoll },
/* 74 */       { .entry = &syscall_signalfd4 },
/* 75 */       { .entry = &syscall_vmsplice },
/* 76 */       { .entry = &syscall_splice },
/* 77 */       { .entry = &syscall_tee },
/* 78 */       { .entry = &syscall_readlinkat },
/* 79 */       { .entry = &syscall_newfstatat },
/* 80 */       { .entry = &syscall_newfstat },
/* 81 */       { .entry = &syscall_sync },
/* 82 */       { .entry = &syscall_fsync },
/* 83 */       { .entry = &syscall_fdatasync },
/* 84 */       { .entry = &syscall_sync_file_range },
/* 85 */       { .entry = &syscall_timerfd_create },
/* 86 */       { .entry = &syscall_timerfd_settime },
/* 87 */       { .entry = &syscall_timerfd_gettime },
/* 88 */       { .entry = &syscall_utimensat },
/* 89 */       { .entry = &syscall_acct },
/* 90 */       { .entry = &syscall_capget },
/* 91 */       { .entry = &syscall_capset },
/* 92 */       { .entry = &syscall_personality },
/* 93 */       { .entry = &syscall_exit },
/* 94 */       { .entry = &syscall_exit_group },
/* 95 */       { .entry = &syscall_waitid },
/* 96 */       { .entry = &syscall_set_tid_address },
/* 97 */       { .entry = &syscall_unshare },
/* 98 */       { .entry = &syscall_futex },
/* 99 */       { .entry = &syscall_set_robust_list },
/* 100 */      { .entry = &syscall_get_robust_list },
/* 101 */      { .entry = &syscall_nanosleep },
/* 102 */      { .entry = &syscall_getitimer },
/* 103 */      { .entry = &syscall_setitimer },
/* 104 */      { .entry = &syscall_kexec_load },
/* 105 */      { .entry = &syscall_init_module },
/* 106 */      { .entry = &syscall_delete_module },
/* 107 */      { .entry = &syscall_timer_create },
/* 108 */      { .entry = &syscall_timer_gettime },
/* 109 */      { .entry = &syscall_timer_getoverrun },
/* 110 */      { .entry = &syscall_timer_settime },
/* 111 */      { .entry = &syscall_timer_delete },
/* 112 */      { .entry = &syscall_clock_settime },
/* 113 */      { .entry = &syscall_clock_gettime },
/* 114 */      { .entry = &syscall_clock_getres },
/* 115 */      { .entry = &syscall_clock_nanosleep },
/* 116 */      { .entry = &syscall_syslog },
/* 117 */      { .entry = &syscall_ptrace },
/* 118 */      { .entry = &syscall_sched_setparam },
/* 119 */      { .entry = &syscall_sched_setscheduler },
/* 120 */      { .entry = &syscall_sched_getscheduler },
/* 121 */      { .entry = &syscall_sched_getparam },
/* 122 */      { .entry = &syscall_sched_setaffinity },
/* 123 */      { .entry = &syscall_sched_getaffinity },
/* 124 */      { .entry = &syscall_sched_yield },
/* 125 */      { .entry = &syscall_sched_get_priority_max },
/* 126 */      { .entry = &syscall_sched_get_priority_min },
/* 127 */      { .entry = &syscall_sched_rr_get_interval },
/* 128 */      { .entry = &syscall_restart_syscall },
/* 129 */      { .entry = &syscall_kill },
/* 130 */      { .entry = &syscall_tkill },
/* 131 */      { .entry = &syscall_tgkill },
/* 132 */      { .entry = &syscall_sigaltstack },
/* 133 */      { .entry = &syscall_rt_sigsuspend },
/* 134 */      { .entry = &syscall_rt_sigaction },
/* 135 */      { .entry = &syscall_rt_sigprocmask },
/* 136 */      { .entry = &syscall_rt_sigpending },
/* 137 */      { .entry = &syscall_rt_sigtimedwait },
/* 138 */      { .entry = &syscall_rt_sigqueueinfo },
/* 139 */      { .entry = &syscall_rt_sigreturn },
/* 140 */      { .entry = &syscall_setpriority },
/* 141 */      { .entry = &syscall_getpriority },
/* 142 */      { .entry = &syscall_reboot },
/* 143 */      { .entry = &syscall_setregid },
/* 144 */      { .entry = &syscall_setgid },
/* 145 */      { .entry = &syscall_setreuid },
/* 146 */      { .entry = &syscall_setuid },
/* 147 */      { .entry = &syscall_setresuid },
/* 148 */      { .entry = &syscall_getresuid },
/* 149 */      { .entry = &syscall_setresgid },
/* 150 */      { .entry = &syscall_getresgid },
/* 151 */      { .entry = &syscall_setfsuid },
/* 152 */      { .entry = &syscall_setfsgid },
/* 153 */      { .entry = &syscall_times },
/* 154 */      { .entry = &syscall_setpgid },
/* 155 */      { .entry = &syscall_getpgid },
/* 156 */      { .entry = &syscall_getsid },
/* 157 */      { .entry = &syscall_setsid },
/* 158 */      { .entry = &syscall_getgroups },
/* 159 */      { .entry = &syscall_setgroups },
/* 160 */      { .entry = &syscall_newuname },
/* 161 */      { .entry = &syscall_sethostname },
/* 162 */      { .entry = &syscall_setdomainname },
/* 163 */      { .entry = &syscall_getrlimit },
/* 164 */      { .entry = &syscall_setrlimit },
/* 165 */      { .entry = &syscall_getrusage },
/* 166 */      { .entry = &syscall_umask },
/* 167 */      { .entry = &syscall_prctl },
/* 168 */      { .entry = &syscall_getcpu },
/* 169 */      { .entry = &syscall_gettimeofday },
/* 170 */      { .entry = &syscall_settimeofday },
/* 171 */      { .entry = &syscall_adjtimex },
/* 172 */      { .entry = &syscall_getpid },
/* 173 */      { .entry = &syscall_getppid },
/* 174 */      { .entry = &syscall_getuid },
/* 175 */      { .entry = &syscall_geteuid },
/* 176 */      { .entry = &syscall_getgid },
/* 177 */      { .entry = &syscall_getegid },
/* 178 */      { .entry = &syscall_gettid },
/* 179 */      { .entry = &syscall_sysinfo },
/* 180 */      { .entry = &syscall_mq_open },
/* 181 */      { .entry = &syscall_mq_unlink },
/* 182 */      { .entry = &syscall_mq_timedsend },
/* 183 */      { .entry = &syscall_mq_timedreceive },
/* 184 */      { .entry = &syscall_mq_notify },
/* 185 */      { .entry = &syscall_mq_getsetattr },
/* 186 */      { .entry = &syscall_msgget },
/* 187 */      { .entry = &syscall_msgctl },
/* 188 */      { .entry = &syscall_msgrcv },
/* 189 */      { .entry = &syscall_msgsnd },
/* 190 */      { .entry = &syscall_semget },
/* 191 */      { .entry = &syscall_semctl },
/* 192 */      { .entry = &syscall_semtimedop },
/* 193 */      { .entry = &syscall_semop },
/* 194 */      { .entry = &syscall_shmget },
/* 195 */      { .entry = &syscall_shmctl },
/* 196 */      { .entry = &syscall_shmat },
/* 197 */      { .entry = &syscall_shmdt },
/* 198 */      { .entry = &syscall_socket },
/* 199 */      { .entry = &syscall_socketpair },
/* 200 */      { .entry = &syscall_bind },
/* 201 */      { .entry = &syscall_listen },
/* 202 */      { .entry = &syscall_accept },
/* 203 */      { .entry = &syscall_connect },
/* 204 */      { .entry = &syscall_getsockname },
/* 205 */      { .entry = &syscall_getpeername },
/* 206 */      { .entry = &syscall_sendto },
/* 207 */      { .entry = &syscall_recvfrom },
/* 208 */      { .entry = &syscall_setsockopt },
/* 209 */      { .entry = &syscall_getsockopt },
/* 210 */      { .entry = &syscall_shutdown },
/* 211 */      { .entry = &syscall_sendmsg },
/* 212 */      { .entry = &syscall_recvmsg },
/* 213 */      { .entry = &syscall_readahead },
/* 214 */      { .entry = &syscall_brk },
/* 215 */      { .entry = &syscall_munmap },
/* 216 */      { .entry = &syscall_mremap },
/* 217 */      { .entry = &syscall_add_key },
/* 218 */      { .entry = &syscall_request_key },
/* 219 */      { .entry = &syscall_keyctl },
/* 220 */      { .entry = &syscall_clone },
/* 221 */      { .entry = &syscall_execve },
/* 222 */      { .entry = &syscall_mmap },
/* 223 */      { .entry = &syscall_fadvise64_64 },
/* 224 */      { .entry = &syscall_swapon },
/* 225 */      { .entry = &syscall_swapoff },
/* 226 */      { .entry = &syscall_mprotect },
/* 227 */      { .entry = &syscall_msync },
/* 228 */      { .entry = &syscall_mlock },
/* 229 */      { .entry = &syscall_munlock },
/* 230 */      { .entry = &syscall_mlockall },
/* 231 */      { .entry = &syscall_munlockall },
/* 232 */      { .entry = &syscall_mincore },
/* 233 */      { .entry = &syscall_madvise },
/* 234 */      { .entry = &syscall_remap_file_pages },
/* 235 */      { .entry = &syscall_mbind },
/* 236 */      { .entry = &syscall_get_mempolicy },
/* 237 */      { .entry = &syscall_set_mempolicy },
/* 238 */      { .entry = &syscall_migrate_pages },
/* 239 */      { .entry = &syscall_move_pages },
/* 240 */      { .entry = &syscall_rt_tgsigqueueinfo },
/* 241 */      { .entry = &syscall_perf_event_open },
/* 242 */      { .entry = &syscall_accept4 },
/* 243 */      { .entry = &syscall_recvmmsg },
/* 244 */      { .entry = &syscall_ni_syscall },
/* 245 */      { .entry = &syscall_ni_syscall },
/* 246 */      { .entry = &syscall_ni_syscall },
/* 247 */      { .entry = &syscall_ni_syscall },
/* 248 */      { .entry = &syscall_ni_syscall },
/* 249 */      { .entry = &syscall_ni_syscall },
/* 250 */      { .entry = &syscall_ni_syscall },
/* 251 */      { .entry = &syscall_ni_syscall },
/* 252 */      { .entry = &syscall_ni_syscall },
/* 253 */      { .entry = &syscall_ni_syscall },
/* 254 */      { .entry = &syscall_ni_syscall },
/* 255 */      { .entry = &syscall_ni_syscall },
/* 256 */      { .entry = &syscall_ni_syscall },
/* 257 */      { .entry = &syscall_ni_syscall },
/* 258 */      { .entry = &syscall_ni_syscall },
/* 259 */      { .entry = &syscall_ni_syscall },
/* 260 */      { .entry = &syscall_wait4 },
/* 261 */      { .entry = &syscall_prlimit64 },
/* 262 */      { .entry = &syscall_fanotify_init },
/* 263 */      { .entry = &syscall_fanotify_mark },
/* 264 */      { .entry = &syscall_name_to_handle_at },
/* 265 */      { .entry = &syscall_open_by_handle_at },
/* 266 */      { .entry = &syscall_clock_adjtime },
/* 267 */      { .entry = &syscall_syncfs },
/* 268 */      { .entry = &syscall_setns },
/* 269 */      { .entry = &syscall_sendmmsg },
/* 270 */      { .entry = &syscall_process_vm_readv },
/* 271 */      { .entry = &syscall_process_vm_writev },
/* 272 */      { .entry = &syscall_kcmp },
/* 273 */      { .entry = &syscall_finit_module },
/* 274 */      { .entry = &syscall_sched_setattr },
/* 275 */      { .entry = &syscall_sched_getattr },
};
