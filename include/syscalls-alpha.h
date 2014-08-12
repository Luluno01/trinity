#pragma once

/*
 * The Alpha Linux syscall table in all its gory mess.
 *
 * Derived from arch/alpha/include/uapi/asm/unistd.h
 */

#include "sanitise.h"
#include "syscall.h"
#include "syscalls/syscalls.h"

struct syscalltable syscalls_alpha[] = {
/* 0 */		{ .entry = &syscall_ni_syscall },	/* osf_syscall */
/* 1 */		{ .entry = &syscall_exit },
/* 2 */		{ .entry = &syscall_fork },
/* 3 */		{ .entry = &syscall_read },
/* 4 */		{ .entry = &syscall_write },
/* 5 */		{ .entry = &syscall_ni_syscall },	/* osf_old_open */
/* 6 */		{ .entry = &syscall_close },
/* 7 */		{ .entry = &syscall_ni_syscall },	/* osf_wait4 */
/* 8 */		{ .entry = &syscall_ni_syscall },	/* osf_old_creat */
/* 9 */		{ .entry = &syscall_link },
/* 10 */	{ .entry = &syscall_unlink },
/* 11 */	{ .entry = &syscall_ni_syscall },	/* osf_execve */
/* 12 */	{ .entry = &syscall_chdir },
/* 13 */	{ .entry = &syscall_fchdir },
/* 14 */	{ .entry = &syscall_mknod },
/* 15 */	{ .entry = &syscall_chmod },
/* 16 */	{ .entry = &syscall_chown },
/* 17 */	{ .entry = &syscall_brk },
/* 18 */	{ .entry = &syscall_ni_syscall },	/* osf_getfsstat */
/* 19 */	{ .entry = &syscall_lseek },
/* 20 */	{ .entry = &syscall_ni_syscall },	/* getxpid */
/* 21 */	{ .entry = &syscall_ni_syscall },	/* osf_mount */
/* 22 */	{ .entry = &syscall_umount },
/* 23 */	{ .entry = &syscall_setuid },
/* 24 */	{ .entry = &syscall_ni_syscall },	/* getxuid */
/* 25 */	{ .entry = &syscall_ni_syscall },	/* exec_with_loader */
/* 26 */	{ .entry = &syscall_ptrace },
/* 27 */	{ .entry = &syscall_ni_syscall },	/* osf_nrecvmsg */
/* 28 */	{ .entry = &syscall_ni_syscall },	/* osf_nsendmsg */
/* 29 */	{ .entry = &syscall_ni_syscall },	/* osf_nrecvfrom */
/* 30 */	{ .entry = &syscall_ni_syscall },	/* osf_naccept */
/* 31 */	{ .entry = &syscall_ni_syscall },	/* osf_ngetpeername */
/* 32 */	{ .entry = &syscall_ni_syscall },	/* osf_ngetsockname */
/* 33 */	{ .entry = &syscall_access },
/* 34 */	{ .entry = &syscall_ni_syscall },	/* osf_chflags */
/* 35 */	{ .entry = &syscall_ni_syscall },	/* osf_fchflags */
/* 36 */	{ .entry = &syscall_sync },
/* 37 */	{ .entry = &syscall_kill },
/* 38 */	{ .entry = &syscall_ni_syscall },	/* osf_old_stat */
/* 39 */	{ .entry = &syscall_setpgid },
/* 40 */	{ .entry = &syscall_ni_syscall },	/* osf_old_lstat */
/* 41 */	{ .entry = &syscall_dup },
/* 42 */	{ .entry = &syscall_pipe },
/* 43 */	{ .entry = &syscall_ni_syscall },	/* osf_set_program_attributes */
/* 44 */	{ .entry = &syscall_ni_syscall },	/* osf_profil */
/* 45 */	{ .entry = &syscall_open },
/* 46 */	{ .entry = &syscall_ni_syscall },	/* osf_old_sigaction */
/* 47 */	{ .entry = &syscall_ni_syscall },	/* getxgid */
/* 48 */	{ .entry = &syscall_ni_syscall },	/* osf_sigprocmask */
/* 49 */	{ .entry = &syscall_ni_syscall },	/* osf_getlogin */
/* 50 */	{ .entry = &syscall_ni_syscall },	/* osf_setlogin */
/* 51 */	{ .entry = &syscall_acct },
/* 52 */	{ .entry = &syscall_sigpending },
/* 53 */	{ .entry = &syscall_ni_syscall },
/* 54 */	{ .entry = &syscall_ioctl },
/* 55 */	{ .entry = &syscall_ni_syscall },	/* osf_reboot */
/* 56 */	{ .entry = &syscall_ni_syscall },	/* osf_revoke */
/* 57 */	{ .entry = &syscall_symlink },
/* 58 */	{ .entry = &syscall_readlink },
/* 59 */	{ .entry = &syscall_execve },
/* 60 */	{ .entry = &syscall_umask },
/* 61 */	{ .entry = &syscall_chroot },
/* 62 */	{ .entry = &syscall_ni_syscall },	/* osf_old_fstat */
/* 63 */	{ .entry = &syscall_getpgrp },
/* 64 */	{ .entry = &syscall_getpagesize },
/* 65 */	{ .entry = &syscall_ni_syscall },	/* osf_mremap */
/* 66 */	{ .entry = &syscall_vfork },
/* 67 */	{ .entry = &syscall_stat },
/* 68 */	{ .entry = &syscall_lstat },
/* 69 */	{ .entry = &syscall_ni_syscall },	/* osf_sbrk */
/* 70 */	{ .entry = &syscall_ni_syscall },	/* osf_sstk */
/* 71 */	{ .entry = &syscall_mmap },		/* OSF/1 mmap is superset of Linux */
/* 72 */	{ .entry = &syscall_ni_syscall },	/* osf_old_vadvise */
/* 73 */	{ .entry = &syscall_munmap },
/* 74 */	{ .entry = &syscall_mprotect },
/* 75 */	{ .entry = &syscall_madvise },
/* 76 */	{ .entry = &syscall_vhangup },
/* 77 */	{ .entry = &syscall_ni_syscall },	/* osf_kmodcall */
/* 78 */	{ .entry = &syscall_ni_syscall },	/* osf_mincore */
/* 79 */	{ .entry = &syscall_getgroups },
/* 80 */	{ .entry = &syscall_setgroups },
/* 81 */	{ .entry = &syscall_ni_syscall },	/* osf_old_getpgrp */
/* 82 */	{ .entry = &syscall_ni_syscall },	/* setpgrp (BSD alias for setpgid) */
/* 83 */	{ .entry = &syscall_ni_syscall },	/* osf_setitimer */
/* 84 */	{ .entry = &syscall_ni_syscall },	/* osf_old_wait */
/* 85 */	{ .entry = &syscall_ni_syscall },	/* osf_table */
/* 86 */	{ .entry = &syscall_ni_syscall },	/* osf_getitimer */
/* 87 */	{ .entry = &syscall_ni_syscall },	/* sys_gethostname */
/* 88 */	{ .entry = &syscall_sethostname },
/* 89 */	{ .entry = &syscall_ni_syscall },	/* getdtablesize */
/* 90 */	{ .entry = &syscall_dup2 },
/* 91 */	{ .entry = &syscall_ni_syscall },	/* sys_fstat */
/* 92 */	{ .entry = &syscall_fcntl },
/* 93 */	{ .entry = &syscall_ni_syscall },	/* osf_select */
/* 94 */	{ .entry = &syscall_poll },
/* 95 */	{ .entry = &syscall_fsync },
/* 96 */	{ .entry = &syscall_setpriority },
/* 97 */	{ .entry = &syscall_socket },
/* 98 */	{ .entry = &syscall_connect },
/* 99 */	{ .entry = &syscall_accept },
/* 100 */	{ .entry = &syscall_getpriority },
/* 101 */	{ .entry = &syscall_send },
/* 102 */	{ .entry = &syscall_recv },
/* 103 */	{ .entry = &syscall_sigreturn },
/* 104 */	{ .entry = &syscall_bind },
/* 105 */	{ .entry = &syscall_setsockopt },
/* 106 */	{ .entry = &syscall_listen },
/* 107 */	{ .entry = &syscall_ni_syscall },	/* osf_plock */
/* 108 */	{ .entry = &syscall_ni_syscall },	/* osf_old_sigvec */
/* 109 */	{ .entry = &syscall_ni_syscall },	/* osf_old_sigblock */
/* 110 */	{ .entry = &syscall_ni_syscall },	/* osf_old_sigsetmask */
/* 111 */	{ .entry = &syscall_sigsuspend },
/* 112 */	{ .entry = &syscall_ni_syscall },	/* osf_sigstack */
/* 113 */	{ .entry = &syscall_recvmsg },
/* 114 */	{ .entry = &syscall_sendmsg },
/* 115 */	{ .entry = &syscall_ni_syscall },	/* osf_old_vtrace */
/* 116 */	{ .entry = &syscall_ni_syscall },	/* osf_gettimeofday */
/* 117 */	{ .entry = &syscall_ni_syscall },	/* osf_getrusage */
/* 118 */	{ .entry = &syscall_getsockopt },
/* 119 */	{ .entry = &syscall_ni_syscall },
/* 120 */	{ .entry = &syscall_readv },
/* 121 */	{ .entry = &syscall_writev },
/* 122 */	{ .entry = &syscall_ni_syscall },	/* osf_settimeofday */
/* 123 */	{ .entry = &syscall_fchown },
/* 124 */	{ .entry = &syscall_fchmod },
/* 125 */	{ .entry = &syscall_recvfrom },
/* 126 */	{ .entry = &syscall_setreuid },
/* 127 */	{ .entry = &syscall_setregid },
/* 128 */	{ .entry = &syscall_rename },
/* 129 */	{ .entry = &syscall_truncate },
/* 130 */	{ .entry = &syscall_ftruncate },
/* 131 */	{ .entry = &syscall_flock },
/* 132 */	{ .entry = &syscall_setgid },
/* 133 */	{ .entry = &syscall_sendto },
/* 134 */	{ .entry = &syscall_shutdown },
/* 135 */	{ .entry = &syscall_socketpair },
/* 136 */	{ .entry = &syscall_mkdir },
/* 137 */	{ .entry = &syscall_rmdir },
/* 138 */	{ .entry = &syscall_ni_syscall },	/* osf_utimes */
/* 139 */	{ .entry = &syscall_ni_syscall },	/* osf_old_sigreturn */
/* 140 */	{ .entry = &syscall_ni_syscall },	/* osf_adjtime */
/* 141 */	{ .entry = &syscall_getpeername },
/* 142 */	{ .entry = &syscall_ni_syscall },	/* osf_gethostid */
/* 143 */	{ .entry = &syscall_ni_syscall },	/* osf_sethostid */
/* 144 */	{ .entry = &syscall_getrlimit },
/* 145 */	{ .entry = &syscall_setrlimit },
/* 146 */	{ .entry = &syscall_ni_syscall },	/* osf_old_killpg */
/* 147 */	{ .entry = &syscall_setsid },
/* 148 */	{ .entry = &syscall_quotactl },
/* 149 */	{ .entry = &syscall_ni_syscall },	/* osf_oldquota */
/* 150 */	{ .entry = &syscall_getsockname },
/* 151 */	{ .entry = &syscall_ni_syscall },
/* 152 */	{ .entry = &syscall_ni_syscall },
/* 153 */	{ .entry = &syscall_ni_syscall },	/* osf_pid_block */
/* 154 */	{ .entry = &syscall_ni_syscall },	/* osf_pid_unblock */
/* 155 */	{ .entry = &syscall_ni_syscall },
/* 156 */	{ .entry = &syscall_sigaction },
/* 157 */	{ .entry = &syscall_ni_syscall },	/* osf_sigwaitprim */
/* 158 */	{ .entry = &syscall_ni_syscall },	/* osf_nfssvc */
/* 159 */	{ .entry = &syscall_ni_syscall },	/* osf_getdirentries */
/* 160 */	{ .entry = &syscall_ni_syscall },	/* osf_statfs */
/* 161 */	{ .entry = &syscall_ni_syscall },	/* osf_fstatfs */
/* 162 */	{ .entry = &syscall_ni_syscall },
/* 163 */	{ .entry = &syscall_ni_syscall },	/* osf_asynch_daemon */
/* 164 */	{ .entry = &syscall_ni_syscall },	/* osf_getfh */
/* 165 */	{ .entry = &syscall_ni_syscall },	/* osf_getdomainname */
/* 166 */	{ .entry = &syscall_setdomainname },
/* 167 */	{ .entry = &syscall_ni_syscall },
/* 168 */	{ .entry = &syscall_ni_syscall },
/* 169 */	{ .entry = &syscall_ni_syscall },	/* osf_exportfs */
/* 170 */	{ .entry = &syscall_ni_syscall },
/* 171 */	{ .entry = &syscall_ni_syscall },
/* 172 */	{ .entry = &syscall_ni_syscall },
/* 173 */	{ .entry = &syscall_ni_syscall },
/* 174 */	{ .entry = &syscall_ni_syscall },
/* 175 */	{ .entry = &syscall_ni_syscall },
/* 176 */	{ .entry = &syscall_ni_syscall },
/* 177 */	{ .entry = &syscall_ni_syscall },
/* 178 */	{ .entry = &syscall_ni_syscall },
/* 179 */	{ .entry = &syscall_ni_syscall },
/* 180 */	{ .entry = &syscall_ni_syscall },
/* 181 */	{ .entry = &syscall_ni_syscall },	/* osf_alt_plock */
/* 182 */	{ .entry = &syscall_ni_syscall },
/* 183 */	{ .entry = &syscall_ni_syscall },
/* 184 */	{ .entry = &syscall_ni_syscall },	/* osf_getmnt */
/* 185 */	{ .entry = &syscall_ni_syscall },
/* 186 */	{ .entry = &syscall_ni_syscall },
/* 187 */	{ .entry = &syscall_ni_syscall },	/* osf_alt_sigpending */
/* 188 */	{ .entry = &syscall_ni_syscall },	/* osf_alt_setsid */
/* 189 */	{ .entry = &syscall_ni_syscall },
/* 190 */	{ .entry = &syscall_ni_syscall },
/* 191 */	{ .entry = &syscall_ni_syscall },
/* 192 */	{ .entry = &syscall_ni_syscall },
/* 193 */	{ .entry = &syscall_ni_syscall },
/* 194 */	{ .entry = &syscall_ni_syscall },
/* 195 */	{ .entry = &syscall_ni_syscall },
/* 196 */	{ .entry = &syscall_ni_syscall },
/* 197 */	{ .entry = &syscall_ni_syscall },
/* 198 */	{ .entry = &syscall_ni_syscall },
/* 199 */	{ .entry = &syscall_ni_syscall },	/* osf_swapon */
/* 200 */	{ .entry = &syscall_msgctl },
/* 201 */	{ .entry = &syscall_msgget },
/* 202 */	{ .entry = &syscall_msgrcv },
/* 203 */	{ .entry = &syscall_msgsnd },
/* 204 */	{ .entry = &syscall_semctl },
/* 205 */	{ .entry = &syscall_semget },
/* 206 */	{ .entry = &syscall_semop },
/* 207 */	{ .entry = &syscall_ni_syscall },	/* osf_utsname */
/* 208 */	{ .entry = &syscall_lchown },
/* 209 */	{ .entry = &syscall_ni_syscall },	/* osf_shmat */
/* 210 */	{ .entry = &syscall_shmctl },
/* 211 */	{ .entry = &syscall_shmdt },
/* 212 */	{ .entry = &syscall_shmget },
/* 213 */	{ .entry = &syscall_ni_syscall },	/* osf_mvalid */
/* 214 */	{ .entry = &syscall_ni_syscall },	/* osf_getaddressconf */
/* 215 */	{ .entry = &syscall_ni_syscall },	/* osf_msleep */
/* 216 */	{ .entry = &syscall_ni_syscall },	/* osf_mwakeup */
/* 217 */	{ .entry = &syscall_msync },
/* 218 */	{ .entry = &syscall_ni_syscall },	/* osf_signal */
/* 219 */	{ .entry = &syscall_ni_syscall },	/* osf_utc_gettime */
/* 220 */	{ .entry = &syscall_ni_syscall },	/* osf_utc_adjtime */
/* 221 */	{ .entry = &syscall_ni_syscall },
/* 222 */	{ .entry = &syscall_ni_syscall },	/* osf_security */
/* 223 */	{ .entry = &syscall_ni_syscall },	/* osf_kloadcall */
/* 224 */	{ .entry = &syscall_ni_syscall },	/* osf_stat */
/* 225 */	{ .entry = &syscall_ni_syscall },	/* osf_lstat */
/* 226 */	{ .entry = &syscall_ni_syscall },	/* osf_fstat */
/* 227 */	{ .entry = &syscall_ni_syscall },	/* osf_statfs64 */
/* 228 */	{ .entry = &syscall_ni_syscall },	/* osf_fstatfs64 */
/* 229 */	{ .entry = &syscall_ni_syscall },
/* 230 */	{ .entry = &syscall_ni_syscall },
/* 231 */	{ .entry = &syscall_ni_syscall },
/* 232 */	{ .entry = &syscall_ni_syscall },
/* 233 */	{ .entry = &syscall_getpgid },
/* 234 */	{ .entry = &syscall_getsid },
/* 235 */	{ .entry = &syscall_sigaltstack },
/* 236 */	{ .entry = &syscall_ni_syscall },	/* osf_waitid */
/* 237 */	{ .entry = &syscall_ni_syscall },	/* osf_priocntlset */
/* 238 */	{ .entry = &syscall_ni_syscall },	/* osf_sigsendset */
/* 239 */	{ .entry = &syscall_ni_syscall },	/* osf_set_speculative */
/* 240 */	{ .entry = &syscall_ni_syscall },	/* osf_msfs_syscall */
/* 241 */	{ .entry = &syscall_ni_syscall },	/* osf_sysinfo */
/* 242 */	{ .entry = &syscall_ni_syscall },	/* osf_uadmin */
/* 243 */	{ .entry = &syscall_ni_syscall },	/* osf_fuser */
/* 244 */	{ .entry = &syscall_ni_syscall },	/* osf_proplist_syscall */
/* 245 */	{ .entry = &syscall_ni_syscall },	/* osf_ntp_adjtime */
/* 246 */	{ .entry = &syscall_ni_syscall },	/* osf_ntp_gettime */
/* 247 */	{ .entry = &syscall_ni_syscall },	/* osf_pathconf */
/* 248 */	{ .entry = &syscall_ni_syscall },	/* osf_fpathconf */
/* 249 */	{ .entry = &syscall_ni_syscall },
/* 250 */	{ .entry = &syscall_ni_syscall },	/* osf_uswitch */
/* 251 */	{ .entry = &syscall_ni_syscall },	/* osf_usleep_thread */
/* 252 */	{ .entry = &syscall_ni_syscall },	/* osf_audcntl */
/* 253 */	{ .entry = &syscall_ni_syscall },	/* osf_audgen */
/* 254 */	{ .entry = &syscall_sysfs },
/* 255 */	{ .entry = &syscall_ni_syscall },	/* osf_subsys_info */
/* 256 */	{ .entry = &syscall_ni_syscall },	/* osf_getsysinfo */
/* 257 */	{ .entry = &syscall_ni_syscall },	/* osf_setsysinfo */
/* 258 */	{ .entry = &syscall_ni_syscall },	/* osf_afs_syscall */
/* 259 */	{ .entry = &syscall_ni_syscall },	/* osf_swapctl */
/* 260 */	{ .entry = &syscall_ni_syscall },	/* osf_memcntl */
/* 261 */	{ .entry = &syscall_ni_syscall },	/* osf_fdatasync */
/* 262 */	{ .entry = &syscall_ni_syscall },
/* 263 */	{ .entry = &syscall_ni_syscall },
/* 264 */	{ .entry = &syscall_ni_syscall },
/* 265 */	{ .entry = &syscall_ni_syscall },
/* 266 */	{ .entry = &syscall_ni_syscall },
/* 267 */	{ .entry = &syscall_ni_syscall },
/* 268 */	{ .entry = &syscall_ni_syscall },
/* 269 */	{ .entry = &syscall_ni_syscall },
/* 270 */	{ .entry = &syscall_ni_syscall },
/* 271 */	{ .entry = &syscall_ni_syscall },
/* 272 */	{ .entry = &syscall_ni_syscall },
/* 273 */	{ .entry = &syscall_ni_syscall },
/* 274 */	{ .entry = &syscall_ni_syscall },
/* 275 */	{ .entry = &syscall_ni_syscall },
/* 276 */	{ .entry = &syscall_ni_syscall },
/* 277 */	{ .entry = &syscall_ni_syscall },
/* 278 */	{ .entry = &syscall_ni_syscall },
/* 279 */	{ .entry = &syscall_ni_syscall },
/* 280 */	{ .entry = &syscall_ni_syscall },
/* 281 */	{ .entry = &syscall_ni_syscall },
/* 282 */	{ .entry = &syscall_ni_syscall },
/* 283 */	{ .entry = &syscall_ni_syscall },
/* 284 */	{ .entry = &syscall_ni_syscall },
/* 285 */	{ .entry = &syscall_ni_syscall },
/* 286 */	{ .entry = &syscall_ni_syscall },
/* 287 */	{ .entry = &syscall_ni_syscall },
/* 288 */	{ .entry = &syscall_ni_syscall },
/* 289 */	{ .entry = &syscall_ni_syscall },
/* 290 */	{ .entry = &syscall_ni_syscall },
/* 291 */	{ .entry = &syscall_ni_syscall },
/* 292 */	{ .entry = &syscall_ni_syscall },
/* 293 */	{ .entry = &syscall_ni_syscall },
/* 294 */	{ .entry = &syscall_ni_syscall },
/* 295 */	{ .entry = &syscall_ni_syscall },
/* 296 */	{ .entry = &syscall_ni_syscall },
/* 297 */	{ .entry = &syscall_ni_syscall },
/* 298 */	{ .entry = &syscall_ni_syscall },
/* 299 */	{ .entry = &syscall_ni_syscall },
/* 300 */	{ .entry = &syscall_bdflush },
/* 301 */	{ .entry = &syscall_ni_syscall },	/* sethae */
/* 302 */	{ .entry = &syscall_mount },
/* 303 */	{ .entry = &syscall_ni_syscall },	/* old_adjtimex */
/* 304 */	{ .entry = &syscall_swapoff },
/* 305 */	{ .entry = &syscall_getdents },
/* 306 */	{ .entry = &syscall_ni_syscall },	/* sys_create_module */
/* 307 */	{ .entry = &syscall_init_module },
/* 308 */	{ .entry = &syscall_delete_module },
/* 309 */	{ .entry = &syscall_ni_syscall },	/* sys_get_kernel_syms */
/* 310 */	{ .entry = &syscall_syslog },
/* 311 */	{ .entry = &syscall_reboot },
/* 312 */	{ .entry = &syscall_clone },
/* 313 */	{ .entry = &syscall_uselib },
/* 314 */	{ .entry = &syscall_mlock },
/* 315 */	{ .entry = &syscall_munlock },
/* 316 */	{ .entry = &syscall_mlockall },
/* 317 */	{ .entry = &syscall_munlockall },
/* 318 */	{ .entry = &syscall_sysinfo },
/* 319 */	{ .entry = &syscall_sysctl },
/* 320 */	{ .entry = &syscall_ni_syscall },	/* sys_idle */
/* 321 */	{ .entry = &syscall_oldumount },
/* 322 */	{ .entry = &syscall_swapon },
/* 323 */	{ .entry = &syscall_times },
/* 324 */	{ .entry = &syscall_personality },
/* 325 */	{ .entry = &syscall_setfsuid },
/* 326 */	{ .entry = &syscall_setfsgid },
/* 327 */	{ .entry = &syscall_ustat },
/* 328 */	{ .entry = &syscall_statfs },
/* 329 */	{ .entry = &syscall_fstatfs },
/* 330 */	{ .entry = &syscall_sched_setparam },
/* 331 */	{ .entry = &syscall_sched_getparam },
/* 332 */	{ .entry = &syscall_sched_setscheduler },
/* 333 */	{ .entry = &syscall_sched_getscheduler },
/* 334 */	{ .entry = &syscall_sched_yield },
/* 335 */	{ .entry = &syscall_sched_get_priority_max },
/* 336 */	{ .entry = &syscall_sched_get_priority_min },
/* 337 */	{ .entry = &syscall_sched_rr_get_interval },
/* 338 */	{ .entry = &syscall_ni_syscall },	/* sys_afs_syscall */
/* 339 */	{ .entry = &syscall_uname },
/* 340 */	{ .entry = &syscall_nanosleep },
/* 341 */	{ .entry = &syscall_mremap },
/* 342 */	{ .entry = &syscall_nfsservctl },
/* 343 */	{ .entry = &syscall_setresuid },
/* 344 */	{ .entry = &syscall_getresuid },
/* 345 */	{ .entry = &syscall_pciconfig_read },
/* 346 */	{ .entry = &syscall_pciconfig_write },
/* 347 */	{ .entry = &syscall_ni_syscall },	/* sys_query_module */
/* 348 */	{ .entry = &syscall_prctl },
/* 349 */	{ .entry = &syscall_pread64 },
/* 350 */	{ .entry = &syscall_pwrite64 },
/* 351 */	{ .entry = &syscall_rt_sigreturn },
/* 352 */	{ .entry = &syscall_rt_sigaction },
/* 353 */	{ .entry = &syscall_rt_sigprocmask },
/* 354 */	{ .entry = &syscall_rt_sigpending },
/* 355 */	{ .entry = &syscall_rt_sigtimedwait },
/* 356 */	{ .entry = &syscall_rt_sigqueueinfo },
/* 357 */	{ .entry = &syscall_rt_sigsuspend },
/* 358 */	{ .entry = &syscall_select },
/* 359 */	{ .entry = &syscall_gettimeofday },
/* 360 */	{ .entry = &syscall_settimeofday },
/* 361 */	{ .entry = &syscall_getitimer },
/* 362 */	{ .entry = &syscall_setitimer },
/* 363 */	{ .entry = &syscall_utimes },
/* 364 */	{ .entry = &syscall_getrusage },
/* 365 */	{ .entry = &syscall_wait4 },
/* 366 */	{ .entry = &syscall_adjtimex },
/* 367 */	{ .entry = &syscall_getcwd },
/* 368 */	{ .entry = &syscall_capget },
/* 369 */	{ .entry = &syscall_capset },
/* 370 */	{ .entry = &syscall_sendfile },
/* 371 */	{ .entry = &syscall_setresgid },
/* 372 */	{ .entry = &syscall_getresgid },
/* 373 */	{ .entry = &syscall_ni_syscall },	/* dipc */
/* 374 */	{ .entry = &syscall_pivot_root },
/* 375 */	{ .entry = &syscall_mincore },
/* 376 */	{ .entry = &syscall_pciconfig_iobase },
/* 377 */	{ .entry = &syscall_getdents64 },
/* 378 */	{ .entry = &syscall_gettid },
/* 379 */	{ .entry = &syscall_readahead },
/* 380 */	{ .entry = &syscall_ni_syscall },
/* 381 */	{ .entry = &syscall_tkill },
/* 382 */	{ .entry = &syscall_setxattr },
/* 383 */	{ .entry = &syscall_lsetxattr },
/* 384 */	{ .entry = &syscall_fsetxattr },
/* 385 */	{ .entry = &syscall_getxattr },
/* 386 */	{ .entry = &syscall_lgetxattr },
/* 387 */	{ .entry = &syscall_fgetxattr },
/* 388 */	{ .entry = &syscall_listxattr },
/* 389 */	{ .entry = &syscall_llistxattr },
/* 390 */	{ .entry = &syscall_flistxattr },
/* 391 */	{ .entry = &syscall_removexattr },
/* 392 */	{ .entry = &syscall_lremovexattr },
/* 393 */	{ .entry = &syscall_fremovexattr },
/* 394 */	{ .entry = &syscall_futex },
/* 395 */	{ .entry = &syscall_sched_setaffinity },
/* 396 */	{ .entry = &syscall_sched_getaffinity },
/* 397 */	{ .entry = &syscall_ni_syscall },	/* tuxcall */
/* 398 */	{ .entry = &syscall_io_setup },
/* 399 */	{ .entry = &syscall_io_destroy },
/* 400 */	{ .entry = &syscall_io_getevents },
/* 401 */	{ .entry = &syscall_io_submit },
/* 402 */	{ .entry = &syscall_io_cancel },
/* 405 */	{ .entry = &syscall_exit_group },
/* 406 */	{ .entry = &syscall_lookup_dcookie },
/* 407 */	{ .entry = &syscall_epoll_create },
/* 408 */	{ .entry = &syscall_epoll_ctl },
/* 409 */	{ .entry = &syscall_epoll_wait },
/* 410 */	{ .entry = &syscall_remap_file_pages },
/* 411 */	{ .entry = &syscall_set_tid_address },
/* 412 */	{ .entry = &syscall_restart_syscall },
/* 413 */	{ .entry = &syscall_fadvise64 },
/* 414 */	{ .entry = &syscall_timer_create },
/* 415 */	{ .entry = &syscall_timer_settime },
/* 416 */	{ .entry = &syscall_timer_gettime },
/* 417 */	{ .entry = &syscall_timer_getoverrun },
/* 418 */	{ .entry = &syscall_timer_delete },
/* 419 */	{ .entry = &syscall_clock_settime },
/* 420 */	{ .entry = &syscall_clock_gettime },
/* 421 */	{ .entry = &syscall_clock_getres },
/* 422 */	{ .entry = &syscall_clock_nanosleep },
/* 423 */	{ .entry = &syscall_semtimedop },
/* 424 */	{ .entry = &syscall_tgkill },
/* 425 */	{ .entry = &syscall_stat64 },
/* 426 */	{ .entry = &syscall_lstat64 },
/* 427 */	{ .entry = &syscall_fstat64 },
/* 428 */	{ .entry = &syscall_ni_syscall },	/* sys_vserver */
/* 429 */	{ .entry = &syscall_mbind },
/* 430 */	{ .entry = &syscall_get_mempolicy },
/* 431 */	{ .entry = &syscall_set_mempolicy },
/* 432 */	{ .entry = &syscall_mq_open },
/* 433 */	{ .entry = &syscall_mq_unlink },
/* 434 */	{ .entry = &syscall_mq_timedsend },
/* 435 */	{ .entry = &syscall_mq_timedreceive },
/* 436 */	{ .entry = &syscall_mq_notify },
/* 437 */	{ .entry = &syscall_mq_getsetattr },
/* 438 */	{ .entry = &syscall_waitid },
/* 439 */	{ .entry = &syscall_add_key },
/* 440 */	{ .entry = &syscall_request_key },
/* 441 */	{ .entry = &syscall_keyctl },
/* 442 */	{ .entry = &syscall_ioprio_set },
/* 443 */	{ .entry = &syscall_ioprio_get },
/* 444 */	{ .entry = &syscall_inotify_init },
/* 445 */	{ .entry = &syscall_inotify_add_watch },
/* 446 */	{ .entry = &syscall_inotify_rm_watch },
/* 447 */	{ .entry = &syscall_fdatasync },
/* 448 */	{ .entry = &syscall_kexec_load },
/* 449 */	{ .entry = &syscall_migrate_pages },
/* 450 */	{ .entry = &syscall_openat },
/* 451 */	{ .entry = &syscall_mkdirat },
/* 452 */	{ .entry = &syscall_mknodat },
/* 453 */	{ .entry = &syscall_fchownat },
/* 454 */	{ .entry = &syscall_futimesat },
/* 455 */	{ .entry = &syscall_fstatat64 },
/* 456 */	{ .entry = &syscall_unlinkat },
/* 457 */	{ .entry = &syscall_renameat },
/* 458 */	{ .entry = &syscall_linkat },
/* 459 */	{ .entry = &syscall_symlinkat },
/* 460 */	{ .entry = &syscall_readlinkat },
/* 461 */	{ .entry = &syscall_fchmodat },
/* 462 */	{ .entry = &syscall_faccessat },
/* 463 */	{ .entry = &syscall_pselect6 },
/* 464 */	{ .entry = &syscall_ppoll },
/* 465 */	{ .entry = &syscall_unshare },
/* 466 */	{ .entry = &syscall_set_robust_list },
/* 467 */	{ .entry = &syscall_get_robust_list },
/* 468 */	{ .entry = &syscall_splice },
/* 469 */	{ .entry = &syscall_sync_file_range },
/* 470 */	{ .entry = &syscall_tee },
/* 471 */	{ .entry = &syscall_vmsplice },
/* 472 */	{ .entry = &syscall_move_pages },
/* 473 */	{ .entry = &syscall_getcpu },
/* 474 */	{ .entry = &syscall_epoll_pwait },
/* 475 */	{ .entry = &syscall_utimensat },
/* 476 */	{ .entry = &syscall_signalfd },
/* 477 */	{ .entry = &syscall_ni_syscall },	/* sys_timerfd */
/* 478 */	{ .entry = &syscall_eventfd },
/* 479 */	{ .entry = &syscall_recvmmsg },
/* 480 */	{ .entry = &syscall_fallocate },
/* 481 */	{ .entry = &syscall_timerfd_create },
/* 482 */	{ .entry = &syscall_timerfd_settime },
/* 483 */	{ .entry = &syscall_timerfd_gettime },
/* 484 */	{ .entry = &syscall_signalfd4 },
/* 485 */	{ .entry = &syscall_eventfd2 },
/* 486 */	{ .entry = &syscall_epoll_create1 },
/* 487 */	{ .entry = &syscall_dup3 },
/* 488 */	{ .entry = &syscall_pipe2 },
/* 489 */	{ .entry = &syscall_inotify_init1 },
/* 490 */	{ .entry = &syscall_preadv },
/* 491 */	{ .entry = &syscall_pwritev },
/* 492 */	{ .entry = &syscall_rt_tgsigqueueinfo },
/* 493 */	{ .entry = &syscall_perf_event_open },
/* 494 */	{ .entry = &syscall_fanotify_init },
/* 495 */	{ .entry = &syscall_fanotify_mark },
/* 496 */	{ .entry = &syscall_prlimit64 },
/* 497 */	{ .entry = &syscall_name_to_handle_at },
/* 498 */	{ .entry = &syscall_open_by_handle_at },
/* 499 */	{ .entry = &syscall_clock_adjtime },
/* 500 */	{ .entry = &syscall_syncfs },
/* 501 */	{ .entry = &syscall_setns },
/* 502 */	{ .entry = &syscall_accept4 },
/* 503 */	{ .entry = &syscall_sendmmsg },
/* 504 */	{ .entry = &syscall_process_vm_readv },
/* 505 */	{ .entry = &syscall_process_vm_writev },
/* 506 */	{ .entry = &syscall_kcmp },
/* 507 */	{ .entry = &syscall_finit_module },
};
