/**
 * RR-Fuzz Strace Parser Module Implementation
 * Provides functionality for parsing syscall records in strace format.
 */

#include "rr_syscallparser.h"
#include <sys/ioctl.h>
#include <termios.h>

/* strdup function implementation if not available */
#ifndef _GNU_SOURCE
static char *strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *p = malloc(len);
    if (p) {
        memcpy(p, s, len);
    }
    return p;
}
#endif

/* ==================== Syscall Name to Number Mapping Table ==================== */

typedef struct {
    const char *name;
    int number;
} syscall_mapping_t;

static const syscall_mapping_t g_syscall_map[] = {
#ifdef TARGET_NR_read
    {"read", TARGET_NR_read},
#endif
#ifdef TARGET_NR_write
    {"write", TARGET_NR_write},
#endif
#ifdef TARGET_NR_open
    {"open", TARGET_NR_open},
#endif
#ifdef TARGET_NR_close
    {"close", TARGET_NR_close},
#endif
#ifdef TARGET_NR_stat
    {"stat", TARGET_NR_stat},
#endif
#ifdef TARGET_NR_fstat
    {"fstat", TARGET_NR_fstat},
#endif
#ifdef TARGET_NR_lstat
    {"lstat", TARGET_NR_lstat},
#endif
#ifdef TARGET_NR_poll
    {"poll", TARGET_NR_poll},
#endif
#ifdef TARGET_NR_lseek
    {"lseek", TARGET_NR_lseek},
#endif
#ifdef TARGET_NR_mmap
    {"mmap", TARGET_NR_mmap},
#endif
#ifdef TARGET_NR_mprotect
    {"mprotect", TARGET_NR_mprotect},
#endif
#ifdef TARGET_NR_munmap
    {"munmap", TARGET_NR_munmap},
#endif
#ifdef TARGET_NR_brk
    {"brk", TARGET_NR_brk},
#endif
#ifdef TARGET_NR_rt_sigaction
    {"rt_sigaction", TARGET_NR_rt_sigaction},
#endif
#ifdef TARGET_NR_rt_sigprocmask
    {"rt_sigprocmask", TARGET_NR_rt_sigprocmask},
#endif
#ifdef TARGET_NR_rt_sigreturn
    {"rt_sigreturn", TARGET_NR_rt_sigreturn},
#endif
#ifdef TARGET_NR_ioctl
    {"ioctl", TARGET_NR_ioctl},
#endif
#ifdef TARGET_NR_pread64
    {"pread64", TARGET_NR_pread64},
#endif
#ifdef TARGET_NR_pwrite64
    {"pwrite64", TARGET_NR_pwrite64},
#endif
#ifdef TARGET_NR_readv
    {"readv", TARGET_NR_readv},
#endif
#ifdef TARGET_NR_writev
    {"writev", TARGET_NR_writev},
#endif
#ifdef TARGET_NR_access
    {"access", TARGET_NR_access},
#endif
#ifdef TARGET_NR_pipe
    {"pipe", TARGET_NR_pipe},
#endif
#ifdef TARGET_NR_select
    {"select", TARGET_NR_select},
#endif
#ifdef TARGET_NR_sched_yield
    {"sched_yield", TARGET_NR_sched_yield},
#endif
#ifdef TARGET_NR_mremap
    {"mremap", TARGET_NR_mremap},
#endif
#ifdef TARGET_NR_msync
    {"msync", TARGET_NR_msync},
#endif
#ifdef TARGET_NR_mincore
    {"mincore", TARGET_NR_mincore},
#endif
#ifdef TARGET_NR_madvise
    {"madvise", TARGET_NR_madvise},
#endif
#ifdef TARGET_NR_shmget
    {"shmget", TARGET_NR_shmget},
#endif
#ifdef TARGET_NR_shmat
    {"shmat", TARGET_NR_shmat},
#endif
#ifdef TARGET_NR_shmctl
    {"shmctl", TARGET_NR_shmctl},
#endif
#ifdef TARGET_NR_dup
    {"dup", TARGET_NR_dup},
#endif
#ifdef TARGET_NR_dup2
    {"dup2", TARGET_NR_dup2},
#endif
#ifdef TARGET_NR_pause
    {"pause", TARGET_NR_pause},
#endif
#ifdef TARGET_NR_nanosleep
    {"nanosleep", TARGET_NR_nanosleep},
#endif
#ifdef TARGET_NR_getitimer
    {"getitimer", TARGET_NR_getitimer},
#endif
#ifdef TARGET_NR_alarm
    {"alarm", TARGET_NR_alarm},
#endif
#ifdef TARGET_NR_setitimer
    {"setitimer", TARGET_NR_setitimer},
#endif
#ifdef TARGET_NR_getpid
    {"getpid", TARGET_NR_getpid},
#endif
#ifdef TARGET_NR_sendfile
    {"sendfile", TARGET_NR_sendfile},
#endif
#ifdef TARGET_NR_socket
    {"socket", TARGET_NR_socket},
#endif
#ifdef TARGET_NR_connect
    {"connect", TARGET_NR_connect},
#endif
#ifdef TARGET_NR_accept
    {"accept", TARGET_NR_accept},
#endif
#ifdef TARGET_NR_sendto
    {"sendto", TARGET_NR_sendto},
#endif
#ifdef TARGET_NR_recvfrom
    {"recvfrom", TARGET_NR_recvfrom},
#endif
#ifdef TARGET_NR_sendmsg
    {"sendmsg", TARGET_NR_sendmsg},
#endif
#ifdef TARGET_NR_recvmsg
    {"recvmsg", TARGET_NR_recvmsg},
#endif
#ifdef TARGET_NR_shutdown
    {"shutdown", TARGET_NR_shutdown},
#endif
#ifdef TARGET_NR_bind
    {"bind", TARGET_NR_bind},
#endif
#ifdef TARGET_NR_listen
    {"listen", TARGET_NR_listen},
#endif
#ifdef TARGET_NR_getsockname
    {"getsockname", TARGET_NR_getsockname},
#endif
#ifdef TARGET_NR_getpeername
    {"getpeername", TARGET_NR_getpeername},
#endif
#ifdef TARGET_NR_socketpair
    {"socketpair", TARGET_NR_socketpair},
#endif
#ifdef TARGET_NR_setsockopt
    {"setsockopt", TARGET_NR_setsockopt},
#endif
#ifdef TARGET_NR_getsockopt
    {"getsockopt", TARGET_NR_getsockopt},
#endif
#ifdef TARGET_NR_clone
    {"clone", TARGET_NR_clone},
#endif
#ifdef TARGET_NR_fork
    {"fork", TARGET_NR_fork},
#endif
#ifdef TARGET_NR_vfork
    {"vfork", TARGET_NR_vfork},
#endif
#ifdef TARGET_NR_execve
    {"execve", TARGET_NR_execve},
#endif
#ifdef TARGET_NR_exit
    {"exit", TARGET_NR_exit},
#endif
#ifdef TARGET_NR_wait4
    {"wait4", TARGET_NR_wait4},
#endif
#ifdef TARGET_NR_kill
    {"kill", TARGET_NR_kill},
#endif
#ifdef TARGET_NR_uname
    {"uname", TARGET_NR_uname},
#endif
#ifdef TARGET_NR_semget
    {"semget", TARGET_NR_semget},
#endif
#ifdef TARGET_NR_semop
    {"semop", TARGET_NR_semop},
#endif
#ifdef TARGET_NR_semctl
    {"semctl", TARGET_NR_semctl},
#endif
#ifdef TARGET_NR_shmdt
    {"shmdt", TARGET_NR_shmdt},
#endif
#ifdef TARGET_NR_msgget
    {"msgget", TARGET_NR_msgget},
#endif
#ifdef TARGET_NR_msgsnd
    {"msgsnd", TARGET_NR_msgsnd},
#endif
#ifdef TARGET_NR_msgrcv
    {"msgrcv", TARGET_NR_msgrcv},
#endif
#ifdef TARGET_NR_msgctl
    {"msgctl", TARGET_NR_msgctl},
#endif
#ifdef TARGET_NR_fcntl
    {"fcntl", TARGET_NR_fcntl},
#endif
#ifdef TARGET_NR_flock
    {"flock", TARGET_NR_flock},
#endif
#ifdef TARGET_NR_fsync
    {"fsync", TARGET_NR_fsync},
#endif
#ifdef TARGET_NR_fdatasync
    {"fdatasync", TARGET_NR_fdatasync},
#endif
#ifdef TARGET_NR_truncate
    {"truncate", TARGET_NR_truncate},
#endif
#ifdef TARGET_NR_ftruncate
    {"ftruncate", TARGET_NR_ftruncate},
#endif
#ifdef TARGET_NR_getdents
    {"getdents", TARGET_NR_getdents},
#endif
#ifdef TARGET_NR_getcwd
    {"getcwd", TARGET_NR_getcwd},
#endif
#ifdef TARGET_NR_chdir
    {"chdir", TARGET_NR_chdir},
#endif
#ifdef TARGET_NR_fchdir
    {"fchdir", TARGET_NR_fchdir},
#endif
#ifdef TARGET_NR_rename
    {"rename", TARGET_NR_rename},
#endif
#ifdef TARGET_NR_mkdir
    {"mkdir", TARGET_NR_mkdir},
#endif
#ifdef TARGET_NR_rmdir
    {"rmdir", TARGET_NR_rmdir},
#endif
#ifdef TARGET_NR_creat
    {"creat", TARGET_NR_creat},
#endif
#ifdef TARGET_NR_link
    {"link", TARGET_NR_link},
#endif
#ifdef TARGET_NR_unlink
    {"unlink", TARGET_NR_unlink},
#endif
#ifdef TARGET_NR_symlink
    {"symlink", TARGET_NR_symlink},
#endif
#ifdef TARGET_NR_readlink
    {"readlink", TARGET_NR_readlink},
#endif
#ifdef TARGET_NR_openat
    {"openat", TARGET_NR_openat},
#endif
#ifdef TARGET_NR_faccessat
    {"faccessat", TARGET_NR_faccessat},
#endif
#ifdef TARGET_NR_faccessat2
    {"faccessat2", TARGET_NR_faccessat2},
#endif
#ifdef TARGET_NR_renameat
    {"renameat", TARGET_NR_renameat},
#endif
#ifdef TARGET_NR_renameat2
    {"renameat2", TARGET_NR_renameat2},
#endif
#ifdef TARGET_NR_unlinkat
    {"unlinkat", TARGET_NR_unlinkat},
#endif
#ifdef TARGET_NR_mkdirat
    {"mkdirat", TARGET_NR_mkdirat},
#endif
#ifdef TARGET_NR_readlinkat
    {"readlinkat", TARGET_NR_readlinkat},
#endif
#ifdef TARGET_NR_symlinkat
    {"symlinkat", TARGET_NR_symlinkat},
#endif
#ifdef TARGET_NR_chmod
    {"chmod", TARGET_NR_chmod},
#endif
#ifdef TARGET_NR_fchmod
    {"fchmod", TARGET_NR_fchmod},
#endif
#ifdef TARGET_NR_chown
    {"chown", TARGET_NR_chown},
#endif
#ifdef TARGET_NR_fchown
    {"fchown", TARGET_NR_fchown},
#endif
#ifdef TARGET_NR_lchown
    {"lchown", TARGET_NR_lchown},
#endif
#ifdef TARGET_NR_umask
    {"umask", TARGET_NR_umask},
#endif
#ifdef TARGET_NR_gettimeofday
    {"gettimeofday", TARGET_NR_gettimeofday},
#endif
#ifdef TARGET_NR_getrlimit
    {"getrlimit", TARGET_NR_getrlimit},
#endif
#ifdef TARGET_NR_getrusage
    {"getrusage", TARGET_NR_getrusage},
#endif
#ifdef TARGET_NR_sysinfo
    {"sysinfo", TARGET_NR_sysinfo},
#endif
#ifdef TARGET_NR_times
    {"times", TARGET_NR_times},
#endif
#ifdef TARGET_NR_ptrace
    {"ptrace", TARGET_NR_ptrace},
#endif
#ifdef TARGET_NR_getuid
    {"getuid", TARGET_NR_getuid},
#endif
#ifdef TARGET_NR_syslog
    {"syslog", TARGET_NR_syslog},
#endif
#ifdef TARGET_NR_getgid
    {"getgid", TARGET_NR_getgid},
#endif
#ifdef TARGET_NR_setuid
    {"setuid", TARGET_NR_setuid},
#endif
#ifdef TARGET_NR_setgid
    {"setgid", TARGET_NR_setgid},
#endif
#ifdef TARGET_NR_geteuid
    {"geteuid", TARGET_NR_geteuid},
#endif
#ifdef TARGET_NR_getegid
    {"getegid", TARGET_NR_getegid},
#endif
#ifdef TARGET_NR_setpgid
    {"setpgid", TARGET_NR_setpgid},
#endif
#ifdef TARGET_NR_getppid
    {"getppid", TARGET_NR_getppid},
#endif
#ifdef TARGET_NR_getpgrp
    {"getpgrp", TARGET_NR_getpgrp},
#endif
#ifdef TARGET_NR_setsid
    {"setsid", TARGET_NR_setsid},
#endif
#ifdef TARGET_NR_setreuid
    {"setreuid", TARGET_NR_setreuid},
#endif
#ifdef TARGET_NR_setregid
    {"setregid", TARGET_NR_setregid},
#endif
#ifdef TARGET_NR_getgroups
    {"getgroups", TARGET_NR_getgroups},
#endif
#ifdef TARGET_NR_setgroups
    {"setgroups", TARGET_NR_setgroups},
#endif
#ifdef TARGET_NR_setresuid
    {"setresuid", TARGET_NR_setresuid},
#endif
#ifdef TARGET_NR_getresuid
    {"getresuid", TARGET_NR_getresuid},
#endif
#ifdef TARGET_NR_setresgid
    {"setresgid", TARGET_NR_setresgid},
#endif
#ifdef TARGET_NR_getresgid
    {"getresgid", TARGET_NR_getresgid},
#endif
#ifdef TARGET_NR_getpgid
    {"getpgid", TARGET_NR_getpgid},
#endif
#ifdef TARGET_NR_setfsuid
    {"setfsuid", TARGET_NR_setfsuid},
#endif
#ifdef TARGET_NR_setfsgid
    {"setfsgid", TARGET_NR_setfsgid},
#endif
#ifdef TARGET_NR_getsid
    {"getsid", TARGET_NR_getsid},
#endif
#ifdef TARGET_NR_capget
    {"capget", TARGET_NR_capget},
#endif
#ifdef TARGET_NR_capset
    {"capset", TARGET_NR_capset},
#endif
#ifdef TARGET_NR_rt_sigpending
    {"rt_sigpending", TARGET_NR_rt_sigpending},
#endif
#ifdef TARGET_NR_rt_sigtimedwait
    {"rt_sigtimedwait", TARGET_NR_rt_sigtimedwait},
#endif
#ifdef TARGET_NR_rt_sigqueueinfo
    {"rt_sigqueueinfo", TARGET_NR_rt_sigqueueinfo},
#endif
#ifdef TARGET_NR_rt_sigsuspend
    {"rt_sigsuspend", TARGET_NR_rt_sigsuspend},
#endif
#ifdef TARGET_NR_sigaltstack
    {"sigaltstack", TARGET_NR_sigaltstack},
#endif
#ifdef TARGET_NR_utime
    {"utime", TARGET_NR_utime},
#endif
#ifdef TARGET_NR_mknod
    {"mknod", TARGET_NR_mknod},
#endif
#ifdef TARGET_NR_uselib
    {"uselib", TARGET_NR_uselib},
#endif
#ifdef TARGET_NR_personality
    {"personality", TARGET_NR_personality},
#endif
#ifdef TARGET_NR_ustat
    {"ustat", TARGET_NR_ustat},
#endif
#ifdef TARGET_NR_statfs
    {"statfs", TARGET_NR_statfs},
#endif
#ifdef TARGET_NR_statx
    {"statx", TARGET_NR_statx},
#endif
#ifdef TARGET_NR_epoll_create
    {"epoll_create", TARGET_NR_epoll_create},
#endif
#ifdef TARGET_NR_epoll_create1
    {"epoll_create1", TARGET_NR_epoll_create1},
#endif
#ifdef TARGET_NR_epoll_ctl
    {"epoll_ctl", TARGET_NR_epoll_ctl},
#endif
#ifdef TARGET_NR_epoll_wait
    {"epoll_wait", TARGET_NR_epoll_wait},
#endif
#ifdef TARGET_NR_epoll_pwait
    {"epoll_pwait", TARGET_NR_epoll_pwait},
#endif
#ifdef TARGET_NR_fstatfs
    {"fstatfs", TARGET_NR_fstatfs},
#endif
#ifdef TARGET_NR_sysfs
    {"sysfs", TARGET_NR_sysfs},
#endif
#ifdef TARGET_NR_getpriority
    {"getpriority", TARGET_NR_getpriority},
#endif
#ifdef TARGET_NR_setpriority
    {"setpriority", TARGET_NR_setpriority},
#endif
#ifdef TARGET_NR_sched_setparam
    {"sched_setparam", TARGET_NR_sched_setparam},
#endif
#ifdef TARGET_NR_sched_getparam
    {"sched_getparam", TARGET_NR_sched_getparam},
#endif
#ifdef TARGET_NR_sched_setscheduler
    {"sched_setscheduler", TARGET_NR_sched_setscheduler},
#endif
#ifdef TARGET_NR_sched_getscheduler
    {"sched_getscheduler", TARGET_NR_sched_getscheduler},
#endif
#ifdef TARGET_NR_sched_get_priority_max
    {"sched_get_priority_max", TARGET_NR_sched_get_priority_max},
#endif
#ifdef TARGET_NR_sched_get_priority_min
    {"sched_get_priority_min", TARGET_NR_sched_get_priority_min},
#endif
#ifdef TARGET_NR_sched_rr_get_interval
    {"sched_rr_get_interval", TARGET_NR_sched_rr_get_interval},
#endif
#ifdef TARGET_NR_mlock
    {"mlock", TARGET_NR_mlock},
#endif
#ifdef TARGET_NR_munlock
    {"munlock", TARGET_NR_munlock},
#endif
#ifdef TARGET_NR_mlockall
    {"mlockall", TARGET_NR_mlockall},
#endif
#ifdef TARGET_NR_munlockall
    {"munlockall", TARGET_NR_munlockall},
#endif
#ifdef TARGET_NR_vhangup
    {"vhangup", TARGET_NR_vhangup},
#endif
#ifdef TARGET_NR_modify_ldt
    {"modify_ldt", TARGET_NR_modify_ldt},
#endif
#ifdef TARGET_NR_pivot_root
    {"pivot_root", TARGET_NR_pivot_root},
#endif
#ifdef TARGET_NR__sysctl
    {"_sysctl", TARGET_NR__sysctl},
#endif
#ifdef TARGET_NR_prctl
    {"prctl", TARGET_NR_prctl},
#endif
#ifdef TARGET_NR_arch_prctl
    {"arch_prctl", TARGET_NR_arch_prctl},
#endif
#ifdef TARGET_NR_adjtimex
    {"adjtimex", TARGET_NR_adjtimex},
#endif
#ifdef TARGET_NR_setrlimit
    {"setrlimit", TARGET_NR_setrlimit},
#endif
#ifdef TARGET_NR_chroot
    {"chroot", TARGET_NR_chroot},
#endif
#ifdef TARGET_NR_sync
    {"sync", TARGET_NR_sync},
#endif
#ifdef TARGET_NR_acct
    {"acct", TARGET_NR_acct},
#endif
#ifdef TARGET_NR_settimeofday
    {"settimeofday", TARGET_NR_settimeofday},
#endif
#ifdef TARGET_NR_mount
    {"mount", TARGET_NR_mount},
#endif
#ifdef TARGET_NR_umount2
    {"umount2", TARGET_NR_umount2},
#endif
#ifdef TARGET_NR_swapon
    {"swapon", TARGET_NR_swapon},
#endif
#ifdef TARGET_NR_swapoff
    {"swapoff", TARGET_NR_swapoff},
#endif
#ifdef TARGET_NR_reboot
    {"reboot", TARGET_NR_reboot},
#endif
#ifdef TARGET_NR_sethostname
    {"sethostname", TARGET_NR_sethostname},
#endif
#ifdef TARGET_NR_setdomainname
    {"setdomainname", TARGET_NR_setdomainname},
#endif
#ifdef TARGET_NR_iopl
    {"iopl", TARGET_NR_iopl},
#endif
#ifdef TARGET_NR_ioperm
    {"ioperm", TARGET_NR_ioperm},
#endif
#ifdef TARGET_NR_create_module
    {"create_module", TARGET_NR_create_module},
#endif
#ifdef TARGET_NR_init_module
    {"init_module", TARGET_NR_init_module},
#endif
#ifdef TARGET_NR_delete_module
    {"delete_module", TARGET_NR_delete_module},
#endif
#ifdef TARGET_NR_get_kernel_syms
    {"get_kernel_syms", TARGET_NR_get_kernel_syms},
#endif
#ifdef TARGET_NR_query_module
    {"query_module", TARGET_NR_query_module},
#endif
#ifdef TARGET_NR_quotactl
    {"quotactl", TARGET_NR_quotactl},
#endif
#ifdef TARGET_NR_nfsservctl
    {"nfsservctl", TARGET_NR_nfsservctl},
#endif
#ifdef TARGET_NR_getpmsg
    {"getpmsg", TARGET_NR_getpmsg},
#endif
#ifdef TARGET_NR_putpmsg
    {"putpmsg", TARGET_NR_putpmsg},
#endif
#ifdef TARGET_NR_afs_syscall
    {"afs_syscall", TARGET_NR_afs_syscall},
#endif
#ifdef TARGET_NR_tuxcall
    {"tuxcall", TARGET_NR_tuxcall},
#endif
#ifdef TARGET_NR_security
    {"security", TARGET_NR_security},
#endif
#ifdef TARGET_NR_gettid
    {"gettid", TARGET_NR_gettid},
#endif
#ifdef TARGET_NR_readahead
    {"readahead", TARGET_NR_readahead},
#endif
#ifdef TARGET_NR_setxattr
    {"setxattr", TARGET_NR_setxattr},
#endif
#ifdef TARGET_NR_lsetxattr
    {"lsetxattr", TARGET_NR_lsetxattr},
#endif
#ifdef TARGET_NR_fsetxattr
    {"fsetxattr", TARGET_NR_fsetxattr},
#endif
#ifdef TARGET_NR_getxattr
    {"getxattr", TARGET_NR_getxattr},
#endif
#ifdef TARGET_NR_lgetxattr
    {"lgetxattr", TARGET_NR_lgetxattr},
#endif
#ifdef TARGET_NR_fgetxattr
    {"fgetxattr", TARGET_NR_fgetxattr},
#endif
#ifdef TARGET_NR_listxattr
    {"listxattr", TARGET_NR_listxattr},
#endif
#ifdef TARGET_NR_llistxattr
    {"llistxattr", TARGET_NR_llistxattr},
#endif
#ifdef TARGET_NR_flistxattr
    {"flistxattr", TARGET_NR_flistxattr},
#endif
#ifdef TARGET_NR_removexattr
    {"removexattr", TARGET_NR_removexattr},
#endif
#ifdef TARGET_NR_lremovexattr
    {"lremovexattr", TARGET_NR_lremovexattr},
#endif
#ifdef TARGET_NR_fremovexattr
    {"fremovexattr", TARGET_NR_fremovexattr},
#endif
#ifdef TARGET_NR_tkill
    {"tkill", TARGET_NR_tkill},
#endif
#ifdef TARGET_NR_time
    {"time", TARGET_NR_time},
#endif
#ifdef TARGET_NR_futex
    {"futex", TARGET_NR_futex},
#endif
#ifdef TARGET_NR_sched_setaffinity
    {"sched_setaffinity", TARGET_NR_sched_setaffinity},
#endif
#ifdef TARGET_NR_sched_getaffinity
    {"sched_getaffinity", TARGET_NR_sched_getaffinity},
#endif
#ifdef TARGET_NR_set_thread_area
    {"set_thread_area", TARGET_NR_set_thread_area},
#endif
#ifdef TARGET_NR_io_setup
    {"io_setup", TARGET_NR_io_setup},
#endif
#ifdef TARGET_NR_io_destroy
    {"io_destroy", TARGET_NR_io_destroy},
#endif
#ifdef TARGET_NR_io_getevents
    {"io_getevents", TARGET_NR_io_getevents},
#endif
#ifdef TARGET_NR_io_submit
    {"io_submit", TARGET_NR_io_submit},
#endif
#ifdef TARGET_NR_io_cancel
    {"io_cancel", TARGET_NR_io_cancel},
#endif
#ifdef TARGET_NR_get_thread_area
    {"get_thread_area", TARGET_NR_get_thread_area},
#endif
#ifdef TARGET_NR_lookup_dcookie
    {"lookup_dcookie", TARGET_NR_lookup_dcookie},
#endif
#ifdef TARGET_NR_epoll_create
    {"epoll_create", TARGET_NR_epoll_create},
#endif
#ifdef TARGET_NR_remap_file_pages
    {"remap_file_pages", TARGET_NR_remap_file_pages},
#endif
#ifdef TARGET_NR_getdents64
    {"getdents64", TARGET_NR_getdents64},
#endif
#ifdef TARGET_NR_set_tid_address
    {"set_tid_address", TARGET_NR_set_tid_address},
#endif
#ifdef TARGET_NR_restart_syscall
    {"restart_syscall", TARGET_NR_restart_syscall},
#endif
#ifdef TARGET_NR_semtimedop
    {"semtimedop", TARGET_NR_semtimedop},
#endif
#ifdef TARGET_NR_fadvise64
    {"fadvise64", TARGET_NR_fadvise64},
#endif
#ifdef TARGET_NR_timer_create
    {"timer_create", TARGET_NR_timer_create},
#endif
#ifdef TARGET_NR_timer_settime
    {"timer_settime", TARGET_NR_timer_settime},
#endif
#ifdef TARGET_NR_timer_gettime
    {"timer_gettime", TARGET_NR_timer_gettime},
#endif
#ifdef TARGET_NR_timer_getoverrun
    {"timer_getoverrun", TARGET_NR_timer_getoverrun},
#endif
#ifdef TARGET_NR_timer_delete
    {"timer_delete", TARGET_NR_timer_delete},
#endif
#ifdef TARGET_NR_clock_settime
    {"clock_settime", TARGET_NR_clock_settime},
#endif
#ifdef TARGET_NR_clock_gettime
    {"clock_gettime", TARGET_NR_clock_gettime},
#endif
#ifdef TARGET_NR_clock_getres
    {"clock_getres", TARGET_NR_clock_getres},
#endif
#ifdef TARGET_NR_clock_nanosleep
    {"clock_nanosleep", TARGET_NR_clock_nanosleep},
#endif
#ifdef TARGET_NR_exit_group
    {"exit_group", TARGET_NR_exit_group},
#endif
#ifdef TARGET_NR_epoll_wait
    {"epoll_wait", TARGET_NR_epoll_wait},
#endif
#ifdef TARGET_NR_epoll_ctl
    {"epoll_ctl", TARGET_NR_epoll_ctl},
#endif
#ifdef TARGET_NR_tgkill
    {"tgkill", TARGET_NR_tgkill},
#endif
#ifdef TARGET_NR_utimes
    {"utimes", TARGET_NR_utimes},
#endif
#ifdef TARGET_NR_vserver
    {"vserver", TARGET_NR_vserver},
#endif
#ifdef TARGET_NR_mbind
    {"mbind", TARGET_NR_mbind},
#endif
#ifdef TARGET_NR_set_mempolicy
    {"set_mempolicy", TARGET_NR_set_mempolicy},
#endif
#ifdef TARGET_NR_get_mempolicy
    {"get_mempolicy", TARGET_NR_get_mempolicy},
#endif
#ifdef TARGET_NR_mq_open
    {"mq_open", TARGET_NR_mq_open},
#endif
#ifdef TARGET_NR_mq_unlink
    {"mq_unlink", TARGET_NR_mq_unlink},
#endif
#ifdef TARGET_NR_mq_timedsend
    {"mq_timedsend", TARGET_NR_mq_timedsend},
#endif
#ifdef TARGET_NR_mq_timedreceive
    {"mq_timedreceive", TARGET_NR_mq_timedreceive},
#endif
#ifdef TARGET_NR_mq_notify
    {"mq_notify", TARGET_NR_mq_notify},
#endif
#ifdef TARGET_NR_mq_getsetattr
    {"mq_getsetattr", TARGET_NR_mq_getsetattr},
#endif
#ifdef TARGET_NR_kexec_load
    {"kexec_load", TARGET_NR_kexec_load},
#endif
#ifdef TARGET_NR_waitid
    {"waitid", TARGET_NR_waitid},
#endif
#ifdef TARGET_NR_add_key
    {"add_key", TARGET_NR_add_key},
#endif
#ifdef TARGET_NR_request_key
    {"request_key", TARGET_NR_request_key},
#endif
#ifdef TARGET_NR_keyctl
    {"keyctl", TARGET_NR_keyctl},
#endif
#ifdef TARGET_NR_ioprio_set
    {"ioprio_set", TARGET_NR_ioprio_set},
#endif
#ifdef TARGET_NR_ioprio_get
    {"ioprio_get", TARGET_NR_ioprio_get},
#endif
#ifdef TARGET_NR_inotify_init
    {"inotify_init", TARGET_NR_inotify_init},
#endif
#ifdef TARGET_NR_inotify_add_watch
    {"inotify_add_watch", TARGET_NR_inotify_add_watch},
#endif
#ifdef TARGET_NR_inotify_rm_watch
    {"inotify_rm_watch", TARGET_NR_inotify_rm_watch},
#endif
#ifdef TARGET_NR_migrate_pages
    {"migrate_pages", TARGET_NR_migrate_pages},
#endif
#ifdef TARGET_NR_openat
    {"openat", TARGET_NR_openat},
#endif
#ifdef TARGET_NR_mkdirat
    {"mkdirat", TARGET_NR_mkdirat},
#endif
#ifdef TARGET_NR_mknodat
    {"mknodat", TARGET_NR_mknodat},
#endif
#ifdef TARGET_NR_fchownat
    {"fchownat", TARGET_NR_fchownat},
#endif
#ifdef TARGET_NR_futimesat
    {"futimesat", TARGET_NR_futimesat},
#endif
#ifdef TARGET_NR_newfstatat
    {"newfstatat", TARGET_NR_newfstatat},
#endif
#ifdef TARGET_NR_unlinkat
    {"unlinkat", TARGET_NR_unlinkat},
#endif
#ifdef TARGET_NR_renameat
    {"renameat", TARGET_NR_renameat},
#endif
#ifdef TARGET_NR_linkat
    {"linkat", TARGET_NR_linkat},
#endif
#ifdef TARGET_NR_symlinkat
    {"symlinkat", TARGET_NR_symlinkat},
#endif
#ifdef TARGET_NR_readlinkat
    {"readlinkat", TARGET_NR_readlinkat},
#endif
#ifdef TARGET_NR_fchmodat
    {"fchmodat", TARGET_NR_fchmodat},
#endif
#ifdef TARGET_NR_faccessat
    {"faccessat", TARGET_NR_faccessat},
#endif
#ifdef TARGET_NR_pselect6
    {"pselect6", TARGET_NR_pselect6},
#endif
#ifdef TARGET_NR_ppoll
    {"ppoll", TARGET_NR_ppoll},
#endif
#ifdef TARGET_NR_unshare
    {"unshare", TARGET_NR_unshare},
#endif
#ifdef TARGET_NR_set_robust_list
    {"set_robust_list", TARGET_NR_set_robust_list},
#endif
#ifdef TARGET_NR_get_robust_list
    {"get_robust_list", TARGET_NR_get_robust_list},
#endif
#ifdef TARGET_NR_splice
    {"splice", TARGET_NR_splice},
#endif
#ifdef TARGET_NR_tee
    {"tee", TARGET_NR_tee},
#endif
#ifdef TARGET_NR_sync_file_range
    {"sync_file_range", TARGET_NR_sync_file_range},
#endif
#ifdef TARGET_NR_vmsplice
    {"vmsplice", TARGET_NR_vmsplice},
#endif
#ifdef TARGET_NR_move_pages
    {"move_pages", TARGET_NR_move_pages},
#endif
#ifdef TARGET_NR_utimensat
    {"utimensat", TARGET_NR_utimensat},
#endif
#ifdef TARGET_NR_epoll_pwait
    {"epoll_pwait", TARGET_NR_epoll_pwait},
#endif
#ifdef TARGET_NR_signalfd
    {"signalfd", TARGET_NR_signalfd},
#endif
#ifdef TARGET_NR_timerfd_create
    {"timerfd_create", TARGET_NR_timerfd_create},
#endif
#ifdef TARGET_NR_eventfd
    {"eventfd", TARGET_NR_eventfd},
#endif
#ifdef TARGET_NR_fallocate
    {"fallocate", TARGET_NR_fallocate},
#endif
#ifdef TARGET_NR_timerfd_settime
    {"timerfd_settime", TARGET_NR_timerfd_settime},
#endif
#ifdef TARGET_NR_timerfd_gettime
    {"timerfd_gettime", TARGET_NR_timerfd_gettime},
#endif
#ifdef TARGET_NR_accept4
    {"accept4", TARGET_NR_accept4},
#endif
#ifdef TARGET_NR_signalfd4
    {"signalfd4", TARGET_NR_signalfd4},
#endif
#ifdef TARGET_NR_eventfd2
    {"eventfd2", TARGET_NR_eventfd2},
#endif
#ifdef TARGET_NR_epoll_create1
    {"epoll_create1", TARGET_NR_epoll_create1},
#endif
#ifdef TARGET_NR_dup3
    {"dup3", TARGET_NR_dup3},
#endif
#ifdef TARGET_NR_pipe2
    {"pipe2", TARGET_NR_pipe2},
#endif
#ifdef TARGET_NR_inotify_init1
    {"inotify_init1", TARGET_NR_inotify_init1},
#endif
#ifdef TARGET_NR_preadv
    {"preadv", TARGET_NR_preadv},
#endif
#ifdef TARGET_NR_pwritev
    {"pwritev", TARGET_NR_pwritev},
#endif
#ifdef TARGET_NR_rt_tgsigqueueinfo
    {"rt_tgsigqueueinfo", TARGET_NR_rt_tgsigqueueinfo},
#endif
#ifdef TARGET_NR_perf_event_open
    {"perf_event_open", TARGET_NR_perf_event_open},
#endif
#ifdef TARGET_NR_recvmmsg
    {"recvmmsg", TARGET_NR_recvmmsg},
#endif
#ifdef TARGET_NR_fanotify_init
    {"fanotify_init", TARGET_NR_fanotify_init},
#endif
#ifdef TARGET_NR_fanotify_mark
    {"fanotify_mark", TARGET_NR_fanotify_mark},
#endif
#ifdef TARGET_NR_prlimit64
    {"prlimit64", TARGET_NR_prlimit64},
#endif
#ifdef TARGET_NR_name_to_handle_at
    {"name_to_handle_at", TARGET_NR_name_to_handle_at},
#endif
#ifdef TARGET_NR_open_by_handle_at
    {"open_by_handle_at", TARGET_NR_open_by_handle_at},
#endif
#ifdef TARGET_NR_clock_adjtime
    {"clock_adjtime", TARGET_NR_clock_adjtime},
#endif
#ifdef TARGET_NR_syncfs
    {"syncfs", TARGET_NR_syncfs},
#endif
#ifdef TARGET_NR_sendmmsg
    {"sendmmsg", TARGET_NR_sendmmsg},
#endif
#ifdef TARGET_NR_setns
    {"setns", TARGET_NR_setns},
#endif
#ifdef TARGET_NR_getcpu
    {"getcpu", TARGET_NR_getcpu},
#endif
#ifdef TARGET_NR_process_vm_readv
    {"process_vm_readv", TARGET_NR_process_vm_readv},
#endif
#ifdef TARGET_NR_process_vm_writev
    {"process_vm_writev", TARGET_NR_process_vm_writev},
#endif
#ifdef TARGET_NR_kcmp
    {"kcmp", TARGET_NR_kcmp},
#endif
#ifdef TARGET_NR_finit_module
    {"finit_module", TARGET_NR_finit_module},
#endif
#ifdef TARGET_NR_sched_setattr
    {"sched_setattr", TARGET_NR_sched_setattr},
#endif
#ifdef TARGET_NR_sched_getattr
    {"sched_getattr", TARGET_NR_sched_getattr},
#endif
#ifdef TARGET_NR_renameat2
    {"renameat2", TARGET_NR_renameat2},
#endif
#ifdef TARGET_NR_seccomp
    {"seccomp", TARGET_NR_seccomp},
#endif
#ifdef TARGET_NR_getrandom
    {"getrandom", TARGET_NR_getrandom},
#endif
#ifdef TARGET_NR_memfd_create
    {"memfd_create", TARGET_NR_memfd_create},
#endif
#ifdef TARGET_NR_kexec_file_load
    {"kexec_file_load", TARGET_NR_kexec_file_load},
#endif
#ifdef TARGET_NR_bpf
    {"bpf", TARGET_NR_bpf},
#endif
#ifdef TARGET_NR_execveat
    {"execveat", TARGET_NR_execveat},
#endif
#ifdef TARGET_NR_userfaultfd
    {"userfaultfd", TARGET_NR_userfaultfd},
#endif
#ifdef TARGET_NR_membarrier
    {"membarrier", TARGET_NR_membarrier},
#endif
#ifdef TARGET_NR_mlock2
    {"mlock2", TARGET_NR_mlock2},
#endif
#ifdef TARGET_NR_copy_file_range
    {"copy_file_range", TARGET_NR_copy_file_range},
#endif
#ifdef TARGET_NR_preadv2
    {"preadv2", TARGET_NR_preadv2},
#endif
#ifdef TARGET_NR_pwritev2
    {"pwritev2", TARGET_NR_pwritev2},
#endif
    {NULL, -1}  /* End marker */
};

/* ==================== Flag Mapping Functions ==================== */

/* Memory protection flags mapping */
static int map_prot_flag(const char *flag_str) {
    if (strcmp(flag_str, "PROT_NONE") == 0) return PROT_NONE;
    if (strcmp(flag_str, "PROT_READ") == 0) return PROT_READ;
    if (strcmp(flag_str, "PROT_WRITE") == 0) return PROT_WRITE;
    if (strcmp(flag_str, "PROT_EXEC") == 0) return PROT_EXEC;
    return 0;
}

/* Memory mapping flags mapping */
static int map_mmap_flag(const char *flag_str) {
    if (strcmp(flag_str, "MAP_SHARED") == 0) return MAP_SHARED;
    if (strcmp(flag_str, "MAP_PRIVATE") == 0) return MAP_PRIVATE;
    if (strcmp(flag_str, "MAP_FIXED") == 0) return MAP_FIXED;
    if (strcmp(flag_str, "MAP_ANONYMOUS") == 0) return MAP_ANONYMOUS;
#ifdef MAP_ANON
    if (strcmp(flag_str, "MAP_ANON") == 0) return MAP_ANON;
#endif
#ifdef MAP_32BIT
    if (strcmp(flag_str, "MAP_32BIT") == 0) return MAP_32BIT;
#endif
#ifdef MAP_GROWSDOWN
    if (strcmp(flag_str, "MAP_GROWSDOWN") == 0) return MAP_GROWSDOWN;
#endif
#ifdef MAP_DENYWRITE
    if (strcmp(flag_str, "MAP_DENYWRITE") == 0) return MAP_DENYWRITE;
#endif
#ifdef MAP_EXECUTABLE
    if (strcmp(flag_str, "MAP_EXECUTABLE") == 0) return MAP_EXECUTABLE;
#endif
#ifdef MAP_LOCKED
    if (strcmp(flag_str, "MAP_LOCKED") == 0) return MAP_LOCKED;
#endif
#ifdef MAP_NORESERVE
    if (strcmp(flag_str, "MAP_NORESERVE") == 0) return MAP_NORESERVE;
#endif
#ifdef MAP_POPULATE
    if (strcmp(flag_str, "MAP_POPULATE") == 0) return MAP_POPULATE;
#endif
#ifdef MAP_NONBLOCK
    if (strcmp(flag_str, "MAP_NONBLOCK") == 0) return MAP_NONBLOCK;
#endif
#ifdef MAP_STACK
    if (strcmp(flag_str, "MAP_STACK") == 0) return MAP_STACK;
#endif
#ifdef MAP_HUGETLB
    if (strcmp(flag_str, "MAP_HUGETLB") == 0) return MAP_HUGETLB;
#endif
    return 0;
}

/* File open flags mapping */
static int map_open_flag(const char *flag_str) {
    if (strcmp(flag_str, "O_RDONLY") == 0) return O_RDONLY;
    if (strcmp(flag_str, "O_WRONLY") == 0) return O_WRONLY;
    if (strcmp(flag_str, "O_RDWR") == 0) return O_RDWR;
    if (strcmp(flag_str, "O_CREAT") == 0) return O_CREAT;
    if (strcmp(flag_str, "O_EXCL") == 0) return O_EXCL;
    if (strcmp(flag_str, "O_NOCTTY") == 0) return O_NOCTTY;
    if (strcmp(flag_str, "O_TRUNC") == 0) return O_TRUNC;
    if (strcmp(flag_str, "O_APPEND") == 0) return O_APPEND;
    if (strcmp(flag_str, "O_NONBLOCK") == 0) return O_NONBLOCK;
    if (strcmp(flag_str, "O_SYNC") == 0) return O_SYNC;
#ifdef O_CLOEXEC
    if (strcmp(flag_str, "O_CLOEXEC") == 0) return O_CLOEXEC;
#endif
    return 0;
}

/* Access mode flags mapping */
static int map_access_flag(const char *flag_str) {
    if (strcmp(flag_str, "F_OK") == 0) return F_OK;
    if (strcmp(flag_str, "R_OK") == 0) return R_OK;
    if (strcmp(flag_str, "W_OK") == 0) return W_OK;
    if (strcmp(flag_str, "X_OK") == 0) return X_OK;
    return 0;
}

/* ==================== Helper Functions Implementation ==================== */

/**
 * Parse a hexadecimal or decimal numeric string into a long integer.
 */
long rr_strace_parse_number(const char *str) {
    if (!str) return 0;
    
    if (strncmp(str, "0x", 2) == 0) {
        return strtol(str, NULL, 16);
    }
    return strtol(str, NULL, 10);
}

/**
 * Identify parameter type.
 */
rr_strace_arg_type_t rr_strace_identify_arg_type(const char *arg_str) {
    if (!arg_str) return RR_STRACE_ARG_TYPE_INT;
    
    if (arg_str[0] == '\"') {
        return RR_STRACE_ARG_TYPE_STR;
    } else if (strncmp(arg_str, "0x", 2) == 0 || 
              (arg_str[0] >= '0' && arg_str[0] <= '9') ||
              (arg_str[0] == '-' && arg_str[1] >= '0' && arg_str[1] <= '9') ||
              strcmp(arg_str, "NULL") == 0) {
        return RR_STRACE_ARG_TYPE_INT;
    } else {
        return RR_STRACE_ARG_TYPE_PTR;
    }
}

/**
 * Parse combined flags string.
 */
static int parse_combined_flags(const char *flag_str, int (*map_flag)(const char*)) {
    if (!flag_str || !map_flag) {
        return 0;
    }
    
    /* If it is purely numeric, return directly */
    char *endptr;
    long value = strtol(flag_str, &endptr, 0);
    if (*flag_str != '\0' && *endptr == '\0') {
        return (int)value;
    }
    
    /* Copy string to allow modification */
    char flag_copy[256];
    strncpy(flag_copy, flag_str, sizeof(flag_copy) - 1);
    flag_copy[sizeof(flag_copy) - 1] = '\0';
    
    /* Parse flags separated by '|' */
    int result = 0;
    char *token = strtok(flag_copy, "|");
    while (token) {
        /* Trim leading/trailing whitespace */
        while (*token && isspace(*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace(*end)) *end-- = '\0';
        
        /* Look up flag value */
        result |= map_flag(token);
        
        token = strtok(NULL, "|");
    }
    
    return result;
}

/**
 * Parse flags.
 */
int rr_strace_parse_flags(const char *flag_str, const char *syscall_name, int arg_index) {
    if (!flag_str || !syscall_name) return 0;
    
    /* mmap syscall */
    if (strcmp(syscall_name, "mmap") == 0) {
        if (arg_index == 2) {  /* prot parameter */
            return parse_combined_flags(flag_str, map_prot_flag);
        } else if (arg_index == 3) {  /* flags parameter */
            return parse_combined_flags(flag_str, map_mmap_flag);
        }
    }
    /* mprotect syscall */
    else if (strcmp(syscall_name, "mprotect") == 0) {
        if (arg_index == 2) { /* prot parameter */
            return parse_combined_flags(flag_str, map_prot_flag);
        }
    }
    /* open/openat syscall */
    else if (strcmp(syscall_name, "open") == 0) {
        if (arg_index == 1) {  /* flags parameter */
            return parse_combined_flags(flag_str, map_open_flag);
        }
    }
    else if (strcmp(syscall_name, "openat") == 0) {
        if (arg_index == 2) {  /* flags parameter */
            return parse_combined_flags(flag_str, map_open_flag);
        }
    }
    /* access/faccessat syscall */
    else if (strcmp(syscall_name, "access") == 0 || 
             strcmp(syscall_name, "faccessat") == 0) {
        if (arg_index == 1 || arg_index == 2) {  /* mode parameter */
            return parse_combined_flags(flag_str, map_access_flag);
        }
    }
    
    /* Default try parsing as number */
    char *endptr;
    long value = strtol(flag_str, &endptr, 0);
    if (*flag_str != '\0' && *endptr == '\0') {
        return (int)value;
    }
    
    return 0;
}

/* ==================== Core API Functions Implementation ==================== */

/**
 * Get syscall number.
 */
int rr_strace_get_syscall_number(const char *syscall_name) {
    if (!syscall_name) return -1;
    
    for (int i = 0; g_syscall_map[i].name != NULL; i++) {
        if (strcmp(g_syscall_map[i].name, syscall_name) == 0) {
            return g_syscall_map[i].number;
        }
    }
    
    return -1;
}

/**
 * Parse a single line strace record.
 */
/**
 * @brief Parse a single strace line
 * 
 * Parses a single line of text strace output into a structured `rr_strace_record_t`.
 * 
 * **Steps**:
 * 1. Extract PID (if present).
 * 2. Extract syscall name.
 * 3. Extract argument list (content between parentheses).
 * 4. Identify and parse each argument (Int/String/Flag/Ptr).
 * 5. Extract return value and error code (errno).
 * 
 * @param line Input text line (modified in-place by strtok/trim).
 * @param record Output record structure.
 * @return int 1 on success, 0 on failure.
 */
int rr_strace_parse_line(char *line, rr_strace_record_t *record) {
    if (!line || !record) return 0;
    
    memset(record, 0, sizeof(rr_strace_record_t));
    
    char *current = line;
    char *next;
    
    /* Skip leading whitespace */
    while (*current && isspace(*current)) current++;
    if (!*current) return 0;
    
    /* Parse PID */
    record->pid = strtol(current, &next, 10);
    if (current == next) return 0;
    current = next;
    
    /* Skip whitespace */
    while (*current && isspace(*current)) current++;
    if (!*current) return 0;
    
    /* Find end of syscall name */
    next = strchr(current, '(');
    if (!next) return 0;
    
    /* Copy syscall name */
    /* 复制系统调用名称 */
    size_t name_len = next - current;
    if (name_len >= sizeof(record->syscall_name)) name_len = sizeof(record->syscall_name) - 1;
    memcpy(record->syscall_name, current, name_len);
    record->syscall_name[name_len] = '\0';
    
    /* Remove trailing whitespace from name */
    char *trim_end = record->syscall_name + name_len - 1;
    while (trim_end >= record->syscall_name && isspace(*trim_end)) {
        *trim_end = '\0';
        trim_end--;
    }
    
    /* Move to argument start */
    current = next + 1;  /* Skip '(' */
    
    /* Find end of argument list */
    next = strchr(current, ')');
    if (!next) return 0;
    
    /* Copy argument string for processing */
    char args_buffer[1024] = {0};
    size_t args_len = next - current;
    if (args_len >= sizeof(args_buffer)) args_len = sizeof(args_buffer) - 1;
    memcpy(args_buffer, current, args_len);
    args_buffer[args_len] = '\0';
    
    /* Parse arguments */
    record->arg_count = 0;
    char *arg_str = args_buffer;
    char *arg_end;
    
    while (*arg_str && record->arg_count < RR_STRACE_MAX_ARGS) {
        /* Skip leading whitespace */
        while (*arg_str && isspace(*arg_str)) arg_str++;
        if (!*arg_str) break;
        
        /* Find argument end */
        if (*arg_str == '"') {
            /* String argument */
            arg_end = strchr(arg_str + 1, '"');
            if (arg_end) arg_end = strchr(arg_end, ',');
        } else {
            /* Non-string argument */
            arg_end = strchr(arg_str, ',');
        }
        
        /* If no more commas, the remaining part is the last argument */
        if (!arg_end) arg_end = arg_str + strlen(arg_str);
        
        /* Temporarily null-terminate for processing */
        char saved_char = *arg_end;
        *arg_end = '\0';
        
        /* Process argument */
        rr_strace_arg_t *arg = &record->args[record->arg_count];
        arg->type = rr_strace_identify_arg_type(arg_str);
        
        if (arg->type == RR_STRACE_ARG_TYPE_STR) {
            /* Process string argument (remove quotes) */
            char *str_start = strchr(arg_str, '"');
            char *str_end = strrchr(arg_str, '"');
            if (str_start && str_end && str_start != str_end) {
                size_t str_len = str_end - str_start - 1;
                if (str_len >= RR_STRACE_MAX_STRING_LENGTH) str_len = RR_STRACE_MAX_STRING_LENGTH - 1;
                memcpy(arg->str, str_start + 1, str_len);
                arg->str[str_len] = '\0';
            } else {
                snprintf(arg->str, RR_STRACE_MAX_STRING_LENGTH, "%s", arg_str);
                arg->value = 0;
            }
        } else if (arg->type == RR_STRACE_ARG_TYPE_PTR) {
            /* Process flags, etc. */
            snprintf(arg->str, RR_STRACE_MAX_STRING_LENGTH, "%s", arg_str);
            arg->value = rr_strace_parse_flags(arg_str, record->syscall_name, record->arg_count);
        } else {
            /* Process numeric argument */
            if (strcmp(arg_str, "NULL") == 0) {
                arg->value = 0;
            } else {
                arg->value = rr_strace_parse_number(arg_str);
            }
        }
        
        record->arg_count++;
        
        /* Restore character */
        *arg_end = saved_char;
        
        /* Move to start of next argument if any */
        if (*arg_end == ',') {
            arg_str = arg_end + 1;
        } else {
            break;
        }
    }
    
    /* Parse return value after '=' */
    current = next + 1;  /* Skip ')' */
    
    /* Find '=' */
    next = strchr(current, '=');
    if (!next) {
        /* Some syscalls (e.g., exit_group) have no return value; this is valid */
        /* Skip trailing whitespace and check for end of line */
        while (*current && isspace(*current)) current++;
        if (*current == '\0') {
            /* Valid syscall with no return value, use default */
            record->ret_value = 0;
            record->has_error = 0;
            return 1;
        }
        return 0;  /* Format error */
    }
    
    current = next + 1;  /* Skip '=' */
    
    /* Skip whitespace */
    while (*current && isspace(*current)) current++;
    if (!*current) return 0;
    
    /* Parse return value */
    record->ret_value = strtol(current, &next, 0);
    current = next;
    
    /* Check for error info */
    next = strstr(current, "errno=");
    if (next) {
        record->has_error = 1;
        current = next + 6;  /* Skip "errno=" */
        record->error_code = strtol(current, &next, 10);
        current = next;
        
        /* Find error description (usually in parentheses) */
        next = strchr(current, '(');
        if (next) {
            current = next + 1;
            next = strchr(current, ')');
            if (next) {
                size_t err_len = next - current;
                if (err_len >= sizeof(record->error_msg)) err_len = sizeof(record->error_msg) - 1;
                memcpy(record->error_msg, current, err_len);
                record->error_msg[err_len] = '\0';
            }
        }
    }
    
    return 1;
}

/**
 * Initialize strace parser.
 */
rr_strace_parser_t *rr_strace_parser_init(const char *filename) {
    if (!filename) return NULL;
    
    rr_strace_parser_t *parser = malloc(sizeof(rr_strace_parser_t));
    if (!parser) return NULL;
    
    memset(parser, 0, sizeof(rr_strace_parser_t));
    
    parser->filename = strdup(filename);
    if (!parser->filename) {
        free(parser);
        return NULL;
    }
    
    return parser;
}

/**
 * Load and parse strace file.
 */
/**
 * @brief Load and parse a complete Strace file
 * 
 * Reads the specified file and parses syscall records line by line.
 * 
 * **Note**: 
 * - Memory-intensive operation; all records are loaded into memory (`parser->records`).
 * - Parsed records are used to drive Replay.
 * 
 * @param parser Parser context (filename must be initialized).
 * @return int 0 on success, -1 on failure.
 */
int rr_strace_parser_load(rr_strace_parser_t *parser) {
    fprintf(stderr, "[FORCE_DEBUG] rr_strace_parser_load called with filename: %s\n", 
            parser ? (parser->filename ? parser->filename : "NULL") : "parser is NULL");
    fflush(stderr);
    
    if (!parser || !parser->filename) return -1;
    
    FILE *file = fopen(parser->filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", parser->filename);
        return -1;
    }
    
    /* Count records first */
    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        count++;
    }
    
    if (count == 0) {
        fclose(file);
        return -1;
    }
    
    /* Allocate records array */
    parser->records = malloc(count * sizeof(rr_strace_record_t));
    if (!parser->records) {
        fclose(file);
        return -1;
    }
    
    /* Rewind file to beginning */
    rewind(file);
    
    /* Read and parse each line */
    int i = 0;
    int skip_execve = 1;  /* Skip first execve call */
    while (fgets(line, sizeof(line), file) && i < count) {
        /* Remove newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        /* Skip execve call, as QEMU user mode does not re-execute execve during replay */
        if (skip_execve && strstr(line, "execve(") != NULL) {
            fprintf(stderr, "[FORCE_DEBUG] Skipping execve record: %s\n", line);
            fflush(stderr);
            skip_execve = 0;  /* Only skip first execve */
            continue;
        }
        
        /* Parse current line */
        if (rr_strace_parse_line(line, &parser->records[i])) {
            i++;
        }
    }
    
    fclose(file);
    parser->record_count = i;
    parser->current_index = 0;
    parser->loaded = 1;
    
    fprintf(stderr, "[FORCE_DEBUG] rr_strace_parser_load completed successfully: loaded %d records\n", i);
    fflush(stderr);
    
    return 0;
}

/**
 * Get next syscall record.
 */
rr_strace_record_t *rr_strace_parser_get_next(rr_strace_parser_t *parser) {
    if (!parser || !parser->loaded || parser->current_index >= parser->record_count) {
        return NULL;
    }
    
    return &parser->records[parser->current_index++];
}

/**
 * Reset parser to beginning.
 */
void rr_strace_parser_reset(rr_strace_parser_t *parser) {
    if (parser) {
        parser->current_index = 0;
    }
}

/**
 * Get parser statistics.
 */
void rr_strace_get_stats(rr_strace_parser_t *parser, size_t *total_records, size_t *current_index) {
    if (parser && total_records && current_index) {
        *total_records = parser->record_count;
        *current_index = parser->current_index;
    }
}

/**
 * Clean up parser resources.
 */
void rr_strace_parser_cleanup(rr_strace_parser_t *parser) {
    if (!parser) return;
    
    if (parser->records) {
        free(parser->records);
    }
    
    if (parser->filename) {
        free(parser->filename);
    }
    
    free(parser);
}

/**
 * Print syscall record (for debugging).
 */
void rr_strace_print_record(const rr_strace_record_t *record) {
    if (!record) return;
    
    printf("PID: %d, Syscall: %s\n", record->pid, record->syscall_name);
    printf("Arguments (%d):\n", record->arg_count);
    for (int i = 0; i < record->arg_count; i++) {
        const rr_strace_arg_t *arg = &record->args[i];
        switch (arg->type) {
            case RR_STRACE_ARG_TYPE_INT:
                printf("  [%d] INT: %ld (0x%lx)\n", i, arg->value, arg->value);
                break;
            case RR_STRACE_ARG_TYPE_PTR:
                printf("  [%d] PTR: %s (%ld)\n", i, arg->str, arg->value);
                break;
            case RR_STRACE_ARG_TYPE_STR:
                printf("  [%d] STR: \"%s\"\n", i, arg->str);
                break;
        }
    }
    
    printf("Return value: %ld (0x%lx)\n", record->ret_value, record->ret_value);
    if (record->has_error) {
        printf("Error: %d (%s)\n", record->error_code, record->error_msg);
    }
    printf("\n");
}
