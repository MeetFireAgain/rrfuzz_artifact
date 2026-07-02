#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Syscall Handler Auto-Generator

Features:
1. Parse all syscalls from syscall_64.tbl.
2. Automatically generate the handler table for rr_syscall_dispatch.c.
3. Automatically classify syscall types.
4. Generate complete C code.

Author: RR-Fuzz Team
Date: 2025-11-05
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class SyscallType(Enum):
    """Syscall type"""
    FILE_IO = "SYSCALL_TYPE_FILE_IO"
    NETWORK = "SYSCALL_TYPE_NETWORK"
    PROCESS = "SYSCALL_TYPE_PROCESS"
    MEMORY = "SYSCALL_TYPE_MEMORY"
    TIME = "SYSCALL_TYPE_TIME"
    SIGNAL = "SYSCALL_TYPE_SIGNAL"
    SYSTEM_INFO = "SYSCALL_TYPE_SYSTEM_INFO"
    IPC = "SYSCALL_TYPE_IPC"
    UNKNOWN = "SYSCALL_TYPE_UNKNOWN"


class SyscallImportance(Enum):
    """Syscall importance"""
    CRITICAL = "SYSCALL_IMPORTANCE_CRITICAL"
    IMPORTANT = "SYSCALL_IMPORTANCE_IMPORTANT"
    OPTIONAL = "SYSCALL_IMPORTANCE_OPTIONAL"
    ENVIRONMENT = "SYSCALL_IMPORTANCE_ENVIRONMENT"


@dataclass
class SyscallInfo:
    """Syscall information"""
    number: int
    abi: str  # common, 64, x32
    name: str
    entry_point: str
    
    # Automatically inferred attributes
    syscall_type: SyscallType = SyscallType.UNKNOWN
    importance: SyscallImportance = SyscallImportance.ENVIRONMENT
    needs_fd_mapping: bool = False
    needs_addr_mapping: bool = False
    is_fd_syscall: bool = False
    
    # Handler function names
    apply_args_func: str = "apply_generic_args"
    apply_fd_mapping_func: Optional[str] = None
    post_hook_func: str = "generic_post_hook"


class SyscallClassifier:
    """Syscall classifier"""
    
    # File I/O related syscalls
    FILE_IO_SYSCALLS = {
        # Basic file operations
        'open', 'openat', 'openat2', 'creat', 'close',
        'read', 'write', 'readv', 'writev', 'pread64', 'pwrite64',
        'preadv', 'pwritev', 'preadv2', 'pwritev2',
        
        # File attributes and status
        'stat', 'fstat', 'lstat', 'newfstatat', 'statx',
        'access', 'faccessat', 'faccessat2', 'chmod', 'fchmod',
        'fchmodat', 'chown', 'fchown', 'lchown', 'fchownat',
        
        # Directory operations
        'getdents', 'getdents64', 'mkdir', 'mkdirat', 'rmdir',
        'chdir', 'fchdir', 'getcwd',
        
        # File control
        'fcntl', 'ioctl', 'lseek', 'dup', 'dup2', 'dup3',
        'pipe', 'pipe2', 'select', 'pselect6', 'poll', 'ppoll',
        'epoll_create', 'epoll_create1', 'epoll_ctl', 'epoll_wait', 'epoll_pwait',
        
        # Filesystem operations
        'mount', 'umount2', 'statfs', 'fstatfs', 'truncate', 'ftruncate',
        'fallocate', 'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2',
        'link', 'linkat', 'symlink', 'symlinkat', 'readlink', 'readlinkat',
        
        # Synchronization operations
        'sync', 'syncfs', 'fsync', 'fdatasync',
        
        # Extended attributes
        'getxattr', 'lgetxattr', 'fgetxattr', 'setxattr', 'lsetxattr', 'fsetxattr',
        'listxattr', 'llistxattr', 'flistxattr', 'removexattr', 'lremovexattr', 'fremovexattr',
    }
    
    # Network-related syscalls
    NETWORK_SYSCALLS = {
        'socket', 'socketpair', 'bind', 'listen', 'accept', 'accept4',
        'connect', 'getsockname', 'getpeername',
        'send', 'sendto', 'sendmsg', 'sendmmsg',
        'recv', 'recvfrom', 'recvmsg', 'recvmmsg',
        'setsockopt', 'getsockopt', 'shutdown',
    }
    
    # Process management related syscalls
    PROCESS_SYSCALLS = {
        'fork', 'vfork', 'clone', 'clone3', 'execve', 'execveat',
        'exit', 'exit_group', 'wait4', 'waitid', 'waitpid',
        'getpid', 'gettid', 'getppid', 'getpgid', 'setpgid',
        'getpgrp', 'setsid', 'getsid',
        'getuid', 'setuid', 'getgid', 'setgid',
        'geteuid', 'setreuid', 'getegid', 'setregid',
        'getresuid', 'setresuid', 'getresgid', 'setresgid',
        'getgroups', 'setgroups',
        'prctl', 'arch_prctl',
        'setns', 'unshare',
        'capget', 'capset',
        'ptrace',
    }
    
    # Memory management related syscalls
    MEMORY_SYSCALLS = {
        'mmap', 'munmap', 'mremap', 'mprotect', 'madvise', 'mlock', 'munlock',
        'mlockall', 'munlockall', 'mincore', 'msync',
        'brk', 'sbrk',
        'mmap2',
        'remap_file_pages',
        'mbind', 'get_mempolicy', 'set_mempolicy', 'migrate_pages', 'move_pages',
    }
    
    # Time-related syscalls
    TIME_SYSCALLS = {
        'time', 'gettimeofday', 'settimeofday',
        'clock_gettime', 'clock_settime', 'clock_getres',
        'clock_nanosleep', 'nanosleep',
        'getitimer', 'setitimer',
        'alarm', 'timer_create', 'timer_settime', 'timer_gettime',
        'timer_getoverrun', 'timer_delete',
        'timerfd_create', 'timerfd_settime', 'timerfd_gettime',
    }
    
    # Signal-related syscalls
    SIGNAL_SYSCALLS = {
        'rt_sigaction', 'rt_sigprocmask', 'rt_sigpending', 'rt_sigtimedwait',
        'rt_sigqueueinfo', 'rt_sigsuspend', 'rt_sigreturn',
        'sigaltstack', 'kill', 'tkill', 'tgkill',
        'signalfd', 'signalfd4',
    }
    
    # IPC-related syscalls
    IPC_SYSCALLS = {
        'msgget', 'msgsnd', 'msgrcv', 'msgctl',
        'semget', 'semop', 'semctl', 'semtimedop',
        'shmget', 'shmat', 'shmdt', 'shmctl',
        'mq_open', 'mq_unlink', 'mq_timedsend', 'mq_timedreceive',
        'mq_notify', 'mq_getsetattr',
        'eventfd', 'eventfd2',
    }
    
    # System information related syscalls
    SYSTEM_INFO_SYSCALLS = {
        'uname', 'sysinfo', 'syslog', 'klogctl',
        'getrusage', 'getrlimit', 'setrlimit', 'prlimit64',
        'getrandom', 'getcpu',
        'sysfs', 'ustat',
        'personality',
        'set_tid_address', 'set_robust_list', 'get_robust_list',
        'sched_setparam', 'sched_getparam', 'sched_setscheduler',
        'sched_getscheduler', 'sched_get_priority_max', 'sched_get_priority_min',
        'sched_rr_get_interval', 'sched_yield', 'sched_setaffinity', 'sched_getaffinity',
        'umask', 'chroot', 'pivot_root',
        'reboot', 'acct', 'init_module', 'delete_module',
        'quotactl', 'lookup_dcookie',
        'perf_event_open', 'fanotify_init', 'fanotify_mark',
        'name_to_handle_at', 'open_by_handle_at',
        'setdomainname', 'sethostname',
        'ioperm', 'iopl', 'modify_ldt',
        'io_setup', 'io_destroy', 'io_getevents', 'io_submit', 'io_cancel',
        'rseq', 'pidfd_open', 'pidfd_send_signal', 'pidfd_getfd',
    }
    
    # CRITICAL syscalls
    CRITICAL_SYSCALLS = {
        'read', 'write', 'open', 'openat', 'close',
        'mmap', 'munmap',
        'send', 'sendto', 'recv', 'recvfrom',
        'exit_group', 'writev', 'sendmsg', 'recvmsg',
    }
    
    # IMPORTANT syscalls
    IMPORTANT_SYSCALLS = {
        'stat', 'fstat', 'lstat', 'newfstatat',
        'mprotect', 'brk', 'ioctl',
        'socket', 'bind', 'listen', 'accept', 'connect',
        'fork', 'clone', 'execve',
        'pread64', 'pwrite64', 'readv',
        'fcntl', 'dup', 'dup2', 'pipe',
    }
    
    # Syscalls requiring FD mapping
    FD_MAPPING_SYSCALLS = {
        'read', 'write', 'readv', 'writev', 'pread64', 'pwrite64',
        'close', 'fstat', 'ioctl', 'fcntl', 'dup', 'dup2', 'dup3',
        'getdents', 'getdents64', 'lseek',
        'fsync', 'fdatasync', 'fchmod', 'fchown', 'ftruncate',
        'fstatfs', 'fchdir', 'flock',
        # Network-related
        'send', 'sendto', 'sendmsg', 'recv', 'recvfrom', 'recvmsg',
        'bind', 'listen', 'accept', 'accept4', 'connect',
        'getsockname', 'getpeername', 'setsockopt', 'getsockopt', 'shutdown',
        # 'at' family (first argument may be dirfd)
        'openat', 'mkdirat', 'unlinkat', 'renameat', 'linkat', 'symlinkat',
        'readlinkat', 'fchmodat', 'fchownat', 'faccessat', 'newfstatat',
    }
    
    # Syscalls requiring address mapping
    ADDR_MAPPING_SYSCALLS = {
        'mmap', 'munmap', 'mremap', 'mprotect', 'madvise',
        'msync', 'mincore', 'mlock', 'munlock',
    }
    
    # FD-creating syscalls (requires mapping established in post_hook)
    FD_CREATING_SYSCALLS = {
        'open', 'openat', 'openat2', 'creat',
        'socket', 'socketpair', 'accept', 'accept4',
        'dup', 'dup2', 'dup3',
        'pipe', 'pipe2',
        'epoll_create', 'epoll_create1',
        'eventfd', 'eventfd2',
        'signalfd', 'signalfd4',
        'timerfd_create',
        'memfd_create',
        'userfaultfd',
    }
    
    @classmethod
    def classify(cls, syscall_name: str) -> Tuple[SyscallType, SyscallImportance]:
        """Classify syscalls"""
        # Determine type
        if syscall_name in cls.FILE_IO_SYSCALLS:
            syscall_type = SyscallType.FILE_IO
        elif syscall_name in cls.NETWORK_SYSCALLS:
            syscall_type = SyscallType.NETWORK
        elif syscall_name in cls.PROCESS_SYSCALLS:
            syscall_type = SyscallType.PROCESS
        elif syscall_name in cls.MEMORY_SYSCALLS:
            syscall_type = SyscallType.MEMORY
        elif syscall_name in cls.TIME_SYSCALLS:
            syscall_type = SyscallType.TIME
        elif syscall_name in cls.SIGNAL_SYSCALLS:
            syscall_type = SyscallType.SIGNAL
        elif syscall_name in cls.IPC_SYSCALLS:
            syscall_type = SyscallType.IPC
        elif syscall_name in cls.SYSTEM_INFO_SYSCALLS:
            syscall_type = SyscallType.SYSTEM_INFO
        else:
            syscall_type = SyscallType.UNKNOWN
        
        # Determine importance
        if syscall_name in cls.CRITICAL_SYSCALLS:
            importance = SyscallImportance.CRITICAL
        elif syscall_name in cls.IMPORTANT_SYSCALLS:
            importance = SyscallImportance.IMPORTANT
        elif syscall_name in cls.FD_MAPPING_SYSCALLS or syscall_name in cls.FD_CREATING_SYSCALLS:
            importance = SyscallImportance.IMPORTANT
        elif syscall_type in [SyscallType.FILE_IO, SyscallType.NETWORK, SyscallType.MEMORY]:
            importance = SyscallImportance.OPTIONAL
        else:
            importance = SyscallImportance.ENVIRONMENT
        
        return syscall_type, importance
    
    @classmethod
    def get_handler_functions(cls, syscall_name: str, 
                             syscall_type: SyscallType) -> Tuple[str, Optional[str], str]:
        """Get handler function names"""
        # apply_args function
        if syscall_type == SyscallType.FILE_IO:
            apply_args = "apply_file_io_args"
        elif syscall_type == SyscallType.NETWORK:
            apply_args = "apply_network_args"
        elif syscall_type == SyscallType.MEMORY:
            apply_args = "apply_memory_args"
        else:
            apply_args = "apply_generic_args"
        
        # apply_fd_mapping function
        if syscall_name in cls.FD_MAPPING_SYSCALLS:
            if syscall_type == SyscallType.FILE_IO:
                apply_fd_mapping = "apply_file_io_fd_mapping"
            elif syscall_type == SyscallType.MEMORY:
                apply_fd_mapping = "apply_memory_fd_mapping"
            elif syscall_type == SyscallType.NETWORK:
                apply_fd_mapping = "apply_file_io_fd_mapping"  # Reuse
            else:
                apply_fd_mapping = None
        else:
            apply_fd_mapping = None
        
        # post_hook function
        if syscall_type == SyscallType.FILE_IO or syscall_name in cls.FD_CREATING_SYSCALLS:
            post_hook = "file_io_post_hook"
        elif syscall_type == SyscallType.NETWORK:
            post_hook = "network_post_hook"
        elif syscall_type == SyscallType.MEMORY:
            post_hook = "memory_post_hook"
        else:
            post_hook = "generic_post_hook"
        
        return apply_args, apply_fd_mapping, post_hook


class SyscallTableParser:
    """Parser for syscall_64.tbl"""
    
    def __init__(self, tbl_file: str):
        self.tbl_file = tbl_file
        self.syscalls: List[SyscallInfo] = []
    
    def parse(self) -> List[SyscallInfo]:
        """Parse syscall table"""
        with open(self.tbl_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Parse line: <number> <abi> <name> <entry_point>
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                try:
                    number = int(parts[0])
                    abi = parts[1]
                    name = parts[2]
                    entry_point = parts[3]
                    
                    # Classify
                    syscall_type, importance = SyscallClassifier.classify(name)
                    
                    # Get handler functions
                    apply_args, apply_fd_mapping, post_hook = \
                        SyscallClassifier.get_handler_functions(name, syscall_type)
                    
                    # Determine flags
                    needs_fd_mapping = name in SyscallClassifier.FD_MAPPING_SYSCALLS
                    needs_addr_mapping = name in SyscallClassifier.ADDR_MAPPING_SYSCALLS
                    is_fd_syscall = name in SyscallClassifier.FD_CREATING_SYSCALLS
                    
                    # Create SyscallInfo
                    info = SyscallInfo(
                        number=number,
                        abi=abi,
                        name=name,
                        entry_point=entry_point,
                        syscall_type=syscall_type,
                        importance=importance,
                        needs_fd_mapping=needs_fd_mapping,
                        needs_addr_mapping=needs_addr_mapping,
                        is_fd_syscall=is_fd_syscall,
                        apply_args_func=apply_args,
                        apply_fd_mapping_func=apply_fd_mapping,
                        post_hook_func=post_hook
                    )
                    
                    self.syscalls.append(info)
                    
                except (ValueError, IndexError) as e:
                    print(f"⚠️  Failed to parse line: {line} ({e})")
                    continue
        
        print(f"✅ Parsed {len(self.syscalls)} syscalls from {self.tbl_file}")
        return self.syscalls


class SyscallHandlerGenerator:
    """Generator for C code handler table"""
    
    def __init__(self, syscalls: List[SyscallInfo]):
        self.syscalls = syscalls
    
    def generate_handler_table(self) -> str:
        """Generate handler table C code"""
        lines = []
        
        lines.append("/* ==================== Automatically Generated Syscall Handler Table ==================== */")
        lines.append("/* This file is automatically generated by syscall_generator.py. Do not modify manually. */")
        lines.append("")
        lines.append("static rr_syscall_handler_t syscall_handlers[] = {")
        
        # Group by type
        by_type = {}
        for sc in self.syscalls:
            type_name = sc.syscall_type.name
            if type_name not in by_type:
                by_type[type_name] = []
            by_type[type_name].append(sc)
        
        # Generate handlers for each type
        for type_name in ['FILE_IO', 'NETWORK', 'PROCESS', 'MEMORY', 'TIME', 
                          'SIGNAL', 'IPC', 'SYSTEM_INFO', 'UNKNOWN']:
            if type_name not in by_type:
                continue
            
            lines.append(f"    /* {type_name.replace('_', ' ')} Class */")
            
            for sc in by_type[type_name]:
                fd_mapping = sc.apply_fd_mapping_func or "NULL"
                
                line = f'    {{"{sc.name}", {sc.number}, {sc.syscall_type.value}, ' \
                       f'{sc.importance.value},\n' \
                       f'     {sc.apply_args_func}, {fd_mapping}, {sc.post_hook_func}, ' \
                       f'{str(sc.needs_fd_mapping).lower()}, ' \
                       f'{str(sc.needs_addr_mapping).lower()}, ' \
                       f'{str(sc.is_fd_syscall).lower()}}},'
                
                lines.append(line)
            
            lines.append("")
        
        lines.append("    /* End marker */")
        lines.append("    {NULL, -1, SYSCALL_TYPE_UNKNOWN, SYSCALL_IMPORTANCE_ENVIRONMENT, "
                    "NULL, NULL, NULL, false, false, false}")
        lines.append("};")
        lines.append("")
        
        return "\n".join(lines)
    
    def generate_stats(self) -> str:
        """Generate statistical information"""
        lines = []
        lines.append("=" * 60)
        lines.append("Syscall Handler Generation Statistics")
        lines.append("=" * 60)
        lines.append(f"\nTotal: {len(self.syscalls)} syscalls\n")
        
        # Statistics by type
        by_type = {}
        for sc in self.syscalls:
            type_name = sc.syscall_type.name
            by_type[type_name] = by_type.get(type_name, 0) + 1
        
        lines.append("Distribution by Type:")
        for type_name, count in sorted(by_type.items(), key=lambda x: -x[1]):
            lines.append(f"  {type_name:20s}: {count:4d}")
        
        # Statistics by importance
        by_importance = {}
        for sc in self.syscalls:
            imp_name = sc.importance.name
            by_importance[imp_name] = by_importance.get(imp_name, 0) + 1
        
        lines.append("\nDistribution by Importance:")
        for imp_name, count in sorted(by_importance.items()):
            lines.append(f"  {imp_name:20s}: {count:4d}")
        
        # Feature statistics
        needs_fd = sum(1 for sc in self.syscalls if sc.needs_fd_mapping)
        needs_addr = sum(1 for sc in self.syscalls if sc.needs_addr_mapping)
        creates_fd = sum(1 for sc in self.syscalls if sc.is_fd_syscall)
        
        lines.append("\nFeature Statistics:")
        lines.append(f"  Requires FD mapping:      {needs_fd:4d}")
        lines.append(f"  Requires address mapping: {needs_addr:4d}")
        lines.append(f"  Creates FD:               {creates_fd:4d}")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Syscall Handler Auto-Generator')
    parser.add_argument('--tbl', default='../../../x86_64/syscall_64.tbl',
                       help='Path to syscall_64.tbl')
    parser.add_argument('--output', default='rr_syscall_dispatch_generated.c',
                       help='Output file path')
    parser.add_argument('--stats', action='store_true',
                       help='Display statistics only')
    
    args = parser.parse_args()
    
    # Parse syscall table
    tbl_file = Path(__file__).parent / args.tbl
    if not tbl_file.exists():
        print(f"❌ File not found: {tbl_file}")
        return 1
    
    print(f"📖 Parsing syscall table: {tbl_file}")
    parser_obj = SyscallTableParser(str(tbl_file))
    syscalls = parser_obj.parse()
    
    # Generate code
    generator = SyscallHandlerGenerator(syscalls)
    
    # Display statistical information
    print("\n" + generator.generate_stats())
    
    if not args.stats:
        # Generate C code
        code = generator.generate_handler_table()
        
        output_file = Path(__file__).parent / args.output
        with open(output_file, 'w') as f:
            f.write(code)
        
        print(f"\n✅ Generated: {output_file}")
        print(f"   Total {len(syscalls)} syscall handlers")
    
    return 0


if __name__ == '__main__':
    exit(main())





























