#!/usr/bin/env python3
"""
内核系统调用表恢复与接口分析模块

功能：
- 恢复 syscall table（Linux/Windows）
- 提取每个系统调用入口和参数
- 分析系统调用接口安全性
- 检测系统调用劫持/挂钩
"""

import logging
import re
import struct
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class KernelType(Enum):
    """内核类型"""
    LINUX = "linux"
    WINDOWS = "windows"
    FREEBSD = "freebsd"
    MACOS = "macos"
    UNKNOWN = "unknown"


class ArchType(Enum):
    """架构类型"""
    X86 = "x86"
    X64 = "x64"
    ARM32 = "arm32"
    ARM64 = "arm64"
    MIPS = "mips"
    RISCV = "riscv"
    UNKNOWN = "unknown"


@dataclass
class SyscallEntry:
    """系统调用条目"""
    number: int
    name: str
    address: int
    handler_name: str = ""
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    return_type: str = ""
    security_level: str = "unknown"
    notes: str = ""
    hook_detected: bool = False
    original_address: int = 0


@dataclass
class SyscallTableInfo:
    """系统调用表信息"""
    kernel_type: KernelType
    arch_type: ArchType
    table_address: int
    table_size: int
    entries: List[SyscallEntry] = field(default_factory=list)
    hooked_syscalls: List[int] = field(default_factory=list)
    missing_syscalls: List[int] = field(default_factory=list)
    security_issues: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SyscallAnalysisResult:
    """系统调用分析结果"""
    table_info: SyscallTableInfo
    dangerous_syscalls: List[SyscallEntry] = field(default_factory=list)
    privilege_syscalls: List[SyscallEntry] = field(default_factory=list)
    io_syscalls: List[SyscallEntry] = field(default_factory=list)
    network_syscalls: List[SyscallEntry] = field(default_factory=list)
    memory_syscalls: List[SyscallEntry] = field(default_factory=list)
    summary: str = ""
    risk_assessment: Dict[str, Any] = field(default_factory=dict)


# Linux x86_64 系统调用表（常见）
LINUX_X64_SYSCALLS = {
    0: ('read', 'ssize_t read(int fd, void *buf, size_t count)'),
    1: ('write', 'ssize_t write(int fd, const void *buf, size_t count)'),
    2: ('open', 'int open(const char *pathname, int flags, mode_t mode)'),
    3: ('close', 'int close(int fd)'),
    4: ('stat', 'int stat(const char *pathname, struct stat *statbuf)'),
    5: ('fstat', 'int fstat(int fd, struct stat *statbuf)'),
    6: ('lstat', 'int lstat(const char *pathname, struct stat *statbuf)'),
    7: ('poll', 'int poll(struct pollfd *fds, nfds_t nfds, int timeout)'),
    8: ('lseek', 'off_t lseek(int fd, off_t offset, int whence)'),
    9: ('mmap', 'void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)'),
    10: ('mprotect', 'int mprotect(void *addr, size_t len, int prot)'),
    11: ('munmap', 'int munmap(void *addr, size_t length)'),
    12: ('brk', 'int brk(void *addr)'),
    13: ('rt_sigaction', 'int rt_sigaction(int sig, const struct sigaction *act, struct sigaction *oact, size_t sigsetsize)'),
    14: ('rt_sigprocmask', 'int rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t sigsetsize)'),
    15: ('rt_sigreturn', 'int rt_sigreturn(void)'),
    16: ('ioctl', 'int ioctl(int fd, unsigned long request, ...)'),
    17: ('pread64', 'ssize_t pread64(int fd, void *buf, size_t count, off_t offset)'),
    18: ('pwrite64', 'ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset)'),
    19: ('readv', 'ssize_t readv(int fd, const struct iovec *iov, int iovcnt)'),
    20: ('writev', 'ssize_t writev(int fd, const struct iovec *iov, int iovcnt)'),
    21: ('access', 'int access(const char *pathname, int mode)'),
    22: ('pipe', 'int pipe(int pipefd[2])'),
    23: ('select', 'int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)'),
    24: ('sched_yield', 'int sched_yield(void)'),
    25: ('mremap', 'void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...)'),
    26: ('msync', 'int msync(void *addr, size_t length, int flags)'),
    27: ('mincore', 'int mincore(void *addr, size_t length, unsigned char *vec)'),
    28: ('madvise', 'int madvise(void *addr, size_t length, int advice)'),
    29: ('shmget', 'int shmget(key_t key, size_t size, int shmflg)'),
    30: ('shmat', 'void *shmat(int shmid, const void *shmaddr, int shmflg)'),
    31: ('shmctl', 'int shmctl(int shmid, int cmd, struct shmid_ds *buf)'),
    32: ('dup', 'int dup(int oldfd)'),
    33: ('dup2', 'int dup2(int oldfd, int newfd)'),
    34: ('pause', 'int pause(void)'),
    35: ('nanosleep', 'int nanosleep(const struct timespec *req, struct timespec *rem)'),
    36: ('getitimer', 'int getitimer(int which, struct itimerval *curr_value)'),
    37: ('alarm', 'unsigned int alarm(unsigned int seconds)'),
    38: ('setitimer', 'int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value)'),
    39: ('getpid', 'pid_t getpid(void)'),
    40: ('sendfile', 'ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)'),
    41: ('socket', 'int socket(int domain, int type, int protocol)'),
    42: ('connect', 'int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)'),
    43: ('accept', 'int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)'),
    44: ('sendto', 'ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)'),
    45: ('recvfrom', 'ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)'),
    46: ('sendmsg', 'ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)'),
    47: ('recvmsg', 'ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)'),
    48: ('shutdown', 'int shutdown(int sockfd, int how)'),
    49: ('bind', 'int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)'),
    50: ('listen', 'int listen(int sockfd, int backlog)'),
    51: ('getsockname', 'int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)'),
    52: ('getpeername', 'int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)'),
    53: ('socketpair', 'int socketpair(int domain, int type, int protocol, int sv[2])'),
    54: ('setsockopt', 'int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)'),
    55: ('getsockopt', 'int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)'),
    56: ('clone', 'long clone(unsigned long flags, void *child_stack, int *ptid, int *ctid, unsigned long newtls)'),
    57: ('fork', 'pid_t fork(void)'),
    58: ('vfork', 'pid_t vfork(void)'),
    59: ('execve', 'int execve(const char *pathname, char *const argv[], char *const envp[])'),
    60: ('exit', 'void exit(int status)'),
    61: ('wait4', 'pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage)'),
    62: ('kill', 'int kill(pid_t pid, int sig)'),
    63: ('uname', 'int uname(struct utsname *buf)'),
    64: ('semget', 'int semget(key_t key, int nsems, int semflg)'),
    65: ('semop', 'int semop(int semid, struct sembuf *sops, size_t nsops)'),
    66: ('semctl', 'int semctl(int semid, int semnum, int cmd, ...)'),
    67: ('shmdt', 'int shmdt(const void *shmaddr)'),
    68: ('msgget', 'int msgget(key_t key, int msgflg)'),
    69: ('msgsnd', 'int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)'),
    70: ('msgrcv', 'ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)'),
    71: ('msgctl', 'int msgctl(int msqid, int cmd, struct msqid_ds *buf)'),
    72: ('fcntl', 'int fcntl(int fd, int cmd, ...)'),
    73: ('flock', 'int flock(int fd, int operation)'),
    74: ('fsync', 'int fsync(int fd)'),
    75: ('fdatasync', 'int fdatasync(int fd)'),
    76: ('truncate', 'int truncate(const char *path, off_t length)'),
    77: ('ftruncate', 'int ftruncate(int fd, off_t length)'),
    78: ('getdents', 'int getdents(int fd, void *dirp, unsigned int count)'),
    79: ('getcwd', 'char *getcwd(char *buf, size_t size)'),
    80: ('chdir', 'int chdir(const char *path)'),
    81: ('fchdir', 'int fchdir(int fd)'),
    82: ('rename', 'int rename(const char *oldpath, const char *newpath)'),
    83: ('mkdir', 'int mkdir(const char *pathname, mode_t mode)'),
    84: ('rmdir', 'int rmdir(const char *pathname)'),
    85: ('creat', 'int creat(const char *pathname, mode_t mode)'),
    86: ('link', 'int link(const char *oldpath, const char *newpath)'),
    87: ('unlink', 'int unlink(const char *pathname)'),
    88: ('symlink', 'int symlink(const char *target, const char *linkpath)'),
    89: ('readlink', 'ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)'),
    90: ('chmod', 'int chmod(const char *pathname, mode_t mode)'),
    91: ('fchmod', 'int fchmod(int fd, mode_t mode)'),
    92: ('chown', 'int chown(const char *pathname, uid_t owner, gid_t group)'),
    93: ('fchown', 'int fchown(int fd, uid_t owner, gid_t group)'),
    94: ('lchown', 'int lchown(const char *pathname, uid_t owner, gid_t group)'),
    95: ('umask', 'mode_t umask(mode_t mask)'),
    96: ('gettimeofday', 'int gettimeofday(struct timeval *tv, struct timezone *tz)'),
    97: ('getrlimit', 'int getrlimit(int resource, struct rlimit *rlim)'),
    98: ('getrusage', 'int getrusage(int who, struct rusage *usage)'),
    99: ('sysinfo', 'int sysinfo(struct sysinfo *info)'),
    100: ('times', 'clock_t times(struct tms *buf)'),
    101: ('ptrace', 'long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)'),
    102: ('getuid', 'uid_t getuid(void)'),
    103: ('syslog', 'int syslog(int type, char *bufp, int len)'),
    104: ('getgid', 'gid_t getgid(void)'),
    105: ('setuid', 'int setuid(uid_t uid)'),
    106: ('setgid', 'int setgid(gid_t gid)'),
    107: ('geteuid', 'uid_t geteuid(void)'),
    108: ('getegid', 'gid_t getegid(void)'),
    109: ('setpgid', 'int setpgid(pid_t pid, pid_t pgid)'),
    110: ('getppid', 'pid_t getppid(void)'),
    111: ('getpgrp', 'pid_t getpgrp(void)'),
    112: ('setsid', 'pid_t setsid(void)'),
    113: ('setreuid', 'int setreuid(uid_t ruid, uid_t euid)'),
    114: ('setregid', 'int setregid(gid_t rgid, gid_t egid)'),
    115: ('getgroups', 'int getgroups(int size, gid_t list[])'),
    116: ('setgroups', 'int setgroups(size_t size, const gid_t list[])'),
    117: ('setresuid', 'int setresuid(uid_t ruid, uid_t euid, uid_t suid)'),
    118: ('getresuid', 'int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)'),
    119: ('setresgid', 'int setresgid(gid_t rgid, gid_t egid, gid_t sgid)'),
    120: ('getresgid', 'int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)'),
    121: ('getpgid', 'pid_t getpgid(pid_t pid)'),
    122: ('setfsuid', 'int setfsuid(uid_t fsuid)'),
    123: ('setfsgid', 'int setfsgid(gid_t fsgid)'),
    124: ('getsid', 'pid_t getsid(pid_t pid)'),
    125: ('capget', 'int capget(cap_user_header_t header, cap_user_data_t datap)'),
    126: ('capset', 'int capset(cap_user_header_t header, const cap_user_data_t datap)'),
    127: ('rt_sigpending', 'int rt_sigpending(sigset_t *set, size_t sigsetsize)'),
    128: ('rt_sigtimedwait', 'int rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout, size_t sigsetsize)'),
    129: ('rt_sigqueueinfo', 'int rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *uinfo)'),
    130: ('rt_sigsuspend', 'int rt_sigsuspend(const sigset_t *mask)'),
    131: ('sigaltstack', 'int sigaltstack(const stack_t *ss, stack_t *oss)'),
    132: ('utime', 'int utime(const char *filename, const struct utimbuf *times)'),
    133: ('mknod', 'int mknod(const char *pathname, mode_t mode, dev_t dev)'),
    134: ('uselib', 'int uselib(const char *library)'),
    135: ('personality', 'int personality(unsigned long persona)'),
    136: ('ustat', 'int ustat(dev_t dev, struct ustat *ubuf)'),
    137: ('statfs', 'int statfs(const char *path, struct statfs *buf)'),
    138: ('fstatfs', 'int fstatfs(int fd, struct statfs *buf)'),
    139: ('sysfs', 'int sysfs(int option, ...)'),
    140: ('getpriority', 'int getpriority(int which, id_t who)'),
    141: ('setpriority', 'int setpriority(int which, id_t who, int prio)'),
    142: ('sched_setparam', 'int sched_setparam(pid_t pid, const struct sched_param *param)'),
    143: ('sched_getparam', 'int sched_getparam(pid_t pid, struct sched_param *param)'),
    144: ('sched_setscheduler', 'int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)'),
    145: ('sched_getscheduler', 'int sched_getscheduler(pid_t pid)'),
    146: ('sched_get_priority_max', 'int sched_get_priority_max(int policy)'),
    147: ('sched_get_priority_min', 'int sched_get_priority_min(int policy)'),
    148: ('sched_rr_get_interval', 'int sched_rr_get_interval(pid_t pid, struct timespec *tp)'),
    149: ('mlock', 'int mlock(const void *addr, size_t len)'),
    150: ('munlock', 'int munlock(const void *addr, size_t len)'),
    151: ('mlockall', 'int mlockall(int flags)'),
    152: ('munlockall', 'int munlockall(void)'),
    153: ('vhangup', 'int vhangup(void)'),
    154: ('modify_ldt', 'int modify_ldt(int func, void *ptr, unsigned long bytecount)'),
    155: ('pivot_root', 'int pivot_root(const char *new_root, const char *put_old)'),
    156: ('_sysctl', 'int _sysctl(struct __sysctl_args *args)'),
    157: ('prctl', 'int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)'),
    158: ('arch_prctl', 'long arch_prctl(int code, unsigned long addr)'),
    159: ('adjtimex', 'int adjtimex(struct timex *buf)'),
    160: ('setrlimit', 'int setrlimit(int resource, const struct rlimit *rlim)'),
    161: ('chroot', 'int chroot(const char *path)'),
    162: ('sync', 'void sync(void)'),
    163: ('acct', 'int acct(const char *filename)'),
    164: ('settimeofday', 'int settimeofday(const struct timeval *tv, const struct timezone *tz)'),
    165: ('mount', 'int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data)'),
    166: ('umount2', 'int umount2(const char *target, int flags)'),
    167: ('swapon', 'int swapon(const char *path, int swapflags)'),
    168: ('swapoff', 'int swapoff(const char *path)'),
    169: ('reboot', 'int reboot(int magic1, int magic2, int cmd, void *arg)'),
    170: ('sethostname', 'int sethostname(const char *name, size_t len)'),
    171: ('setdomainname', 'int setdomainname(const char *name, size_t len)'),
    172: ('iopl', 'int iopl(int level)'),
    173: ('ioperm', 'int ioperm(unsigned long from, unsigned long num, int turn_on)'),
    174: ('create_module', 'caddr_t create_module(const char *name, size_t size)'),
    175: ('init_module', 'int init_module(void *module_image, unsigned long len, const char *param_values)'),
    176: ('delete_module', 'int delete_module(const char *name, int flags)'),
    177: ('get_kernel_syms', 'int get_kernel_syms(struct kernel_sym *table)'),
    178: ('query_module', 'int query_module(const char *name, int which, void *buf, size_t bufsize, size_t *ret)'),
    179: ('quotactl', 'int quotactl(int cmd, const char *special, int id, void *addr)'),
    180: ('nfsservctl', 'int nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp)'),
    181: ('getpmsg', 'int getpmsg(void)'),
    182: ('putpmsg', 'int putpmsg(void)'),
    183: ('afs_syscall', 'int afs_syscall(void)'),
    184: ('tuxcall', 'int tuxcall(void)'),
    185: ('security', 'int security(void)'),
    186: ('gettid', 'pid_t gettid(void)'),
    187: ('readahead', 'ssize_t readahead(int fd, off64_t offset, size_t count)'),
    188: ('setxattr', 'int setxattr(const char *path, const char *name, const void *value, size_t size, int flags)'),
    189: ('lsetxattr', 'int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags)'),
    190: ('fsetxattr', 'int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)'),
    191: ('getxattr', 'ssize_t getxattr(const char *path, const char *name, void *value, size_t size)'),
    192: ('lgetxattr', 'ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size)'),
    193: ('fgetxattr', 'ssize_t fgetxattr(int fd, const char *name, void *value, size_t size)'),
    194: ('listxattr', 'ssize_t listxattr(const char *path, char *list, size_t size)'),
    195: ('llistxattr', 'ssize_t llistxattr(const char *path, char *list, size_t size)'),
    196: ('flistxattr', 'ssize_t flistxattr(int fd, char *list, size_t size)'),
    197: ('removexattr', 'int removexattr(const char *path, const char *name)'),
    198: ('lremovexattr', 'int lremovexattr(const char *path, const char *name)'),
    199: ('fremovexattr', 'int fremovexattr(int fd, const char *name)'),
    200: ('tkill', 'int tkill(int tid, int sig)'),
    201: ('time', 'time_t time(time_t *tloc)'),
    202: ('futex', 'int futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2, int val3)'),
    203: ('sched_setaffinity', 'int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask)'),
    204: ('sched_getaffinity', 'int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask)'),
    205: ('set_thread_area', 'int set_thread_area(struct user_desc *u_info)'),
    206: ('io_setup', 'int io_setup(unsigned nr_events, aio_context_t *ctx_idp)'),
    207: ('io_destroy', 'int io_destroy(aio_context_t ctx_id)'),
    208: ('io_getevents', 'int io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout)'),
    209: ('io_submit', 'int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp)'),
    210: ('io_cancel', 'int io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result)'),
    211: ('get_thread_area', 'int get_thread_area(struct user_desc *u_info)'),
    212: ('lookup_dcookie', 'int lookup_dcookie(u64 cookie, char *buffer, size_t len)'),
    213: ('epoll_create', 'int epoll_create(int size)'),
    214: ('epoll_ctl_old', 'int epoll_ctl_old(int epfd, int op, int fd, struct epoll_event *event)'),
    215: ('epoll_wait_old', 'int epoll_wait_old(int epfd, struct epoll_event *events, int maxevents, int timeout)'),
    216: ('remap_file_pages', 'int remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags)'),
    217: ('getdents64', 'int getdents64(int fd, void *dirp, unsigned int count)'),
    218: ('set_tid_address', 'long set_tid_address(int *tidptr)'),
    219: ('restart_syscall', 'long restart_syscall(void)'),
    220: ('semtimedop', 'int semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout)'),
    221: ('fadvise64', 'int fadvise64(int fd, off_t offset, size_t len, int advice)'),
    222: ('timer_create', 'int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid)'),
    223: ('timer_settime', 'int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value)'),
    224: ('timer_gettime', 'int timer_gettime(timer_t timerid, struct itimerspec *curr_value)'),
    225: ('timer_getoverrun', 'int timer_getoverrun(timer_t timerid)'),
    226: ('timer_delete', 'int timer_delete(timer_t timerid)'),
    227: ('clock_settime', 'int clock_settime(clockid_t clockid, const struct timespec *tp)'),
    228: ('clock_gettime', 'int clock_gettime(clockid_t clockid, struct timespec *tp)'),
    229: ('clock_getres', 'int clock_getres(clockid_t clockid, struct timespec *res)'),
    230: ('clock_nanosleep', 'int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *request, struct timespec *remain)'),
    231: ('exit_group', 'void exit_group(int status)'),
    232: ('epoll_wait', 'int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)'),
    233: ('epoll_ctl', 'int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)'),
    234: ('tgkill', 'int tgkill(int tgid, int tid, int sig)'),
    235: ('utimes', 'int utimes(const char *filename, const struct timeval times[2])'),
    236: ('mbind', 'long mbind(void *addr, unsigned long len, int mode, const unsigned long *nodemask, unsigned long maxnode, unsigned flags)'),
    237: ('set_mempolicy', 'long set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode)'),
    238: ('get_mempolicy', 'long get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags)'),
    239: ('mq_open', 'mqd_t mq_open(const char *name, int oflag, mode_t mode, struct mq_attr *attr)'),
    240: ('mq_unlink', 'int mq_unlink(const char *name)'),
    241: ('mq_timedsend', 'int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout)'),
    242: ('mq_timedreceive', 'ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout)'),
    243: ('mq_notify', 'int mq_notify(mqd_t mqdes, const struct sigevent *sevp)'),
    244: ('mq_getsetattr', 'int mq_getsetattr(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr)'),
    245: ('kexec_load', 'long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags)'),
    246: ('kexec_file_load', 'long kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline_ptr, unsigned long flags)'),
    247: ('vserver', 'int vserver(void)'),
    248: ('waitid', 'int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options, struct rusage *rusage)'),
    249: ('add_key', 'key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring)'),
    250: ('request_key', 'key_serial_t request_key(const char *type, const char *description, const char *callout_info, key_serial_t dest_keyring)'),
    251: ('keyctl', 'long keyctl(int cmd, ...)'),
    252: ('ioprio_set', 'int ioprio_set(int which, int who, int ioprio)'),
    253: ('ioprio_get', 'int ioprio_get(int which, int who)'),
    254: ('inotify_init', 'int inotify_init(void)'),
    255: ('inotify_add_watch', 'int inotify_add_watch(int fd, const char *pathname, uint32_t mask)'),
    256: ('inotify_rm_watch', 'int inotify_rm_watch(int fd, int wd)'),
    257: ('migrate_pages', 'long migrate_pages(int pid, unsigned long maxnode, const unsigned long *from, const unsigned long *to)'),
    258: ('openat', 'int openat(int dirfd, const char *pathname, int flags, mode_t mode)'),
    259: ('mkdirat', 'int mkdirat(int dirfd, const char *pathname, mode_t mode)'),
    260: ('mknodat', 'int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)'),
    261: ('fchownat', 'int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)'),
    262: ('futimesat', 'int futimesat(int dirfd, const char *pathname, const struct timeval times[2])'),
    263: ('newfstatat', 'int newfstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)'),
    264: ('unlinkat', 'int unlinkat(int dirfd, const char *pathname, int flags)'),
    265: ('renameat', 'int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)'),
    266: ('linkat', 'int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)'),
    267: ('symlinkat', 'int symlinkat(const char *target, int newdirfd, const char *linkpath)'),
    268: ('readlinkat', 'ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)'),
    269: ('fchmodat', 'int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)'),
    270: ('faccessat', 'int faccessat(int dirfd, const char *pathname, int mode, int flags)'),
    271: ('pselect6', 'int pselect6(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask)'),
    272: ('ppoll', 'int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)'),
    273: ('unshare', 'int unshare(int flags)'),
    274: ('set_robust_list', 'int set_robust_list(struct robust_list_head *head, size_t len)'),
    275: ('get_robust_list', 'int get_robust_list(pid_t pid, struct robust_list_head **head_ptr, size_t *len_ptr)'),
    276: ('splice', 'ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)'),
    277: ('tee', 'ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags)'),
    278: ('sync_file_range', 'int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)'),
    279: ('vmsplice', 'ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags)'),
    280: ('move_pages', 'long move_pages(int pid, unsigned long count, void **pages, const int *nodes, int *status, int flags)'),
    281: ('utimensat', 'int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags)'),
    282: ('epoll_pwait', 'int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask)'),
    283: ('signalfd', 'int signalfd(int fd, const sigset_t *mask, int flags)'),
    284: ('timerfd_create', 'int timerfd_create(clockid_t clockid, int flags)'),
    285: ('eventfd', 'int eventfd(unsigned int initval, int flags)'),
    286: ('fallocate', 'int fallocate(int fd, int mode, off_t offset, off_t len)'),
    287: ('timerfd_settime', 'int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value)'),
    288: ('timerfd_gettime', 'int timerfd_gettime(int fd, struct itimerspec *curr_value)'),
    289: ('accept4', 'int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)'),
    290: ('signalfd4', 'int signalfd4(int fd, const sigset_t *mask, size_t sizemask, int flags)'),
    291: ('eventfd2', 'int eventfd2(unsigned int initval, int flags)'),
    292: ('epoll_create1', 'int epoll_create1(int flags)'),
    293: ('dup3', 'int dup3(int oldfd, int newfd, int flags)'),
    294: ('pipe2', 'int pipe2(int pipefd[2], int flags)'),
    295: ('inotify_init1', 'int inotify_init1(int flags)'),
    296: ('preadv', 'ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)'),
    297: ('pwritev', 'ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)'),
    298: ('rt_tgsigqueueinfo', 'int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo)'),
    299: ('perf_event_open', 'int perf_event_open(struct perf_event_attr *attr, int pid, int cpu, int group_fd, unsigned long flags)'),
    300: ('recvmmsg', 'int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags, struct timespec *timeout)'),
    301: ('fanotify_init', 'int fanotify_init(unsigned int flags, unsigned int event_f_flags)'),
    302: ('fanotify_mark', 'int fanotify_mark(int fanotify_fd, unsigned int flags, unsigned long mask, int dirfd, const char *pathname)'),
    303: ('prlimit64', 'int prlimit64(pid_t pid, int resource, const struct rlimit64 *new_limit, struct rlimit64 *old_limit)'),
    304: ('name_to_handle_at', 'int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags)'),
    305: ('open_by_handle_at', 'int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags)'),
    306: ('clock_adjtime', 'int clock_adjtime(clockid_t clock_id, struct timex *buf)'),
    307: ('syncfs', 'int syncfs(int fd)'),
    308: ('setns', 'int setns(int fd, int nstype)'),
    309: ('getcpu', 'int getcpu(unsigned int *cpu, unsigned int *node, struct getcpu_cache *tcache)'),
    310: ('process_vm_readv', 'ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)'),
    311: ('process_vm_writev', 'ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)'),
    312: ('kcmp', 'int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2)'),
    313: ('finit_module', 'int finit_module(int fd, const char *param_values, int flags)'),
    314: ('sched_setattr', 'int sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags)'),
    315: ('sched_getattr', 'int sched_getattr(pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags)'),
    316: ('renameat2', 'int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)'),
    317: ('seccomp', 'int seccomp(unsigned int operation, unsigned int flags, void *args)'),
    318: ('getrandom', 'ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)'),
    319: ('memfd_create', 'int memfd_create(const char *name, unsigned int flags)'),
    320: ('kexec_file_load', 'long kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline_ptr, unsigned long flags)'),
    321: ('bpf', 'int bpf(int cmd, union bpf_attr *attr, unsigned int size)'),
    322: ('execveat', 'int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)'),
    323: ('userfaultfd', 'int userfaultfd(int flags)'),
    324: ('membarrier', 'int membarrier(int cmd, unsigned int flags, int cpu_id)'),
    325: ('mlock2', 'int mlock2(const void *addr, size_t len, int flags)'),
    326: ('copy_file_range', 'ssize_t copy_file_range(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out, size_t len, unsigned int flags)'),
    327: ('preadv2', 'ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)'),
    328: ('pwritev2', 'ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)'),
    329: ('pkey_mprotect', 'int pkey_mprotect(void *addr, size_t len, int prot, int pkey)'),
    330: ('pkey_alloc', 'int pkey_alloc(unsigned int flags, unsigned int init_val)'),
    331: ('pkey_free', 'int pkey_free(int pkey)'),
    332: ('statx', 'int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf)'),
    333: ('io_pgetevents', 'int io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout, const struct __aio_sigset *sig)'),
    334: ('rseq', 'int rseq(struct rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig)'),
    # ... 更多系统调用
}

# Windows 系统调用表（部分）
WINDOWS_SYSCALLS = {
    # Windows 系统调用号在不同版本可能不同
    # 这里提供常见系统调用的名称映射
    'NtCreateFile': {'category': 'file', 'risk': 'medium'},
    'NtOpenFile': {'category': 'file', 'risk': 'medium'},
    'NtReadFile': {'category': 'file', 'risk': 'low'},
    'NtWriteFile': {'category': 'file', 'risk': 'medium'},
    'NtClose': {'category': 'handle', 'risk': 'low'},
    'NtCreateProcess': {'category': 'process', 'risk': 'high'},
    'NtOpenProcess': {'category': 'process', 'risk': 'high'},
    'NtTerminateProcess': {'category': 'process', 'risk': 'high'},
    'NtCreateThread': {'category': 'thread', 'risk': 'high'},
    'NtOpenThread': {'category': 'thread', 'risk': 'medium'},
    'NtTerminateThread': {'category': 'thread', 'risk': 'medium'},
    'NtAllocateVirtualMemory': {'category': 'memory', 'risk': 'high'},
    'NtFreeVirtualMemory': {'category': 'memory', 'risk': 'medium'},
    'NtProtectVirtualMemory': {'category': 'memory', 'risk': 'high'},
    'NtReadVirtualMemory': {'category': 'memory', 'risk': 'high'},
    'NtWriteVirtualMemory': {'category': 'memory', 'risk': 'critical'},
    'NtCreateSection': {'category': 'memory', 'risk': 'medium'},
    'NtOpenSection': {'category': 'memory', 'risk': 'medium'},
    'NtMapViewOfSection': {'category': 'memory', 'risk': 'medium'},
    'NtUnmapViewOfSection': {'category': 'memory', 'risk': 'low'},
    'NtLoadDriver': {'category': 'driver', 'risk': 'critical'},
    'NtUnloadDriver': {'category': 'driver', 'risk': 'critical'},
    'NtSetValueKey': {'category': 'registry', 'risk': 'medium'},
    'NtDeleteValueKey': {'category': 'registry', 'risk': 'medium'},
    'NtCreateKey': {'category': 'registry', 'risk': 'medium'},
    'NtOpenKey': {'category': 'registry', 'risk': 'medium'},
    'NtDeleteKey': {'category': 'registry', 'risk': 'medium'},
    'NtDeviceIoControlFile': {'category': 'device', 'risk': 'high'},
    'NtQueryInformationProcess': {'category': 'info', 'risk': 'medium'},
    'NtSetInformationProcess': {'category': 'info', 'risk': 'high'},
    'NtQueryInformationThread': {'category': 'info', 'risk': 'medium'},
    'NtSetInformationThread': {'category': 'info', 'risk': 'medium'},
    'NtQuerySystemInformation': {'category': 'info', 'risk': 'medium'},
    'NtSetSystemInformation': {'category': 'info', 'risk': 'high'},
    'NtDuplicateObject': {'category': 'handle', 'risk': 'medium'},
    'NtSignalAndWaitForSingleObject': {'category': 'sync', 'risk': 'low'},
    'NtWaitForSingleObject': {'category': 'sync', 'risk': 'low'},
    'NtWaitForMultipleObjects': {'category': 'sync', 'risk': 'low'},
    'NtCreateEvent': {'category': 'sync', 'risk': 'low'},
    'NtOpenEvent': {'category': 'sync', 'risk': 'low'},
    'NtSetEvent': {'category': 'sync', 'risk': 'low'},
    'NtClearEvent': {'category': 'sync', 'risk': 'low'},
    'NtCreateMutant': {'category': 'sync', 'risk': 'low'},
    'NtOpenMutant': {'category': 'sync', 'risk': 'low'},
    'NtReleaseMutant': {'category': 'sync', 'risk': 'low'},
    'NtCreateSemaphore': {'category': 'sync', 'risk': 'low'},
    'NtOpenSemaphore': {'category': 'sync', 'risk': 'low'},
    'NtReleaseSemaphore': {'category': 'sync', 'risk': 'low'},
    'NtCreateTimer': {'category': 'sync', 'risk': 'low'},
    'NtOpenTimer': {'category': 'sync', 'risk': 'low'},
    'NtSetTimer': {'category': 'sync', 'risk': 'low'},
    'NtCancelTimer': {'category': 'sync', 'risk': 'low'},
    'NtCreateIoCompletion': {'category': 'io', 'risk': 'low'},
    'NtOpenIoCompletion': {'category': 'io', 'risk': 'low'},
    'NtSetIoCompletion': {'category': 'io', 'risk': 'low'},
    'NtRemoveIoCompletion': {'category': 'io', 'risk': 'low'},
    'NtCreatePort': {'category': 'ipc', 'risk': 'medium'},
    'NtCreateWaitablePort': {'category': 'ipc', 'risk': 'medium'},
    'NtListenPort': {'category': 'ipc', 'risk': 'medium'},
    'NtConnectPort': {'category': 'ipc', 'risk': 'medium'},
    'NtAcceptConnectPort': {'category': 'ipc', 'risk': 'medium'},
    'NtCompleteConnectPort': {'category': 'ipc', 'risk': 'medium'},
    'NtRequestPort': {'category': 'ipc', 'risk': 'medium'},
    'NtRequestWaitReplyPort': {'category': 'ipc', 'risk': 'medium'},
    'NtReplyPort': {'category': 'ipc', 'risk': 'medium'},
    'NtReplyWaitReplyPort': {'category': 'ipc', 'risk': 'medium'},
    'NtReplyWaitReceivePort': {'category': 'ipc', 'risk': 'medium'},
    'NtImpersonateClientOfPort': {'category': 'ipc', 'risk': 'high'},
    'NtCreateToken': {'category': 'security', 'risk': 'critical'},
    'NtOpenProcessToken': {'category': 'security', 'risk': 'high'},
    'NtOpenThreadToken': {'category': 'security', 'risk': 'high'},
    'NtDuplicateToken': {'category': 'security', 'risk': 'high'},
    'NtAdjustPrivilegesToken': {'category': 'security', 'risk': 'critical'},
    'NtAccessCheck': {'category': 'security', 'risk': 'medium'},
    'NtAccessCheckAndAuditAlarm': {'category': 'security', 'risk': 'medium'},
    'NtPrivilegeCheck': {'category': 'security', 'risk': 'medium'},
    'NtSetSecurityObject': {'category': 'security', 'risk': 'high'},
    'NtQuerySecurityObject': {'category': 'security', 'risk': 'medium'},
}


class SyscallTableRecovery:
    """系统调用表恢复与分析"""
    
    def __init__(self, binary_path: str = None, kernel_type: KernelType = None,
                 arch_type: ArchType = None, config: Dict[str, Any] = None):
        """
        初始化系统调用表恢复器
        
        Args:
            binary_path: 内核二进制文件路径
            kernel_type: 内核类型
            arch_type: 架构类型
            config: 配置参数
        """
        self.binary_path = binary_path
        self.kernel_type = kernel_type or KernelType.UNKNOWN
        self.arch_type = arch_type or ArchType.UNKNOWN
        self.config = config or {}
        
        # 系统调用分类
        self.syscall_categories = {
            'dangerous': [
                'execve', 'ptrace', 'mprotect', 'mmap', 'munmap',
                'setuid', 'setgid', 'setreuid', 'setregid',
                'chroot', 'mount', 'umount2', 'pivot_root',
                'kexec_load', 'init_module', 'finit_module', 'delete_module',
                'reboot', 'acct', 'swapon', 'swapoff',
                'prctl', 'arch_prctl', 'seccomp',
                # Windows
                'NtWriteVirtualMemory', 'NtCreateProcess', 'NtLoadDriver',
                'NtAdjustPrivilegesToken', 'NtCreateToken'
            ],
            'privilege': [
                'setuid', 'setgid', 'setreuid', 'setregid', 'setresuid', 'setresgid',
                'setfsuid', 'setfsgid', 'capset', 'prctl',
                'NtAdjustPrivilegesToken', 'NtCreateToken', 'NtDuplicateToken'
            ],
            'io': [
                'read', 'write', 'open', 'close', 'stat', 'lstat', 'fstat',
                'pread64', 'pwrite64', 'readv', 'writev', 'sendfile',
                'splice', 'tee', 'vmsplice',
                'NtReadFile', 'NtWriteFile', 'NtCreateFile', 'NtOpenFile'
            ],
            'network': [
                'socket', 'connect', 'accept', 'bind', 'listen',
                'sendto', 'recvfrom', 'sendmsg', 'recvmsg',
                'shutdown', 'getsockname', 'getpeername', 'socketpair',
                'setsockopt', 'getsockopt',
                'NtDeviceIoControlFile'  # 可能用于网络操作
            ],
            'memory': [
                'mmap', 'munmap', 'mprotect', 'brk', 'mremap',
                'msync', 'mincore', 'madvise', 'mlock', 'munlock',
                'mlockall', 'munlockall', 'shmat', 'shmdt',
                'NtAllocateVirtualMemory', 'NtFreeVirtualMemory',
                'NtProtectVirtualMemory', 'NtReadVirtualMemory',
                'NtWriteVirtualMemory', 'NtCreateSection', 'NtMapViewOfSection'
            ]
        }
    
    def detect_kernel_type(self) -> KernelType:
        """检测内核类型"""
        if self.kernel_type != KernelType.UNKNOWN:
            return self.kernel_type
        
        if self.binary_path:
            try:
                # 使用 strings 检测内核特征
                result = subprocess.run(
                    ['strings', self.binary_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    strings_output = result.stdout
                    
                    # Linux 特征
                    if any(sig in strings_output for sig in ['Linux', 'linux', 'kernel', 'sys_call_table']):
                        return KernelType.LINUX
                    
                    # Windows 特征
                    if any(sig in strings_output for sig in ['ntoskrnl', 'NTOSKRNL', 'KeServiceDescriptorTable', 'KiServiceTable']):
                        return KernelType.WINDOWS
                    
                    # FreeBSD 特征
                    if any(sig in strings_output for sig in ['FreeBSD', 'freebsd', 'sysent']):
                        return KernelType.FREEBSD
                    
                    # macOS 特征
                    if any(sig in strings_output for sig in ['Darwin', 'macOS', 'XNU']):
                        return KernelType.MACOS
            except Exception as e:
                logger.warning(f"检测内核类型失败: {e}")
        
        return KernelType.UNKNOWN
    
    def detect_arch_type(self) -> ArchType:
        """检测架构类型"""
        if self.arch_type != ArchType.UNKNOWN:
            return self.arch_type
        
        if self.binary_path:
            try:
                # 使用 file 命令检测架构
                result = subprocess.run(
                    ['file', self.binary_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    output = result.stdout.lower()
                    
                    if 'x86-64' in output or 'amd64' in output:
                        return ArchType.X64
                    elif 'i386' in output or 'i686' in output or 'x86' in output:
                        return ArchType.X86
                    elif 'arm64' in output or 'aarch64' in output:
                        return ArchType.ARM64
                    elif 'arm' in output:
                        return ArchType.ARM32
                    elif 'mips' in output:
                        return ArchType.MIPS
                    elif 'riscv' in output:
                        return ArchType.RISCV
            except Exception as e:
                logger.warning(f"检测架构类型失败: {e}")
        
        return ArchType.UNKNOWN
    
    def find_syscall_table_address(self) -> Optional[int]:
        """
        查找系统调用表地址
        
        Returns:
            系统调用表地址，如果未找到返回 None
        """
        if not self.binary_path:
            return None
        
        kernel_type = self.detect_kernel_type()
        arch_type = self.detect_arch_type()
        
        try:
            # 使用 radare2 或 objdump 查找符号
            result = subprocess.run(
                ['r2', '-q', '-c', 'is~sys_call_table', self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                # 解析地址
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            addr = int(parts[1], 16)
                            return addr
                        except ValueError:
                            continue
        except Exception as e:
            logger.warning(f"查找 syscall table 地址失败: {e}")
        
        # 尝试使用 objdump
        try:
            result = subprocess.run(
                ['objdump', '-t', self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'sys_call_table' in line or 'KiServiceTable' in line:
                        parts = line.split()
                        for part in parts:
                            if part.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in part):
                                try:
                                    addr = int(part, 16)
                                    return addr
                                except ValueError:
                                    continue
        except Exception as e:
            logger.warning(f"objdump 查找失败: {e}")
        
        return None
    
    def recover_syscall_table(self) -> SyscallTableInfo:
        """
        恢复系统调用表
        
        Returns:
            系统调用表信息
        """
        kernel_type = self.detect_kernel_type()
        arch_type = self.detect_arch_type()
        
        table_info = SyscallTableInfo(
            kernel_type=kernel_type,
            arch_type=arch_type,
            table_address=0,
            table_size=0
        )
        
        # 获取系统调用表地址
        table_addr = self.find_syscall_table_address()
        if table_addr:
            table_info.table_address = table_addr
        
        # 根据内核类型填充系统调用表
        if kernel_type == KernelType.LINUX:
            self._fill_linux_syscall_table(table_info, arch_type)
        elif kernel_type == KernelType.WINDOWS:
            self._fill_windows_syscall_table(table_info)
        else:
            # 尝试从二进制中提取
            self._extract_syscall_table_from_binary(table_info)
        
        # 检测挂钩
        self._detect_hooks(table_info)
        
        return table_info
    
    def _fill_linux_syscall_table(self, table_info: SyscallTableInfo, 
                                   arch_type: ArchType) -> None:
        """填充 Linux 系统调用表"""
        syscall_data = LINUX_X64_SYSCALLS
        
        for num, (name, prototype) in syscall_data.items():
            entry = SyscallEntry(
                number=num,
                name=name,
                address=0,  # 需要从实际表中获取
                handler_name=f'sys_{name}',
                parameters=self._parse_parameters(prototype),
                return_type=self._parse_return_type(prototype),
                security_level=self._assess_security_level(name)
            )
            table_info.entries.append(entry)
        
        table_info.table_size = len(syscall_data)
    
    def _fill_windows_syscall_table(self, table_info: SyscallTableInfo) -> None:
        """填充 Windows 系统调用表"""
        # Windows 系统调用号在不同版本可能不同
        # 这里使用名称映射
        
        for idx, (name, info) in enumerate(WINDOWS_SYSCALLS.items()):
            entry = SyscallEntry(
                number=idx,  # 实际号码需要从 SSDT 获取
                name=name,
                address=0,
                handler_name=name,
                security_level=info['risk'],
                notes=f"Category: {info['category']}"
            )
            table_info.entries.append(entry)
        
        table_info.table_size = len(WINDOWS_SYSCALLS)
    
    def _extract_syscall_table_from_binary(self, table_info: SyscallTableInfo) -> None:
        """从二进制中提取系统调用表"""
        if not self.binary_path:
            return
        
        try:
            # 使用 radare2 分析
            result = subprocess.run(
                ['r2', '-q', '-c', 'aaa; afl~sys_', self.binary_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[-1]
                        if name.startswith('sys_') or name.startswith('SymFromAddr'):
                            try:
                                addr = int(parts[0], 16)
                                entry = SyscallEntry(
                                    number=0,  # 需要进一步分析
                                    name=name.replace('sys_', ''),
                                    address=addr,
                                    handler_name=name
                                )
                                table_info.entries.append(entry)
                            except ValueError:
                                continue
        except Exception as e:
            logger.warning(f"从二进制提取 syscall table 失败: {e}")
    
    def _parse_parameters(self, prototype: str) -> List[Dict[str, Any]]:
        """解析函数原型中的参数"""
        parameters = []
        
        # 提取参数部分
        match = re.search(r'\(([^)]+)\)', prototype)
        if match:
            params_str = match.group(1)
            if params_str.strip() and params_str.strip() != 'void':
                for param in params_str.split(','):
                    param = param.strip()
                    if param:
                        # 解析类型和名称
                        parts = param.rsplit(' ', 1)
                        if len(parts) == 2:
                            param_type = parts[0]
                            param_name = parts[1]
                        else:
                            param_type = param
                            param_name = ''
                        
                        parameters.append({
                            'type': param_type,
                            'name': param_name,
                            'is_pointer': '*' in param_type,
                            'is_array': '[' in param_name or '[' in param_type
                        })
        
        return parameters
    
    def _parse_return_type(self, prototype: str) -> str:
        """解析返回类型"""
        match = re.match(r'^([^(]+)', prototype)
        if match:
            return match.group(1).strip()
        return ''
    
    def _assess_security_level(self, syscall_name: str) -> str:
        """评估系统调用的安全级别"""
        dangerous_syscalls = self.syscall_categories['dangerous']
        privilege_syscalls = self.syscall_categories['privilege']
        
        if syscall_name in dangerous_syscalls:
            return 'critical'
        elif syscall_name in privilege_syscalls:
            return 'high'
        elif any(cat in syscall_name.lower() for cat in ['exec', 'create', 'write', 'modify']):
            return 'medium'
        else:
            return 'low'
    
    def _detect_hooks(self, table_info: SyscallTableInfo) -> None:
        """检测系统调用挂钩"""
        # 这需要实际的内存分析或内核调试
        # 这里提供检测逻辑框架
        
        hooked_patterns = [
            # 检测地址是否在模块范围外
            # 检测地址是否指向可疑代码
        ]
        
        for entry in table_info.entries:
            # 简化检测：如果地址为 0 或异常值，标记为可能被挂钩
            if entry.address == 0 and entry.number > 0:
                entry.hook_detected = True
                entry.notes += " [可能被挂钩或未实现]"
                table_info.hooked_syscalls.append(entry.number)
    
    def analyze_syscall_usage(self, syscall_numbers: List[int]) -> SyscallAnalysisResult:
        """
        分析系统调用使用情况
        
        Args:
            syscall_numbers: 使用的系统调用号列表
            
        Returns:
            系统调用分析结果
        """
        table_info = self.recover_syscall_table()
        
        result = SyscallAnalysisResult(table_info=table_info)
        
        # 分类系统调用
        for entry in table_info.entries:
            if entry.number in syscall_numbers:
                # 按类别分组
                for category, syscalls in self.syscall_categories.items():
                    if entry.name in syscalls:
                        if category == 'dangerous':
                            result.dangerous_syscalls.append(entry)
                        elif category == 'privilege':
                            result.privilege_syscalls.append(entry)
                        elif category == 'io':
                            result.io_syscalls.append(entry)
                        elif category == 'network':
                            result.network_syscalls.append(entry)
                        elif category == 'memory':
                            result.memory_syscalls.append(entry)
        
        # 生成风险评估
        result.risk_assessment = self._generate_risk_assessment(result)
        result.summary = self._generate_summary(result)
        
        return result
    
    def _generate_risk_assessment(self, result: SyscallAnalysisResult) -> Dict[str, Any]:
        """生成风险评估"""
        assessment = {
            'total_syscalls_used': len(result.dangerous_syscalls) + 
                                   len(result.privilege_syscalls) +
                                   len(result.io_syscalls) +
                                   len(result.network_syscalls) +
                                   len(result.memory_syscalls),
            'dangerous_count': len(result.dangerous_syscalls),
            'privilege_count': len(result.privilege_syscalls),
            'risk_score': 0.0,
            'risk_factors': []
        }
        
        # 计算风险评分
        assessment['risk_score'] = (
            len(result.dangerous_syscalls) * 10 +
            len(result.privilege_syscalls) * 7 +
            len(result.network_syscalls) * 3 +
            len(result.memory_syscalls) * 5
        )
        
        # 识别风险因素
        if result.dangerous_syscalls:
            assessment['risk_factors'].append('使用了危险系统调用')
        
        if result.privilege_syscalls:
            assessment['risk_factors'].append('涉及权限提升相关系统调用')
        
        if result.memory_syscalls:
            assessment['risk_factors'].append('涉及内存操作系统调用')
        
        return assessment
    
    def _generate_summary(self, result: SyscallAnalysisResult) -> str:
        """生成分析摘要"""
        summary = f"系统调用分析完成。"
        summary += f"共使用 {result.risk_assessment['total_syscalls_used']} 个系统调用。"
        
        if result.dangerous_syscalls:
            summary += f"其中 {len(result.dangerous_syscalls)} 个为危险系统调用。"
        
        if result.risk_assessment['risk_score'] > 50:
            summary += "整体风险较高，建议深入分析。"
        elif result.risk_assessment['risk_score'] > 20:
            summary += "存在一定风险，需要关注。"
        else:
            summary += "风险较低。"
        
        return summary
    
    def get_syscall_by_number(self, number: int) -> Optional[SyscallEntry]:
        """
        根据号码获取系统调用信息
        
        Args:
            number: 系统调用号
            
        Returns:
            系统调用条目
        """
        table_info = self.recover_syscall_table()
        
        for entry in table_info.entries:
            if entry.number == number:
                return entry
        
        return None
    
    def get_syscall_by_name(self, name: str) -> Optional[SyscallEntry]:
        """
        根据名称获取系统调用信息
        
        Args:
            name: 系统调用名称
            
        Returns:
            系统调用条目
        """
        table_info = self.recover_syscall_table()
        
        for entry in table_info.entries:
            if entry.name == name:
                return entry
        
        return None
    
    def generate_syscall_report(self, output_format: str = 'markdown') -> str:
        """
        生成系统调用报告
        
        Args:
            output_format: 输出格式
            
        Returns:
            报告内容
        """
        table_info = self.recover_syscall_table()
        
        if output_format == 'markdown':
            report = "# 系统调用表分析报告\n\n"
            report += f"## 基本信息\n\n"
            report += f"- 内核类型: {table_info.kernel_type.value}\n"
            report += f"- 架构类型: {table_info.arch_type.value}\n"
            report += f"- 表地址: 0x{table_info.table_address:x}\n"
            report += f"- 表大小: {table_info.table_size}\n\n"
            
            report += "## 系统调用列表\n\n"
            report += "| 号码 | 名称 | 处理函数 | 安全级别 | 备注 |\n"
            report += "|------|------|----------|----------|------|\n"
            
            for entry in table_info.entries[:100]:  # 限制输出数量
                report += f"| {entry.number} | {entry.name} | {entry.handler_name} | {entry.security_level} | {entry.notes} |\n"
            
            if table_info.hooked_syscalls:
                report += "\n## 检测到的挂钩\n\n"
                for num in table_info.hooked_syscalls:
                    entry = self.get_syscall_by_number(num)
                    if entry:
                        report += f"- 系统调用 {num} ({entry.name}): 可能被挂钩\n"
            
            return report
        
        return ""


def recover_syscall_table(binary_path: str, kernel_type: str = 'auto',
                          arch_type: str = 'auto') -> SyscallTableInfo:
    """
    恢复系统调用表便捷函数
    
    Args:
        binary_path: 内核二进制文件路径
        kernel_type: 内核类型
        arch_type: 架构类型
        
    Returns:
        系统调用表信息
    """
    kt = KernelType(kernel_type) if kernel_type != 'auto' else None
    at = ArchType(arch_type) if arch_type != 'auto' else None
    
    recovery = SyscallTableRecovery(binary_path, kt, at)
    return recovery.recover_syscall_table()


def analyze_syscall_sequence(syscall_numbers: List[int], 
                             binary_path: str = None) -> SyscallAnalysisResult:
    """
    分析系统调用序列
    
    Args:
        syscall_numbers: 系统调用号列表
        binary_path: 内核二进制文件路径（可选）
        
    Returns:
        系统调用分析结果
    """
    recovery = SyscallTableRecovery(binary_path)
    return recovery.analyze_syscall_usage(syscall_numbers)


# 导出主要类和函数
__all__ = [
    'SyscallTableRecovery',
    'SyscallTableInfo',
    'SyscallEntry',
    'SyscallAnalysisResult',
    'KernelType',
    'ArchType',
    'recover_syscall_table',
    'analyze_syscall_sequence',
    'LINUX_X64_SYSCALLS',
    'WINDOWS_SYSCALLS'
]