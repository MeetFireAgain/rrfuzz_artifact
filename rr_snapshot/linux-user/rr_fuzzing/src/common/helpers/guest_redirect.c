/*
 * Guest Connect Redirector (i386 No-Libc Version)
 * Intercepts connect(), rewrites /ram/novasock to /tmp/novasock
 */

#define AF_UNIX 1
#define SOCK_STREAM 1

/* Basic types for i386 */
typedef unsigned short sa_family_t;
typedef unsigned int socklen_t;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

struct sockaddr_un {
    sa_family_t sun_family;
    char sun_path[108];
};

/* 
 * syscall number for connect on i386.
 * Note: Some older uClibc use socketcall (102), but QEMU handles 362 (connect) too.
 * If uClibc wrappers use socketcall, overriding 'connect' symbol is still fine,
 * because we are replacing the WRAPPER.
 * Our implementation will use the direct syscall 362 for simplicity.
 */
#define __NR_connect 362
#define __NR_write 4

/* Helper for syscalls */
static inline int my_syscall3(int num, int arg1, int arg2, int arg3) {
    int res;
    __asm__ volatile (
        "int $0x80"
        : "=a" (res)
        : "0" (num), "b" (arg1), "c" (arg2), "d" (arg3)
        : "memory"
    );
    return res;
}

/* Minimal strlen */
static int my_strlen(const char *s) {
    int len = 0;
    while (*s++) len++;
    return len;
}

/* Minimal strncmp */
static int my_strncmp(const char *s1, const char *s2, int n) {
    while (n > 0) {
        if (*s1 != *s2) return (*s1 - *s2);
        if (*s1 == 0) return 0;
        s1++; s2++; n--;
    }
    return 0;
}

/* Minimal memcpy */
static void my_memcpy(void *dest, const void *src, int n) {
    char *d = (char *)dest;
    const char *s = (const char *)src;
    while (n--) *d++ = *s++;
}

/* Log to stderr (fd 2) */
static void log_msg(const char *msg) {
    my_syscall3(__NR_write, 2, (int)msg, my_strlen(msg));
}

/* The interceptor */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr && addr->sa_family == AF_UNIX) {
        const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;
        
        /* Check for target path: /ram/novasock */
        /* Path might not be null terminated if len matches, but usually is */
        if (my_strncmp(sun->sun_path, "/ram/novasock", 13) == 0) {
            log_msg("[GuestRedirect] Intercepting connect to /ram/novasock\n");
            
            struct sockaddr_un new_addr;
            /* Zero out */
            int i;
            char *p = (char *)&new_addr;
            for(i=0; i<sizeof(new_addr); i++) p[i] = 0;
            
            new_addr.sun_family = AF_UNIX;
            /* Redirect to /tmp/novasock */
            const char *target = "/tmp/novasock";
            my_memcpy(new_addr.sun_path, target, my_strlen(target) + 1);
            
            log_msg("[GuestRedirect] Redirecting to /tmp/novasock\n");
            
            return my_syscall3(__NR_connect, sockfd, (int)&new_addr, sizeof(new_addr));
        }
    }
    
    /* Passthrough */
    return my_syscall3(__NR_connect, sockfd, (int)addr, addrlen);
}
