#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// Original connect function pointer
static int (*original_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!original_connect) {
        original_connect = dlsym(RTLD_NEXT, "connect");
        if (!original_connect) {
            fprintf(stderr, "[SockRedirect] Failed to find original connect\n");
            return -1;
        }
    }

    if (addr->sa_family == AF_UNIX) {
        const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;
        // Check if path wants to be redirected
        // Target: /ram/novasock
        if (strncmp(sun->sun_path, "/ram/novasock", 108) == 0) {
            fprintf(stderr, "[SockRedirect] Intercepting connect to %s\n", sun->sun_path);
            
            // Construct new path
            struct sockaddr_un new_addr;
            memset(&new_addr, 0, sizeof(new_addr));
            new_addr.sun_family = AF_UNIX;
            
            // Hardcoded redirect for now, or env var
            const char *redirect_base = getenv("REDIRECT_SOCK_ROOT");
            if (redirect_base) {
                snprintf(new_addr.sun_path, sizeof(new_addr.sun_path), "%s/ram/novasock", redirect_base);
            } else {
                 // Fallback or error
                 fprintf(stderr, "[SockRedirect] REDIRECT_SOCK_ROOT not set!\n");
                 return original_connect(sockfd, addr, addrlen);
            }

            fprintf(stderr, "[SockRedirect] Redirecting to %s\n", new_addr.sun_path);
            return original_connect(sockfd, (struct sockaddr *)&new_addr, sizeof(new_addr));
        }
    }

    return original_connect(sockfd, addr, addrlen);
}
