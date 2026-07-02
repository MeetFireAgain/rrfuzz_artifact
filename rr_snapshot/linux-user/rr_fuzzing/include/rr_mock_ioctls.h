#ifndef RR_MOCK_IOCTLS_H
#define RR_MOCK_IOCTLS_H

#include "qemu/osdep.h"
#include "qemu.h"

/* Returns 1 if handled (mocked), 0 otherwise */
int rr_try_mock_ioctl(int fd, int cmd, abi_long arg);

/* Fixes common firmware ABI issues (like MIPS 'at' corruption) */
void rr_fix_mips_abi(void *cpu_env);

/* The compatibility sink page (allocated during init) */
extern abi_ulong g_rr_compat_sink_page;

#endif
