#include "rr_mock_ioctls.h"
#include "qemu.h"
#include <string.h>

/* Global sink page for rogue stores */
abi_ulong g_rr_compat_sink_page = 0;

/* [RRFUZZ] Mocking framework for special firmware requirements.
   This provides a cleaner way to handle hardware dependencies without polluting syscall.c. */

int rr_try_mock_ioctl(int fd, int cmd, abi_long arg)
{
    static int mock_wireless_enabled = -1;

    if (mock_wireless_enabled == -1) {
        mock_wireless_enabled = (getenv("RR_MOCK_WIRELESS") != NULL);
    }

    if (!mock_wireless_enabled) {
        return 0;
    }

    /* Mock Wireless Extensions (0x8Bxx range) */
    if ((cmd & 0xFF00) == 0x8B00) {
        /* SIOCGIWNAME: Get interface name */
        if (cmd == 0x8B01) {
            void *p = lock_user(VERIFY_WRITE, arg, 16, 0);
            if (p) {
                /* Return a dummy name 'wlan0' to satisfy firmware checks */
                memset(p, 0, 16);
                strncpy((char *)p, "wlan0", 15);
                unlock_user(p, arg, 16);
            }
            return 1; /* Handled */
        }

        /* Generic handling for other 0x8Bxx: Zero out buffer to avoid garbage crashes */
        /* Most struct iwreq are <= 32 bytes. */
        void *p = lock_user(VERIFY_WRITE, arg, 32, 0);
        if (p) {
            memset(p, 0, 32);
            unlock_user(p, arg, 32);
        }
        return 1; /* Handled, return success to guest */
    }

    return 0;
}

void rr_fix_mips_abi(void *cpu_env)
{
#ifdef TARGET_MIPS
    CPUMIPSState *env = (CPUMIPSState *)cpu_env;
    
    /* [RRFUZZ] MIPS 'at' ($1) Register Fixup
       Many firmware binaries (like TOTOLINK boa) use 'at' for stack alignment in _start
       but forget to clear it. uClibc sometimes uses 'at' as a pointer in its
       internal assembly stubs (e.g. for errno), leading to Segfaults.
       
       We point 'at' to a safe 'sink page' if it looks corrupted or NULL but is about 
       to be used. */
    target_ulong current_at = env->active_tc.gpr[1];
    if (getenv("RR_MOCK_WIRELESS")) {
        if (current_at == (target_ulong)0xfffffff8 || current_at == 0) {
            if (g_rr_compat_sink_page != 0) {
                env->active_tc.gpr[1] = g_rr_compat_sink_page;
            }
        }
    }
#endif
}
