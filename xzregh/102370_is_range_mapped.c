// /home/kali/xzre-ghidra/xzregh/102370_is_range_mapped.c
// Function: is_range_mapped @ 0x102370
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_range_mapped(u8 * addr, u64 length, global_context_t * ctx)


/*
 * AutoDoc: Userland page-probe that avoids importing `mincore(2)`. The helper aligns the requested address downward, then walks one page at a time toward `addr + length`, invoking the host's `pselect` with NULL fd sets and the page pointer passed in as the signal mask argument. If `pselect` faults with EFAULT the page is unmapped, otherwise the loop continues until every page succeeds. The routine relies on `ctx->libc_imports` to surface both `pselect` and `__errno_location`, and it refuses to touch addresses below 0x01000000 to avoid probing NULL or vsyscall.
 */
#include "xzre_types.h"


BOOL is_range_mapped(u8 *addr,u64 length,global_context_t *ctx)

{
  libc_imports_t *plVar1;
  BOOL BVar2;
  int iVar3;
  int *piVar4;
  sigset_t *sigmask;
  undefined8 local_38;
  undefined8 local_30;
  
  if (length == 0) {
    return 0;
  }
  if (addr < (u8 *)0x1000000) {
LAB_00102393:
    BVar2 = 0;
  }
  else {
    sigmask = (sigset_t *)((ulong)addr & 0xfffffffffffff000);
    if (sigmask < addr + length) {
      if (ctx == (global_context_t *)0x0) goto LAB_00102393;
      do {
        local_38 = 0;
        plVar1 = ctx->libc_imports;
        if (((plVar1 == (libc_imports_t *)0x0) || (plVar1->__errno_location == (_func_26 *)0x0)) ||
           (plVar1->pselect == (_func_24 *)0x0)) goto LAB_00102393;
        local_30 = 1;
        iVar3 = (*plVar1->pselect)(1,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,(timespec *)&local_38
                                   ,sigmask);
        if ((iVar3 < 0) &&
           ((piVar4 = (*ctx->libc_imports->__errno_location)(), *piVar4 == 0xe ||
            (sigmask == (sigset_t *)0x0)))) {
          *piVar4 = 0;
          goto LAB_00102393;
        }
        sigmask = sigmask + 0x200;
      } while (sigmask < addr + length);
    }
    BVar2 = 1;
  }
  return BVar2;
}

