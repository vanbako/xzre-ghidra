// /home/kali/xzre-ghidra/xzregh/102370_is_range_mapped.c
// Function: is_range_mapped @ 0x102370
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_range_mapped(u8 * addr, u64 length, global_context_t * ctx)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief verify if a memory range is mapped
 *
 *   @param addr the start address
 *   @param length the length of the range to check
 *   @param ctx a structure with a libc_import_t field at offset 0x10
 *   @return BOOL TRUE if the whole range is mapped, FALSE otherwise
 */

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

