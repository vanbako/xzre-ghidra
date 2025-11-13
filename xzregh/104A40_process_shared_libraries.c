// /home/kali/xzre-ghidra/xzregh/104A40_process_shared_libraries.c
// Function: process_shared_libraries @ 0x104A40
// Calling convention: unknown
// Prototype: undefined process_shared_libraries(void)


/*
 * AutoDoc: Wrapper around `process_shared_libraries_map` that first resolves `r_debug` out of ld.so,
 * copies the caller-provided struct into a local scratch copy, and feeds the scratch copy into
 * the map-walker. On success it propagates the filled-in handles (and libc import table) back to
 * the caller so later stages never have to read `r_debug` again.
 */
#include "xzre_types.h"


bool process_shared_libraries(undefined8 *param_1)

{
  int iVar1;
  long lVar2;
  int *piVar3;
  bool bVar4;
  Elf64_Sym *r_debug_sym;
  uchar *debug_block;
  undefined8 tmp_state;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  lVar2 = elf_symbol_get(*(undefined8 *)(param_1[1] + 8),0x5b0,0x8c0);
  bVar4 = FALSE;
  if (lVar2 != 0) {
    debug_block = (uchar *)param_1[1];
    piVar3 = (int *)(*(long *)(lVar2 + 8) + **(long **)(debug_block + 8));
    bVar4 = FALSE;
    if (0 < *piVar3) {
      r_debug_sym = (Elf64_Sym *)*param_1;
      tmp_state = param_1[2];
      local_28 = param_1[3];
      local_20 = param_1[4];
      local_18 = param_1[5];
      local_10 = param_1[6];
      iVar1 = process_shared_libraries_map(*(undefined8 *)(piVar3 + 2),&r_debug_sym);
      bVar4 = iVar1 != 0;
    }
  }
  return bVar4;
}

