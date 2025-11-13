// /home/kali/xzre-ghidra/xzregh/10AB70_secret_data_append_item.c
// Function: secret_data_append_item @ 0x10AB70
// Calling convention: unknown
// Prototype: undefined secret_data_append_item(void)


/*
 * AutoDoc: Calls the singleton appender only when a supplied index is non-zero, making it easy to gate optional fingerprint operations. The various secret-data tables use it to share common code while respecting per-item enable flags.
 */
#include "xzre_types.h"


undefined8
secret_data_append_item
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,undefined8 param_5)

{
  undefined8 uVar1;
  
  if (param_4 != 0) {
    uVar1 = secret_data_append_singleton(param_5,param_5,param_1,param_3,param_2);
    return uVar1;
  }
  return 0;
}

