// /home/kali/xzre-ghidra/xzregh/10ABE0_secret_data_append_items.c
// Function: secret_data_append_items @ 0x10ABE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_items(secret_data_item_t * items, u64 items_count, secret_data_appender_fn appender)


/*
 * AutoDoc: Batch driver for arrays of secret_data_item_t. It assigns sequential indexes to entries that have not been initialised yet,
 * calls the provided appender for each descriptor (passing the 1-based ordinal and the recorded code pointer), and stops at the
 * first failure so callers know whether the entire batch completed.
 */

#include "xzre_types.h"

BOOL secret_data_append_items
               (secret_data_item_t *items,u64 items_count,secret_data_appender_fn appender)

{
  BOOL BVar1;
  secret_data_item_t *psVar2;
  u32 uVar3;
  uint index;
  ulong uVar4;
  
  uVar3 = 0;
  uVar4 = 0;
  while( TRUE ) {
    while( TRUE ) {
      if (items_count <= uVar4) {
        return TRUE;
      }
      index = (int)uVar4 + 1;
      psVar2 = items + uVar4;
      uVar4 = (ulong)index;
      if (psVar2->index != 0) break;
      psVar2->index = uVar3;
    }
    BVar1 = (*appender)((secret_data_shift_cursor_t)(psVar2->shift_cursor).index,
                        psVar2->operation_index,psVar2->shift_count,index,psVar2->code);
    if (BVar1 == FALSE) break;
    uVar3 = uVar3 + 1;
  }
  return FALSE;
}

