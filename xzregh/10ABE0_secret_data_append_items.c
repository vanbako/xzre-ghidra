// /home/kali/xzre-ghidra/xzregh/10ABE0_secret_data_append_items.c
// Function: secret_data_append_items @ 0x10ABE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_items(secret_data_item_t * items, u64 items_count, appender * appender)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief appends multiple secret data items at once
 *
 *   @param items items to append
 *   @param items_count number of items to append
 *   @param appender @ref secret_data_append_item
 *   @return BOOL TRUE if all items have been appended successfully, FALSE otherwise
 */

BOOL secret_data_append_items(secret_data_item_t *items,u64 items_count,appender *appender)

{
  BOOL BVar1;
  secret_data_item_t *psVar2;
  u32 uVar3;
  uint uVar4;
  ulong uVar5;
  
  uVar3 = 0;
  uVar5 = 0;
  while( true ) {
    while( true ) {
      if (items_count <= uVar5) {
        return 1;
      }
      uVar4 = (int)uVar5 + 1;
      psVar2 = items + uVar5;
      uVar5 = (ulong)uVar4;
      if (psVar2->index != 0) break;
      psVar2->index = uVar3;
    }
    BVar1 = (*appender)((secret_data_shift_cursor_t)(psVar2->shift_cursor).index,
                        psVar2->operation_index,psVar2->shift_count,uVar4,psVar2->code);
    if (BVar1 == 0) break;
    uVar3 = uVar3 + 1;
  }
  return 0;
}

