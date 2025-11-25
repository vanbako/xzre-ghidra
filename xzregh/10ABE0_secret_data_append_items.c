// /home/kali/xzre-ghidra/xzregh/10ABE0_secret_data_append_items.c
// Function: secret_data_append_items @ 0x10ABE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_items(secret_data_item_t * items, u64 items_count, secret_data_appender_fn appender)


/*
 * AutoDoc: Batch driver for `secret_data_item_t` descriptors. It walks the array in order, stamping a monotonically increasing slot index
 * onto entries whose `ordinal` is still zero, and dispatches the provided appender for whichever descriptor already carries an ordinal.
 * Each callback receives a 1-based array index alongside the cursor/operation/code tuple, and any failure terminates the walk so
 * callers can bail out without partially populating the log.
 */

#include "xzre_types.h"

BOOL secret_data_append_items
               (secret_data_item_t *items,u64 items_count,secret_data_appender_fn appender)

{
  BOOL append_ok;
  secret_data_item_t *descriptor;
  u32 ordinal_cursor;
  uint index;
  ulong items_cursor;
  
  ordinal_cursor = 0;
  items_cursor = 0;
  while( TRUE ) {
    while( TRUE ) {
      // AutoDoc: Report success once we’ve scanned every descriptor without the appender signalling a failure.
      if (items_count <= items_cursor) {
        return TRUE;
      }
      // AutoDoc: Keep a 1-based ordinal for the callback; `secret_data_append_item` treats index 0 as “disabled descriptor”.
      index = (int)items_cursor + 1;
      descriptor = items + items_cursor;
      items_cursor = (ulong)index;
      // AutoDoc: Skip dormant entries by assigning the next slot number until we hit one that already has a published ordinal.
      if (descriptor->ordinal != 0) break;
      descriptor->ordinal = ordinal_cursor;
    }
    // AutoDoc: Invoke the per-descriptor appender with the recorded cursor/op-slot/bits tuple plus the array index.
    append_ok = (*appender)((secret_data_shift_cursor_t)(descriptor->bit_cursor).bit_position,
                        descriptor->operation_slot,descriptor->bits_to_shift,index,descriptor->anchor_pc);
    // AutoDoc: Abort the batch immediately so callers know the attestation set is incomplete.
    if (append_ok == FALSE) break;
    // AutoDoc: Advance the slot so the next dormant entry we encounter gets a new ordinal.
    ordinal_cursor = ordinal_cursor + 1;
  }
  return FALSE;
}

