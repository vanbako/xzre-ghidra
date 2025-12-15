// /home/kali/xzre-ghidra/xzregh/107170_contains_null_pointers.c
// Function: contains_null_pointers @ 0x107170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall contains_null_pointers(void * * pointers, uint num_pointers)


/*
 * AutoDoc: Linear probe used before invoking crypto helpers. It walks an array of pointers until it reaches `num_pointers` entries or
 * finds a NULL slot; the helper returns TRUE the moment it spots a NULL so callers can abort when any import failed to resolve.
 */
#include "xzre_types.h"

BOOL contains_null_pointers(void **pointers,uint num_pointers)

{
  void **candidate_slot;
  size_t slot_index;
  
  slot_index = 0;
  do {
    // AutoDoc: Stop once we have checked the requested number of slots and report FALSE when no NULL pointers were seen.
    if (num_pointers <= (uint)slot_index) {
      return FALSE;
    }
    candidate_slot = pointers + slot_index;
    slot_index = slot_index + 1;
  // AutoDoc: Return TRUE the instant a NULL slot is encountered so callers can bail out before dereferencing it.
  } while (*candidate_slot != (void *)0x0);
  return TRUE;
}

