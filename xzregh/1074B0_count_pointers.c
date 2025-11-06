// /home/kali/xzre-ghidra/xzregh/1074B0_count_pointers.c
// Function: count_pointers @ 0x1074B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall count_pointers(void * * ptrs, u64 * count_out, libc_imports_t * funcs)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief count the number of non-NULL pointers in the `malloc`'d memory block @p ptrs
 *
 *   @param ptrs pointer to a `malloc`'d memory block
 *   @param count_out will be filled with the number of non-NULL pointers
 *   @param funcs used for `malloc_usable_size`
 *   @return BOOL TRUE if the operation succeeded, FALSE otherwise
 *
 * Upstream implementation excerpt (xzre/xzre_code/count_pointers.c):
 *     BOOL count_pointers(
 *     	void **ptrs,
 *     	u64 *count_out, 
 *     	libc_imports_t *funcs
 *     ){
 *     	if(!ptrs) return FALSE;
 *     	if(!funcs) return FALSE;
 *     	if(!funcs->malloc_usable_size) return FALSE;
 *     	size_t blockSize = funcs->malloc_usable_size(ptrs);
 *     	if(blockSize - 8 > 127) return FALSE;
 *     	size_t nWords = blockSize >> 3;
 *     	
 *     	size_t i;
 *     	for(i=0; i < nWords && ptrs[i]; ++i);
 *     	*count_out = i;
 *     	return TRUE;
 *     }
 */

BOOL count_pointers(void **ptrs,u64 *count_out,libc_imports_t *funcs)

{
  BOOL BVar1;
  size_t nWords;
  size_t i;
  size_t blockSize;
  
  if (((ptrs == (void **)0x0) || (funcs == (libc_imports_t *)0x0)) ||
     (funcs->malloc_usable_size == (_func_17 *)0x0)) {
    return 0;
  }
  nWords = (*funcs->malloc_usable_size)(ptrs);
  if (nWords - 8 < 0x80) {
    i = 0;
    do {
      blockSize = i;
      if (ptrs[i] == (void *)0x0) break;
      i = (size_t)((int)i + 1);
      blockSize = nWords >> 3;
    } while (i < nWords >> 3);
    *count_out = blockSize;
    BVar1 = 1;
  }
  else {
    BVar1 = 0;
  }
  return BVar1;
}

