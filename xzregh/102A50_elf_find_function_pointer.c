// /home/kali/xzre-ghidra/xzregh/102A50_elf_find_function_pointer.c
// Function: elf_find_function_pointer @ 0x102A50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_find_function_pointer(StringXrefId xref_id, void * * pOutCodeStart, void * * pOutCodeEnd, void * * pOutFptrAddr, elf_info_t * elf_info, string_references_t * xrefs, global_context_t * ctx)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief this function searches for a function pointer, pointing to a function
 *   designated by the given @p xref_id
 *
 *   @param xref_id the index to use to retrieve the function from @p xrefs
 *   @param pOutCodeStart output variable that will receive the function start address
 *   @param pOutCodeEnd output variable that will receive the function end address
 *   @param pOutFptrAddr output variable that will receive the address of the function pointer
 *   @param elf_info sshd elf context
 *   @param xrefs array of resolved functions, filled by @ref elf_find_string_references
 *   @param ctx the global context. used to retrieve the 'uses_endbr64' field
 *   @return BOOL TRUE if the function pointer was found, FALSE otherwise
 */

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

