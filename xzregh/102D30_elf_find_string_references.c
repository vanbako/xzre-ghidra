// /home/kali/xzre-ghidra/xzregh/102D30_elf_find_string_references.c
// Function: elf_find_string_references @ 0x102D30
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_find_string_references(elf_info_t * elf_info, string_references_t * refs)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief parses the ELF rodata section, looking for strings and the instructions that reference them
 *
 *   @param elf_info the executable to find strings in
 *   @param refs structure that will be populated with the results
 *   @return BOOL
 */

BOOL elf_find_string_references(elf_info_t *elf_info,string_references_t *refs)

{
  void **ppvVar1;
  dasm_ctx_t *pdVar2;
  Elf64_Rela *pEVar3;
  EncodedStringId EVar4;
  BOOL BVar5;
  dasm_ctx_t *code_start;
  char *pcVar6;
  u8 *puVar7;
  void **ppvVar8;
  dasm_ctx_t *pdVar9;
  Elf64_Rela *pEVar10;
  dasm_ctx_t *ctx;
  long lVar11;
  string_item_t *psVar12;
  dasm_ctx_t *code_end;
  dasm_ctx_t **ppdVar13;
  void **ppvVar14;
  dasm_ctx_t *pdVar15;
  EncodedStringId local_94;
  u64 local_90 [2];
  dasm_ctx_t *local_80;
  u64 local_78;
  undefined1 local_65;
  undefined4 local_64;
  int local_58;
  long local_50;
  u64 local_48;
  
  EVar4 = STR_xcalloc_zero_size;
  psVar12 = refs->entries;
  do {
    ((string_item_t *)&psVar12->string_id)->string_id = EVar4;
    EVar4 = EVar4 + 8;
    psVar12 = psVar12 + 1;
  } while (EVar4 != 0xe8);
  ppdVar13 = &local_80;
  for (lVar11 = 0x16; lVar11 != 0; lVar11 = lVar11 + -1) {
    *(undefined4 *)ppdVar13 = 0;
    ppdVar13 = (dasm_ctx_t **)((long)ppdVar13 + 4);
  }
  local_90[0] = 0;
  local_90[1] = 0;
  code_start = (dasm_ctx_t *)elf_get_code_segment(elf_info,local_90);
  ctx = (dasm_ctx_t *)&local_80;
  if ((code_start != (dasm_ctx_t *)0x0) && (0x10 < local_90[0])) {
    code_end = (dasm_ctx_t *)(code_start->_unknown810 + (local_90[0] - 0x28));
    pcVar6 = (char *)0x0;
    while( true ) {
      local_94 = 0;
      pcVar6 = elf_find_string(elf_info,&local_94,pcVar6);
      if (pcVar6 == (char *)0x0) break;
      lVar11 = 0;
      do {
        if (((*(long *)(refs->entries[0]._unknown1718 + lVar11 + 0x14) == 0) &&
            (*(EncodedStringId *)(refs->entries[0]._unknown1718 + lVar11 + -4) == local_94)) &&
           (puVar7 = find_string_reference((u8 *)code_start,(u8 *)code_end,pcVar6),
           puVar7 != (u8 *)0x0)) {
          *(u8 **)(refs->entries[0]._unknown1718 + lVar11 + 0x14) = puVar7;
        }
        lVar11 = lVar11 + 0x20;
      } while (lVar11 != 0x360);
      pcVar6 = pcVar6 + 1;
    }
    ppvVar14 = &refs->entries[0].func_start;
    ppvVar1 = &refs[1].entries[0].func_start;
    ppvVar8 = ppvVar14;
    do {
      pdVar15 = (dasm_ctx_t *)ppvVar8[2];
      if (pdVar15 != (dasm_ctx_t *)0x0) {
        if (code_start <= pdVar15) {
          if ((dasm_ctx_t *)*ppvVar8 < code_start) {
            *ppvVar8 = code_start;
          }
          if (code_start != pdVar15) goto LAB_00102e58;
        }
        if (code_start <= (dasm_ctx_t *)((long)ppvVar8[1] - 1U)) {
          ppvVar8[1] = code_start;
        }
      }
LAB_00102e58:
      ppvVar8 = ppvVar8 + 4;
      pdVar15 = code_start;
    } while (ppvVar8 != ppvVar1);
LAB_00102e64:
    if (pdVar15 < code_end) {
      BVar5 = x86_dasm(ctx,(u8 *)pdVar15,(u8 *)code_end);
      pdVar15 = (dasm_ctx_t *)((long)&pdVar15->instruction + 1);
      if (BVar5 != 0) {
        pdVar15 = (dasm_ctx_t *)((long)local_80->_unknown810 + (local_78 - 0x28));
        if (local_58 == 0x168) {
          if (local_48 == 0) goto LAB_00102e64;
          pdVar9 = (dasm_ctx_t *)((long)local_80->_unknown810 + local_48 + local_78 + -0x28);
LAB_00102ee5:
          if (pdVar9 == (dasm_ctx_t *)0x0) goto LAB_00102e64;
        }
        else {
          pdVar9 = local_80;
          if (local_58 == 0xa5fe) goto LAB_00102ee5;
          if (((local_58 != 0x10d) || ((local_65 & 0x48) != 0x48)) ||
             ((local_64 & 0xff00ff00) != 0x5000000)) goto LAB_00102e64;
          pdVar9 = (dasm_ctx_t *)(pdVar15->_unknown810 + local_50 + -0x28);
        }
        if ((code_start <= pdVar9) && (ppvVar8 = ppvVar14, pdVar9 <= code_end)) {
          do {
            pdVar2 = (dasm_ctx_t *)ppvVar8[2];
            if (pdVar2 != (dasm_ctx_t *)0x0) {
              if (pdVar9 <= pdVar2) {
                if ((dasm_ctx_t *)*ppvVar8 < pdVar9) {
                  *ppvVar8 = pdVar9;
                }
                if (pdVar2 != pdVar9) goto LAB_00102f31;
              }
              if (pdVar9 <= (dasm_ctx_t *)((long)ppvVar8[1] - 1U)) {
                ppvVar8[1] = pdVar9;
              }
            }
LAB_00102f31:
            ppvVar8 = ppvVar8 + 4;
          } while (ppvVar8 != ppvVar1);
        }
      }
      goto LAB_00102e64;
    }
    while (pEVar10 = elf_find_rela_reloc(elf_info,0,(u64)code_start), ppvVar8 = ppvVar14,
          pEVar10 != (Elf64_Rela *)0x0) {
      do {
        pEVar3 = (Elf64_Rela *)ppvVar8[2];
        if (pEVar3 != (Elf64_Rela *)0x0) {
          if (pEVar10 <= pEVar3) {
            if ((Elf64_Rela *)*ppvVar8 < pEVar10) {
              *ppvVar8 = pEVar10;
            }
            if (pEVar10 != pEVar3) goto LAB_00102f8e;
          }
          if (pEVar10 <= (Elf64_Rela *)((long)ppvVar8[1] - 1U)) {
            ppvVar8[1] = pEVar10;
          }
        }
LAB_00102f8e:
        ppvVar8 = ppvVar8 + 4;
      } while (ppvVar8 != ppvVar1);
    }
    do {
      ctx = (dasm_ctx_t *)ppvVar14[2];
      if (ctx != (dasm_ctx_t *)0x0) {
        if (code_end <= ctx) {
          if ((dasm_ctx_t *)*ppvVar14 < code_end) {
            *ppvVar14 = code_end;
          }
          if (ctx != code_end) goto LAB_00102fad;
        }
        ctx = (dasm_ctx_t *)((long)ppvVar14[1] + -1);
        if (code_end <= ctx) {
          ppvVar14[1] = code_end;
        }
      }
LAB_00102fad:
      ppvVar14 = ppvVar14 + 4;
    } while (ppvVar14 != ppvVar1);
  }
  return (BOOL)ctx;
}

