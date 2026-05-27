/* LD_AUDIT library: dump every relocation slot the loader wrote, as JSONL.
 *
 * Hook choice: la_activity(LA_ACT_CONSISTENT), not la_preinit.
 *
 *   la_activity(LA_ACT_CONSISTENT) is fired by rtld itself from
 *   _dl_audit_activity_nsid after the initial load+reloc batch is done
 *   but before control transfers to the executable's _start. la_preinit,
 *   in contrast, is fired from glibc's _dl_init which is in turn called
 *   from glibc's __libc_start_main inside libc.so.6 — so it only fires
 *   when the executable was linked against glibc's libc.
 *
 *   Using la_activity means the oracle ALSO works for cross-loaded
 *   non-glibc binaries (e.g. musl, klibc) invoked via
 *   `/lib64/ld-linux-x86-64.so.2 <binary>`: glibc rtld loads + relocates
 *   them under audit, we dump the resulting reloc'd memory, and _exit(0)
 *   before the foreign libc's _start ever runs. That avoids the SIGSEGV
 *   that musl's __libc_start_main otherwise hits when handed a glibc-set
 *   up stack/TLS.
 *
 * Why walk the reloc tables ourselves instead of la_symbind64?
 *
 *   glibc only calls la_symbind64 for R_*_JUMP_SLOT relocations
 *   (elf/do-rel.h:151-160). R_*_GLOB_DAT, R_*_COPY, R_*_64, R_*_RELATIVE,
 *   R_*_IRELATIVE, R_*_RELR (when present), and the TLS family are all
 *   bound silently. Worst case: musl-built BIND_NOW binaries produce
 *   almost no JUMP_SLOTs (~6 in libc.musl), so la_symbind64 would see
 *   ~0.3% of bindings. By LA_ACT_CONSISTENT, every reloc-bound slot
 *   already holds the value the loader chose; we read those slots out of
 *   the live process. This library therefore doesn't define la_symbind64
 *   at all.
 *
 * Output is one JSON object per line on the stream named by
 *   AUDIT_LOG=<path>      defaults to stderr.
 *
 * Event types: "version", "auxv", "objopen", "search", "r_debug",
 *              "consistent", "serinfo", "reloc".
 *
 *   "version"    handshake; emitted from la_version.
 *   "auxv"       /proc/self/auxv (AT_PHDR/PHENT/PHNUM, AT_BASE, AT_ENTRY,
 *                AT_HWCAP/HWCAP2, AT_PLATFORM, AT_EXECFN, AT_SECURE,
 *                AT_RANDOM 16-byte canary seed, ...) — the loader's INPUT.
 *   "objopen"    one per DSO at first mapping; carries lmid and load base.
 *   "search"     one per probe glibc makes when resolving a SONAME (every
 *                directory tried, with LA_SER_* origin classification).
 *   "r_debug"    snapshot of the official rtld<->debugger struct
 *                (r_version, r_state, r_brk, r_ldbase) at CONSISTENT.
 *   "consistent" marker that the post-load+reloc batch is complete.
 *   "serinfo"    per-DSO RTLD_DI_SERINFO: the search path glibc would use
 *                for THIS DSO's dependents (static prediction; pairs with
 *                "search" runtime observation).
 *   "reloc"      one per slot the loader wrote; see below.
 *
 * Every observed value is decoded to
 *   "owner": { "dso": "<path>", "off": "0x..." }
 * by intersecting with /proc/self/maps captured at LA_ACT_CONSISTENT
 * time. This (dso, off) form is ASLR-invariant — diff it against the
 * static loader prediction directly. The raw 8-byte word read out of the
 * slot is also emitted under "value" for forensic / live-debug
 * correlation, but its absolute address varies across runs.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

static FILE *log_fp;

#define MAX_MAPS 1024
static struct link_map *saved_maps[MAX_MAPS];
static int n_maps;

/* /proc/self/maps snapshot, captured at LA_ACT_CONSISTENT. */
#define MAX_PROCMAPS 4096
#define PATH_POOL_SZ (1 << 20)
struct procmap { uint64_t start, end; const char *path; };
static struct procmap g_pm[MAX_PROCMAPS];
static int g_npm;
static char path_pool[PATH_POOL_SZ];
static size_t path_pool_used;

static const char *
intern_path(const char *s, size_t n)
{
    if (path_pool_used + n + 1 > PATH_POOL_SZ) return "";
    char *p = path_pool + path_pool_used;
    memcpy(p, s, n); p[n] = 0;
    path_pool_used += n + 1;
    return p;
}

static void
load_procmaps(void)
{
    g_npm = 0;
    path_pool_used = 0;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char *line = NULL; size_t cap = 0; ssize_t len;
    while ((len = getline(&line, &cap, f)) != -1 && g_npm < MAX_PROCMAPS) {
        /* format: START-END PERMS OFFSET DEV INODE PATH */
        uint64_t s, e;
        int pos = 0;
        if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %n", &s, &e, &pos) < 2)
            continue;
        const char *path = "";
        if (pos > 0 && (size_t)pos < (size_t)len) {
            char *p = line + pos;
            while (*p == ' ' || *p == '\t') p++;
            char *end = p;
            while (*end && *end != '\n') end++;
            if (end > p) path = intern_path(p, end - p);
        }
        g_pm[g_npm].start = s;
        g_pm[g_npm].end   = e;
        g_pm[g_npm].path  = path;
        g_npm++;
    }
    free(line);
    fclose(f);

    /* Fold anonymous mappings (path="") into the immediately-preceding
     * path-backed mapping if they are contiguous. This catches BSS extensions
     * (e.g. libc.so.6's _res / __environ live in an anon page right after
     * libc's last rw-p file mapping). Stops at the first non-contiguous gap
     * so we don't accidentally absorb unrelated regions. */
    for (int i = 1; i < g_npm; i++) {
        if (!g_pm[i].path[0] && g_pm[i - 1].path[0]
            && g_pm[i].start == g_pm[i - 1].end) {
            g_pm[i].path = g_pm[i - 1].path;
        }
    }
}

/* Find the mapping containing addr. Returns the path and sets *out_off to
 * (addr - DSO load base). The load base = lowest mapping with the same
 * interned path pointer. */
static const char *
owner_of(uint64_t addr, uint64_t *out_off)
{
    int hit = -1;
    for (int i = 0; i < g_npm; i++) {
        if (addr >= g_pm[i].start && addr < g_pm[i].end) { hit = i; break; }
    }
    if (hit < 0) return NULL;
    const char *path = g_pm[hit].path;
    if (!path || !*path) return NULL;
    uint64_t base = g_pm[hit].start;
    for (int i = 0; i < g_npm; i++) {
        if (g_pm[i].path == path && g_pm[i].start < base) base = g_pm[i].start;
    }
    *out_off = addr - base;
    return path;
}

static const char *
reloc_type_name(unsigned long t)
{
    switch (t) {
    case R_X86_64_NONE:      return "NONE";
    case R_X86_64_64:        return "64";
    case R_X86_64_PC32:      return "PC32";
    case R_X86_64_GOT32:     return "GOT32";
    case R_X86_64_PLT32:     return "PLT32";
    case R_X86_64_COPY:      return "COPY";
    case R_X86_64_GLOB_DAT:  return "GLOB_DAT";
    case R_X86_64_JUMP_SLOT: return "JUMP_SLOT";
    case R_X86_64_RELATIVE:  return "RELATIVE";
    case R_X86_64_GOTPCREL:  return "GOTPCREL";
    case R_X86_64_32:        return "32";
    case R_X86_64_32S:       return "32S";
    case R_X86_64_16:        return "16";
    case R_X86_64_PC16:      return "PC16";
    case R_X86_64_8:         return "8";
    case R_X86_64_PC8:       return "PC8";
    case R_X86_64_DTPMOD64:  return "DTPMOD64";
    case R_X86_64_DTPOFF64:  return "DTPOFF64";
    case R_X86_64_TPOFF64:   return "TPOFF64";
    case R_X86_64_TLSGD:     return "TLSGD";
    case R_X86_64_TLSLD:     return "TLSLD";
    case R_X86_64_DTPOFF32:  return "DTPOFF32";
    case R_X86_64_GOTTPOFF:  return "GOTTPOFF";
    case R_X86_64_TPOFF32:   return "TPOFF32";
    case R_X86_64_PC64:      return "PC64";
    case R_X86_64_GOTOFF64:  return "GOTOFF64";
    case R_X86_64_GOTPC32:   return "GOTPC32";
    case R_X86_64_IRELATIVE: return "IRELATIVE";
    case R_X86_64_TLSDESC:   return "TLSDESC";
    default:                 return "UNKNOWN";
    }
}

/* --- JSON helpers --------------------------------------------------------- */
static void
jstr(FILE *fp, const char *s)
{
    fputc('"', fp);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", fp); break;
        case '\\': fputs("\\\\", fp); break;
        case '\n': fputs("\\n",  fp); break;
        case '\r': fputs("\\r",  fp); break;
        case '\t': fputs("\\t",  fp); break;
        default:
            if (c < 0x20) fprintf(fp, "\\u%04x", c);
            else          fputc(c, fp);
        }
    }
    fputc('"', fp);
}

/* Emit ",\"owner\":<value>" decoding addr to (dso, off), or null. */
static void
emit_owner(FILE *fp, uint64_t addr)
{
    uint64_t off = 0;
    const char *path = owner_of(addr, &off);
    fputs(",\"owner\":", fp);
    if (path) {
        fputs("{\"dso\":", fp); jstr(fp, path);
        fprintf(fp, ",\"off\":\"0x%lx\"}", (unsigned long)off);
    } else {
        fputs("null", fp);
    }
}

/* --- auxv / r_debug / objsearch / serinfo -------------------------------- */

/* /proc/self/auxv: the kernel-supplied input vector. This is the rtld's
 * *input*; without it the loader's behaviour is underdetermined. Captured
 * once at la_version time, before glibc touches anything. */
static const char *
auxv_type_name(uint64_t t)
{
    switch (t) {
    case AT_NULL:           return "AT_NULL";
    case AT_IGNORE:         return "AT_IGNORE";
    case AT_EXECFD:         return "AT_EXECFD";
    case AT_PHDR:           return "AT_PHDR";
    case AT_PHENT:          return "AT_PHENT";
    case AT_PHNUM:          return "AT_PHNUM";
    case AT_PAGESZ:         return "AT_PAGESZ";
    case AT_BASE:           return "AT_BASE";
    case AT_FLAGS:          return "AT_FLAGS";
    case AT_ENTRY:          return "AT_ENTRY";
    case AT_NOTELF:         return "AT_NOTELF";
    case AT_UID:            return "AT_UID";
    case AT_EUID:           return "AT_EUID";
    case AT_GID:            return "AT_GID";
    case AT_EGID:           return "AT_EGID";
    case AT_PLATFORM:       return "AT_PLATFORM";
    case AT_HWCAP:          return "AT_HWCAP";
    case AT_CLKTCK:         return "AT_CLKTCK";
    case AT_SECURE:         return "AT_SECURE";
    case AT_BASE_PLATFORM:  return "AT_BASE_PLATFORM";
    case AT_RANDOM:         return "AT_RANDOM";
    case AT_HWCAP2:         return "AT_HWCAP2";
    case AT_RSEQ_FEATURE_SIZE: return "AT_RSEQ_FEATURE_SIZE";
    case AT_RSEQ_ALIGN:     return "AT_RSEQ_ALIGN";
    case AT_EXECFN:         return "AT_EXECFN";
#ifdef AT_SYSINFO
    case AT_SYSINFO:        return "AT_SYSINFO";
#endif
    case AT_SYSINFO_EHDR:   return "AT_SYSINFO_EHDR";
    case AT_MINSIGSTKSZ:    return "AT_MINSIGSTKSZ";
    default:                return "AT_UNKNOWN";
    }
}

static void
emit_auxv(void)
{
    FILE *f = fopen("/proc/self/auxv", "rb");
    if (!f) return;
    fputs("{\"event\":\"auxv\",\"entries\":[", log_fp);
    int n = 0;
    Elf64_auxv_t e;
    while (fread(&e, sizeof e, 1, f) == 1) {
        if (e.a_type == AT_NULL) break;
        if (n++) fputc(',', log_fp);
        fputs("{\"type\":", log_fp);
        jstr(log_fp, auxv_type_name(e.a_type));
        fprintf(log_fp, ",\"raw\":%lu", (unsigned long)e.a_type);
        if (e.a_type == AT_PLATFORM || e.a_type == AT_BASE_PLATFORM
            || e.a_type == AT_EXECFN) {
            const char *s = (const char *)(uintptr_t)e.a_un.a_val;
            fputs(",\"str\":", log_fp);
            if (s) jstr(log_fp, s); else fputs("null", log_fp);
        } else if (e.a_type == AT_RANDOM) {
            const unsigned char *p =
                (const unsigned char *)(uintptr_t)e.a_un.a_val;
            fputs(",\"bytes\":\"", log_fp);
            if (p) for (int i = 0; i < 16; i++) fprintf(log_fp, "%02x", p[i]);
            fputs("\"", log_fp);
        } else {
            fprintf(log_fp, ",\"value\":\"0x%lx\"",
                    (unsigned long)e.a_un.a_val);
        }
        fputc('}', log_fp);
    }
    fputs("]}\n", log_fp);
    fclose(f);
}

/* The official rtld <-> debugger contract. Captured at LA_ACT_CONSISTENT.
 *
 * Note: glibc's _dl_audit_activity_nsid fires la_activity BEFORE
 * _dl_debug_change_state flips r_state to RT_CONSISTENT, so at our
 * CONSISTENT hook _r_debug.r_state still reads RT_ADD. This is honest
 * reporting of glibc's audit-vs-debug ordering, not a stale read. */
static const char *
r_state_name(int s)
{
    switch (s) {
    case RT_CONSISTENT: return "RT_CONSISTENT";
    case RT_ADD:        return "RT_ADD";
    case RT_DELETE:     return "RT_DELETE";
    default:            return "RT_UNKNOWN";
    }
}

static void
emit_rdebug(void)
{
    fprintf(log_fp,
            "{\"event\":\"r_debug\",\"r_version\":%d,\"r_state\":\"%s\","
            "\"r_brk\":\"0x%lx\",\"r_ldbase\":\"0x%lx\"}\n",
            _r_debug.r_version, r_state_name(_r_debug.r_state),
            (unsigned long)_r_debug.r_brk,
            (unsigned long)_r_debug.r_ldbase);
}

/* LA_SER_* flag bits. Decoded into a `|`-joined name string in JSON; raw
 * value also emitted for forensic clarity. Default system paths come back
 * with flags=0 (glibc only tags LA_SER_RUNPATH / LIBPATH / CONFIG when
 * they apply); we represent that as "LA_SER_NONE". */
static void
serpath_flag_emit(FILE *fp, unsigned int f)
{
    fprintf(fp, "\"flag_raw\":%u,\"flag\":\"", f);
    if (f == 0) { fputs("LA_SER_NONE\"", fp); return; }
    int first = 1;
    if (f & LA_SER_ORIG)    { fputs(first?"LA_SER_ORIG":"|LA_SER_ORIG", fp); first=0; }
    if (f & LA_SER_LIBPATH) { fputs(first?"LA_SER_LIBPATH":"|LA_SER_LIBPATH", fp); first=0; }
    if (f & LA_SER_RUNPATH) { fputs(first?"LA_SER_RUNPATH":"|LA_SER_RUNPATH", fp); first=0; }
    if (f & LA_SER_CONFIG)  { fputs(first?"LA_SER_CONFIG":"|LA_SER_CONFIG", fp); first=0; }
    if (f & LA_SER_DEFAULT) { fputs(first?"LA_SER_DEFAULT":"|LA_SER_DEFAULT", fp); first=0; }
    if (f & LA_SER_SECURE)  { fputs(first?"LA_SER_SECURE":"|LA_SER_SECURE", fp); first=0; }
    unsigned int known = LA_SER_ORIG|LA_SER_LIBPATH|LA_SER_RUNPATH
                        |LA_SER_CONFIG|LA_SER_DEFAULT|LA_SER_SECURE;
    if (f & ~known)
        fprintf(fp, first?"LA_SER_OTHER":"|LA_SER_OTHER");
    fputc('"', fp);
}

/* Per-DSO search-path prediction via dlinfo(RTLD_DI_SERINFO). Pairs with
 * the la_objsearch runtime trace: serinfo says "where I would look",
 * objsearch says "where I actually looked, in order, and which probe won". */
static void
emit_serinfo(struct link_map *map)
{
    void *handle = (void *)map;
    Dl_serinfo size_only;
    if (dlinfo(handle, RTLD_DI_SERINFOSIZE, &size_only) != 0) return;
    if (size_only.dls_size == 0 || size_only.dls_cnt == 0) return;
    Dl_serinfo *si = malloc(size_only.dls_size);
    if (!si) return;
    si->dls_size = size_only.dls_size;
    si->dls_cnt  = size_only.dls_cnt;
    if (dlinfo(handle, RTLD_DI_SERINFOSIZE, si) != 0
        || dlinfo(handle, RTLD_DI_SERINFO, si) != 0) {
        free(si);
        return;
    }
    const char *n = (map->l_name && *map->l_name) ? map->l_name : "<main>";
    fputs("{\"event\":\"serinfo\",\"dso\":", log_fp);
    jstr(log_fp, n);
    fputs(",\"paths\":[", log_fp);
    for (unsigned int i = 0; i < si->dls_cnt; i++) {
        if (i) fputc(',', log_fp);
        fputs("{\"dir\":", log_fp);
        jstr(log_fp, si->dls_serpath[i].dls_name ?
                     si->dls_serpath[i].dls_name : "");
        fputc(',', log_fp);
        serpath_flag_emit(log_fp, si->dls_serpath[i].dls_flags);
        fputc('}', log_fp);
    }
    fputs("]}\n", log_fp);
    free(si);
}

/* --- emission ------------------------------------------------------------- */
static void
emit_objopen(struct link_map *map, long lmid)
{
    const char *n = (map->l_name && *map->l_name) ? map->l_name : "<main>";
    fputs("{\"event\":\"objopen\",\"name\":", log_fp);
    jstr(log_fp, n);
    fprintf(log_fp, ",\"lmid\":%ld,\"base\":\"0x%lx\"}\n",
            lmid, (unsigned long)map->l_addr);
}

static void
emit_reloc(const struct link_map *l, const char *dso_path, const char *src,
           const ElfW(Rela) *r, const ElfW(Sym) *sym_entry, const char *name)
{
    unsigned long rtype = ELF64_R_TYPE(r->r_info);
    unsigned char *addr = (unsigned char *)(l->l_addr + r->r_offset);
    unsigned long st_value = 0, st_size = 0;
    unsigned char st_info = 0;
    if (sym_entry) {
        st_value = (unsigned long)sym_entry->st_value;
        st_size  = (unsigned long)sym_entry->st_size;
        st_info  = sym_entry->st_info;
    }

    if (rtype == R_X86_64_COPY) {
        size_t n = st_size < 32 ? st_size : 32;
        fputs("{\"event\":\"reloc\",\"dso\":", log_fp);
        jstr(log_fp, dso_path);
        fprintf(log_fp,
                ",\"src\":\"%s\",\"off\":\"0x%lx\",\"type\":\"COPY\",\"sym\":",
                src, (unsigned long)r->r_offset);
        jstr(log_fp, name);
        fprintf(log_fp, ",\"size\":%lu,\"bytes\":\"", st_size);
        for (size_t k = 0; k < n; k++) fprintf(log_fp, "%02x", addr[k]);
        fputs("\"}\n", log_fp);
        return;
    }

    uint64_t observed = 0;
    memcpy(&observed, addr, sizeof(observed));

    fputs("{\"event\":\"reloc\",\"dso\":", log_fp);
    jstr(log_fp, dso_path);
    fprintf(log_fp,
            ",\"src\":\"%s\",\"off\":\"0x%lx\",\"type\":\"%s\",\"sym\":",
            src, (unsigned long)r->r_offset, reloc_type_name(rtype));
    jstr(log_fp, name);
    fprintf(log_fp,
            ",\"st_value\":\"0x%lx\",\"st_info\":\"0x%x\","
            "\"addend\":%ld,\"value\":\"0x%lx\"",
            st_value, st_info, (long)r->r_addend, (unsigned long)observed);
    /* For relocs whose value is meant to be a code/data pointer into some
     * loaded DSO, decode owner. Skip TLS relocs (value is an offset, not an
     * address). */
    switch (rtype) {
    case R_X86_64_TPOFF64:
    case R_X86_64_DTPOFF64:
    case R_X86_64_DTPMOD64:
    case R_X86_64_TLSDESC:
        break;
    default:
        emit_owner(log_fp, observed);
    }
    fputs("}\n", log_fp);
}

static void
emit_relr(const char *dso_path, uint64_t file_off, uint64_t value)
{
    fputs("{\"event\":\"reloc\",\"dso\":", log_fp);
    jstr(log_fp, dso_path);
    fprintf(log_fp,
            ",\"src\":\"RELR\",\"off\":\"0x%lx\",\"type\":\"RELATIVE\","
            "\"value\":\"0x%lx\"",
            (unsigned long)file_off, (unsigned long)value);
    emit_owner(log_fp, value);
    fputs("}\n", log_fp);
}

/* --- dynamic-section scan ------------------------------------------------- */
/* glibc's elf_get_dynamic_info (elf/get-dynamic-info.h) pre-adjusts d_ptr by
 * adding l_addr for DT_RELA, DT_REL, DT_RELR, DT_JMPREL, DT_STRTAB, DT_SYMTAB,
 * DT_HASH, DT_PLTGOT, DT_VERSYM, DT_GNU_HASH. The mutation happens in place on
 * l->l_ld entries, so reading l_ld's d_ptr for those tags gives runtime VMAs.
 * (See elf/get-dynamic-info.h:65-110 in glibc 2.39.) */
struct dynview {
    ElfW(Addr) rela;     ElfW(Xword) relasz;     ElfW(Xword) relaent;
    ElfW(Addr) jmprel;   ElfW(Xword) pltrelsz;   ElfW(Xword) pltrel;
    ElfW(Addr) relr;     ElfW(Xword) relrsz;     ElfW(Xword) relrent;
    ElfW(Addr) symtab;
    ElfW(Addr) strtab;
};

static void
scan_dynamic(const ElfW(Dyn) *dyn, struct dynview *out)
{
    memset(out, 0, sizeof(*out));
    if (!dyn) return;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
        case DT_RELA:     out->rela     = dyn->d_un.d_ptr; break;
        case DT_RELASZ:   out->relasz   = dyn->d_un.d_val; break;
        case DT_RELAENT:  out->relaent  = dyn->d_un.d_val; break;
        case DT_JMPREL:   out->jmprel   = dyn->d_un.d_ptr; break;
        case DT_PLTRELSZ: out->pltrelsz = dyn->d_un.d_val; break;
        case DT_PLTREL:   out->pltrel   = dyn->d_un.d_val; break;
        case DT_RELR:     out->relr     = dyn->d_un.d_ptr; break;
        case DT_RELRSZ:   out->relrsz   = dyn->d_un.d_val; break;
        case DT_RELRENT:  out->relrent  = dyn->d_un.d_val; break;
        case DT_SYMTAB:   out->symtab   = dyn->d_un.d_ptr; break;
        case DT_STRTAB:   out->strtab   = dyn->d_un.d_ptr; break;
        }
    }
}

static void
walk_rela(const struct link_map *l, const char *dso_path, const char *src,
          const ElfW(Rela) *table, size_t count,
          const ElfW(Sym) *symtab, const char *strtab)
{
    for (size_t i = 0; i < count; i++) {
        const ElfW(Rela) *r = &table[i];
        unsigned long rsym = ELF64_R_SYM(r->r_info);
        const ElfW(Sym) *sym = (rsym && symtab) ? &symtab[rsym] : NULL;
        const char *name = (sym && strtab) ? strtab + sym->st_name : "";
        emit_reloc(l, dso_path, src, r, sym, name);
    }
}

/* RELR encoding (gabi DT_RELR): even-valued entries are the start address
 * (file VMA, adjusted by l_addr at use-time); odd-valued entries are bitmaps
 * where bit 0 is the marker and bits 1..63 describe the next 63 slots after
 * the last address, each covering one word. */
static void
walk_relr(const struct link_map *l, const char *dso_path,
          const ElfW(Relr) *table, size_t count)
{
    ElfW(Addr) where = 0;
    ElfW(Addr) where_off = 0;     /* file VMA of `where` */
    for (size_t i = 0; i < count; i++) {
        ElfW(Relr) e = table[i];
        if ((e & 1) == 0) {
            where_off = e;
            where     = l->l_addr + e;
            uint64_t v = 0;
            memcpy(&v, (void *)where, sizeof(v));
            emit_relr(dso_path, where_off, v);
            where     += sizeof(ElfW(Addr));
            where_off += sizeof(ElfW(Addr));
        } else {
            for (int bit = 1; bit < 64; bit++) {
                if (e & (1ULL << bit)) {
                    ElfW(Addr) a   = where     + (bit - 1) * sizeof(ElfW(Addr));
                    ElfW(Addr) aof = where_off + (bit - 1) * sizeof(ElfW(Addr));
                    uint64_t v = 0;
                    memcpy(&v, (void *)a, sizeof(v));
                    emit_relr(dso_path, aof, v);
                }
            }
            where     += 63 * sizeof(ElfW(Addr));
            where_off += 63 * sizeof(ElfW(Addr));
        }
    }
}

static void
dump_relocs(const struct link_map *l)
{
    const char *n = (l->l_name && *l->l_name) ? l->l_name : "<main>";

    struct dynview d;
    scan_dynamic(l->l_ld, &d);

    const ElfW(Sym) *symtab = (const ElfW(Sym) *)d.symtab;
    const char *strtab = (const char *)d.strtab;

    if (d.rela && d.relasz) {
        size_t ent = d.relaent ? d.relaent : sizeof(ElfW(Rela));
        walk_rela(l, n, "RELA", (const ElfW(Rela) *)d.rela,
                  d.relasz / ent, symtab, strtab);
    }

    if (d.jmprel && d.pltrelsz) {
        if (d.pltrel == DT_RELA || d.pltrel == 0) {
            walk_rela(l, n, "JMPREL", (const ElfW(Rela) *)d.jmprel,
                      d.pltrelsz / sizeof(ElfW(Rela)), symtab, strtab);
        }
    }

    if (d.relr && d.relrsz) {
        size_t ent = d.relrent ? d.relrent : sizeof(ElfW(Relr));
        walk_relr(l, n, (const ElfW(Relr) *)d.relr, d.relrsz / ent);
    }
}

/* --- audit ABI entry points ---------------------------------------------- */
unsigned int
la_version(unsigned int v)
{
    const char *p = getenv("AUDIT_LOG");
    log_fp = (p && *p) ? fopen(p, "w") : stderr;
    setvbuf(log_fp, NULL, _IOLBF, 0);
    fprintf(log_fp,
            "{\"event\":\"version\",\"requested\":%u,\"got\":%u}\n",
            v, LAV_CURRENT);
    emit_auxv();
    return LAV_CURRENT;
}

unsigned int
la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
    emit_objopen(map, (long)lmid);
    if (n_maps < MAX_MAPS) saved_maps[n_maps++] = map;
    return 0;
}

/* Fires once per probe glibc makes when resolving a SONAME (l-strings in
 * DT_NEEDED, dlopen names, etc). `flag` classifies the probe's origin
 * (LA_SER_ORIG = as-requested, LA_SER_LIBPATH = LD_LIBRARY_PATH,
 * LA_SER_RUNPATH = DT_RPATH/RUNPATH, LA_SER_CONFIG = /etc/ld.so.cache,
 * LA_SER_DEFAULT = built-in default). Returning `name` unchanged passes
 * the probe through to the loader unmodified. */
char *
la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
{
    fputs("{\"event\":\"search\",\"name\":", log_fp);
    jstr(log_fp, name ? name : "");
    fputc(',', log_fp);
    serpath_flag_emit(log_fp, flag);
    fputs("}\n", log_fp);
    return (char *)name;
}

void
la_activity(uintptr_t *cookie, unsigned int action)
{
    /* LA_ACT_ADD (1)        — rtld is about to add objects to the namespace.
     * LA_ACT_CONSISTENT (0) — the namespace is now consistent: all loads and
     *                         all relocations are done. We dump here and
     *                         _exit(0) before any user code (incl. foreign
     *                         libc's __libc_start_main) runs.
     * LA_ACT_DELETE (2)     — never reached because we _exit first. */
    static int saw_add = 0;
    if (action == LA_ACT_ADD) { saw_add = 1; return; }
    if (action != LA_ACT_CONSISTENT || !saw_add) return;

    load_procmaps();
    emit_rdebug();
    fprintf(log_fp,
            "{\"event\":\"consistent\",\"n_objects\":%d,\"n_mappings\":%d}\n",
            n_maps, g_npm);
    for (int i = 0; i < n_maps; i++) emit_serinfo(saved_maps[i]);
    for (int i = 0; i < n_maps; i++) dump_relocs(saved_maps[i]);
    fflush(log_fp);
    _exit(0);
}
