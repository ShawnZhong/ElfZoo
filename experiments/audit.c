/* LD_AUDIT library: dump every relocation slot the loader wrote, as JSONL.
 *
 * Why preinit + walk-the-relocs instead of la_symbind64?
 *
 *   glibc only calls la_symbind64 for R_*_JUMP_SLOT relocations
 *   (elf/do-rel.h:151-160). R_*_GLOB_DAT, R_*_COPY, R_*_64, etc. are bound
 *   silently. Worst case: musl-built BIND_NOW binaries produce almost no
 *   JUMP_SLOTs (only ~6 in libc.musl), so la_symbind64 would see ~0.3% of
 *   bindings. By preinit, every reloc-bound slot already holds the value
 *   the loader chose; we read those slots out of the live process. This
 *   library therefore doesn't define la_symbind64 at all.
 *
 * Output is one JSON object per line on the stream named by
 *   AUDIT_LOG=<path>      defaults to stderr.
 *
 * Event types: "version", "objopen", "preinit", "reloc".
 *
 * Every observed value is decoded to
 *   "owner": { "dso": "<path>", "off": "0x..." }
 * by intersecting with /proc/self/maps captured at preinit time. This
 * (dso, off) form is ASLR-invariant — diff it against the static loader
 * prediction directly. The raw 8-byte word read out of the slot is also
 * emitted under "value" for forensic / live-debug correlation, but its
 * absolute address varies across runs.
 */

#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static FILE *log_fp;

#define MAX_MAPS 1024
static struct link_map *saved_maps[MAX_MAPS];
static int n_maps;

/* /proc/self/maps snapshot, captured at preinit. */
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
    return LAV_CURRENT;
}

unsigned int
la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
    emit_objopen(map, (long)lmid);
    if (n_maps < MAX_MAPS) saved_maps[n_maps++] = map;
    return 0;
}

void
la_preinit(uintptr_t *cookie)
{
    load_procmaps();
    fprintf(log_fp,
            "{\"event\":\"preinit\",\"n_objects\":%d,\"n_mappings\":%d}\n",
            n_maps, g_npm);
    for (int i = 0; i < n_maps; i++) dump_relocs(saved_maps[i]);
    fflush(log_fp);
}
