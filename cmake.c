#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <glob.h>
#include <dirent.h> 

#ifdef _WIN32
    #include <io.h>  
    #include <windows.h>  
    #define getcwd _getcwd
    #define SHARED_NAME ".dll"
    #define LINK_RULES ""
#else
    #include <unistd.h>   
    #include <sys/stat.h> 
    #ifdef __APPLE__
        #define EXE_RULES "-Wl,-rpath,@loader_path"
        #define LINK_RULES "-Wl,-install_name,@loader_path/libpocketpy.dylib -Wl,-rpath,@loader_path" 
        #define SHARED_NAME ".dylib"
    #else
        #define LINK_RULES "-Wl,-rpath,." 
        #define EXE_RULES LINK_RULES
        #define SHARED_NAME ".so"
    #endif
#endif

#ifndef DEBUG
#define DEBUG 1
#endif

#if DEBUG
#define DPRINTF(...) do { printf("DEBUG: "); printf(__VA_ARGS__); } while(0)
#else
#define DPRINTF(...) do {} while(0)
#endif

#define MAX_LINE 1024
#define MAX_VARS 512
#define MAX_TARGETS 128
#define MAX_DEFS 64
#define MAX_LIBS 64
#define MAX_INCS 32
#define MAX_SRCS 128
#define MAX_STACK 32

// ---- Helper functions ----
static int has_suffix(const char *name, const char *ext) {
    size_t nlen = strlen(name);
    size_t elen = strlen(ext);
    return nlen >= elen && strcmp(name + nlen - elen, ext) == 0;
}
static void add_string(char ***list, int *count, const char *value) { *list = realloc(*list, (*count + 1) * sizeof(char *)); (*list)[*count] = strdup(value); (*count)++; }
void append_to_buf(char **buf, size_t *buflen, const char *path) {
    size_t need = strlen(*buf) + strlen(path) + 2;
    if (need > *buflen) {
        *buflen = need * 2;
        *buf = realloc(*buf, *buflen);
        if (!*buf) return;
    }
    strcat(*buf, path);
    strcat(*buf, " ");
}
#ifndef _WIN32
void collect_files(const char *dir, char **buf, size_t *buflen, const char *ext) {
    DIR *dp = opendir(dir);
    if (!dp) return;
    struct dirent *entry;
    while ((entry = readdir(dp))) {
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;

        char path[1024];
        snprintf(path,sizeof(path),"%s/%s",dir,entry->d_name);

        struct stat st;
        if (stat(path,&st)==0) {
            if (S_ISDIR(st.st_mode)) {
                collect_files(path, buf, buflen, ext);
            } else if (S_ISREG(st.st_mode)) {
                if (!ext || has_suffix(entry->d_name, ext)) {
                    append_to_buf(buf, buflen, path);
                }
            } else if (S_ISDIR(st.st_mode)) {
                collect_files(path, buf, buflen, ext);
            }

        }
    }
    closedir(dp);
}
#else
void collect_files(const char *dir, char **buf, size_t *buflen, const char *ext) {
    char searchPath[MAX_PATH];
    snprintf(searchPath, sizeof(searchPath), "%s\\*", dir);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(searchPath, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        const char *name = ffd.cFileName;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;

        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", dir, name);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            collect_files(path, buf, buflen, ext);
        } else {
            if (!ext || has_suffix(name, ext)) {
                append_to_buf(buf, buflen, path);
            }
        }
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
}
#endif
static void trim_token(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len && (s[len-1] == ' ' || s[len-1] == '\t' ||
                   s[len-1] == '\n' || s[len-1] == ')')) {
        s[--len] = 0;
    }
    while (*s == ' ' || *s == '\t' || *s == '\n') {
        memmove(s, s+1, strlen(s));
    }
    len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len-1] == '"') {
        s[len-1] = 0;
        memmove(s, s+1, strlen(s));
    }
}
// ---- Variable Table ----
typedef struct {
    char *key;
    char *val;
} Var;
Var vars[MAX_VARS];
int nvars = 0;
static char **global_incs = NULL;
static int nglobal_incs = 0;
// ---- Target Table ----
typedef struct {
    char name[128];
    char type[16];

    char **srcs;
    int nsrc;

    char **defs;
    int ndef;

    char **incs;
    int ninc;

    char **libs;
    int nlib;
} Target;

Target targets[MAX_TARGETS];
int ntarget = 0;

// ---- Condition Stack ----
int cond_stack[MAX_STACK];
int cond_level = 0;

// ---- Variable Table ----
const char *getvar(const char *key) {
    for (int i = 0; i < nvars; ++i)
        if (strcmp(vars[i].key, key) == 0) return vars[i].val;
    return "";
}
void setvar(const char *key, const char *val) {
    for (int i = 0; i < nvars; ++i) {
        if (strcmp(vars[i].key, key) == 0) {
            free(vars[i].val);
            vars[i].val = strdup(val);
            return;
        }
    }

    vars[nvars].key = strdup(key);
    vars[nvars].val = strdup(val);
    nvars++;
}

// --- Variable Expansion ---
void expand_vars(const char *src, char *buf, int buflen) {
    char *dst = buf;
    const char *p = src;
    while (*p && (dst - buf) < buflen - 1) {
        if (p[0] == '$' && p[1] == '{') {
            const char *end = strchr(p, '}');
            if (!end) { *dst++ = *p++; continue; }
            char key[256];
            size_t len = end - (p + 2);
            if (len >= sizeof(key)) len = sizeof(key) - 1;
            memcpy(key, p + 2, len);
            key[len] = '\0';

            const char *val = getvar(key);
            if (!val) val = "";
            if (DEBUG) DPRINTF("Expanding variable: ${%s} -> %s\n", key, val);

            for (const char *v = val; *v && (dst - buf) < buflen - 1; ++v) *dst++ = *v;
            p = end + 1;
        } else {
            *dst++ = *p++;
        }
    }
    *dst = '\0';
}
// ---- Conditional Block Logic ----
void cond_push(int val) {
    if (cond_level + 1 < MAX_STACK)
        cond_stack[++cond_level] = val && cond_stack[cond_level - 1];
    if (DEBUG) DPRINTF("Pushed condition: %d (level %d)\n", val, cond_level);
}
void cond_pop() {
    if (cond_level > 0) {
        if (DEBUG) DPRINTF("Popped condition (was level %d)\n", cond_level);
        cond_level--;
    }
}
int cond_active() { return cond_stack[cond_level]; }

// ---- Improved if() expression evaluator ----
int eval_simple_if(char *expr) {
    while (*expr == ' ' || *expr == '\t' || *expr == '\n') expr++;

    char *or_parts[16];
    int nor = 0;

    char *save_or;
    char *part = strtok_r(expr, "OR", &save_or);
    while (part && nor < 16) {
        or_parts[nor++] = part;
        part = strtok_r(NULL, "OR", &save_or);
    }

    int or_result = 0;

    for (int i = 0; i < nor; i++) {
        char *p = or_parts[i];

        char *and_parts[16];
        int nand = 0;

        char *save_and;
        char *ap = strtok_r(p, "AND", &save_and);
        while (ap && nand < 16) {
            and_parts[nand++] = ap;
            ap = strtok_r(NULL, "AND", &save_and);
        }

        int and_result = 1;

        for (int j = 0; j < nand; j++) {
            char *tok = and_parts[j];

            while (*tok == ' ' || *tok == '\t') tok++;

            int invert = 0;
            if (strncmp(tok, "NOT ", 4) == 0) {
                invert = 1;
                tok += 4;
            }

            char var[128], op[128], val[128];
            if (sscanf(tok, "%127s %127s %127s", var, op, val) == 3 &&
                strcmp(op, "STREQUAL") == 0) {

                int cmp = strcmp(getvar(var), val) == 0;
                and_result &= invert ? !cmp : cmp;
                continue;
            }

            const char *vval = getvar(tok);
            int flag = (strcmp(vval, "ON") == 0 ||
                        strcmp(vval, "1") == 0 ||
                        (vval[0] && strcmp(vval, "OFF") != 0 && strcmp(vval, "0") != 0));

            if (invert) flag = !flag;

            and_result &= flag;
        }

        or_result |= and_result;
    }

    return or_result;
}

// ---- Multi-line CMake Parser ----
char *read_cmake_cmd(FILE *fi, char *buf, int buflen) {
    char *out = buf;
    int depth = 0, found = 0;
    while (fgets(out, buflen - (out - buf), fi)) {
        char *hash = strchr(out, '#');
        if (hash) *hash = 0;
        size_t l = strlen(out);
        for (char *c = out; *c; ++c) {
            if (*c == '(') depth++;
            else if (*c == ')') depth--;
        }
        out += l;
        if (strchr(buf, '(')) found = 1;
        if (found && depth <= 0) break;
    }
    *out = 0;
    char *start = buf;
    while (*start == ' ' || *start == '\t' || *start == '\n') start++;
    char *end = buf + strlen(buf) - 1;
    while (end > start && (*end == '\n' || *end == ' ' || *end == '\t')) *end-- = 0;
    if (!*start) return NULL;
    memmove(buf, start, strlen(start) + 1);
    if (DEBUG) DPRINTF("Read CMake command: [%s]\n", buf);
    return buf;
}

// ---- Command Handlers ----
void cmd_cmake_minimum_required(const char *args) {
    DPRINTF("cmake_minimum_required: %s\n", args);
}
void cmd_message(const char *args) {
    trim_token((char*)args);
    printf("%s\n", args);
}
void cmd_add_compile_options(const char *args) {
    char filtered[1024] = "";
    char *saveptr = NULL;

    for (char *tok = strtok_r((char*)args, " ", &saveptr);
         tok;
         tok = strtok_r(NULL, " ", &saveptr)) {

#ifndef _WIN32
        // Skip MSVC-style flags on Unix
        if (tok[0] == '/' && tok[1] != '\0')
            continue;
#endif

        strcat(filtered, tok);
        strcat(filtered, " ");
    }

    char buf[1024];
    snprintf(buf, sizeof(buf), "%s %s", getvar("CMAKE_C_FLAGS"), filtered);
    setvar("CMAKE_C_FLAGS", buf);
}

void cmd_set(const char *args) {
    char key[128], val[768] = "";
    if (sscanf(args, "%127s %767[^\n\r)]", key, val) >= 1) {
        trim_token(key);
        trim_token(val);

        // --- FILTER CMAKE_C_FLAGS ON NON-WINDOWS ---
        if (strcmp(key, "CMAKE_C_FLAGS") == 0) {
#ifndef _WIN32
            char filtered[1024] = "";
            char tmp[1024];
            strncpy(tmp, val, sizeof(tmp));
            tmp[sizeof(tmp)-1] = 0;

            char *saveptr = NULL;
            for (char *tok = strtok_r(tmp, " ", &saveptr);
                 tok;
                 tok = strtok_r(NULL, " ", &saveptr)) {
                if (tok[0] == '/' && tok[1] != '\0')
                    continue;

                strcat(filtered, tok);
                strcat(filtered, " ");
            }

            setvar(key, filtered);
            return;
#endif
        }

        setvar(key, val);
    }
}

void cmd_add_definitions(const char *args) {
    char def[256];

    sscanf(args, "%255s", def);
    trim_token(def);

    for (int i = 0; i < ntarget; i++) {
        add_string(&targets[i].defs, &targets[i].ndef, def);
    }

    if (DEBUG) DPRINTF("add_definitions to all targets: %s\n", def);
}
void cmd_add_library(const char *args) {
    char name[128], type[64];

    char *rest = malloc(65536);
    if (!rest) return;
    rest[0] = '\0';

    sscanf(args, "%127s %63s %65535[^\n\r)]", name, type, rest);

    trim_token(name);
    trim_token(type);

    Target *t = &targets[ntarget++];
    strcpy(t->name, name);

    if (strcasecmp(type, "STATIC") == 0) {
        strcpy(t->type, "STATIC");
    } else if (strcasecmp(type, "SHARED") == 0) {
        strcpy(t->type, "SHARED");
    } else {
        strcpy(t->type, "EXE");
    }

    t->srcs = NULL;
    t->nsrc = 0;
    t->defs = NULL;
    t->ndef = 0;
    t->incs = NULL;
    t->ninc = 0;
    t->libs = NULL;
    t->nlib = 0;

    char *saveptr = NULL;
    char *tok = strtok_r(rest, " ", &saveptr);

    while (tok) {
        trim_token(tok);
        if (*tok) {
            t->srcs = realloc(t->srcs, (t->nsrc + 1) * sizeof(char *));
            t->srcs[t->nsrc] = strdup(tok);
            t->nsrc++;
        }
        tok = strtok_r(NULL, " ", &saveptr);
    }

    DPRINTF("add_library: %s type %s [%d srcs]\n",
            t->name, t->type, t->nsrc);

    free(rest);
}
void cmd_add_executable(const char *args) {
    char name[128];

    char *rest = malloc(65536);
    rest[0] = '\0';

    sscanf(args, "%127s %65535[^\n\r)]", name, rest);
    trim_token(name);

    Target *t = &targets[ntarget++];
    strcpy(t->name, name);
    strcpy(t->type, "EXE");

    t->srcs = NULL; t->nsrc = 0;
    t->defs = NULL; t->ndef = 0;
    t->incs = NULL; t->ninc = 0;
    t->libs = NULL; t->nlib = 0;

    char *saveptr = NULL;
    char *tok = strtok_r(rest, " ", &saveptr);

    while (tok) {
        trim_token(tok);
        if (*tok)
            add_string(&t->srcs, &t->nsrc, tok);
        tok = strtok_r(NULL, " ", &saveptr);
    }

    DPRINTF("add_executable: %s [%d srcs]\n", name, t->nsrc);
    free(rest);
}
void cmd_include(const char *args) {
    char fname[256];
    sscanf(args, "%255s", fname);

    char *f = fname;
    while (*f == '"' || *f == '\'') f++;

    char *quote = strrchr(f, '"');
    if (quote) *quote = 0;

    if (DEBUG) DPRINTF("include: %s\n", f);

    FILE *inc = fopen(f, "r");
    if (!inc) {
        DPRINTF("include failed: %s not found\n", f);
        return;
    }

    char cmdline[MAX_LINE * 4];
    while (read_cmake_cmd(inc, cmdline, sizeof cmdline)) {
        char expcmd[MAX_LINE * 4];
        expand_vars(cmdline, expcmd, sizeof expcmd);

        char *p = expcmd;

        if (strncmp(p, "set(", 4) == 0)
            cmd_set(p + 4);
        else if (strncmp(p, "add_executable(", 15) == 0)
            cmd_add_executable(p + 15);
        else if (strncmp(p, "add_library(", 12) == 0)
            cmd_add_library(p + 12);
        else if (strncmp(p, "add_definitions(", 16) == 0)
            cmd_add_definitions(p + 16);
        else if (DEBUG)
            DPRINTF("include: unknown command '%s'\n", p);
    }

    fclose(inc);
}
void cmd_add_subdirectory(const char *args) {
    char dir[256];
    sscanf(args, "%255s", dir);

    char fname[512];
    snprintf(fname, sizeof(fname), "%s/CMakeLists.txt", dir);

    cmd_include(fname);
}
static void parse_and_add_includes(const char *rest, char ***incs, int *nincs) {
    char buf[4096];
    strncpy(buf, rest, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;

    trim_token(buf);

    char *saveptr = NULL;
    char *dir = strtok_r(buf, " ", &saveptr);

    while (dir) {
        trim_token(dir);
        if (*dir)
            add_string(incs, nincs, dir);
        dir = strtok_r(NULL, " ", &saveptr);
    }
}
void cmd_include_directories_global(const char *args) {
    char rest[4096];

    if (sscanf(args, "%4095[^\n\r)]", rest) != 1)
        return;

    parse_and_add_includes(rest, &global_incs, &nglobal_incs);

    DPRINTF("include_directories (global): %s\n", rest);
}
void cmd_include_dirs(const char *args) {
    char tname[128], scope[32], rest[4096];

    if (sscanf(args, "%127s %31s %[^\n\r)]", tname, scope, rest) != 3)
        return;

    trim_token(tname);
    trim_token(scope);
    trim_token(rest);

    for (int i = 0; i < ntarget; i++) {
        if (strcmp(targets[i].name, tname) == 0) {
            parse_and_add_includes(rest, &targets[i].incs, &targets[i].ninc);
        }
    }

    DPRINTF("target_include_directories: %s %s\n", tname, scope);
}
void cmd_target_link_libs(const char *args) {
    char tname[128];
    char libs[4096] = {0};

    DPRINTF("RAW args = '%s'\n", args);

    while (*args == '(' || isspace(*args))
        args++;

    char cleaned[4096];
    strncpy(cleaned, args, sizeof(cleaned));
    cleaned[sizeof(cleaned)-1] = 0;

    char *end = cleaned + strlen(cleaned) - 1;
    while (end >= cleaned && (*end == ')' || isspace(*end))) {
        *end = 0;
        end--;
    }

    if (sscanf(cleaned, " %127[^ )] %4095[^)]", tname, libs) != 2) {
        DPRINTF("target_link_libraries: parse failed: '%s'\n", cleaned);
        return;
    }

    DPRINTF("PARSED tname='%s'\n", tname);
    DPRINTF("PARSED libs='%s'\n", libs);

    trim_token(tname);

    Target *dst = NULL;
    for (int i = 0; i < ntarget; i++) {
        if (strcmp(targets[i].name, tname) == 0) {
            dst = &targets[i];
            break;
        }
    }
    if (!dst) return;

    char *saveptr = NULL;
    char *lib = strtok_r(libs, " ", &saveptr);

    while (lib) {
        trim_token(lib);

        DPRINTF("Processing lib token='%s'\n", lib);

        add_string(&dst->libs, &dst->nlib, lib);

        for (int i = 0; i < ntarget; i++) {
            if (strcmp(targets[i].name, lib) == 0) {
                Target *src = &targets[i];

                DPRINTF("Propagating from target '%s' to '%s'\n", src->name, dst->name);
                for (int j = 0; j < src->ninc; j++) add_string(&dst->incs, &dst->ninc, src->incs[j]);
                for (int j = 0; j < src->ndef; j++) add_string(&dst->defs, &dst->ndef, src->defs[j]);
                for (int j = 0; j < src->nlib; j++) add_string(&dst->libs, &dst->nlib, src->libs[j]);
            }
        }

        lib = strtok_r(NULL, " ", &saveptr);
    }

    DPRINTF("Final libs for target '%s':\n", dst->name);
    for (int j = 0; j < dst->nlib; j++)
        DPRINTF("  lib[%d] = '%s'\n", j, dst->libs[j]);

    DPRINTF("target_link_libraries: %s\n", tname);
}
void cmd_project(const char *args) {
    char name[128] = {0};
    if (sscanf(args, "%127[^\n\r)]", name) == 1) {
        trim_token(name);
        setvar("PROJECT_NAME", name);
        DPRINTF("project: set PROJECT_NAME = %s\n", name);
    }
}

void cmd_file_glob(const char *args) {
    char var[128];
    char pattern[512];
    memset(pattern, 0, sizeof(pattern));

    if (sscanf(args, "%127s %511[^\n\r)]", var, pattern) < 2) {
        DPRINTF("file(GLOB_RECURSE): parse fail '%s'\n", args);
        return;
    }

    trim_token(var);
    trim_token(pattern);

    if (strchr(pattern, ' ')) {
        setvar(var, pattern);
        return;
    }

    char expanded[512]; 
    memset(expanded, 0, sizeof(expanded));
    expand_vars(pattern, expanded, sizeof(expanded));
    DPRINTF("file(GLOB_RECURSE): raw='%s' expanded='%s'\n", pattern, expanded);

    char dir[512];
    memset(dir, 0, sizeof(dir));
    strncpy(dir, expanded, sizeof(dir) - 1);

    const char *ext = NULL;
    char *star = strstr(dir, "/*");
    if (star) {
        ext = star + 1;
        *star = '\0';

        if (ext[0] == '*') {
            ext++;
            if (ext[0] == '\0' || strcmp(ext, ".*") == 0) {
                ext = NULL;
            }
        }
    }

    if (!*dir) {
        DPRINTF("file(GLOB_RECURSE): empty dir after expansion\n");
        setvar(var, "");
        return;
    }

    size_t buflen = 1024;
    char *buf = malloc(buflen);
    if (!buf) return;
    buf[0] = '\0';

    collect_files(dir, &buf, &buflen, ext);

    setvar(var, buf);
    DPRINTF("file(GLOB_RECURSE): %s = '%s'\n", var, buf);

    free(buf);
}
// ---- Main ----
int main(void) {
    setvar("CMAKE_C_FLAGS", "");
    setvar("CMAKE_C_STANDARD", "99");
    setvar("CMAKE_C_COMPILER", "gcc");  
    #ifdef _WIN32
        setvar("WIN32", "ON");
        #ifdef _MSC_VER
            setvar("MSVC", "ON");
        #endif
    #else
        setvar("UNIX", "ON");
        #ifdef __APPLE__
            setvar("APPLE", "ON");
        #endif
    #endif
    cond_stack[0] = 1; cond_level = 0;

    FILE *f = fopen("CMakeLists.txt", "r");
    if (!f) { puts("CMakeLists.txt not found."); return 1; }

    char cwd[256];
    if (getcwd(cwd, sizeof(cwd))) {
        setvar("CMAKE_CURRENT_LIST_DIR", cwd);
    }

    char cmdline[MAX_LINE*16];
    while (read_cmake_cmd(f, cmdline, sizeof cmdline)) {
        char expcmd[MAX_LINE*16];
        expand_vars(cmdline, expcmd, sizeof expcmd);

        // --- CONDITION handling
        if (strncmp(expcmd, "if(", 3) == 0) {
            const char *start = strchr(expcmd, '(');
            const char *end   = strrchr(expcmd, ')');
            char expr[512] = {0};
            if (start && end && end > start) {
                strncpy(expr, start + 1, end - start - 1);
                char *first = expr;
                while (*first == ' ' || *first == '\t' || *first == '\n') first++;
                char *last = first + strlen(first) - 1;
                while (last > first && (*last == ' ' || *last == '\t' || *last == '\n')) *last-- = 0;
                cond_push(eval_simple_if(first));
            } else {
                cond_push(0);
            }
            continue;
        }
        if (strncmp(expcmd, "elseif(", 7) == 0) {
            if (cond_level > 0) cond_level--;

            const char *start = strchr(expcmd, '(');
            const char *end   = strrchr(expcmd, ')');
            char expr[512] = {0};

            if (start && end && end > start) {
                strncpy(expr, start + 1, end - start - 1);
                char *first = expr;
                while (*first == ' ' || *first == '\t' || *first == '\n') first++;
                char *last = first + strlen(first) - 1;
                while (last > first && (*last == ' ' || *last == '\t' || *last == '\n')) *last-- = 0;
                cond_push(eval_simple_if(first));
            } else {
                cond_push(0);
            }
            continue;
        }
        if (strncmp(expcmd, "else", 4)==0) {
            if (cond_level) cond_stack[cond_level] = !cond_stack[cond_level];
            if (DEBUG) DPRINTF("else reached. inverting cond to %d\n", cond_stack[cond_level]);
            continue;
        }
        if (strncmp(expcmd, "endif", 5)==0) {
            cond_pop();
            continue;
        }
        if (!cond_active()) {
            if (DEBUG) DPRINTF("Skipping command (inactive condition): %s\n", expcmd);
            continue;
        }

        // --- COMMAND HANDLING ---
        if (strncmp(expcmd, "set(", 4)==0)
            cmd_set(expcmd+4);
        else if (strncmp(expcmd, "project(", 8)==0)
            cmd_project(expcmd+8);
        else if (strncmp(expcmd, "file(GLOB_RECURSE", 17)==0)
            cmd_file_glob(expcmd+17);
        else if (strncmp(expcmd, "add_definitions(", 16)==0)
            cmd_add_definitions(expcmd+16);
        else if (strncmp(expcmd, "add_executable(",15)==0)
            cmd_add_executable(expcmd+15);
        else if (strncmp(expcmd, "add_library(", 12)==0)
            cmd_add_library(expcmd+12);
        else if (strncmp(expcmd, "include_directories(",20)==0)
            cmd_include_directories_global(expcmd+20);
        else if (strncmp(expcmd, "target_include_directories(",27)==0)
            cmd_include_dirs(expcmd+27);
        else if (strncmp(expcmd, "target_link_libraries(", 21)==0)
            cmd_target_link_libs(expcmd+21);
        else if (strncmp(expcmd, "include(", 8)==0)
            cmd_include(expcmd+8);
        else if (strncmp(expcmd, "cmake_minimum_required(", 23)==0)
            cmd_cmake_minimum_required(expcmd+23);
        else if (strncmp(expcmd, "message(", 8)==0)
            cmd_message(expcmd+8);
        else if (strncmp(expcmd, "add_compile_options(", 20)==0)
            cmd_add_compile_options(expcmd+20);
        else if (strncmp(expcmd, "add_subdirectory(", 16)==0)
            cmd_add_subdirectory(expcmd+16);

        // --- STUBS for advanced features ---
        else if (strncmp(expcmd, "FetchContent_Declare(", 20)==0)
            DPRINTF("Skipping FetchContent_Declare\n");
        else if (strncmp(expcmd, "FetchContent_MakeAvailable(", 27)==0)
            DPRINTF("Skipping FetchContent_MakeAvailable\n");
        else if (strncmp(expcmd, "find_package(", 13)==0)
            DPRINTF("Skipping find_package\n");
        else if (strncmp(expcmd, "target_link_options(", 20)==0)
            DPRINTF("Skipping target_link_options\n");
        else if (strncmp(expcmd, "set_source_files_properties(", 28)==0)
            DPRINTF("Skipping set_source_files_properties\n");
        else if (strncmp(expcmd, "set_target_properties(", 22)==0)
            DPRINTF("Skipping set_target_properties\n");
        else if (DEBUG)
            DPRINTF("Unknown or skipped command: %s\n", expcmd);
    }

    fclose(f);

    // ---- Write out Makefile ----
    FILE *mk = fopen("Makefile", "w");
    fprintf(mk, "all:");
    for (int i = 0; i < ntarget; i++) {
    Target *t = &targets[i];
        if (!*t->name) continue;
        if (strcmp(t->type, "EXE") == 0) fprintf(mk, " %s", t->name);
        else if (strcmp(t->type, "STATIC") == 0) fprintf(mk, " lib%s.a", t->name);
        else if (strcmp(t->type, "SHARED") == 0) fprintf(mk, " lib%s%s", t->name, SHARED_NAME);
    }
    fprintf(mk, "\n\n");

    for (int i = 0; i < ntarget; i++) {
        Target *t = &targets[i];
        if (!*t->name) continue;

        if (strcmp(t->type, "EXE") == 0) {
            fprintf(mk, "%s: ", t->name);
            for (int j = 0; j < t->nsrc; j++) fprintf(mk, "%s ", t->srcs[j]);
            for (int j = 0; j < t->nlib; j++) fprintf(mk, "lib%s%s ", t->libs[j], SHARED_NAME);
            fprintf(mk, "\n\t%s %s -L. %s",
                    getvar("CMAKE_C_COMPILER"),
                    getvar("CMAKE_C_FLAGS"),
                    EXE_RULES);
            if (strcmp(getvar("CMAKE_C_STANDARD"), "11") == 0) fprintf(mk, " -std=c11");
            for (int j = 0; j < t->ndef; j++) fprintf(mk, " %s", t->defs[j]);
            for (int j = 0; j < t->ninc; j++) fprintf(mk, " -I%s", t->incs[j]);
            for (int j = 0; j < nglobal_incs; j++) fprintf(mk, " -I%s", global_incs[j]);
            for (int j = 0; j < t->nsrc; j++)fprintf(mk, " %s", t->srcs[j]);
            for (int j = 0; j < t->nlib; j++) fprintf(mk, " -l%s", t->libs[j]);
            fprintf(mk, " -o %s\n\n", t->name);
        } else if (strcmp(t->type, "STATIC") == 0) {
            fprintf(mk, "lib%s.a: ", t->name);
            // fprintf(mk, " -L. ");
            for (int j = 0; j < t->nsrc; j++) fprintf(mk, "%s ", t->srcs[j]);
            fprintf(mk, "\n\t%s %s", getvar("CMAKE_C_COMPILER"), getvar("CMAKE_C_FLAGS"));
            if (strcmp(getvar("CMAKE_C_STANDARD"), "11")==0) fprintf(mk," -std=c11");
            for (int j = 0; j < t->ndef; j++) fprintf(mk, " %s", t->defs[j]);
            for (int j = 0; j < t->ninc; j++) fprintf(mk, " -I%s", t->incs[j]);
            for (int j = 0; j < nglobal_incs; j++) fprintf(mk, " -I%s", global_incs[j]);
            for (int j = 0; j < t->nsrc; j++) fprintf(mk, " %s", t->srcs[j]);
            fprintf(mk, "\n\tar rcs lib%s.a *.o\n\n", t->name);
        } else if (strcmp(t->type, "STATIC") == 0) {
            fprintf(mk, "        lib%s.a: ", t->name);
            for (int j = 0; j < t->nsrc; j++) fprintf(mk, "%s ", t->srcs[j]);
            fprintf(mk, "\n\t%s %s",
                    getvar("CMAKE_C_COMPILER"),
                    getvar("CMAKE_C_FLAGS"));
            if (strcmp(getvar("CMAKE_C_STANDARD"), "11") == 0) fprintf(mk, " -std=c11");
            for (int j = 0; j < t->ndef; j++) fprintf(mk, " %s", t->defs[j]);
            for (int j = 0; j < t->ninc; j++) fprintf(mk, " -I%s", t->incs[j]);
            for (int j = 0; j < nglobal_incs; j++) fprintf(mk, " -I%s", global_incs[j]);
            for (int j = 0; j < t->nsrc; j++) fprintf(mk, " %s", t->srcs[j]);
            fprintf(mk, "\n        \tar rcs lib%s.a *.o\n\n", t->name);
        } else if (strcmp(t->type, "SHARED") == 0) {
            fprintf(mk, "lib%s%s: ", t->name, SHARED_NAME);
            for (int j = 0; j < t->nsrc; j++) fprintf(mk, "%s ", t->srcs[j]);
            fprintf(mk, "\n\t%s -shared -fPIC %s -L. %s",
                    getvar("CMAKE_C_COMPILER"),
                    getvar("CMAKE_C_FLAGS"),
                    LINK_RULES);
            if (strcmp(getvar("CMAKE_C_STANDARD"), "11") == 0) fprintf(mk, " -std=c11");
            for (int j = 0; j < t->ndef; j++) fprintf(mk, " %s", t->defs[j]);
            for (int j = 0; j < t->ninc; j++) fprintf(mk, " -I%s", t->incs[j]);
            for (int j = 0; j < nglobal_incs; j++) fprintf(mk, " -I%s", global_incs[j]);
            for (int j = 0; j < t->nsrc; j++) fprintf(mk, " %s", t->srcs[j]);
            for (int j = 0; j < t->nlib; j++) fprintf(mk, " -l%s", t->libs[j]);
            fprintf(mk, " -o lib%s%s\n\n", t->name, SHARED_NAME);
        }
    }

    fprintf(mk, "clean:\n\trm -f *.o *.a *%s ", SHARED_NAME);
    for (int i = 0; i < ntarget; i++) {
        Target *t = &targets[i];
        if (!*t->name) continue;
        if (strcmp(t->type, "EXE") == 0) fprintf(mk, "%s ", t->name);
        else if (strcmp(t->type, "STATIC") == 0) fprintf(mk, "lib%s.a ", t->name);
        else if (strcmp(t->type, "SHARED") == 0) fprintf(mk, "lib%s%s ", t->name, SHARED_NAME);
    }
    fprintf(mk, "\n");
    fclose(mk);

    puts("Wrote to Makefile. Type 'make'");
    return 0;
}
