#ifndef LOADER_H
#define LOADER_H

#include<bfd.h>
#include"section_db.h"
#include"symbol_db.h"

typedef struct binary_t binary_t;
typedef struct symbol_t symbol_t;

#define UL64 unsigned long /* uint64_t */
#define UI8  unsigned char /* uint8_t  */
#define BINARY binary_t
#define SYMBOL symbol_t
#define SECTION section_t

typedef enum{
    SECTION_CODE = 0,
    SECTION_DATA = 1,
    SECTION_NONE = 2    
} e_section_type_t;

typedef enum{
    ARCH_UNKNOW = 0,
    ARCH_x86_64 = 1,
    ARCH_i386 = 2
} e_binary_arch_t;

typedef enum{
    BIN_ELF = 0,
    BIN_UNKNOW = 1
} e_binary_type_t;

typedef enum{
    SYMBOL_UNKNOW = 0,
    SYMBOL_FUNCTION = 1
} e_symbol_type_t;

static bfd* open_bfd(const char* binary_name);
int load(const char* binary_name, BINARY* bin, e_binary_type_t type);
VOID unload(BINARY* bin);
BINARY* ctor_binary(VOID);
static SECTION* ctor_section(VOID);
static SYMBOL* ctor_symbol(VOID);
static int load_sym(SYMBOL_DB_PTR symbol_db, bfd*);
static int load_dynsym(SYMBOL_DB_PTR symbol_db, bfd* bfd_handle);
static int load_sections(bfd*, BINARY*);
SYMBOL_DB_PTR init_symbol_db(BINARY*);
SECTION_DB_PTR init_section_db(BINARY*);
static VOID insert_section(SECTION_DB_PTR, SECTION_PTR);
static VOID insert_symbol(SYMBOL_DB_PTR, SYMBOL*);
VOID dump_bin_info(BINARY*);
VOID dump_sections_info(BINARY*);
VOID dump_symbols_info(BINARY*);
#endif