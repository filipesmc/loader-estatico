/*
  - REFERÊNCIA LIBBFD, CONTÉM A DESCRIÇÃO DE TODAS AS FUNÇÕES UTILIZADAS NO CÓDIGO.
  - https://ftp.gnu.org/old-gnu/Manuals/bfd-2.9.1/html_chapter/bfd_toc.html

*/

#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include"loader.h"

struct symbol_db_t{
    symbol_ptr head;
    symbol_ptr tail;
};

struct section_db_t{
    section_ptr head;
    section_ptr tail;
};

/*
    Estrutura representa um binário ELF.
*/
struct binary_t{
    const char* bin_name;
    e_binary_type_t bin_type;
    const char* type_string;
    e_binary_arch_t bin_arch;
    const char* arch_string;
    unsigned bits;
    UL64 entry;
    SYMBOL_DB_PTR symbols;
    section_db_ptr sections;
};

/*
    Representa os simbolos de um binário.
*/
struct symbol_t{
    e_symbol_type_t sym_type;
    const char* sym_string;
    UL64 sym_addr;
    symbol_ptr next;
    symbol_ptr prev;
};

/*
    Representa as seções de um binário.
*/
struct section_t{
    binary_t* binary;
    const char* section_name;
    e_section_type_t sec_type;
    UL64 virtual_memory_addr;
    UL64 size;
    UI8  *bytes;
    section_ptr next;
    section_ptr prev;
};

BINARY* ctor_binary(VOID){
    BINARY* binary = (BINARY* )calloc(1, sizeof(binary_t));
    binary->bin_name = NULL;
    binary->type_string = NULL;
    binary->arch_string = NULL;
    binary->bin_type = BIN_ELF;
    binary->bin_arch = ARCH_UNKNOW;
    binary->bits = 0;
    binary->entry = 0;
    binary->sections = NULL;
    binary->symbols = NULL;
    return binary;
}

section_db_ptr init_section_db(BINARY* bin){
    section_db_ptr section_db = (section_db_ptr)calloc(1, sizeof(section_db_t));
    section_db->head = NULL;
    section_db->tail = NULL;
    bin->sections = section_db;
    return section_db;
}

static VOID insert_section(section_db_ptr db, section_ptr node){
    if(db->head == NULL && db->tail == NULL){
        db->head = node;
        db->tail = node;
        return;
    }

    node->prev = db->tail;
    db->tail->next = node;
    db->tail = node;
}

static section_ptr ctor_section(VOID){
    section_ptr section = (section_ptr)calloc(1, sizeof(section_t));
    section->binary = NULL;
    section->section_name = NULL;
    section->sec_type = SECTION_NONE;
    section->virtual_memory_addr = 0;
    section->size = 0;
    section->bytes = NULL;
    section->next = NULL;
    section->prev = NULL;

    return section;
}

SYMBOL_DB_PTR init_symbol_db(BINARY* bin){
    SYMBOL_DB_PTR symbol_db = (SYMBOL_DB_PTR)calloc(1, sizeof(symbol_db_t));
    symbol_db->head = NULL;
    symbol_db->tail = NULL;
    bin->symbols = symbol_db;
    return symbol_db;
}

static VOID insert_symbol(SYMBOL_DB_PTR db, symbol_ptr node){
    if(db->head == NULL && db->tail == NULL){
        db->head = node;
        db->tail = node;
        return;
    }

    node->prev = db->tail;
    db->tail->next = node;
    db->tail = node;
}

static symbol_ptr ctor_symbol(VOID){
    symbol_ptr symbol = (symbol_ptr)calloc(1, sizeof(symbol_t));
    symbol->sym_string = NULL;
    symbol->sym_type = SYMBOL_UNKNOW;
    symbol->sym_addr = 0;
    symbol->next = NULL;
    symbol->prev = NULL;
    return symbol;
}

section_ptr get_section(BINARY* bin){

    section_ptr section = bin->sections->head;
    
    while(section){
        if(strcmp(section->section_name, ".text") == 0){
            return section;
        }
        section = section->next;
    }

    return NULL;
}

/* Antes de fazer a análise, precisamos abrir o arquivo(binario) e 
    checar algumas condições antes de retornar o mesmo.
    A função faz uso das estruturas internas da libbfd, abre o bin em si
    checa suas propriedades como foi mencionado e se as condições forem 
    as definidas para o nosso proprósito, retorna um ponteiro para um handle.
*/

static bfd* open_bfd(const char* binary_name){
    static int bfd_inited = 0;
    bfd* bfd_handle = NULL;

    if(!bfd_inited){
        bfd_init();
        bfd_inited = 1;
    }

    bfd_handle = bfd_openr(binary_name, NULL); /* NULL porque a propria libfd vai nos dizer qual formato é.*/

    if(!bfd_handle){
        fprintf(stderr, "[+] Erro [ %s ] ao abrir o arquivo %s.\n", bfd_errmsg(bfd_get_error()), binary_name);
        return NULL;
    }

    /*bfd_object pode ser tanto um executável, shared lib ou relocatable*/
    if(!bfd_check_format(bfd_handle, bfd_object)){
        fprintf(stderr, "[+] Arquivo %s não é um executável, erro [ %s ]\n", binary_name, bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    bfd_set_error(bfd_error_no_error);

    if(bfd_get_flavour(bfd_handle) == bfd_target_unknown_flavour){
        fprintf(stderr, "[+] Formato de binário não suportado, erro [ %s ].\n", bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    return bfd_handle;
}

static int load_sections(bfd* bfd_handle, BINARY* bin){
    
    unsigned int flags = 0;
    UL64 size = 0;
    UL64 vma = 0;
    asection* bfd_section = bfd_handle->sections;
    const char* section_name = NULL; 
    section_ptr section = NULL;
    e_section_type_t section_type;

    for(bfd_section; bfd_section->next != NULL; bfd_section = bfd_section->next){

        flags = bfd_section->flags;

        section_type = SECTION_NONE;
        
        if(flags & SEC_CODE){
            section_type = SECTION_CODE;
        }else if(flags & SEC_DATA){
            section_type = SECTION_DATA;
        }else{
            continue;
        }

        size = bfd_section_size(bfd_section);
        section_name = bfd_section_name(bfd_section);
        vma = bfd_section_vma(bfd_section);

        if(!section_name){
            section_name = "*no section name*";
        }    

        section = ctor_section();
        section->binary = bin;
        section->sec_type = section_type;
        section->virtual_memory_addr = vma;
        section->section_name = section_name;
        section->size = size;
        section->bytes = (UI8 *)malloc(size);
        
        if(section->bytes == NULL){
            fprintf(stderr, "[+] Erro ao locar recursos.\n");
            return -1;
        }

        if(!bfd_get_section_contents(bfd_handle, bfd_section, section->bytes, 0, size)){
            fprintf(stderr, "[+] Erro [ %s ] ao ler a seção [ %s ].\n", bfd_errmsg(bfd_get_error()), section->section_name);
            return -1;
        }

        insert_section(bin->sections, section);
    }

    

    return 0;
}

/*sendo implementada durante jogo Brasil X Croácia, mas nem ligo, não gosto de futebol*/
static int load_sym(SYMBOL_DB_PTR symbol_db, bfd* handler){
    asymbol** bfd_symtab = NULL;
    symbol_ptr sym = NULL; 
    long nbytes_to_alloc = 0;

    nbytes_to_alloc = bfd_get_symtab_upper_bound(handler);
    
    if(nbytes_to_alloc < 0){
        fprintf(stderr, "[+] Erro ao ler SYMTAB [ %s ]\n", bfd_errmsg(bfd_get_error()));
        return -1;
    }else if(nbytes_to_alloc){
        bfd_symtab = calloc(1, nbytes_to_alloc);
        if(bfd_symtab == NULL){
            fprintf(stderr, "[+] Não foi possível alocar recursos. [ bfd_symtab]\n");
            return -1;
        }
    }

    long n_symtables = bfd_canonicalize_symtab(handler, bfd_symtab);

    if(n_symtables < 0){
        fprintf(stderr, "[+] Erro ao ler a tabela de simbolos [ %s ]\n", bfd_errmsg(bfd_get_error()));
        return -1;
    }

    int i = 0;
    for(i; i < n_symtables; ++i){
        
        if(bfd_symtab[i]->flags & (1 << 3)){

            symbol_ptr symbol = ctor_symbol(); /* crio um objeto do tipo symbol_t*/

            /* populo o objeto */
            symbol->sym_string = bfd_symtab[i]->name;
            symbol->sym_type = SYMBOL_FUNCTION;
            symbol->sym_addr = bfd_asymbol_value(bfd_symtab[i]);

            /* adiciono na lista */
            insert_symbol(symbol_db, symbol);
        }
    }   

    if(bfd_symtab){
        free(bfd_symtab);
    }

    return 0;
}

static int load_dynsym(SYMBOL_DB_PTR symbol_db, bfd* bfd_handler){

    long nbytes_to_alloc = 0;
    long n_symbols = 0;
    asymbol** bfd_dynsym = NULL;
    symbol_ptr symbol = NULL;

    nbytes_to_alloc = bfd_get_dynamic_symtab_upper_bound(bfd_handler);

    if(nbytes_to_alloc < 0){
        fprintf(stderr, "[+] Erro [ %s ] ao ler as tabelas de símbolos dinamicos!\n", bfd_errmsg(bfd_get_error()));
        return -1;
    }else if(nbytes_to_alloc){
        
        bfd_dynsym = (asymbol**) calloc(1, nbytes_to_alloc);
        
        if(!bfd_dynsym){
            fprintf(stderr, "[+] Erro ao alocar recursos\n");
            return -1;
        }
    }

    n_symbols = bfd_canonicalize_dynamic_symtab(bfd_handler, bfd_dynsym);

    if(n_symbols < 0){
        fprintf(stderr, "[+] Erro [ %s ] ao ler as tabelas de símbolos dinamicos!\n", bfd_errmsg(bfd_get_error()));
        return -1;
    }

    int i = 0;

    for(i; i < n_symbols; ++i){

        if(bfd_dynsym[i]->flags & (1 << 3)){
            
            symbol_ptr symbol = ctor_symbol();
            symbol->sym_type = SYMBOL_FUNCTION;
            symbol->sym_string = bfd_dynsym[i]->name;
            symbol->sym_addr = bfd_asymbol_value(bfd_dynsym[i]);
            insert_symbol(symbol_db, symbol);
        }        

    }

    if(bfd_dynsym){
        free(bfd_dynsym);
    }

    return 0;
}

void dump_bin_info(BINARY* bin){
    printf("[+] Binário: %s\n[+] Tipo: %s\n[+] Arch: %s (%u bits)\n[+] Entry point addr @0x%016jx\n", bin->bin_name, bin->type_string, bin->arch_string, bin->bits, bin->entry);

}

void dump_sections_info(BINARY* bin){
    
    section_ptr section = bin->sections->head;

    printf("\n------------------------------------------- Seções\n");
    while(section->next != NULL){
        printf("Nome: %-35s Endereço: 0x%016jx Tipo: %s Tam.: %-8ju\n", section->section_name, section->virtual_memory_addr, section->sec_type == SECTION_CODE ? "CODE" : "DATA", section->size); 
        section = section->next;
    }
}

void dump_symbols_info(BINARY* bin){
    
    symbol_ptr symbol = bin->symbols->head;

    printf("\n------------------------------------------- Símbolos\n");
    while(symbol->next != NULL){
        printf("Nome: %-35s Endereço: 0x%016jx Tipo: %s\n", symbol->sym_string, symbol->sym_addr, (symbol->sym_type & SYMBOL_FUNCTION) ? "FUNÇÃO" : "");
        symbol = symbol->next;
    }
}

/* Essa função parseia o binário e carrega esse arquivo pra dentro da struct BINARY
    que também é passada como paramêtro. */
int load(const char* binary_name, BINARY* bin, e_binary_type_t type){

    bfd* bfd_handle = NULL;
    const bfd_arch_info_type* bfd_arch_info;

    bfd_handle = open_bfd(binary_name);
    if(!bfd_handle){
        return -1;
    }

    bin->bin_name = binary_name;
    bin->type_string = bfd_handle->xvec->name;
    bin->entry = bfd_get_start_address(bfd_handle);

    switch (bfd_handle->xvec->flavour)
    {
    case bfd_target_elf_flavour:
        bin->bin_type = BIN_ELF;
        break;
    case bfd_target_unknown_flavour:
        bin->bin_type = BIN_UNKNOW;
        break;
    default:
        fprintf(stderr, "[+] Formato de binário [ %s ] não suportado!\n", bfd_errmsg(bfd_get_error()));
        exit(1);
    }

    bfd_arch_info = bfd_get_arch_info(bfd_handle);
    bin->arch_string = bfd_arch_info->printable_name;

    switch (bfd_arch_info->mach)
    {
    case bfd_mach_i386_i386:
        bin->bin_arch = ARCH_i386;
        bin->bits = 32;
        break;
    case bfd_mach_x86_64:
        bin->bin_arch = ARCH_x86_64;
        bin->bits = 64;
        break;
    default:
        fprintf(stderr, "[+] Arquitetura não suportada: %s\n", bfd_arch_info->printable_name);
        return -1;
    }

    load_sym(bin->symbols, bfd_handle);
    load_dynsym(bin->symbols, bfd_handle);

    if(load_sections(bfd_handle, bin) < 0){
        return -1;
    }

    if(bfd_handle){
        bfd_close(bfd_handle);
        return 0;
    }

    return 1;
}

VOID unload(BINARY* bin){

    section_ptr section = bin->sections->head;
    symbol_ptr symbol = bin->symbols->head;

    for(section_ptr aux = section; aux->next != NULL; aux = aux->next){

        if(aux->bytes){
            free(aux->bytes);
        }

        aux->section_name = NULL;
        aux->binary = NULL;

        if(aux){
            free(aux);
        }
    }
    
    section = NULL;

    for(symbol_ptr aux = symbol; aux->next != NULL; aux = aux->next){

        aux->sym_string = NULL;

        if(aux){
            free(aux);
        }
    }
    
    symbol = NULL;

    bin->arch_string = NULL;
    bin->bin_name = NULL;
    bin->type_string = NULL;

    if(bin){
        free(bin);
    }

}


