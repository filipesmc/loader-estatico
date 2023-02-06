#include<stdio.h>
#include<string.h>
#include<stdint.h>
#include<unistd.h>
#include<stdlib.h>
#include"loader.h"

int main(int argc, char**argv){

    size_t i = 0;
    int option = 0;

    if(argc == 1){

        printf("--> Uso: %s -b bin_path.\n", argv[0]);
        exit(1);
    }

    while((option = getopt(argc, argv, "b")) != -1){


        BINARY* bin = ctor_binary();
        SYMBOL_DB_PTR symbol = init_symbol_db(bin);
        SECTION_DB_PTR section = init_section_db(bin);

        if(load(argv[2], bin, BIN_UNKNOW) < 0){
            return 1;
        }

        dump_bin_info(bin);
        dump_sections_info(bin);
        dump_symbols_info(bin);

        unload(bin);
        free(symbol);
        free(section);
    }
   



    return 0;
}