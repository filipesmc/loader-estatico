Loader estático de binário.

- O loader usa a LIBBFD (Binary File Descriptor) que através de sua interface conseguimos parsear e extrair informções de diversos formatos de binários. Nesse programa só parsearei binários ELF. Ele mostra as seções, símbolos, tamanhos, endereços e tipos. Pode ser extendido.

- Modo de uso: ./loader -b nome_binario

- Como compilar:

    gcc -c -std=c11 loader.c -o loader.o
    gcc -std=c11 loader.o main.c -o exec -lbfd

- No debian se faz necessário baixar o binutils-dev que vem incluso a lib. O header dela é bfd.h e está em /usr/include/bfd.h

- Um caso de uso é quando você quer verificar em que seção os dados ou código pertence e pegar o endereço.

- Compilem e testem!# loader-estatico
