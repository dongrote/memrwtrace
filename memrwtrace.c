#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

typedef void (*callback_function_t)(uint32_t , uint32_t);

struct MipsInstruction {
    uint32_t virtual_address;
    uint32_t original_instruction;
    uint8_t opcode;
    uint8_t rs;
    uint8_t rt;
    uint8_t pad;
    int16_t immediate;
};

struct MipsInstructionDatabase {
    struct MipsInstruction * instructions;
    int dblength;
    int num_instructions;
};

struct MipsInstructionDatabase * _midb = NULL;


void hexprint(unsigned char  *data, int len)
{
    int i;
    for(i=0; i<len; i++) {
        if( i % 16 == 0 ){
            fprintf(stderr,"%08x: ", i);
        }
        fprintf(stderr,"%02x ", data[i]);
        if( (i+1) % 16 == 0) {
            fprintf(stderr,"\n");
            continue;
        }
        if( (i+1) % 8 == 0) {
            fprintf(stderr,"  ");
            continue;
        }
        if( (i+1) % 4 == 0) {
            fprintf(stderr," ");
        }
    }
    fprintf(stderr,"\n");
}


int16_t mipsbe_get_immediate(uint32_t instruction)
{
    return (int16_t)(instruction & 0x0000ffff);
}

uint8_t mipsbe_get_rt(uint32_t instruction)
{
    return (uint8_t)((instruction & 0x001f0000) >> (32-(5+5+6)));
}

uint8_t mipsbe_get_rs(uint32_t instruction)
{
    return (uint8_t)((instruction & 0x03e00000) >> (32-(5+6)));
}

uint8_t mipsbe_get_opcode(uint32_t instruction)
{
    return (uint8_t)((instruction & 0xfc000000) >> (32-6));
}

struct MipsInstructionDatabase *init_mipsinstructiondatabase(void)
{
    struct MipsInstructionDatabase *midb = malloc(sizeof(*midb));
    midb->dblength = 1;
    midb->instructions = malloc(midb->dblength * sizeof(struct MipsInstruction));
    midb->num_instructions = 0;
    return midb;
}

void free_mipsinstructiondatabase(struct MipsInstructionDatabase *midb)
{
    if(midb->instructions != NULL) {
        free(midb->instructions);
    }
    free(midb);
}

int init_mipsinstruction(struct MipsInstruction *mi, uint32_t vaddr, uint32_t instruction)
{
    mi->original_instruction = instruction;
    mi->opcode = mipsbe_get_opcode(instruction);
    mi->rs = mipsbe_get_rs(instruction);
    mi->rt = mipsbe_get_rt(instruction);
    mi->immediate = mipsbe_get_immediate(instruction);
    mi->virtual_address = vaddr;
    fprintf(stderr, "Instruction opcode (%d) rs (%d) rt (%d) imm (%d)\n",
            mi->opcode, mi->rs, mi->rt, mi->immediate);
    return 0;
}

int midb_grow(struct MipsInstructionDatabase *midb)
{
    int newsize = midb->dblength << 1;
    struct MipsInstruction * newbuffer = realloc(midb->instructions, newsize*sizeof(midb->instructions[0]));
    if (newbuffer == NULL) {
        errno = ENOMEM;
        return -1;
    }
    midb->dblength = newsize;
    midb->instructions = newbuffer;
    return 0;
}

int midb_add_instruction(struct MipsInstructionDatabase *midb, uint32_t vaddr, uint32_t instruction)
{
    if ( midb->num_instructions == midb->dblength ) {
        if( midb_grow(midb) ) {
            errno = ENOMEM;
            return -1;
        }
    }
    init_mipsinstruction(&midb->instructions[midb->num_instructions++], vaddr, instruction);
    return 0;
}


const char * get_shstrtab(Elf32_Ehdr *elffile, uint32_t elflen)
{
    int section_index = elffile->e_shstrndx;
    Elf32_Shdr * section_header_table = (Elf32_Shdr*)((char*)elffile + elffile->e_shoff);
    if (section_index > elffile->e_shnum) {
        errno = EINVAL;
        return -1;
    }
    if ((elffile->e_shoff + (section_index * elffile->e_shentsize)) > elflen) {
        errno = EINVAL;
        return -1;
    }
    return (char*)elffile + section_header_table[section_index].sh_offset;
}

const char * resolve_string_table_index(Elf32_Ehdr * elffile, uint32_t filelen, int table_index)
{
    int i;
    char * shstrtab = get_shstrtab(elffile, filelen);
    if (shstrtab == (char*)-1) {
        errno = EINVAL;
        return -1;
    }
    return (const char*)shstrtab + table_index;
}

Elf32_Off elf32_get_entry_point(Elf32_Ehdr *elffile, uint32_t filelen)
{
    return elffile->e_entry;
}

int elf32_section_count(Elf32_Ehdr *elffile, uint32_t len)
{
    return elffile->e_shnum;
}

Elf32_Off elf32_get_virtual_load_address(Elf32_Ehdr *elffile, uint32_t len)
{
    /* get phdr with offset 0 */
    /* return virtual address attribute of this phdr */
    int i;
    int program_header_count = elffile->e_phnum;
    Elf32_Phdr * phdr = elffile->e_phoff + (void*) elffile;
    for(i=0;i<program_header_count;i++) {
        phdr = &phdr[1];
        if (phdr->p_offset == 0) {
            return phdr->p_vaddr;
        }
    }
    return (Elf32_Off)-1;
}

Elf32_Shdr * elf32_get_section_header(Elf32_Ehdr *elffile, uint32_t elflen, int index)
{
    Elf32_Shdr * sh = (Elf32_Shdr*)((unsigned char*)elffile + elffile->e_shoff);
    return &sh[index];
}

unsigned char * elf32_get_section_offset_by_index(Elf32_Ehdr *elffile, uint32_t elflen, int index)
{
    Elf32_Shdr * section_header = elf32_get_section_header(elffile, elflen, index);
    return section_header->sh_offset;
}

Elf32_Shdr * elf32_get_section_header_by_name(Elf32_Ehdr *elffile, uint32_t elflen, const char *section_name)
{
    int i;
    char * name;
    Elf32_Shdr *shdr;
    int section_count = elf32_section_count(elffile, elflen);
    for (i=0; i<section_count; i++) {
        shdr = elf32_get_section_header(elffile, elflen, i);
        name = resolve_string_table_index(elffile, elflen, shdr->sh_name);
        if( strcmp(name, section_name) == 0 ) {
            return shdr;
        }
    }
    return NULL;
}

unsigned char * elf32_get_section_offset_by_name(Elf32_Ehdr *elffile, uint32_t elflen, const char *section_name)
{
    Elf32_Shdr *shdr = NULL;
    shdr = elf32_get_section_header_by_name(elffile, elflen, section_name);
    if(shdr != NULL) {
        return shdr->sh_offset;
    }
    return NULL;
}

uint32_t elf32_get_section_size(Elf32_Ehdr *elffile, uint32_t elflen, int index)
{
    Elf32_Shdr *shdr = elf32_get_section_header(elffile, elflen, index);
    if( shdr != NULL ) {
        return shdr->sh_size;
    }
    return 0;
}

uint32_t elf32_get_section_size_by_name(Elf32_Ehdr *elffile, uint32_t elflen, const char *name)
{
    Elf32_Shdr *shdr = elf32_get_section_header_by_name(elffile, elflen, name);
    if( shdr != NULL ) {
        return shdr->sh_size;
    }
    return 0;
}

unsigned char * read_file(const char *filepath, uint32_t *len)
{
    int fd = open(filepath, O_RDONLY);
    off_t bytes_read;
    off_t filesize = lseek(fd, 0, SEEK_END);
    unsigned char * buffer = malloc(filesize);

    if ( buffer == NULL ) {
        errno = ENOMEM;
        return -1;
    }

    lseek(fd, 0, SEEK_SET);
    bytes_read = read(fd, buffer, filesize);
    if (bytes_read != filesize) {
        fprintf(stderr, "Error: read %d bytes, expected %d\n", bytes_read, filesize);
        free(buffer);
        errno = EINVAL;
        return -1;
    }

    if (len != NULL) {
        *len = (uint32_t)filesize;
    }

    return buffer;
}


void analyze_section(unsigned char *section, uint32_t length, uint32_t loadaddress, callback_function_t cbfunc)
{
    uint8_t opcode, rs, rt;
    int16_t immediate;
    fprintf(stderr,"Analyzing %p to %p\n", section, section + length);
    uint32_t * instruction_pointer = (uint32_t*)section;
    for (; instruction_pointer < section+length; instruction_pointer++) {
        cbfunc(loadaddress + ((uint32_t)instruction_pointer - (uint32_t)section), *instruction_pointer);
    }
}

void register_instruction(uint32_t virtualaddress, uint32_t instruction)
{
    uint8_t opcode, rs, rt;
    uint16_t immediate;
    opcode = mipsbe_get_opcode(instruction);
    rs = mipsbe_get_rs(instruction);
    rt = mipsbe_get_rt(instruction);
    immediate = mipsbe_get_immediate(instruction);
    switch (opcode) {
        case 0x28:
        case 0x29:
        case 0x2b:
            midb_add_instruction(_midb, virtualaddress, instruction);
            break;
        case 0x20:
        case 0x24:
        case 0x21:
        case 0x25:
        case 0x23:
            midb_add_instruction(_midb, virtualaddress, instruction);
            break;
        default:
            break;
    }
}

struct MipsInstruction * midb_lookup_instruction_by_vaddr(struct MipsInstructionDatabase *midb, uint32_t vaddr)
{
    struct MipsInstruction * mi;
    int i;
    for(i=0; i<midb->num_instructions; i++) {
        mi = &midb->instructions[i];
        if( mi->virtual_address == vaddr ){
            return mi;
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    char * string;
    uint32_t file_len;
    uint32_t reg;
    int i, pid, status;
    if(argc < 2) {
        fprintf(stderr, "Usage: %s elf_file\n", argv[0]);
        exit(-1);
    }

    char * target_file_path = argv[1];
    char * childargv[] = { target_file_path, NULL };
    char * childenvp[] = {NULL};

    unsigned char * target_file = read_file(target_file_path, &file_len);

    if (target_file == (unsigned char*)-1) {
        fprintf(stderr, "Error reading in file \"%s\".", target_file_path);
        exit(-1);
    }

    _midb = init_mipsinstructiondatabase();

    fprintf(stderr,"target_file %p\n", target_file);

    unsigned char * dottext_offset = elf32_get_section_offset_by_name((Elf32_Ehdr*)target_file, file_len, ".text");
    unsigned char * dottext_vaddr = (unsigned char*)((uint32_t)dottext_offset + (uint32_t)target_file);
    uint32_t dottext_length = elf32_get_section_size_by_name((Elf32_Ehdr*)target_file, file_len, ".text");
    fprintf(stderr,".text section offset: %p (%d)\n", dottext_offset, dottext_offset);
    fprintf(stderr,".text section size: %d\n", dottext_length);
    uint32_t load_vaddr = elf32_get_virtual_load_address((Elf32_Ehdr*)target_file, file_len);
    load_vaddr += (uint32_t)dottext_offset;

    analyze_section(dottext_vaddr, dottext_length, load_vaddr, register_instruction);


    struct MipsInstruction * mi;
    printf("[");
    for(i=0; i<_midb->num_instructions;i++) {
        mi = &_midb->instructions[i];
        printf("{\"address\": %d, \"rs\": %d, \"immediate\": %d}",
            mi->virtual_address, mi->rs, mi->immediate);
        if( i+1 < _midb->num_instructions ) {
            printf(", ");
        }
    }
    printf("]\n");

    free_mipsinstructiondatabase(_midb);
    free(target_file);

    return 0;
}
