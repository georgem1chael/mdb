/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

/* ELF parsing */
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>

#define MAX_SYMBOLS 1024

#define TOOL "mdb"

#define die(...) \
    do { \
        fprintf(stderr, TOOL": " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

typedef struct {
    char name[128];
    uint64_t addr;
} Symbol;

Symbol sym_table[MAX_SYMBOLS]; //inmemory symbol table

int sym_count = 0; //how many symbols loaded

//Removed hardcode breakpoint

void process_inspect(int pid) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
            die("%s", strerror(errno));
  
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);
    if (current_ins == -1) 
        die("(peekdata) %s", strerror(errno));
   
    fprintf(stderr, "=> 0x%llx: 0x%lx\n", regs.rip, current_ins);
 
}

long set_breakpoint(int pid, long addr) {
    return 0; 
}

void process_step(int pid) {

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));
 
    waitpid(pid, 0, 0);
}

void serve_breakpoint(int pid, long original_instruction) {
    return;
}

// Load symtab from ELF binary
void load_symbols(const char *filename){
    //Initialise libelf and opening file
    if(elf_version(EV_CURRENT) == EV_NONE)
	die("libelf init failed: %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    if(fd < 0)
	die("Cannot open %s: %s", filename, strerror(errno));

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if(!elf)
	die("elf_begin failed: %s", elf_errmsg(-1));

    //Findind .symtab
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;

    if(elf_getshdrstrndx(elf, &shstrndx) != 0)
	die("elf_getshdrstrndx failed: %s", elf_errmsg(-1));

    while((scn = elf_nextscn(elf, scn)) != NULL){
	if(gelf_getshdr(scn, &shdr) != &shdr)
	   die("gelf_getshdr failed: %s", elf_errmsg(-1));

	if (shdr.sh_type == SHT_SYMTAB) {
            Elf_Data *data = elf_getdata(scn, NULL);
            int count = shdr.sh_size / shdr.sh_entsize;

            for (int i = 0; i < count && sym_count < MAX_SYMBOLS; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);

                //only store named functions and object
                if (sym.st_value == 0) continue;

                const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!name || name[0] == '\0') continue;

                strncpy(sym_table[sym_count].name, name, 127);
                sym_table[sym_count].addr = sym.st_value;
                sym_count++;
            }
        }
    }

    elf_end(elf);
    close(fd);

    fprintf(stderr, "[mdb] loaded %d symbols from %s\n ", sym_count, filename);
}

uint64_t find_symbol(const char *name){
    for(int i=0; i < sym_count; i++){
        if(strcmp(sym_table[i].name, name) == 0)
           return sym_table[i].addr;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("usage: mdb <program>");

    load_symbols(argv[1]);

    /* fork() for executing the program that is analyzed.  */
    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            die("%s", strerror(errno));
        case 0:  /* Code that is run by the child. */
            /* Start tracing.  */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* execvp() is a system call, the child will block and
               the parent must do waitpid().
               The waitpid() of the parent is in the label
               waitpid_for_execvp.
             */
            execvp(argv[1], argv + 1);
            die("%s", strerror(errno));
    }

    /* Code that is run by the parent.  */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    waitpid(pid, 0, 0);

    /* [PHASE 0] Temporarily resume child so it exits cleanly */
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, 0, 0); /* wait for child to exit */
    return 0;
}
