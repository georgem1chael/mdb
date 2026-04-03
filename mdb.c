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

#define MAX_BREAKPOINTS 64

typedef struct{
	uint64_t addr;
	long original_byte; //original code before the injected int3
	int enabled; // 1 = active else 0 if symbol is not resolved yet
	char symbol[128];
} Breakpoint;

Breakpoint bp_table[MAX_BREAKPOINTS];
int bp_count = 0;


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

void breakpoint_command(const char *arg){
	uint64_t addr = 0;
	char symbol[128] = {0};

	if(arg[0] == '*'){
		// Breakpoint using hex address
		addr = (uint64_t)strtoull(arg+1, NULL, 16);
		snprintf(symbol, sizeof(symbol), "%s", arg);
		if(addr == 0){
			fprintf(stderr, "Invalid address: %s\n", arg);
			return;
		}
	}
	else{
		// Breakpoint using symbol name
		addr = find_symbol(arg);
		snprintf(symbol, sizeof(symbol), "%s", arg);
		if(addr == 0){
			// Symbol not foound, ask to set it as pending
			fprintf(stderr, "Symbol '%s' not found, Enable as pending breakpoint? (y/n) ", arg);
			fflush(stderr);
			char ans[8];
			if(!fgets(ans, sizeof(ans), stdin)) 
				return;
			if(ans[0] == 'y' || ans[0] == 'Y'){
				if(bp_count >= MAX_BREAKPOINTS){
					fprintf(stderr, "Breakpoint table full.\n");
					return;
				}
				bp_table[bp_count].addr = 0;
				bp_table[bp_count].enabled = 0;
				bp_table[bp_count].original_byte = 0;
				strncpy(bp_table[bp_count].symbol, symbol, 127);
				bp_count++;
				fprintf(stderr, "Pending breakpoint %d set for '%s'.\n", bp_count, arg);
			}
			return;
		}
	}

	if(bp_count >= MAX_BREAKPOINTS){
		fprintf(stderr, "Breakpoint table full.\n");
		return;
	}
	
	bp_table[bp_count].addr = addr;
	bp_table[bp_count].enabled = 1;
	bp_table[bp_count].original_byte = 0; // will be filled later
	strncpy(bp_table[bp_count].symbol, symbol, 127);
	bp_count++;
	
	if(arg[0] == '*')
		fprintf(stderr, "Breakpoint %d set at %s.\n", bp_count, symbol);
	else
		fprintf(stderr, "Breakpoint %d set at %s (0x%lx). \n", bp_count, symbol, addr);	
}

void list_command(void){
	if(bp_count == 0){
		fprintf(stderr, "No breakpoints set. \n");
		return;
	}
	for(int i =0; i < bp_count; i++){
		if(bp_table[i].enabled)
			fprintf(stderr, " %d: %s at 0x%lx [enabled]\n", i+1, bp_table[i].symbol, bp_table[i].addr);
		else
			fprintf(stderr, " %d: %s [pending]\n", i+1, bp_table[i].symbol);
	}
}

void delete_command(const char *arg){
	int n = atoi(arg);
	if(n < 1 || n > bp_count){
		fprintf(stderr, "No breakpoint number %d.\n", n);
		return;
	}
	fprintf(stderr, "Delete breakpoint %d (%s).\n", n, bp_table[n-1].symbol);
	for(int i=n-1; i < bp_count - 1; i++)
		bp_table[i] = bp_table[i+1];
	bp_count--;
}

//Main command loop for all inputs
void command_loop(void){
	char line[256];

	while(1){
		fprintf(stderr, "(mdb) ");
		fflush(stderr);
		if(!fgets(line, sizeof(line), stdin))
			break;
		line[strcspn(line, "\n")] = '\0';
		if(strncmp(line, "b ", 2) == 0){
			//Breakpoint command
			breakpoint_command(line+2);
		}
		else if(strcmp(line, "l") == 0){
			//List Breakpoints
			list_command();
		}
		else if(strncmp(line, "d ", 2) == 0){
			//Delete breakpoint
			delete_command(line+2);
		}
		else if (strcmp(line, "r") == 0) {
           		// run
           		fprintf(stderr, "[stub] r command - not yet implemented\n");
		} 
		else if (strcmp(line, "c") == 0) {
            		// continue
            		fprintf(stderr, "[stub] c command - not yet implemented\n");
        	}
	     	else if (strcmp(line, "q") == 0) {
            		fprintf(stderr, "Bye\n");
            		exit(0);

        	}
		else if (line[0] != '\0') {
            		fprintf(stderr, "Unknown command: %s\n", line);
            		fprintf(stderr, "Commands: b <sym|*addr>, l, d <n>, r, c, q\n");
        	}
	}
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("usage: mdb <program>");

    load_symbols(argv[1]);

    command_loop();

    return 0;
}
