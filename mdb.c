/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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

/* Dissambly */
#include <capstone/capstone.h>

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
    uint64_t size;
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

csh cs_handle;

/* Read size bytes from child process memory into buf using PTRACE_PEEKDATA */
void read_child_memory(pid_t pid, uint64_t addr, uint8_t *buf, size_t size) {
    // PTRACE_PEEKDATA reads 8 bytes at a time
    size_t i = 0;
    while (i < size) {
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), 0);
        if (word == -1 && errno != 0) break;

        //copy up to 8 bytes into buffer
        size_t to_copy = size - i < 8 ? size - i : 8;
        memcpy(buf + i, &word, to_copy);
        i += 8;
    }
}

/* Disassemble up to 11 instructions from addr in the child process, resolving symbol names */
void disas_at(pid_t pid, uint64_t addr) {
    // read 128 bytes from child mem,  enough for 11 instructions
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));
    read_child_memory(pid, addr, buf, sizeof(buf));

    cs_insn *insn;
    size_t count = cs_disasm(cs_handle, buf, sizeof(buf), addr, 0, &insn);

    if (count == 0) {
        fprintf(stderr, "[mdb] disassembly failed at 0x%lx.\n", addr);
        return;
    }

    size_t limit = count < 11 ? count : 11;
    for (size_t i = 0; i < limit; i++) {

        // check if this address matches a symbol
        const char *sym = NULL;
        for (int s = 0; s < sym_count; s++) {
            if (sym_table[s].addr == insn[i].address) {
                sym = sym_table[s].name;
                break;
            }
        }
	
	
	// repplace address with symbol names using Capstone
	char op_str_resolved[512];
	strncpy(op_str_resolved, insn[i].op_str, sizeof(op_str_resolved));

	// check immediate operands directly from Capstone
	cs_x86 *x86 = &insn[i].detail->x86;
	for (int op = 0; op < x86->op_count; op++) {
    		if (x86->operands[op].type == X86_OP_IMM) {
        		uint64_t imm = (uint64_t)x86->operands[op].imm;
        		for (int s = 0; s < sym_count; s++) {
            			if (sym_table[s].addr == imm) {
                			snprintf(op_str_resolved, sizeof(op_str_resolved),"%s <%s>",insn[i].op_str, sym_table[s].name);
                			break;
           			}
        		}
    		}
	}	

        if (i == 0)
            fprintf(stderr, "> ");
        else
            fprintf(stderr, "   ");

        if (sym)
        	fprintf(stderr, "0x%lx <%s>:\t%-8s %s\n",insn[i].address, sym,insn[i].mnemonic, op_str_resolved);
	else
		fprintf(stderr, "0x%lx:\t\t%-8s %s\n",insn[i].address,insn[i].mnemonic, op_str_resolved);
        bool is_ret = false;
        for (int g = 0; g < insn[i].detail->groups_count; g++) {
            if (insn[i].detail->groups[g] == CS_GRP_RET) {
                is_ret = true;
                break;
            }
        }
        if (is_ret) break;
    }

    cs_free(insn, count);
}

/* Load the symbol table from the ELF binary's .symtab section */
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
		sym_table[sym_count].size = sym.st_size;
                sym_count++;
            }
        }
    }

    elf_end(elf);
    close(fd);

    fprintf(stderr, "[mdb] loaded %d symbols from %s\n ", sym_count, filename);
}

/* Return the address of a symbol by name, or 0 if not found */
uint64_t find_symbol(const char *name){
    for(int i=0; i < sym_count; i++){
        if(strcmp(sym_table[i].name, name) == 0)
           return sym_table[i].addr;
    }
    return 0;
}

/* Set a breakpoint by symbol name or hex address */
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

/* List all currently set breakpoints with their status */
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

/* Delete breakpoint by 1-based number */
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

pid_t child_pid = -1;


/* Inject INT3 0xCC at each enabled breakpoint address in the child process */
void inject_bp(pid_t pid){
	for(int i=0; i<bp_count; i++){
		if(!bp_table[i].enabled) 
			continue;
		long orig = ptrace(PTRACE_PEEKDATA, pid, (void *)bp_table[i].addr, 0);
		if(orig == -1)
			die("(peekdata) %s", strerror(errno));
		bp_table[i].original_byte = orig;
		
		long mask = (orig & 0xFFFFFFFFFFFFFF00) | 0xCC;
		if(ptrace(PTRACE_POKEDATA, pid, (void *)bp_table[i].addr, (void *)mask) == -1)
				die("(pokedata) %s", strerror(errno));
		fprintf(stderr, "[mdb] breakpoint %d injected at 0x%lx.\n", i+1, bp_table[i].addr);
	}
}


/* Return the index of the breakpoint at addr, or -1 if not found */
int find_bp(uint64_t addr){
	for(int i =0; i < bp_count; i++){
		if(bp_table[i].enabled && bp_table[i].addr == addr)
			return i;
	}
	return -1;
}

/* Continue child execution and wait for a breakpoint hit, exit, or fatal signal */
int wait_for_signal(void) {
    int status;
    if (ptrace(PTRACE_CONT, child_pid, 0, 0) == -1)
        die("(cont) %s", strerror(errno));

    waitpid(child_pid, &status, 0);

    // check if child exited normally
    if (WIFEXITED(status)) {
        fprintf(stderr, "[mdb] process exited with code %d.\n", WEXITSTATUS(status));
        child_pid = -1;
        return 0;
    }

    //Handle SIGSEGV
    if (WIFSIGNALED(status)) {
    	fprintf(stderr, "[mdb] process terminated by signal %d (%s).\n",
        WTERMSIG(status), strsignal(WTERMSIG(status)));
    	child_pid = -1;
    	return 0;
    }

    //check if child was stopped by our SIGTRAP
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1)
            die("(getregs) %s", strerror(errno));

        uint64_t hit_addr = regs.rip - 1;
        int idx = find_bp(hit_addr);

        if (idx == -1) {
            fprintf(stderr, "[mdb] stopped at unknown address 0x%lx.\n", hit_addr);
            return 1;
        }

        fprintf(stderr, "[mdb] hit breakpoint %d: %s at 0x%lx.\n",
            idx + 1, bp_table[idx].symbol, hit_addr);

        // restore orig byte
        if (ptrace(PTRACE_POKEDATA, child_pid, (void *)hit_addr,
                (void *)bp_table[idx].original_byte) == -1)
            die("(pokedata restore) %s", strerror(errno));

        // revert rip to the breakpoint address
        regs.rip = hit_addr;
        if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1)
            die("(setregs) %s", strerror(errno));
        disas_at(child_pid, hit_addr);
	//stopped at breakpoint
	return 1;
    }

    return 1;
}

/* Continue the child process until next breakpoint or exit */
void continue_command(void){
	if(child_pid == -1){
		fprintf(stderr, "No process running. Use 'r' first.\n");
		return;
	}
	wait_for_signal();
}

/* Fork and exec the target binary, inject breakpoints, then run until first stop */
void run_command(const char *filename){
	char full_path[512];
   	if (filename[0] != '/' && !(filename[0] == '.' && filename[1] == '/')) {
        	snprintf(full_path, sizeof(full_path), "./%s", filename);
        	filename = full_path;
    	}
	if(child_pid != -1){
		fprintf(stderr, "Program already runnning.\n");
		return;
	}
	child_pid = fork();
	switch(child_pid){
		case -1:
			die("%s", strerror(errno));
		case 0:
			//child
			ptrace(PTRACE_TRACEME, 0, 0, 0);
			execvp(filename, (char *[]){(char*)filename, NULL});
			die("%s", strerror(errno));
	}

	// Parent
	ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_EXITKILL);
	waitpid(child_pid, 0, 0);
	inject_bp(child_pid);
	fprintf(stderr, "[mdb] process %d started.\n", child_pid);
	wait_for_signal();
}

/* Return the name of the nearest symbol at or before addr */
const char *find_function(uint64_t addr){
	for(int i =0; i < sym_count; i++){
		// exact match
		if(sym_table[i].addr == addr)
			return sym_table[i].name;
	}
	const char *nearest = "??";
	uint64_t nearest_addr = 0;
	for(int i = 0; i < sym_count; i++){
		// range check for functions with known size
		if(sym_table[i].addr <= addr && sym_table[i].addr > nearest_addr){
			nearest_addr = sym_table[i].addr;
			nearest = sym_table[i].name;
		}
	}
	return nearest;
}

/* Execute a single instruction in the child process and print the new RIP */
void step_command(void){
	if(child_pid == -1){
		fprintf(stderr, "No process running. Use 'r' first.\n");
		return;
	}

	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1)
		die("(getregs) %s", strerror(errno));
	
	if(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) == -1)
		die("(singlestep) %s", strerror(errno));

	int status;
	waitpid(child_pid, &status, 0);

	if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1)
		die("(getregs) %s", strerror(errno));

	fprintf(stderr, "0x%llx in %s ()\n", regs.rip, find_function(regs.rip));
}


/* Print disassembly from the current RIP of the child process */
void disas_command(void){
	if(child_pid == -1){
		fprintf(stderr, "No process runnig. Use 'r' first.\n");
		return;
	}

	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1)
		die("(getregs) %s", strerror(errno));

	disas_at(child_pid, regs.rip);
}

/* Main REPL: read and dispatch commands until EOF or 'q' */
void command_loop(const char *filename){
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
           		run_command(filename);
		} 
		else if (strcmp(line, "c") == 0) {
            		// continue
            		continue_command();
        	}
		else if (strcmp(line, "si") == 0){
			step_command();
		}
		else if (strcmp(line, "disas") == 0){
			disas_command();
		}
	     	else if (strcmp(line, "q") == 0) {
            		fprintf(stderr, "Bye\n");
            		exit(0);
        	}
		else if (line[0] != '\0') {
            		fprintf(stderr, "Unknown command: %s\n", line);
            		fprintf(stderr, "Commands: b <sym|*addr>, l, d <n>, r, c, si, disas, q\n");
        	}
	}
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("usage: mdb <program>");

    load_symbols(argv[1]);

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK)
	    die("Failed to initialise Capstone");

    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_option(cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    command_loop(argv[1]);

    return 0;
}
