#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/personality.h>

//TODO: option: reverse roles after exec, so child traces parent, see strace "--daemonize=grandchild" option
//TODO: option: detach but tracee stopped to make it traceable by other tracer
//TODO: test to read "invalid" memory regions

void print_maps(pid_t pid, FILE *output_file) {

    char maps_path[100];
    memset(maps_path, 0, 100);
    snprintf(maps_path, 99, "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) {
        perror("fopen(\"/proc/PID/maps\")");
        return;
    }

    char buffer[512];
    size_t read = 0;
    size_t write = 0;
    size_t towrite = 0;
    do {
        read = fread(buffer, 1, 512, maps);
        if (read > 0) {
            // something was read
            write = 0;
            towrite = 0;
            do {
                write = fwrite(&buffer[towrite], 1, read-towrite, output_file);
                if (write < (read-towrite)) {
                    // error
                    int error = ferror(maps);
                    if (error != 0) {
                        perror("fwrite");
                        fclose(maps);
                        return;
                    }
                }
                towrite += write;
            } while(towrite < read);
        }
        if (read < 512) {
            // eof or error
            int eof = feof(maps);
            if (eof != 0) {
                break;
            }
            int error = ferror(maps);
            if (error != 0) {
                perror("fread(\"/proc/PID/maps\")");
                fclose(maps);
                return;
            }
        }
    } while(read > 0);
    fclose(maps);
}

void print_hex(uint8_t *number, int size, FILE *restrict out) {
    for(int i=size-1; i>=0; i--) {
        uint8_t n = number[i];
        char c = (n>>4)+48;
        c = c>57 ? c+39 : c;
        fputc(c, out);
        c = (n&15) + 48;
        c = c>57 ? c+39 : c;
        fputc(c, out);
    }
}

void print_hex_rev(uint8_t *number, int size, FILE *restrict out) {
    for(int i=0; i<=size-1; i++) {
        uint8_t n = number[i];
        char c = (n>>4)+48;
        c = c>57 ? c+39 : c;
        fputc(c, out);
        c = (n&15) + 48;
        c = c>57 ? c+39 : c;
        fputc(c, out);
    }
}

void print_hex_nolead(uint8_t *number, int size, FILE *restrict out) {
    bool lead = 1;
    for(int i=size-1; i>=0; i--) {
        uint8_t n = number[i];
        char c = (n>>4)+48;
        c = c>57 ? c+39 : c;
        if (c != 48 || lead == 0) {
            lead = 0;
            fputc(c, out);
        }
        c = (n&15) + 48;
        c = c>57 ? c+39 : c;
        if (c != 48 || lead == 0) {
            lead = 0;
            fputc(c, out);
        }
    }
}

void print_hex_nolead_rev(uint8_t *number, int size, FILE *restrict out) {
    bool lead = 1;
    for(int i=0; i<=size-1; i++) {
        uint8_t n = number[i];
        char c = (n>>4)+48;
        c = c>57 ? c+39 : c;
        if (c != 48 || lead == 0) {
            lead = 0;
            fputc(c, out);
        }
        c = (n&15) + 48;
        c = c>57 ? c+39 : c;
        if (c != 48 || lead == 0) {
            lead = 0;
            fputc(c, out);
        }
    }
}

void print_help(FILE *f) {
    fputs(
        "iaddrtrace [options] [--] program [arguments]\n"
        "Options:\n"
        "    -s ADDR     -- Comma-separated list of addresses to start the output in hex\n"
        "    -d ADDR     -- Comma-separated list of addresses to stop the output in hex\n"
        "    -o FILE     -- Use FILE instead of stdout\n"
        "    -m FILE     -- Write /proc/PID/maps to FILE\n"
        "    -n          -- Spin instead of waiting\n"
        "    -i          -- Print memory at address\n"
        "    -k          -- Kill tracee on trace end\n"
        "    -p          -- Turn off ASLR\n"
    ,f);
}

static uint8_t *address_start_bytes = 0;
static unsigned long long int *address_start = 0;
static size_t address_start_num = 0;
static unsigned long long int *address_stop = 0;
static size_t address_stop_num = 0;
static FILE *output_file = 0;
static bool opt_kill = false;
static FILE *maps_file = NULL;
static bool spin = false;
static bool print_ins = false;
static bool no_aslr = false;

static int byte_swap(pid_t pid, unsigned long long int addr, uint8_t *save) {
    //fprintf(stderr, "Swap %llx %x\n", addr, *save);
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (data == -1) {
        int error = errno;
        if (error != 0) { // return value maybe actual data, not an error
            fputs("ptrace(PTRACE_PEEKDATA): ", stderr);
            fputs(strerror(error), stderr);
            fputs("\nFailed to peek data at ", stderr);
            print_hex_nolead((uint8_t *) &addr, sizeof(addr), stderr);
            fputc('\n', stderr);
            return -1;
        }
    }
    uint8_t old_byte = (uint8_t) (data & 0xff);
    data = (data & ~0xff) | *save; // exchange lowest byte
    *save = old_byte;
    errno = 0;
    long err = ptrace(PTRACE_POKEDATA, pid, addr, data);
    if (err == -1) {
        int error = errno;
        fputs("ptrace(PTRACE_POKEDATA): ", stderr);
        fputs(strerror(error), stderr);
        fputs("\nFailed to poke data at ", stderr);
        print_hex_nolead((uint8_t *) &addr, sizeof(addr), stderr);
        fputc('\n', stderr);
        return -1;
    }
    return 0;
}

static int breakpoints_enable(pid_t pid, unsigned long long int *list, size_t num, uint8_t** save) {
    if (num == 0) {
        *save = NULL;
        return 0;
    }
    *save = (uint8_t*) calloc(num, sizeof(uint8_t));
    if (*save == NULL) {
        fputs("Out of memory\n", stderr);
        exit(1);
    }
    size_t i = 0;
    int err = 0;
    for (i = 0; i<num; i++) {
        (*save)[i] = 0xcc; // int3
        err = byte_swap(pid, list[i], &((*save)[i]));
        if (err != 0) {
            return -1;
        }
    }
    return 0;
}

static int breakpoints_disable(pid_t pid, unsigned long long int *list, size_t num, uint8_t** save) {
    if (num == 0) {
        *save = NULL;
        return 0;
    }
    size_t i = 0;
    int err = 0;
    for (i = 0; i<num; i++) {
        err = byte_swap(pid, list[i], &((*save)[i]));
        if (err != 0) {
            return -1;
        }
    }
    free(*save);
    *save = NULL;
    return 0;
}

static int in_address_list(unsigned long long int *list, size_t num, unsigned long long int needle) {
    size_t i=0;
    for (i=0; i<num; i++) {
        //fprintf(stderr, "CMP %llx %llx\n", list[i], needle);
        if (list[i] == needle) {
            return 1;
        }
    }
    return 0;
}

static void parse_address_list(const char *in_list, unsigned long long int **out_list, size_t *num) {
    /* count comma-separated segments */
    size_t segments = 0;
    {
        const char *seg = in_list;
        const char *found = in_list;
        while((found = strchr(seg, ',')) != NULL) {
            segments++;
            seg = found+1;
        }
        segments++;
    }
    if (segments == 0) {
        *num = 0;
        *out_list = NULL;
        return;
    }
    /* allocate list */
    *out_list = (unsigned long long int *) calloc(segments, sizeof(unsigned long long int));
    if (*out_list == NULL) {
        fputs("Out of memory\n", stderr);
        exit(1);
    }
    /* try to parse each segment */
    size_t i = 0;
    char *str = strdup(in_list);
    char *seg_next = str;
    char *token = NULL;
    char *endptr = NULL;
    for(i = 0; i < segments; i++) {
        token = strsep(&seg_next, ",");
        if (token == NULL) {
            fputs("Invalid option ", stderr);
            fputs(in_list, stderr);
            fputc('\n', stderr);
            exit(1);
        }
        (*out_list)[i] = strtoull(token, &endptr, 16);
        if (*endptr != 0) {
            fputs("Invalid address ", stderr);
            fputs(token, stderr);
            fputc('\n', stderr);
            exit(1);
        }
    }
    free(str);
    *num = segments;
}

int main(int argc, char** argv) {

    if (argc < 2) {
        print_help(stderr);
        exit(1);
    }

    int argv_program_index = 1;
    {
        int opt;
        while ((opt = getopt(argc, argv, "+hkpins:d:m:o:")) != -1) {
            switch(opt) {
                case 's':
                {
                    if (*optarg == '-') {
                        fputs("Invalid option s\n", stderr);
                        exit(1);
                    }
                    parse_address_list(optarg, &address_start, &address_start_num);
                }
                break;
                case 'd':
                {
                    if (*optarg == '-') {
                        fputs("Invalid option d\n", stderr);
                        exit(1);
                    }
                    parse_address_list(optarg, &address_stop, &address_stop_num);
                }
                break;
                case 'm':
                {
                    errno = 0;
                    maps_file = fopen(optarg, "a");
                    if (maps_file == NULL) {
                        perror("fopen");
                        fputs("Failed to open maps file: ", stderr);
                        fputs(optarg, stderr);
                        fputc('\n', stderr);
                        exit(1);
                    }
                }
                break;
                case 'n':
                {
                    spin = true;
                }
                break;
                case 'i':
                {
                    print_ins = true;
                }
                break;
                case 'p':
                {
                    no_aslr = true;
                }
                break;
                case 'o':
                {
                    errno = 0;
                    output_file = fopen(optarg, "w");
                    if (output_file == NULL) {
                        perror("fopen");
                        fputs("Failed to open output file: ", stderr);
                        fputs(optarg, stderr);
                        fputc('\n', stderr);
                        exit(1);
                    }
                }
                break;

                case 'k':
                    opt_kill = true;
                break;
                case '?':
                    exit(1);
                break;
                case ':':
                    fputs("Missing argument for option: ", stderr);
                    fputc(optopt, stderr);
                    fputc('\n', stderr);
                    exit(1);
                break;
                case 'h':
                default:
                    print_help(stderr);
                    exit(1);
                break;
            }
        }
        argv_program_index = optind;
        if (argv_program_index == argc) {
            fputs("No program\n", stderr);
            exit(1);
        }
    }

    if (output_file == 0) {
        output_file = stdout;
    }

    fputs("# program: ", output_file);
    {
        int i = 0;
        for (i = argv_program_index; i<argc; i++) {
            fputs(argv[i], output_file);
            fputc(' ', output_file);
        }
    }
    fputc('\n', output_file);
    fputs("# start:", output_file);
    {
        size_t i = 0;
        for(i = 0; i<address_start_num; i++) {
            fputc(' ', output_file);
            print_hex_nolead((uint8_t *) &address_start[i], sizeof(address_start[i]), output_file);
        }
    }
    fputc('\n', output_file);
    fputs("# stop:", output_file);
    {
        size_t i = 0;
        for(i = 0; i<address_stop_num; i++) {
            fputc(' ', output_file);
            print_hex_nolead((uint8_t *) &address_stop[i], sizeof(address_stop[i]), output_file);
        }
    }
    fputc('\n', output_file);
    fprintf(output_file, "# tracer pid: %d\n", getpid());

    fflush(output_file);
    // fork and exec tracee
    errno = 0;
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }
    if (pid == 0) {
        // child
        long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (ret != 0) {
            perror("ptrace(PTRACE_TRACEME)");
        }
        if (no_aslr == true) {
            errno = 0;
            int err = personality(ADDR_NO_RANDOMIZE);
            if (err == -1) {
                perror("personality(ADDR_NO_RANDOMIZE)");
            }
        }
        errno = 0;
        execvp(argv[argv_program_index], &argv[argv_program_index]);
        perror("exec");
        exit(1);
    }

    // parent
    fprintf(output_file, "# tracee pid: %d\n", pid);
    int waitstatus = 0;
    pid_t werr = waitpid(pid, &waitstatus, 0);
    long ret = 0;
    int error = 0;
    int detach = 0;

    // Options: stop on tracee exit (to print tracee maps) and kill tracee on tracer exit
    ret = ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL);
    if (ret != 0) {
        perror("ptrace(PTRACE_SETOPTIONS)");
        error = 1;
        goto done;
    }

    // debug loop 
    struct user_regs_struct regs;
    int started = 1;
    if (address_start != NULL) {
        started = 0;
    }
    int cont = 0;
    breakpoints_enable(pid, address_start, address_start_num, &address_start_bytes);
    int breakpoints = 1;
    if (started == 0) {
        ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
        if (ret != 0) {
            perror("ptrace(PTRACE_CONT)");
            error = 1;
            goto done;
        }
        werr = waitpid(pid, &waitstatus, 0);
        if (werr == -1) {
            if (errno == EINTR) {
                fputs("# EINTR\n", output_file);
            } else {
                fputs("# ", output_file);
                fputs(strerror(errno), output_file);
                fputc('\n', output_file);
                error = 1;
                goto done;
            }
        }
    }

    while(WIFEXITED(waitstatus) == 0 && WIFSIGNALED(waitstatus) == 0) {
        errno = 0;
        if (cont == 0) {
            ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (ret != 0) {
                perror("ptrace(PTRACE_GETREGS)");
                error = 1;
                goto done;
            }
            //printf("stop %llx\n", regs.rip);
            
            if (started == 0) {
                // check if start condition is met
                if (in_address_list(address_start, address_start_num, regs.rip-1) == 1) {
                    //fprintf(stderr, "Found start address %llx\n", regs.rip-1);
                    // Disable breakpoint
                    if (breakpoints == 1) {
                        breakpoints_disable(pid, address_start, address_start_num, &address_start_bytes);
                        breakpoints = 0;
                    }
                    // Interrupt sets rip to start address + 1
                    // Reset rip to rip-1
                    regs.rip = regs.rip-1;
                    ret = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                    if (ret != 0) {
                        perror("ptrace(PTRACE_SETREGS)");
                        error = 1;
                        goto done;
                    }
                    started = 1;
                }
            } 
            if (started == 1) {
                print_hex_nolead((uint8_t *) &regs.rip, sizeof(regs.rip), output_file);
                if (print_ins == true) {
                    errno = 0;
                    long ins = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL);
                    fputc(' ', output_file);
                    print_hex_rev((uint8_t *) &ins, sizeof(ins), output_file);
                }

                fputc('\n', output_file);
                // check if stop condition is met
                if (in_address_list(address_stop, address_stop_num, regs.rip) == 1) {
                    started = 0;
                    cont = 1;
                    detach = 1;
                    goto done;
                }
            }
        }

        // Last instruction, print maps
        if (waitstatus>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))) {
            goto done;
        }

        if (cont == 0) {
            ret = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            if (ret != 0) {
                perror("ptrace(PTRACE_SINGLESTEP)");
                error = 1;
                goto done;
            }
        }

            if (spin == true) {

                werr = 0;
                waitstatus = 0;

                do {
// Backoff, increases user time, decreases system time
//                unsigned long spinwait = 1000;
//                    for (unsigned long w=0; w<spinwait; w++) {
//                        asm("nop");
//                        asm("nop");
//                        asm("nop");
//                        asm("nop");
//                        asm("nop");
//                    }
                    werr = waitpid(pid, &waitstatus, WNOHANG);
                } while(werr == 0);
            } else {
                // wait
                werr = waitpid(pid, &waitstatus, 0);
            }
            if (werr == -1) {
                if (errno == EINTR) {
                    fputs("# EINTR\n", output_file);
                } else {
                    fputs("# ", output_file);
                    fputs(strerror(errno), output_file);
                    fputc('\n', output_file);
                    error = 1;
                    goto done;
                }
            }

            if(WIFEXITED(waitstatus) != 0 || WIFSIGNALED(waitstatus) != 0) {
                break;
            }

    }


    done:
        fputs("# exit", output_file);
        fputc('\n', output_file);
        // print tracee maps
        if (pid != -1) {
            fflush(output_file);
            if (maps_file != NULL) {
                print_maps(pid, maps_file);
                fflush(maps_file);
                fclose(maps_file);
                maps_file = NULL;
            }
        }
        if (detach == 1 && opt_kill == false) {
            ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
            if (ret != 0) {
                perror("ptrace(PTRACE_DETACH)");
                error = 1;
            }
        }
        if ((detach == 1 && opt_kill == true) || (error == 1 && pid != -1)) {
            int iret = kill(pid, SIGKILL);
            if (iret != 0) {
                perror("kill(SIGKILL)");
            }
        }
        fputs("# done", output_file);
        fputc('\n', output_file);
        fflush(output_file);

        if (output_file != stdout && output_file != NULL) {
            fclose(output_file);
        }

    return 0;
}
