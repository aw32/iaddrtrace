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

#define ERROR_PRINTF(...) fprintf(stderr, "%s:%d = %d %s : ", __func__, __LINE__, errno, strerror(errno)); fprintf(stderr, __VA_ARGS__);

void print_maps(pid_t pid, FILE *output_file) {

    char maps_path[100];
    memset(maps_path, 0, 100);
    snprintf(maps_path, 99, "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) {
        ERROR_PRINTF("fopen %s\n", maps_path);
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
                        ERROR_PRINTF("fwrite to %s\n", maps_path);
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
                ERROR_PRINTF("fread from %s\n", maps_path);
                fclose(maps);
                return;
            }
        }
    } while(read > 0);
    fclose(maps);
}

int print_hex(uint8_t *number, int size, FILE *restrict out) {
    for(int i=size-1; i>=0; i--) {
        uint8_t n = number[i];
        char c = (n>>4)+48;
        c = c>57 ? c+39 : c;
        if (fputc(c, out) == EOF) {
            ERROR_PRINTF("fputc\n");
            return -1;
        }
        c = (n&15) + 48;
        c = c>57 ? c+39 : c;
        if (fputc(c, out) == EOF) {
            ERROR_PRINTF("fputc\n");
            return -1;
        }
    }
    return 0;
}

int print_hex_rev(uint8_t *number, int size, FILE *restrict out) {
    for(int i=0; i<=size-1; i++) {
        uint8_t n = number[i];
        char c = (n>>4)+48;
        c = c>57 ? c+39 : c;
        if (fputc(c, out) == EOF) {
            ERROR_PRINTF("fputc\n");
            return -1;
        }
        c = (n&15) + 48;
        c = c>57 ? c+39 : c;
        if (fputc(c, out) == EOF) {
            ERROR_PRINTF("fputc\n");
            return -1;
        }
    }
    return 0;
}

int print_hex_nolead(uint8_t *number, int size, FILE *restrict out) {
    bool lead = 1;
    for(int i=size-1; i>=0; i--) {
        uint8_t n = number[i];
        char c = (n>>4)+48;
        c = c>57 ? c+39 : c;
        if (c != 48 || lead == 0) {
            lead = 0;
            if (fputc(c, out) == EOF) {
                ERROR_PRINTF("fputc\n");
                return -1;
            }
        }
        c = (n&15) + 48;
        c = c>57 ? c+39 : c;
        if (c != 48 || lead == 0) {
            lead = 0;
            if (fputc(c, out) == EOF) {
                ERROR_PRINTF("fputc\n");
                return -1;
            }
        }
    }
    return 0;
}

int print_hex_nolead_rev(uint8_t *number, int size, FILE *restrict out) {
    bool lead = 1;
    for(int i=0; i<=size-1; i++) {
        uint8_t n = number[i];
        char c = (n>>4)+48;
        c = c>57 ? c+39 : c;
        if (c != 48 || lead == 0) {
            lead = 0;
            if (fputc(c, out) == EOF) {
                ERROR_PRINTF("fputc\n");
                return -1;
            }
        }
        c = (n&15) + 48;
        c = c>57 ? c+39 : c;
        if (c != 48 || lead == 0) {
            lead = 0;
            if (fputc(c, out) == EOF) {
                ERROR_PRINTF("fputc\n");
                return -1;
            }
        }
    }
    return 0;
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
        "    -p          -- Keep ASLR on\n"
    ,f);
}

static uint8_t *address_start_bytes = NULL;
static unsigned long long int *address_start = NULL;
static size_t address_start_num = 0;
static unsigned long long int *address_stop = NULL;
static size_t address_stop_num = 0;
static FILE *output_file = NULL;
static char *output_file_path = NULL;
static bool opt_kill = false;
static FILE *maps_file = NULL;
static char *maps_file_path = NULL;
static bool spin = false;
static bool print_ins = false;
static bool keep_aslr = false;
static pid_t pid = -1;

static int byte_swap(pid_t pid, unsigned long long int addr, uint8_t *save) {
    //fprintf(stderr, "Swap %llx %x\n", addr, *save);
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (data == -1) {
        int error = errno;
        if (error != 0) { // return value maybe actual data, not an error
            ERROR_PRINTF("ptrace(PTRACE_PEEKDATA) Failed to peek data at %llx\n", addr);
            return -1;
        }
    }
    uint8_t old_byte = (uint8_t) (data & 0xff);
    data = (data & ~0xff) | *save; // exchange lowest byte
    *save = old_byte;
    errno = 0;
    long err = ptrace(PTRACE_POKEDATA, pid, addr, data);
    if (err == -1) {
        ERROR_PRINTF("ptrace(PTRACE_POKEDATA) Failed to poke data at %llx\n", addr);
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
        ERROR_PRINTF("calloc %ld bytes Out of memoy\n", num * sizeof(uint8_t));
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
        ERROR_PRINTF("calloc %ld bytes Out of memoy\n", segments * sizeof(unsigned long long int));
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
            ERROR_PRINTF("Invalid option %s\n", in_list);
            exit(1);
        }
        (*out_list)[i] = strtoull(token, &endptr, 16);
        if (*endptr != 0) {
            ERROR_PRINTF("Invalid address %s\n", token);
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
                    maps_file_path = optarg;
                    maps_file = fopen(optarg, "a");
                    if (maps_file == NULL) {
                        ERROR_PRINTF("fopen Failed to open maps file %s\n", optarg);
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
                    keep_aslr = true;
                }
                break;
                case 'o':
                {
                    errno = 0;
                    output_file_path = optarg;
                    output_file = fopen(optarg, "w");
                    if (output_file == NULL) {
                        ERROR_PRINTF("fopen Failed to open output file %s\n", optarg);
                        goto cleanup;
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
                    goto cleanup;
                break;
                case 'h':
                default:
                    print_help(stderr);
                    goto cleanup;
                break;
            }
        }
        argv_program_index = optind;
        if (argv_program_index == argc) {
            fputs("No program\n", stderr);
            exit(1);
        }
    }

    if (output_file == NULL) {
        output_file = stdout;
    }

    if(fputs("# program: ", output_file) == EOF) {
        ERROR_PRINTF("fputs: write to %s\n", output_file_path);
        goto cleanup;
    }
    {
        int i = 0;
        for (i = argv_program_index; i<argc; i++) {
            if (fputs(argv[i], output_file) == EOF) {
                ERROR_PRINTF("fputs: write to %s\n", output_file_path);
                goto cleanup;
            }
            if (fputc(' ', output_file) == EOF) {
                ERROR_PRINTF("fputc: write to %s\n", output_file_path);
                goto cleanup;
            }
        }
    }
    if (fputc('\n', output_file) == EOF) {
        ERROR_PRINTF("fputc: write to %s\n", output_file_path);
        goto cleanup;
    }
    if (fputs("# start:", output_file) == EOF) {
        ERROR_PRINTF("fputs: write to %s\n", output_file_path);
        goto cleanup;
    }
    {
        size_t i = 0;
        for(i = 0; i<address_start_num; i++) {
            if (fputc(' ', output_file) == EOF) {
                ERROR_PRINTF("fputc: write to %s\n", output_file_path);
                goto cleanup;
            }
            if (print_hex_nolead((uint8_t *) &address_start[i], sizeof(address_start[i]), output_file) != 0) {
                goto cleanup;
            }
        }
    }
    fputc('\n', output_file);
    fputs("# stop:", output_file);
    {
        size_t i = 0;
        for(i = 0; i<address_stop_num; i++) {
            if (fputc(' ', output_file) == EOF) {
                ERROR_PRINTF("fputc: write to %s\n", output_file_path);
                goto cleanup;
            }
            if (print_hex_nolead((uint8_t *) &address_stop[i], sizeof(address_stop[i]), output_file) != 0) {
                goto cleanup;
            }
        }
    }
    if (fputc('\n', output_file) == EOF) {
        ERROR_PRINTF("fputc: write to %s\n", output_file_path);
        goto cleanup;
    }
    if (fprintf(output_file, "# tracer pid: %d\n", getpid()) == EOF) {
        ERROR_PRINTF("fprintf: write to %s\n", output_file_path);
        goto cleanup;
    }

    if (fflush(output_file) == EOF) {
        ERROR_PRINTF("fflush: write to %s\n", output_file_path);
        goto cleanup;
    }
    // fork and exec tracee
    errno = 0;
    pid = fork();
    if (pid == -1) {
        ERROR_PRINTF("fork\n");
        goto cleanup;
    }
    if (pid == 0) {
        // child
        long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (ret != 0) {
            ERROR_PRINTF("ptrace(PTRACE_TRACEME)\n");
            exit(1);
        }
        if (keep_aslr == false) {
            errno = 0;
            int err = personality(ADDR_NO_RANDOMIZE);
            if (err == -1) {
                ERROR_PRINTF("personality(ADDR_NO_RANDOMIZE)\n");
                exit(1);
            }
        }
        errno = 0;
        execvp(argv[argv_program_index], &argv[argv_program_index]);
        ERROR_PRINTF("execvp\n");
        exit(1);
    }

    // parent
    if (fprintf(output_file, "# tracee pid: %d\n", pid) == EOF) {
        ERROR_PRINTF("fprintf: write to %s\n", output_file_path);
        goto cleanup;
    }
    int waitstatus = 0;
    pid_t werr = waitpid(pid, &waitstatus, 0);
    long ret = 0;

    // Options: stop on tracee exit (to print tracee maps) and kill tracee on tracer exit
    int options = PTRACE_O_TRACEEXIT;
    if (opt_kill == true) {
        options |= PTRACE_O_EXITKILL;
    }
    ret = ptrace(PTRACE_SETOPTIONS, pid, NULL, options);
    if (ret != 0) {
        ERROR_PRINTF("ptrace(PTRACE_SETOPTIONS)\n");
        goto cleanup;
    }

    // debug loop 
    struct user_regs_struct regs;
    int started = 1;
    if (address_start != NULL) {
        started = 0;
    }
    int cont = 0;
    ret = breakpoints_enable(pid, address_start, address_start_num, &address_start_bytes);
    if (ret != 0) {
        ERROR_PRINTF("breakpoints_enable Failed to activate breakpoints. Are the start addresses correct?\n");
        goto cleanup;
    }
    int breakpoints = 1;
    if (started == 0) {
        ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
        if (ret != 0) {
            ERROR_PRINTF("ptrace(PTRACE_CONT)\n");
            goto cleanup;
        }
        werr = waitpid(pid, &waitstatus, 0);
        if (werr == -1) {
            if (errno == EINTR) {
                if (fputs("# EINTR\n", output_file) == EOF) {
                    ERROR_PRINTF("fputs: write to %s\n", output_file_path);
                    goto cleanup;
                }
            } else {
                if (fprintf(output_file, "# %s\n", strerror(errno)) < 0) {
                    ERROR_PRINTF("fprintf: write to %s\n", output_file_path);
                }
                goto cleanup;
            }
        }
    }

    while(WIFEXITED(waitstatus) == 0 && WIFSIGNALED(waitstatus) == 0) {
        errno = 0;
        if (cont == 0) {
            ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (ret != 0) {
                ERROR_PRINTF("ptrace(PTRACE_GETREGS)\n");
                goto cleanup;
            }
            //printf("stop %llx\n", regs.rip);
            
            if (started == 0) {
                // check if start condition is met
                if (in_address_list(address_start, address_start_num, regs.rip-1) == 1) {
                    //fprintf(stderr, "Found start address %llx\n", regs.rip-1);
                    // Disable breakpoint
                    if (breakpoints == 1) {
                        if (breakpoints_disable(pid, address_start, address_start_num, &address_start_bytes) != 0) {
                            ERROR_PRINTF("breakpoints_disable Failed to deactivate breakpoints.\n");
                            goto cleanup;
                        }
                        breakpoints = 0;
                    }
                    // Interrupt sets rip to start address + 1
                    // Reset rip to rip-1
                    regs.rip = regs.rip-1;
                    ret = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                    if (ret != 0) {
                        ERROR_PRINTF("ptrace(PTRACE_SETREGS)\n");
                        goto cleanup;
                    }
                    started = 1;
                }
            } 
            if (started == 1) {
                print_hex_nolead((uint8_t *) &regs.rip, sizeof(regs.rip), output_file);
                if (print_ins == true) {
                    errno = 0;
                    long ins = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL);
                    if (ins < 0 && errno != 0) {
                        ERROR_PRINTF("ptrace(PTRACE_PEEKTEXT)\n");
                    }
                    if (fputc(' ', output_file) == EOF) {
                        ERROR_PRINTF("fputc: write to %s\n", output_file_path);
                        goto cleanup;
                    }
                    if (print_hex_rev((uint8_t *) &ins, sizeof(ins), output_file) != 0) {
                        goto cleanup;
                    }
                }

                if (fputc('\n', output_file) == EOF) {
                    ERROR_PRINTF("fputc: write to %s\n", output_file_path);
                    goto cleanup;
                }
                // check if stop condition is met
                if (in_address_list(address_stop, address_stop_num, regs.rip) == 1) {
                    started = 0;
                    cont = 1;
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
                ERROR_PRINTF("ptrace(PTRACE_SINGLESTEP)\n");
                goto cleanup;
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
                    if (fputs("# EINTR\n", output_file) == EOF) {
                        ERROR_PRINTF("fputs: write to %s\n", output_file_path);
                        goto cleanup;
                    }
                } else {
                    if (fprintf(output_file, "# %s\n", strerror(errno)) < 0) {
                        ERROR_PRINTF("fprintf: write to %s\n", output_file_path);
                    }
                    goto cleanup;
                }
            }

            if(WIFEXITED(waitstatus) != 0 || WIFSIGNALED(waitstatus) != 0) {
                break;
            }

    }


    done:
        if (fputs("# exit", output_file) == EOF) {
            ERROR_PRINTF("fputs: write to %s\n", output_file_path);
        }
        if (fputc('\n', output_file) == EOF) {
            ERROR_PRINTF("fputc: write to %s\n", output_file_path);
        }
        // print tracee maps
        if (pid != -1) {
            if (fflush(output_file) == EOF) {
                ERROR_PRINTF("fflush: write to %s\n", output_file_path);
            } else
            if (maps_file != NULL) {
                print_maps(pid, maps_file);
                if (fflush(maps_file) == EOF) {
                    ERROR_PRINTF("fflush: write to %s\n", maps_file_path);
                }
            }
        }
        if (fputs("# done", output_file) == EOF) {
            ERROR_PRINTF("fputs: write to %s\n", output_file_path);
        }
        if (fputc('\n', output_file) == EOF) {
            ERROR_PRINTF("fputc: write to %s\n", output_file_path);
        }
        if (fflush(output_file) == EOF) {
            ERROR_PRINTF("fflush: write to %s\n", output_file_path);
        }
    cleanup:
        if (pid != -1) {
            if (opt_kill == false) {
                // continue tracee and detach
                ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
                if (ret != 0) {
                    ERROR_PRINTF("ptrace(PTRACE_DETACH)\n");
                }
            } else {
                int iret = kill(pid, SIGKILL);
                if (iret != 0) {
                    ERROR_PRINTF("kill(SIGKILL)\n");
                }
            }
        }
        if (output_file != stdout && output_file != NULL) {
            fclose(output_file);
        }
        if (maps_file != NULL) {
            fclose(maps_file);
            maps_file = NULL;
        }
        if (address_start_bytes != NULL) {
            free(address_start_bytes);
            address_start_bytes = NULL;
        }
        if (address_start != NULL) {
            free(address_start);
            address_start = NULL;
        }
        if (address_stop != NULL) {
            free(address_stop);
            address_stop = NULL;
        }

    return 0;
}
