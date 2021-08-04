#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/personality.h>

//TODO: Check every ptrace return value
//TODO: Kill tracee on error

void print_help(FILE *f) {
    fprintf(f, "iaddrtrace [options] [--] program [arguments]\n");
    fprintf(f, "Options:\n");
    fprintf(f, "    -s ADDR     -- Comma-separated list of addresses to start the output in hex\n");
    fprintf(f, "    -d ADDR     -- Comma-separated list of addresses to stop the output in hex\n");
    fprintf(f, "    -o FILE     -- Use FILE instead of stderr\n");
}

static uint8_t *address_start_bytes = 0;
static unsigned long long int *address_start = 0;
static size_t address_start_num = 0;
static unsigned long long int *address_stop = 0;
static size_t address_stop_num = 0;
static FILE *output_file = 0;

static int byte_swap(pid_t pid, unsigned long long int addr, uint8_t *save) {
    //fprintf(stderr, "Swap %llx %x\n", addr, *save);
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (data == -1) {
        int error = errno;
        if (error != 0) { // return value maybe actual data, not an error
            fprintf(stderr, "Failed to peek data at %llx: %s\n", addr, strerror(error));
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
        fprintf(stderr, "Failed to poke data at %llx: %s\n", addr, strerror(error));
        return -1;
    }
    return 0;
}

static int breakpoints_enable(pid_t pid, unsigned long long int *list, size_t num, uint8_t** save) {
    *save = (uint8_t*) calloc(num, sizeof(uint8_t));
    if (*save == NULL) {
        fprintf(stderr, "Out of memory\n");
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
    /* allocate list */
    *out_list = (unsigned long long int *) calloc(segments, sizeof(unsigned long long int));
    if (*out_list == NULL) {
        fprintf(stderr, "Out of memory\n");
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
            fprintf(stderr, "Invalid option %s\n", in_list);
            exit(1);
        }
        (*out_list)[i] = strtoull(token, &endptr, 16);
        if (*endptr != 0) {
            fprintf(stderr, "Invalid address %s\n", token);
            exit(1);
        }
    }
    free(str);
    *num = segments;
}

int main(int argc, char** argv) {

    int argv_program_index = 1;
    {
        int opt;
        while ((opt = getopt(argc, argv, "+hs:d:o:")) != -1) {
            switch(opt) {
                case 's':
                {
                    if (*optarg == '-') {
                        fprintf(stderr, "Invalid option s\n");
                        exit(1);
                    }
                    parse_address_list(optarg, &address_start, &address_start_num);
                }
                break;
                case 'd':
                {
                    if (*optarg == '-') {
                        fprintf(stderr, "Invalid option d\n");
                        exit(1);
                    }
                    parse_address_list(optarg, &address_stop, &address_stop_num);
                }
                break;
                case 'o':
                    errno = 0;
                    output_file = fopen(optarg, "w");
                    if (output_file == NULL) {
                        int error = errno;
                        errno = 0;
                        fprintf(stderr, "Error on opening the output file: %s %s\n", optarg, strerror(error));
                        exit(1);
                    }
                break;
                case '?':
                    exit(1);
                break;
                case ':':
                    fprintf(stderr, "Missing argument for option: %c\n", optopt);
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
            fprintf(stderr, "No program\n");
            exit(1);
        }
    }

    if (output_file == 0) {
        output_file = stderr;
    }

    fprintf(output_file, "# program: ");
    {
        int i = 0;
        for (i = argv_program_index; i<argc; i++) {
            fprintf(output_file, "%s ", argv[i]);
        }
    }
    fprintf(output_file, "\n");
    fprintf(output_file, "# start:");
    {
        size_t i = 0;
        for(i = 0; i<address_start_num; i++) {
            fprintf(output_file, " %llx",address_start[i]);
        }
    }
    fprintf(output_file, "\n");
    fprintf(output_file, "# stop:");
    {
        size_t i = 0;
        for(i = 0; i<address_stop_num; i++) {
            fprintf(output_file, " %llx", address_stop[i]);
        }
    }
    fprintf(output_file, "\n");
    fflush(output_file);

    errno = 0;
    pid_t pid = fork();
    if (pid == -1) {
        int error = errno;
        errno = 0;
        fprintf(stderr, "Failed to fork: %s\n", strerror(error));
        if (output_file != stderr && output_file != NULL) {
            fclose(output_file);
        }
        exit(1);
    }
    if (pid == 0) {
        // child
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        errno = 0;
        int err = personality(ADDR_NO_RANDOMIZE);
        if (err == -1) {
            fprintf(stderr, "Failed to set personality: %s\n", strerror(errno));
        }
        errno = 0;
        execvp(argv[argv_program_index], &argv[argv_program_index]);
        fprintf(stderr, "Failed to exec: %s\n", strerror(errno));
        exit(1);
    }

    // parent
    int waitstatus = 0;
    pid_t werr = waitpid(pid, &waitstatus, 0);

    // debug loop 
    struct user_regs_struct regs;
    int started = 1;
    if (address_start != NULL) {
        started = 0;
    }
    int cont = 0;
    breakpoints_enable(pid, address_start, address_start_num, &address_start_bytes);
    int breakpoints = 1;
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    while(WIFEXITED(waitstatus) == 0 && WIFSIGNALED(waitstatus) == 0) {
        errno = 0;
        werr = waitpid(pid, &waitstatus, 0);
        if (werr == -1) {
            if (errno == EINTR) {
                fprintf(output_file, "# EINTR\n");
            } else {
                fprintf(output_file, "# %s\n", strerror(errno));
            }
        }
        if(WIFEXITED(waitstatus) != 0 || WIFSIGNALED(waitstatus) != 0) {
            break;
        }
        if (cont == 0) {
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            //fprintf(output_file, "stop %llx\n", regs.rip);
            
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
                    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                    started = 1;
                }
            } 
            if (started == 1) {
                fprintf(output_file, "%llx\n", regs.rip);
                // check if stop condition is met
                if (in_address_list(address_stop, address_stop_num, regs.rip) == 1) {
                    started = 0;
                    fflush(output_file);
                    cont = 1;
                    ptrace(PTRACE_DETACH, pid, NULL, NULL);
                }
            }
        }
        if (cont == 0) {
            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        }
    }

    fprintf(output_file, "# done\n");
    fflush(output_file);

    if (output_file != stderr && output_file != NULL) {
        fclose(output_file);
    }

    return 0;
}
