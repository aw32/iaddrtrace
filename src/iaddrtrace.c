#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/personality.h>

void print_help(FILE *f) {
    fprintf(f, "iaddrtrace [options] [--] program [arguments]\n");
    fprintf(f, "Options:\n");
    fprintf(f, "    -s ADDR     -- Address to start the output in hex\n");
    fprintf(f, "    -d ADDR     -- Address to stop the output in hex\n");
    fprintf(f, "    -o FILE     -- Use FILE instead of stderr\n");
}


static unsigned long long int address_start = 0;
static unsigned long long int address_stop = 0;
static FILE *output_file = 0;

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
                    char *endptr = optarg;
                    address_start = strtoull(optarg, &endptr, 16);
                    if (*optarg != 0 && *endptr != 0) {
                        fprintf(stderr, "Invalid option s\n");
                        exit(1);
                    }
                }
                break;
                case 'd':
                {
                    if (*optarg == '-') {
                        fprintf(stderr, "Invalid option d\n");
                        exit(1);
                    }
                    char *endptr = optarg;
                    address_stop = strtoull(optarg, &endptr, 16);
                    if (*optarg != 0 && *endptr != 0) {
                        fprintf(stderr, "Invalid option d\n");
                        exit(1);
                    }
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
    for (int i = argv_program_index; i<argc; i++) {
        fprintf(output_file, "%s ", argv[i]);
    }
    fprintf(output_file, "\n");
    fprintf(output_file, "# start: %llx\n", address_start);
    fprintf(output_file, "# stop: %llx\n", address_stop);


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
    
    struct user_regs_struct regs;
    int started = 1;
    if (address_start != 0) {
        started = 0;
    }
    do {
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if (regs.rip == address_start) {
            started = 1;
        }
        if (started == 1) {
            fprintf(output_file, "%llx\n", regs.rip);
        }
        if (regs.rip != address_start && regs.rip == address_stop) {
            started = 0;
        }
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        errno = 0;
        werr = waitpid(pid, &waitstatus, 0);
        if (werr == -1) {
            if (errno == EINTR) {
                fprintf(output_file, "# EINTR\n");
            } else {
                fprintf(output_file, "# %s\n", strerror(errno));
            }
        }
    } while(WIFEXITED(waitstatus) == 0 && WIFSIGNALED(waitstatus) == 0);

    fprintf(output_file, "# done\n");

    if (output_file != stderr && output_file != NULL) {
        fclose(output_file);
    }

    return 0;
}
