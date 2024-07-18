#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/SmmServicesTableLib.h>

#include "corctf.h"

const CHAR8 *Flag = "corctf{test_flag_test_flag_test}";

typedef struct
{
    UINT8 Note[16];
}DIARY_NOTE;

#define NUM_PAGES 20

DIARY_NOTE Book[NUM_PAGES];

#define ADD_NOTE 0x1337
#define GET_NOTE 0x1338
#define DUMP_NOTES 0x31337

typedef struct
{
    UINT32 Cmd;
    UINT32 Idx;
    union TRANSFER_DATA
    {
        DIARY_NOTE Note;
        UINT8 *Dest;
    } Data;
}COMM_DATA;

VOID
TransferNote (
    IN DIARY_NOTE *Note,
    IN UINT32 Idx,
    IN BOOLEAN In
    )
{
    if (In)
    {
        CopyMem(&Book[Idx], Note, sizeof(DIARY_NOTE));
    }
    else
    {
        CopyMem(Note, &Book[Idx], sizeof(DIARY_NOTE));
    }
}

VOID
DumpNotes (
    IN UINT8 *Dest
    )
{
    CopyMem(Dest, &Book, sizeof(Book));
}

EFI_STATUS
EFIAPI
CorctfSmmHandler (
    IN EFI_HANDLE  DispatchHandle,
    IN CONST VOID  *Context         OPTIONAL,
    IN OUT VOID    *CommBuffer      OPTIONAL,
    IN OUT UINTN   *CommBufferSize  OPTIONAL
    )
{
    COMM_DATA *CommData = (COMM_DATA *)CommBuffer;

    if (*CommBufferSize != sizeof(COMM_DATA))
    {
        DEBUG((DEBUG_INFO, "Invalid size passed to %a\n", __FUNCTION__));
        DEBUG((DEBUG_INFO, "Expected Size: 0x%lx, got 0x%lx\n", sizeof(COMM_DATA), *CommBufferSize));
        goto Failure;
    }
    
    if ((CommData->Cmd == ADD_NOTE || CommData->Cmd == GET_NOTE) && CommData->Idx >= NUM_PAGES)
    {
        DEBUG((DEBUG_INFO, "Invalid idx passed to %a\n", __FUNCTION__));
        goto Failure;
    }

    switch (CommData->Cmd)
    {
        case ADD_NOTE:
            TransferNote(&(CommData->Data.Note), CommData->Idx, TRUE);
            break;
        case GET_NOTE:
            TransferNote(&(CommData->Data.Note), CommData->Idx, FALSE);
            break;
        case DUMP_NOTES:
            DumpNotes(CommData->Data.Dest);
            break;
        default:
            DEBUG((DEBUG_INFO, "Invalid cmd passed to %a, got 0x%lx\n", __FUNCTION__, CommData->Cmd));
            goto Failure;
    }

    return EFI_SUCCESS;

    Failure:
    *CommBufferSize = -1;
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CorctfSmmInit (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
    EFI_STATUS Status;
    EFI_HANDLE DispatchHandle;

    ASSERT (FeaturePcdGet (PcdSmmSmramRequire));
    DEBUG ((DEBUG_INFO, "Corctf Diary Note Handler initiailizing\n"));
    Status = gSmst->SmiHandlerRegister (
                CorctfSmmHandler,
                &gEfiSmmCorctfProtocolGuid,
                &DispatchHandle
                );

    if (EFI_ERROR (Status)) 
    {
        DEBUG ((DEBUG_ERROR, "%a: SmiHandlerRegister(): %r\n",
            __FUNCTION__, Status));
    }
    else
    {
        DEBUG ((DEBUG_INFO, "Corctf SMM Diary Note handler installed successfully!\n"));
        DEBUG ((DEBUG_INFO, "Unlike heap notes, storing your notes in SMM will give you true secrecy!\n", 0));
        DEBUG ((DEBUG_INFO, "This place is so secretive that we even hid a flag in here!\n"
            "Just to tease you a bit, the first few characters are: %.6a\n", Flag));
    }

    return Status;
}