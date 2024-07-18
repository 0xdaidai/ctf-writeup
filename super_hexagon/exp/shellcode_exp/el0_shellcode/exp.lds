ENTRY(_start)
SECTIONS
{
. = 0x402000;
t : { *(.text) }
. = 0x412000;
d : { *(.bss) }
}