ENTRY(_start)
SECTIONS
{
. = 0xFFFFFFFFC0000030;
t : { *(.text) }
. = 0xFFFFFFFFC0019000;
d : { *(.bss) }
}