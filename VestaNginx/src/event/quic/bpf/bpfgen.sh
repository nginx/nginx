#!/bin/bash

export LANG=C

set -e

if [ $# -lt 1 ]; then
    echo "Usage: PROGNAME=foo LICENSE=bar $0 <bpf object file>"
    exit 1
fi


self=$0
filename=$1
funcname=$PROGNAME

generate_head()
{
    cat << END
/* AUTO-GENERATED, DO NOT EDIT. */

#include <stddef.h>
#include <stdint.h>

#include "ngx_bpf.h"


END
}

generate_tail()
{
    cat << END

ngx_bpf_program_t $PROGNAME = {
    .relocs = bpf_reloc_prog_$funcname,
    .nrelocs = sizeof(bpf_reloc_prog_$funcname)
               / sizeof(bpf_reloc_prog_$funcname[0]),
    .ins = bpf_insn_prog_$funcname,
    .nins = sizeof(bpf_insn_prog_$funcname)
            / sizeof(bpf_insn_prog_$funcname[0]),
    .license = "$LICENSE",
    .type = BPF_PROG_TYPE_SK_REUSEPORT,
};

END
}

process_relocations()
{
    echo "static ngx_bpf_reloc_t bpf_reloc_prog_$funcname[] = {"

    objdump -r $filename | awk '{

    if (enabled && $NF > 0) {
        off = strtonum(sprintf("0x%s", $1));
        name = $3;

        printf("    { \"%s\", %d },\n", name, off/8);
    }

    if ($1 == "OFFSET") {
        enabled=1;
    }
}'
    echo "};"
    echo
}

process_section()
{
    echo "static struct bpf_insn bpf_insn_prog_$funcname[] = {"
    echo "    /* opcode dst          src         offset imm */"

    section_info=$(objdump -h $filename --section=$funcname | grep "1 $funcname")

    # dd doesn't know hex
    length=$(printf "%d" 0x$(echo $section_info | cut -d ' ' -f3))
    offset=$(printf "%d" 0x$(echo $section_info | cut -d ' ' -f6))

    for ins in $(dd if="$filename" bs=1 count=$length skip=$offset status=none | xxd -p -c 8)
    do
        opcode=0x${ins:0:2}
        srcdst=0x${ins:2:2}

        # bytes are dumped in LE order
        offset=0x${ins:6:2}${ins:4:2}                        # short
        immedi=0x${ins:14:2}${ins:12:2}${ins:10:2}${ins:8:2} # int

        dst="$(($srcdst & 0xF))"
        src="$(($srcdst & 0xF0))"
        src="$(($src >> 4))"

        opcode=$(printf "0x%x" $opcode)
        dst=$(printf "BPF_REG_%d" $dst)
        src=$(printf "BPF_REG_%d" $src)
        offset=$(printf "%d" $offset)
        immedi=$(printf "0x%x" $immedi)

        printf "    { %4s, %11s, %11s, (int16_t) %6s, %10s },\n" $opcode $dst $src $offset $immedi
    done

cat << END
};

END
}

generate_head
process_relocations
process_section
generate_tail

