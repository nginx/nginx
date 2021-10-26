/* AUTO-GENERATED, DO NOT EDIT. */

#include <stddef.h>
#include <stdint.h>

#include "ngx_bpf.h"


static ngx_bpf_reloc_t bpf_reloc_prog_ngx_quic_reuseport_helper[] = {
    { "ngx_quic_sockmap", 55 },
};

static struct bpf_insn bpf_insn_prog_ngx_quic_reuseport_helper[] = {
    /* opcode dst          src         offset imm */
    { 0x79,   BPF_REG_4,   BPF_REG_1, (int16_t)      0,        0x0 },
    { 0x79,   BPF_REG_3,   BPF_REG_1, (int16_t)      8,        0x0 },
    { 0xbf,   BPF_REG_2,   BPF_REG_4, (int16_t)      0,        0x0 },
    {  0x7,   BPF_REG_2,   BPF_REG_0, (int16_t)      0,        0x8 },
    { 0x2d,   BPF_REG_2,   BPF_REG_3, (int16_t)     54,        0x0 },
    { 0xbf,   BPF_REG_5,   BPF_REG_4, (int16_t)      0,        0x0 },
    {  0x7,   BPF_REG_5,   BPF_REG_0, (int16_t)      0,        0x9 },
    { 0x2d,   BPF_REG_5,   BPF_REG_3, (int16_t)     51,        0x0 },
    { 0xb7,   BPF_REG_5,   BPF_REG_0, (int16_t)      0,       0x14 },
    { 0xb7,   BPF_REG_0,   BPF_REG_0, (int16_t)      0,        0x9 },
    { 0x71,   BPF_REG_6,   BPF_REG_2, (int16_t)      0,        0x0 },
    { 0x67,   BPF_REG_6,   BPF_REG_0, (int16_t)      0,       0x38 },
    { 0xc7,   BPF_REG_6,   BPF_REG_0, (int16_t)      0,       0x38 },
    { 0x65,   BPF_REG_6,   BPF_REG_0, (int16_t)     10, 0xffffffff },
    { 0xbf,   BPF_REG_2,   BPF_REG_4, (int16_t)      0,        0x0 },
    {  0x7,   BPF_REG_2,   BPF_REG_0, (int16_t)      0,        0xd },
    { 0x2d,   BPF_REG_2,   BPF_REG_3, (int16_t)     42,        0x0 },
    { 0xbf,   BPF_REG_5,   BPF_REG_4, (int16_t)      0,        0x0 },
    {  0x7,   BPF_REG_5,   BPF_REG_0, (int16_t)      0,        0xe },
    { 0x2d,   BPF_REG_5,   BPF_REG_3, (int16_t)     39,        0x0 },
    { 0xb7,   BPF_REG_0,   BPF_REG_0, (int16_t)      0,        0xe },
    { 0x71,   BPF_REG_5,   BPF_REG_2, (int16_t)      0,        0x0 },
    { 0xb7,   BPF_REG_6,   BPF_REG_0, (int16_t)      0,        0x8 },
    { 0x2d,   BPF_REG_6,   BPF_REG_5, (int16_t)     35,        0x0 },
    {  0xf,   BPF_REG_5,   BPF_REG_0, (int16_t)      0,        0x0 },
    {  0xf,   BPF_REG_4,   BPF_REG_5, (int16_t)      0,        0x0 },
    { 0x2d,   BPF_REG_4,   BPF_REG_3, (int16_t)     32,        0x0 },
    { 0xbf,   BPF_REG_4,   BPF_REG_2, (int16_t)      0,        0x0 },
    {  0x7,   BPF_REG_4,   BPF_REG_0, (int16_t)      0,        0x9 },
    { 0x2d,   BPF_REG_4,   BPF_REG_3, (int16_t)     29,        0x0 },
    { 0x71,   BPF_REG_4,   BPF_REG_2, (int16_t)      1,        0x0 },
    { 0x67,   BPF_REG_4,   BPF_REG_0, (int16_t)      0,       0x38 },
    { 0x71,   BPF_REG_3,   BPF_REG_2, (int16_t)      2,        0x0 },
    { 0x67,   BPF_REG_3,   BPF_REG_0, (int16_t)      0,       0x30 },
    { 0x4f,   BPF_REG_3,   BPF_REG_4, (int16_t)      0,        0x0 },
    { 0x71,   BPF_REG_4,   BPF_REG_2, (int16_t)      3,        0x0 },
    { 0x67,   BPF_REG_4,   BPF_REG_0, (int16_t)      0,       0x28 },
    { 0x4f,   BPF_REG_3,   BPF_REG_4, (int16_t)      0,        0x0 },
    { 0x71,   BPF_REG_4,   BPF_REG_2, (int16_t)      4,        0x0 },
    { 0x67,   BPF_REG_4,   BPF_REG_0, (int16_t)      0,       0x20 },
    { 0x4f,   BPF_REG_3,   BPF_REG_4, (int16_t)      0,        0x0 },
    { 0x71,   BPF_REG_4,   BPF_REG_2, (int16_t)      5,        0x0 },
    { 0x67,   BPF_REG_4,   BPF_REG_0, (int16_t)      0,       0x18 },
    { 0x4f,   BPF_REG_3,   BPF_REG_4, (int16_t)      0,        0x0 },
    { 0x71,   BPF_REG_4,   BPF_REG_2, (int16_t)      6,        0x0 },
    { 0x67,   BPF_REG_4,   BPF_REG_0, (int16_t)      0,       0x10 },
    { 0x4f,   BPF_REG_3,   BPF_REG_4, (int16_t)      0,        0x0 },
    { 0x71,   BPF_REG_4,   BPF_REG_2, (int16_t)      7,        0x0 },
    { 0x67,   BPF_REG_4,   BPF_REG_0, (int16_t)      0,        0x8 },
    { 0x4f,   BPF_REG_3,   BPF_REG_4, (int16_t)      0,        0x0 },
    { 0x71,   BPF_REG_2,   BPF_REG_2, (int16_t)      8,        0x0 },
    { 0x4f,   BPF_REG_3,   BPF_REG_2, (int16_t)      0,        0x0 },
    { 0x7b,  BPF_REG_10,   BPF_REG_3, (int16_t)  65528,        0x0 },
    { 0xbf,   BPF_REG_3,  BPF_REG_10, (int16_t)      0,        0x0 },
    {  0x7,   BPF_REG_3,   BPF_REG_0, (int16_t)      0, 0xfffffff8 },
    { 0x18,   BPF_REG_2,   BPF_REG_0, (int16_t)      0,        0x0 },
    {  0x0,   BPF_REG_0,   BPF_REG_0, (int16_t)      0,        0x0 },
    { 0xb7,   BPF_REG_4,   BPF_REG_0, (int16_t)      0,        0x0 },
    { 0x85,   BPF_REG_0,   BPF_REG_0, (int16_t)      0,       0x52 },
    { 0xb7,   BPF_REG_0,   BPF_REG_0, (int16_t)      0,        0x1 },
    { 0x95,   BPF_REG_0,   BPF_REG_0, (int16_t)      0,        0x0 },
};


ngx_bpf_program_t ngx_quic_reuseport_helper = {
    .relocs = bpf_reloc_prog_ngx_quic_reuseport_helper,
    .nrelocs = sizeof(bpf_reloc_prog_ngx_quic_reuseport_helper)
               / sizeof(bpf_reloc_prog_ngx_quic_reuseport_helper[0]),
    .ins = bpf_insn_prog_ngx_quic_reuseport_helper,
    .nins = sizeof(bpf_insn_prog_ngx_quic_reuseport_helper)
            / sizeof(bpf_insn_prog_ngx_quic_reuseport_helper[0]),
    .license = "BSD",
    .type = BPF_PROG_TYPE_SK_REUSEPORT,
};
