/*
 * FlagVault CTF — "Stack Builder"
 * Category: Reverse Engineering
 * Difficulty: Medium | Points: 350
 *
 * The flag is never stored as a string literal anywhere in the binary.
 * It is built byte-by-byte on the stack at runtime using arithmetic.
 * strings/xxd will show nothing. You need GDB or Ghidra to catch it.
 *
 * Flag: FlagVault{st4ck_bu1ld3r_fl4g}
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * Each byte of the flag is computed individually so the compiler
 * cannot fold it into a string constant. The volatile keyword
 * prevents optimisation away. The bytes are scattered across
 * multiple stack-allocated arrays and assembled last-minute.
 */

static void build_and_print(void) {
    /* Flag: FlagVault{st4ck_bu1ld3r_fl4g}  — 34 bytes + null */
    volatile char seg0[10];  /* "FlagVault" */
    volatile char seg1[1];   /* "{" */
    volatile char seg2[23];  /* "st4ck_bu1ld3r_fl4g"  */
    volatile char seg3[2];   /* "}" + null */

    /* ── Segment 0: "FlagVault" ── */
    seg0[0] = 0x46;           /* F  */
    seg0[1] = 0x40 + 0x2c;   /* l  (0x6c) */
    seg0[2] = 0x61;           /* a  */
    seg0[3] = 0x30 + 0x37;   /* g  (0x67) */
    seg0[4] = 0x56;           /* V  */
    seg0[5] = 0x55 + 0x10;   /* a  (0x61 — actually 0x61=a, 0x55=U... let me fix) */
    seg0[6] = 0x75;           /* u  */
    seg0[7] = 0x6c;           /* l  */
    seg0[8] = 0x74;           /* t  */
    seg0[9] = '\0';

    /* ── Segment 0 corrected: F=0x46 l=0x6c a=0x61 g=0x67 V=0x56 a=0x61 u=0x75 l=0x6c t=0x74 */
    seg0[0] = 70;             /* 'F' */
    seg0[1] = 108;            /* 'l' */
    seg0[2] = 97;             /* 'a' */
    seg0[3] = 103;            /* 'g' */
    seg0[4] = 86;             /* 'V' */
    seg0[5] = 97;             /* 'a' */
    seg0[6] = 117;            /* 'u' */
    seg0[7] = 108;            /* 'l' */
    seg0[8] = 116;            /* 't' */
    seg0[9] = '\0';

    /* ── Segment 1: "{" ── */
    seg1[0] = 0x7b;           /* '{' */

    /* ── Segment 2: "st4ck_bu1ld3r_fl4g" (18 chars) ── */
    /* s=0x73 t=0x74 4=0x34 c=0x63 k=0x6b _=0x5f b=0x62 u=0x75 1=0x31 l=0x6c d=0x64 3=0x33 r=0x72 _=0x5f f=0x66 l=0x6c 4=0x34 g=0x67 */
    seg2[0]  = 0x73;          /* s */
    seg2[1]  = 0x70 + 0x04;  /* t (0x74) */
    seg2[2]  = 0x30 + 0x04;  /* 4 (0x34) */
    seg2[3]  = 0x60 + 0x03;  /* c (0x63) */
    seg2[4]  = 0x60 + 0x0b;  /* k (0x6b) */
    seg2[5]  = 0x5f;          /* _ */
    seg2[6]  = 0x62;          /* b */
    seg2[7]  = 0x75;          /* u */
    seg2[8]  = 0x31;          /* 1 */
    seg2[9]  = 0x6c;          /* l */
    seg2[10] = 0x64;          /* d */
    seg2[11] = 0x33;          /* 3 */
    seg2[12] = 0x72;          /* r */
    seg2[13] = 0x5f;          /* _ */
    seg2[14] = 0x66;          /* f */
    seg2[15] = 0x6c;          /* l */
    seg2[16] = 0x34;          /* 4 */
    seg2[17] = 0x67;          /* g */
    seg2[18] = '\0';

    /* ── Segment 3: "}" ── */
    seg3[0] = 0x7d;           /* '}' */
    seg3[1] = '\0';

    /* Assemble on the stack into a final buffer */
    volatile char flag[64];
    volatile int i = 0, j = 0;

    /* copy seg0 */
    for (j = 0; seg0[j]; j++) flag[i++] = seg0[j];
    /* copy seg1 */
    flag[i++] = seg1[0];
    /* copy seg2 */
    for (j = 0; seg2[j]; j++) flag[i++] = seg2[j];
    /* copy seg3 */
    flag[i++] = seg3[0];
    flag[i]   = '\0';

    /* The flag now lives entirely on the stack — never in .rodata */
    printf("\n[+] Stack construction complete.\n");
    printf("[+] Flag: %s\n\n", (const char *)flag);
}

int main(void) {
    printf("\n[*] FlagVault CTF :: Stack Builder\n");
    printf("[*] Building flag byte-by-byte on the stack...\n");
    fflush(stdout);
    build_and_print();
    return 0;
}
