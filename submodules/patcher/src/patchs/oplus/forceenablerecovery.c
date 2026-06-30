#include "patchs/oplus/forceenablerecovery.h"
#include "arm64_inst/utils.h"

/*
 * OPlus ABL refuses Recovery while the bootloader looks locked. Because this
 * project fakes a locked state, `reboot recovery` hits that gate. The gate is
 * structured like the (already handled) fastboot one:
 *
 *     <guard b.cond/cbz>  ; skip the refusal block when the gate is not armed
 *     adrp/add x1, "if olock secure lock state, Not allow Recovery:%d"
 *     ... DebugPrint + olock unlock-data verification ...
 *     b .                 ; <- terminal self-branch; watchdog turns it into a
 *                         ;    boot-logo -> black-screen -> reboot loop
 *
 * Normal boot survives because the guard's register is 0 for non-recovery and
 * the path falls through to the continue-boot label. To let Recovery through we
 * (1) turn the guard into an unconditional branch so the refusal block is always
 * skipped, and (2) replace the terminal self-branch with a NOP so any path that
 * still reaches it falls through to the normal continue-boot code instead of
 * spinning forever.
 *
 * Every step is match-or-skip: if an anchor is not found the buffer is left
 * untouched, so the patch is a no-op on unaffected images.
 */

/* "b ." (branch to self) encodes as exactly 0x14000000 (imm26 == 0). */
#define AARCH64_B_SELF 0x14000000u
/* Bytes after the message reference within which the terminal hang lives. */
#define RECOVERY_HANG_WINDOW 0x400

static int32_t find_recovery_gate_adrl(char* buffer, int32_t size) {
    for (int32_t i = 0; i + 8 <= size; i += 4) {
        int64_t off = calc_adrl_file_offset(buffer, i, 0);
        if (off < 0) continue;
        /* the reference points at the start of the string literal */
        if (str_at(buffer, size, off,
                   "if olock secure lock state, Not allow Recovery"))
            return i;
    }
    return -1;
}

static bool patch_recovery_guard(char* buffer, int32_t size, int32_t adrl_off) {
    (void)size;
    if (adrl_off < 4) return false;
    DecodedInst d = decode_at(buffer, adrl_off - 4);
    if (d.type != INST_BCOND && d.type != INST_CBZ_W && d.type != INST_CBNZ_W &&
        d.type != INST_CBZ_X && d.type != INST_CBNZ_X) {
        printf("OPlus Warning: recovery guard branch not found before 0x%X\n",
               adrl_off);
        return false;
    }
    write_instr(buffer, adrl_off - 4, change_to_b(d.raw));
    printf("Patched recovery refusal guard at 0x%X to always skip\n",
           adrl_off - 4);
    return true;
}

static bool patch_recovery_hang(char* buffer, int32_t size, int32_t adrl_off) {
    int32_t end = adrl_off + RECOVERY_HANG_WINDOW;
    if (end > size - 4) end = size - 4;
    for (int32_t i = adrl_off; i <= end; i += 4) {
        if (read_instr(buffer, i) == AARCH64_B_SELF) {
            write_instr(buffer, i, NOP);
            printf("Patched recovery hang (self-branch) at 0x%X to NOP\n", i);
            return true;
        }
    }
    printf("OPlus Warning: recovery hang self-branch not found near 0x%X\n",
           adrl_off);
    return false;
}

bool patch_recovery(char* buffer, int32_t size, int32_t global_var_offset) {
    (void)global_var_offset;
    int32_t adrl = find_recovery_gate_adrl(buffer, size);
    if (adrl < 0) {
        printf("OPlus Warning: 'Not allow Recovery' gate not found, "
               "skipping recovery patch\n");
        return false;
    }
    printf("Recovery gate message reference at 0x%X\n", adrl);

    bool guard_ok = patch_recovery_guard(buffer, size, adrl);
    bool hang_ok  = patch_recovery_hang(buffer, size, adrl);
    return guard_ok || hang_ok;
}
