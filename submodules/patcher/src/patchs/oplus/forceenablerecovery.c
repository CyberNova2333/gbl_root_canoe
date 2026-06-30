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
 *     b .                 ; <- terminal self-branch; the watchdog turns it into
 *                         ;    a boot-logo -> black-screen -> reboot loop
 *
 * Fix, defused in order of importance:
 *   (P2) replace the terminal self-branch (b .) with NOP so the refusal path
 *        falls through to the normal continue-boot code. This alone stops the
 *        loop and is the safest possible edit: an instruction that can only
 *        spin forever becomes a fall-through.
 *   (P1) turn the guard before the message load into an unconditional branch so
 *        the refusal block is skipped entirely. On a genuinely unlocked device
 *        (the supported state) the guard already skips, so this is a no-op
 *        there and only helps the olock-locked case.
 *
 * Everything is heavily validated and match-or-skip: any anchor that does not
 * look exactly as expected is left untouched, so a mismatched / future image is
 * never half-patched into an unbootable EFI. Re-running is idempotent.
 */

/* "b ." (branch to self) encodes as exactly 0x14000000 (imm26 == 0). */
#define AARCH64_B_SELF 0x14000000u
/* The whole gate (message ref .. terminal hang) lives in a small span. */
#define RECOVERY_WINDOW 0x200

static const char RECOVERY_NEEDLE[] =
    "if olock secure lock state, Not allow Recovery";

/* target of a conditional compare/branch (BCOND/CBZ/CBNZ share imm19@[23:5]) */
static bool cond_branch_target(const DecodedInst* d, int32_t off, int64_t* tgt) {
    if (d->type != INST_BCOND && d->type != INST_CBZ_W && d->type != INST_CBNZ_W &&
        d->type != INST_CBZ_X && d->type != INST_CBNZ_X)
        return false;
    *tgt = (int64_t)off + d->simm;
    return true;
}

/* target of an unconditional B (0x14000000 | imm26) */
static int64_t uncond_b_target(uint32_t raw, int32_t off) {
    int32_t imm = (int32_t)(raw & 0x03FFFFFF);
    if (imm & 0x02000000) imm |= (int32_t)0xFC000000;
    return (int64_t)off + ((int64_t)imm << 2);
}

/* Locate the single reference to the recovery-refusal message. Returns the
 * ADRP offset, sets *count to how many references exist (ambiguity guard). */
static int32_t find_recovery_gate_adrl(char* buffer, int32_t size, int32_t* count) {
    int32_t found = -1;
    *count = 0;
    for (int32_t i = 0; i + 8 <= size; i += 4) {
        int64_t off = calc_adrl_file_offset(buffer, i, 0);
        if (off < 0) continue;
        if (str_at(buffer, size, off, RECOVERY_NEEDLE)) {
            if (found < 0) found = i;
            (*count)++;
        }
    }
    return found;
}

/* P1: guard branch directly in front of the message load. */
static bool patch_recovery_guard(char* buffer, int32_t size, int32_t adrl_off) {
    (void)size;
    if (adrl_off < 4) return false;

    DecodedInst d = decode_at(buffer, adrl_off - 4);
    int64_t tgt;
    if (!cond_branch_target(&d, adrl_off - 4, &tgt)) {
        printf("OPlus recovery: guard at 0x%X is not a conditional branch "
               "(already patched / unexpected layout), skip\n", adrl_off - 4);
        return false;
    }
    /* It must skip *forward* over the refusal block to a nearby continuation. */
    if ((tgt & 3) || tgt <= adrl_off || tgt > (int64_t)adrl_off + RECOVERY_WINDOW) {
        printf("OPlus recovery: guard target 0x%llX out of expected range, skip\n",
               (unsigned long long)tgt);
        return false;
    }

    uint32_t newb = change_to_b(d.raw);
    write_instr(buffer, adrl_off - 4, newb);

    /* self-verify: the write must now be an unconditional B to the same place */
    uint32_t back = read_instr(buffer, adrl_off - 4);
    if ((back & 0xFC000000u) != 0x14000000u ||
        uncond_b_target(back, adrl_off - 4) != tgt) {
        printf("OPlus recovery: guard self-verify FAILED at 0x%X, reverting\n",
               adrl_off - 4);
        write_instr(buffer, adrl_off - 4, d.raw);
        return false;
    }
    printf("OPlus recovery: guard 0x%X -> unconditional B 0x%llX\n",
           adrl_off - 4, (unsigned long long)tgt);
    return true;
}

/* P2: terminal self-branch -> NOP. Require exactly one in the window. */
static bool patch_recovery_hang(char* buffer, int32_t size, int32_t adrl_off) {
    int32_t end = adrl_off + RECOVERY_WINDOW;
    if (end > size - 4) end = size - 4;

    int32_t hit = -1, n = 0;
    for (int32_t i = adrl_off; i <= end; i += 4) {
        if (read_instr(buffer, i) == AARCH64_B_SELF) {
            if (hit < 0) hit = i;
            n++;
        }
    }
    if (hit < 0) {
        printf("OPlus recovery: terminal self-branch not found near 0x%X "
               "(already patched / unexpected layout), skip\n", adrl_off);
        return false;
    }
    if (n > 1) {
        printf("OPlus recovery: %d self-branches in window, ambiguous, skip "
               "for safety\n", n);
        return false;
    }

    write_instr(buffer, hit, NOP);
    if (read_instr(buffer, hit) != (uint32_t)NOP) {
        printf("OPlus recovery: hang self-verify FAILED at 0x%X, reverting\n", hit);
        write_instr(buffer, hit, AARCH64_B_SELF);
        return false;
    }
    printf("OPlus recovery: terminal hang 0x%X -> NOP\n", hit);
    return true;
}

bool patch_recovery(char* buffer, int32_t size, int32_t global_var_offset) {
    (void)global_var_offset;

    int32_t count = 0;
    int32_t adrl = find_recovery_gate_adrl(buffer, size, &count);
    if (adrl < 0) {
        printf("OPlus recovery: 'Not allow Recovery' gate not present, "
               "skipping (no change)\n");
        return false;
    }
    if (count != 1) {
        printf("OPlus recovery: %d references to the gate message, ambiguous, "
               "skipping for safety (no change)\n", count);
        return false;
    }
    printf("OPlus recovery: gate message reference at 0x%X\n", adrl);

    /* Idempotency: if the guard slot is already an unconditional B and there is
     * no surviving self-branch in the window, the patch was applied before. */
    int32_t scan_end = adrl + RECOVERY_WINDOW;
    if (scan_end > size - 4) scan_end = size - 4;
    bool has_self_branch = false;
    for (int32_t i = adrl; i <= scan_end; i += 4)
        if (read_instr(buffer, i) == AARCH64_B_SELF) { has_self_branch = true; break; }
    bool guard_is_b = adrl >= 4 &&
                      (read_instr(buffer, adrl - 4) & 0xFC000000u) == 0x14000000u;
    if (guard_is_b && !has_self_branch) {
        printf("OPlus recovery: gate already patched, no change\n");
        return true;
    }

    /* P2 first: it is the critical, safest fix. */
    bool hang_ok  = patch_recovery_hang(buffer, size, adrl);
    bool guard_ok = patch_recovery_guard(buffer, size, adrl);

    if (!hang_ok) {
        printf("OPlus recovery: WARNING - terminal hang was NOT defused; "
               "Recovery may still boot-loop\n");
    }
    return hang_ok || guard_ok;
}
