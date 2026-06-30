#include "patchs/oplus/forceenablerecovery.h"
#include "arm64_inst/utils.h"

/*
 * ============================ STATUS: DISABLED ============================
 * This patch is NOT wired into PatchBuffer. It is kept for the analysis and
 * for completion once the correct target is confirmed on-device.
 *
 * Why disabled: deeper disassembly showed the routine that holds this gate
 * (0x4e50 on the analysed image) is the bootloader / fastboot-mode handler,
 * and the gate's "continue" label (0x6d64) is its FASTBOOT-LAUNCH branch
 * (it prints "Launching fastboot" / "Fastboot Build Info" and locates the
 * fastboot transport protocol; 0x3e440 right after it is the fastboot
 * unlock-verify, which itself can ResetSystem). So redirecting the refusal
 * there would send `reboot recovery` into fastboot, not Recovery, and could
 * still reboot. The real "boot the selected recovery image" exit is not in
 * this function and could not be pinned down with confidence from the binary
 * alone. Enabling a wrong guess here risks misboot / a loop on a device the
 * user cannot currently recover, so it stays off until validated on-device.
 *
 * What IS confirmed and useful: the loop is a real cold reset. 0x29268 is a
 * ResetSystem wrapper ([gRT+0x68]); the olock gate hits `mov w0,#0x3e; bl
 * ResetSystem` on the recovery-refusal path.
 * =========================================================================
 *
 * OPlus ABL refuses Recovery while the bootloader looks locked. Because this
 * project fakes a locked state, the normal system boots but `reboot recovery`
 * is rejected and the device reboots, looping forever.
 *
 * The decision routine has two refusal sites, both reached *only* when the
 * "boot recovery" flag (call it w_rec) is set:
 *
 *   (A) first, olock-gated block:
 *         <guard b.cond>            ; skip unless olock-secure AND recovery
 *         adrp x1,"...Not allow Recovery:%d"
 *         ... olock verification ...
 *         mov w0,#0x3e ; bl reset   ; ResetSystem -> reboot
 *
 *   (B) the lock-state block (the one that actually bites a normal install):
 *         cbz  w_rec, <cont>        ; non-recovery jumps to the continue label
 *         adrp x1,"...Not allow Fastboot."   <- block entry, recovery-only
 *         ... DebugPrint ...
 *         mov w0,#0x3e ; bl reset   ; ResetSystem -> reboot
 *         ...
 *         b .                       ; fallback self-hang
 *
 * 0x29268 was confirmed to be a ResetSystem wrapper ([gRT+0x68]); the reboot is
 * a real cold reset, not a watchdog timeout. Every path into block (B) is
 * recovery-only and the "<cont>" label (target of the cbz) is exactly where a
 * normal boot continues in both lock states, so the fix is:
 *
 *   (B) overwrite the block-entry instruction with an unconditional branch to
 *       <cont>. This sends every recovery refusal straight to the normal
 *       continue path, before the ResetSystem, and touches recovery only.
 *   (A) turn the guard into an unconditional branch so the olock block is
 *       always skipped (defuses its reset too).
 *   (C) replace the fallback self-hang with NOP (belt-and-suspenders; no longer
 *       reachable for recovery once (B) is applied).
 *
 * Everything is validated and match-or-skip: any anchor that does not look
 * exactly as expected is left untouched, so a mismatched / future image is
 * never half-patched into an unbootable EFI. Re-running is idempotent. (B) is
 * the critical fix; if it cannot be applied the code warns loudly.
 */

#define AARCH64_B_SELF 0x14000000u          /* "b ." (branch to self)       */
#define RECOVERY_WINDOW 0x200               /* span of the gate, in bytes   */

static const char REC_NEEDLE[] = "if olock secure lock state, Not allow Recovery";
static const char FB_NEEDLE[]  = "if olock secure lock state, Not allow Fastboot";

/* condition compare/branch target (BCOND/CBZ/CBNZ share imm19@[23:5]) */
static bool cond_branch_target(const DecodedInst* d, int32_t off, int64_t* tgt) {
    if (d->type != INST_BCOND && d->type != INST_CBZ_W && d->type != INST_CBNZ_W &&
        d->type != INST_CBZ_X && d->type != INST_CBNZ_X)
        return false;
    *tgt = (int64_t)off + d->simm;
    return true;
}

static int64_t uncond_b_target(uint32_t raw, int32_t off) {
    int32_t imm = (int32_t)(raw & 0x03FFFFFF);
    if (imm & 0x02000000) imm |= (int32_t)0xFC000000;
    return (int64_t)off + ((int64_t)imm << 2);
}

/* encode "B <to>" placed at file offset <from> */
static uint32_t encode_b(int32_t from, int64_t to) {
    int64_t off = (to - (int64_t)from) >> 2;
    return 0x14000000u | ((uint32_t)off & 0x03FFFFFFu);
}

/* first ADRL referencing needle; *count = number of such references */
static int32_t find_str_adrl(char* buffer, int32_t size, const char* needle,
                             int32_t* count) {
    int32_t found = -1;
    *count = 0;
    for (int32_t i = 0; i + 8 <= size; i += 4) {
        int64_t off = calc_adrl_file_offset(buffer, i, 0);
        if (off < 0) continue;
        if (str_at(buffer, size, off, needle)) {
            if (found < 0) found = i;
            (*count)++;
        }
    }
    return found;
}

/* in-range forward, 4-byte-aligned continuation target */
static bool target_sane(int64_t tgt, int32_t from, int32_t size) {
    return (tgt & 3) == 0 && tgt > from &&
           tgt <= (int64_t)from + RECOVERY_WINDOW && tgt + 4 <= size;
}

/* (B) redirect the refusal-block entry to the normal continue label. */
static bool patch_refuse_redirect(char* buffer, int32_t size, int32_t fb_adrl) {
    if (fb_adrl < 4) return false;

    DecodedInst guard = decode_at(buffer, fb_adrl - 4);
    int64_t cont;
    if (!cond_branch_target(&guard, fb_adrl - 4, &cont)) {
        printf("OPlus recovery: no cbz/cbnz before fastboot gate at 0x%X, skip "
               "redirect\n", fb_adrl - 4);
        return false;
    }
    if (!target_sane(cont, fb_adrl, size)) {
        printf("OPlus recovery: continue target 0x%llX out of range, skip "
               "redirect\n", (unsigned long long)cont);
        return false;
    }

    uint32_t newb = encode_b(fb_adrl, cont);
    uint32_t orig = read_instr(buffer, fb_adrl);
    write_instr(buffer, fb_adrl, newb);

    uint32_t back = read_instr(buffer, fb_adrl);
    if ((back & 0xFC000000u) != 0x14000000u ||
        uncond_b_target(back, fb_adrl) != cont) {
        printf("OPlus recovery: redirect self-verify FAILED at 0x%X, reverting\n",
               fb_adrl);
        write_instr(buffer, fb_adrl, orig);
        return false;
    }
    printf("OPlus recovery: refusal block 0x%X -> B 0x%llX (skip ResetSystem)\n",
           fb_adrl, (unsigned long long)cont);
    return true;
}

/* (A) guard before the "Not allow Recovery" message -> unconditional skip. */
static bool patch_recovery_guard(char* buffer, int32_t size, int32_t rec_adrl) {
    if (rec_adrl < 4) return false;

    DecodedInst d = decode_at(buffer, rec_adrl - 4);
    int64_t tgt;
    if (!cond_branch_target(&d, rec_adrl - 4, &tgt)) {
        printf("OPlus recovery: guard at 0x%X not a conditional branch, skip\n",
               rec_adrl - 4);
        return false;
    }
    if (!target_sane(tgt, rec_adrl - 4, size)) {
        printf("OPlus recovery: guard target 0x%llX out of range, skip\n",
               (unsigned long long)tgt);
        return false;
    }

    uint32_t newb = change_to_b(d.raw);
    write_instr(buffer, rec_adrl - 4, newb);
    uint32_t back = read_instr(buffer, rec_adrl - 4);
    if ((back & 0xFC000000u) != 0x14000000u ||
        uncond_b_target(back, rec_adrl - 4) != tgt) {
        printf("OPlus recovery: guard self-verify FAILED at 0x%X, reverting\n",
               rec_adrl - 4);
        write_instr(buffer, rec_adrl - 4, d.raw);
        return false;
    }
    printf("OPlus recovery: olock guard 0x%X -> unconditional B 0x%llX\n",
           rec_adrl - 4, (unsigned long long)tgt);
    return true;
}

/* (C) terminal self-branch -> NOP. Require exactly one in the window. */
static bool patch_recovery_hang(char* buffer, int32_t size, int32_t rec_adrl) {
    int32_t end = rec_adrl + RECOVERY_WINDOW;
    if (end > size - 4) end = size - 4;

    int32_t hit = -1, n = 0;
    for (int32_t i = rec_adrl; i <= end; i += 4) {
        if (read_instr(buffer, i) == AARCH64_B_SELF) { if (hit < 0) hit = i; n++; }
    }
    if (hit < 0) return false;          /* already NOP / not present */
    if (n > 1) {
        printf("OPlus recovery: %d self-branches in window, skip for safety\n", n);
        return false;
    }
    write_instr(buffer, hit, NOP);
    if (read_instr(buffer, hit) != (uint32_t)NOP) {
        write_instr(buffer, hit, AARCH64_B_SELF);
        return false;
    }
    printf("OPlus recovery: fallback hang 0x%X -> NOP\n", hit);
    return true;
}

bool patch_recovery(char* buffer, int32_t size, int32_t global_var_offset) {
    (void)global_var_offset;

    int32_t rec_cnt = 0, fb_cnt = 0;
    int32_t rec_adrl = find_str_adrl(buffer, size, REC_NEEDLE, &rec_cnt);
    int32_t fb_adrl  = find_str_adrl(buffer, size, FB_NEEDLE, &fb_cnt);

    if (rec_adrl < 0 && fb_adrl < 0) {
        printf("OPlus recovery: gate not present, skipping (no change)\n");
        return false;
    }
    if (rec_cnt > 1 || fb_cnt > 1) {
        printf("OPlus recovery: ambiguous gate references (rec=%d fb=%d), "
               "skipping for safety (no change)\n", rec_cnt, fb_cnt);
        return false;
    }

    bool redirect_ok = false, guard_ok = false, hang_ok = false;

    /* (B) the critical fix */
    if (fb_adrl >= 0)
        redirect_ok = patch_refuse_redirect(buffer, size, fb_adrl);
    else
        printf("OPlus recovery: fastboot-gate anchor gone (already patched?)\n");

    /* (A) + (C) defense around the olock block */
    if (rec_adrl >= 0) {
        guard_ok = patch_recovery_guard(buffer, size, rec_adrl);
        hang_ok  = patch_recovery_hang(buffer, size, rec_adrl);
    }

    if (!redirect_ok && fb_adrl >= 0) {
        printf("OPlus recovery: WARNING - reset bypass NOT applied; recovery may "
               "still reboot-loop\n");
    }
    if (redirect_ok || guard_ok || hang_ok)
        return true;

    printf("OPlus recovery: nothing to do (already patched / unexpected layout)\n");
    return false;
}
