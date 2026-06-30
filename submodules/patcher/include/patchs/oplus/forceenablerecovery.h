#ifndef OPLUS_RECOVERY_H
#define OPLUS_RECOVERY_H
#include <stdint.h>
#include <stdbool.h>
/*
 * Neutralise the OPlus "olock secure lock state" gate that refuses to boot
 * Recovery once the device reports a (fake-)locked bootloader. Without this
 * the normal system boots fine but `reboot recovery` traps in an infinite
 * self-branch -> watchdog reset -> boot-loop.
 */
bool patch_recovery(char* buffer, int32_t size, int32_t global_var_offset);
#endif /* OPLUS_RECOVERY_H */
