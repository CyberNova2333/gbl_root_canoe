#ifndef PATCHS_CORE_H
#define PATCHS_CORE_H
#include <stdint.h>
#include <stdbool.h>
/* keep_warning: when true, SKIP the "remove yellow warning" patch. Removing
 * that patch is required for third-party Recovery to boot under fake-lock on
 * OPlus devices (the warning patch's control-flow change also trips the
 * recovery AVB path). Trade-off: the orange/yellow unlock warning is shown. */
bool PatchBuffer(char* data, int32_t size, bool keep_warning);
#endif /* PATCHS_CORE_H */