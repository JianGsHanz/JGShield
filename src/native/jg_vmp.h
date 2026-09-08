/* jg_vmp.h -- native VMP-lite interpreter public API.
 * The protected method body lives ONLY as PRIVATE bytecode in .rodata;
 * ART never sees dalvik for those methods. Mirrors experiments/vmp_lite/vmp_core.h. */
#ifndef JG_VMP_H
#define JG_VMP_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Run private VMP bytecode. args[] seeds registers 0..nargs-1 (the protected
 * method's first parameter lives at register `param_reg`, so callers pass
 * nargs = param_reg + 1 and place the argument at args[param_reg]).
 * Returns the 64-bit result register. */
int64_t jg_vmp_run(const uint8_t *code, size_t len, const int64_t *args, int nargs);

/* De-obfuscate a full blob (magic 0xFD 0xC2 + per-blob xor key + code) into a
 * malloc'd code buffer. Caller frees. outlen receives the code length. */
uint8_t *jg_vmp_deobfuscate(const uint8_t *blob, size_t blen, size_t *outlen);

#ifdef __cplusplus
}
#endif

#endif /* JG_VMP_H */
