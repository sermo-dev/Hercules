// C API of spike/kernel-spike (libkernel_spike.a). Strings are JSON, free with kernel_spike_free_string.
#include <stdint.h>
char *kernel_spike_run_bench(const char *data_dir);      // kernel chainstate benches (regtest)
char *kernel_spike_run_verify(const char *testdata_dir); // script-verify vectors + mainnet blocks
void kernel_spike_free_string(char *s);
