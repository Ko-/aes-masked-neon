# Vectorizing Higher-Order Masking

This repository contains three masked AES-128 implementations that are optimized for the ARM Cortex-A8 with NEON:

- 1 block, 4 shares;
- 2 blocks, 4 shares;
- 1 block, 8 shares.

They are part of a [paper](https://ko.stoffelen.nl/papers/cosade2018-aesneon.pdf) that was published at [COSADE 2018](https://www.cosade.org/).


## Compiling

The code is meant to be compiled using `gcc` on a native ARM Cortex-A8 running Linux. Cross-compiling might also work, as is the case for using other compilers/assemblers, depending on how compatible they are with `gas` assembly. First, set the number of blocks and shares by changing `NUM_BLOCKS` and `NUM_SHARES` in `Makefile`. Then execute `make`.

Running the binaries might give 'Illegal instruction' errors. The binaries measure CPU cycles using a special CCNT register that is only accessible in kernel mode. To enable access in user mode, the `enableccnt` kernel module needs to be inserted. Make sure `linux-headers` or `linux-headers-$(uname -r)` is installed. In the `enableccnt` directory, issue `sudo make`, followed by `sudo insmod enableccnt.ko`. Removing all calls to `cpucycles_cortex()` and removing the dependency in the Makefile is of course also a possible workaround, if you don't care about measuring clock cycles.

## Security warning

We studied the security of these implementations in [this paper](https://ko.stoffelen.nl/papers/cosade2018-aesneon.pdf). Of course, it remains hard to give any guarantees, so please refrain from using these implementations in a production setting without full awareness of the risks and a clear picture of your attacker model. Also note that the key expansion is currently not implemented, let alone masked.

## Replicating results

### Disable frequency scaling

By default, frequency scaling is enabled, saving energy when the CPU load is low. For consistent results, its preferable to disable this. This way, one can also fix the clock frequency. To do so, do this as root:
```
# echo userspace > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
# echo 1000000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_setspeed
```

### Benchmark

The `benchmark` binary executes `aes_enc` `NUM_TESTS` times and prints the median number of cycles. Note that `NUM_TESTS 1` will make sure that the ciphertext that is printed is actually correct.

### Analysis
`analysis` needs to be run as root. Before executing AES but after the sharing and bitslicing of input, GPIO pin P9_27 is set to high such that it can be used as trigger. It is turned low immediately after executing AES.
