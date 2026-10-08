# Root pre-test amendment for check 04

A configured PHC path may be the fixed /dev/ptp_hyperv alias or its exact observed resolved /dev/ptpN identity. The existing helper still requires the alias to resolve to a character device named hyperv and the daemon to hold that same device. Arbitrary other device paths, drivers or providers refuse. This matches two names for one observed device; it introduces no provider fallback or UTC truth claim. Microsoft documents both paths: https://learn.microsoft.com/en-us/azure/virtual-machines/linux/time-sync .

The new synthetic case accepts the observed /dev/ptp0 and refuses /dev/ptp1 with facts still bound to ptp0. The original selected-source, configuration-equivalence and conditional accuracy/rate checks remain. Suitable for guarded integration verification; no actual provider behavior is asserted.
