# Root pre-test amendment for check 03

The added no-handle spawn failure path uses the original phase deadline. It does not create another owner, timer, provider call, network request or cleanup retry. The bounded hold tolerates a missing handle without claiming that a child was never created, reaped or terminated. The existing final refusal keeps direct and privileged cleanup unproven.

The new focused test supplies a spawning function that raises, an injected clock and sleeper. It checks one attempted fixed command, the unchanged original forty-second boundary, and false cleanup flags. Real process creation remains guarded in the harness. Existing changed-candidate methods are retained to check integration; all operational counters must remain zero and all Python source hashes unchanged. Suitable for the guarded check; actual provider compatibility remains unqualified.

Source pins:

- phase7_live_adapter/monitor.py: `d0e22ac39a9df117b1459502280329596dc7050277eddda3a2fd5beb49f10f40`
- test_monitor.py: `0818dd49c267acdd215f00ba9caacce697216d8551599d1f17374cd3adbf64e1`
- offline_check.py: `cb318d60fb284c2d7a2ed90b86bbe100a3ec2c494fc9489d33fbe0e26960f08a`
