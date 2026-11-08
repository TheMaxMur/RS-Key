<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Testing roadmap

[Testing](testing.md) describes the checks you can run. This page lists
the work left and the evidence needed to close it.

| Work | Completion evidence |
|---|---|
| Close security decision coverage | Each reachable condition has an independence witness in its relevant profile. Coupled, unreachable and unsupported decisions have a source-level reason. Continue through the Secure worker. |
| Test the C and assembly paths | Mutate and test the device implementations separately. Compare results against independent arithmetic and crypto checks. |
| Extend failure campaigns | Exercise recovery across correlated faults, including a second cut during repair. Compare recovered state with an independent model and keep a minimized input for each regression. |
| Exercise more build profiles on the image | Run matching command and resource checks on the release and unoptimized profiles where the operation is supported. Record the board, image identity, enabled features and exact case list. |
| Expand physical TrustZone checks | Run the remaining access and recovery cases on the relevant RP2350 steppings and boot policies. Include reset during active crypto, debug and ROM/update access, and OTP controls under enforced Secure Boot. |
| Test the physical display and host clients | Keep the modeled gesture and PIN cases. Check the actual panel, touch input, power and browser or desktop behavior with the same ceremonies. |
| Close the conformance comparison | Compare applicable FIDO case IDs with pico-fido under matching tool and profile settings. Record each failure and pending reason. |
| Make release evidence reproducible | Tie each image and board result to the artifact it actually ran. Keep logs and reproducible commands for checks outside the ordinary merge gate. |

The [test campaign records](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/reports/testing-campaigns.md)
contain previous runs, residual reviews and experiment commands.
