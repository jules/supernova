<div align="center">
    <h1>
        SuperNova
    </h1>

**Warning: this implementation is experimental and not audited. Please use at your own risk.**
</div>

This repository contains an implementation of the [SuperNova](https://eprint.iacr.org/2022/1758) protocol, written in Rust. SuperNova is a novel recursive proof system and an extension of the [Nova](https://eprint.iacr.org/2021/370) protocol, which introduces folding schemes to circuit arithmetizations, in order to compress multiple executions of the same circuit into one. SuperNova builds on top of this by introducing a VM-like construction where a prover defines circuits separately for each VM instruction, and folds any executed program into the correct circuits, instruction by instruction.

## Progress

- [x] R1CS arithmetization
- [ ] Vanilla Plonk arithmetization
- [x] Prover/verifier construction
- [ ] Tests

## Disclaimer

Nova and SuperNova are research works done by Srinath Setty ([GitHub](https://github.com/srinathsetty), [TWitter](https://twitter.com/srinathtv/)), [Abhiram Kothapalli](https://twitter.com/abhiramko/) (and Ioanna Tzialla for Nova), and this repository heavily relies on the earlier implementation of [Nova](https://github.com/microsoft/Nova). All credit goes to them!
