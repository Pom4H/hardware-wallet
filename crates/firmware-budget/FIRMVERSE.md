# Firmverse execution target

This crate has two linked Cortex-M roles:

- `embedded-probe` measures the complete trusted software surface for Flash budgeting;
- `firmverse-probe` links the same surface for the Firmverse Cortex-M33 virtual board and exposes the non-inlined `firmverse_done` completion point.

The Firmverse workflow executes the real ELF, paints free RAM before reset, measures the whole-program stack high-water mark, and uploads JSON/Markdown evidence tied to the ELF hash. The initial smoke scenario is a lower bound; the 32 KiB stack selection gate remains until successful maximum-size chain, USB/UI interrupt, storage and update scenarios are modeled.
