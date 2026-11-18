# MSVC runtime parity on Ghidra 12.2

With MSVC 19.52.37029, Ghidra 12.2 returns a missing p-code error for the static CRT routine `__GSHandlerCheckCommon` in three optimized x64 `types.exe` fixtures. The separate PDB's public function records identify the symbol. A replay of the archived Windows PE files also produced the same failure in stock Ghidra on Linux. [Windows CI artifacts](https://github.com/YurilLAB/BinaryRat/actions/runs/44398492713)

| Fixture | Ghidra entry | PDB section 1 offset (decimal) | Completed exports |
| --- | --- | --- | --- |
| `msvc/O1/types` | `ram:140001260` | 608 | 496 of 497 |
| `msvc/O2/types` | `ram:1400012d0` | 720 | 496 of 497 |
| `msvc/Ox/types` | `ram:140001300` | 768 | 496 of 497 |

Serial, parallel and scheduled exports matched byte for byte across all 497 records in each case. The incomplete row had no C text or prototype and reported `Bad instruction count exceeded` and missing p-code at `r0x000140020137`. The timeout, cancellation and startup-failure flags were false. All 497 uncached scheduler leases completed.

The verifier compares the complete files first. It can then report one documented stock failure for a matching fixture ID, entry address, analyzed body SHA-256 and exact diagnostic. Every other record must contain successful C output. Persistent cold and warm cache proofs still require successful C output for every record. [Verifier](../../benchmarks/verify_ghidra.py)
