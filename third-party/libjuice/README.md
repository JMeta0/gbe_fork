# libjuice 1.7.2 (vendored)

[libjuice](https://github.com/paullouisageneau/libjuice) is a lightweight
UDP Interactive Connectivity Establishment (ICE) library by Paul-Louis
Ageneau. It provides the emulator's internet transport with:

- ICE agent (RFC 8445): candidate gathering (host + server-reflexive via STUN
  + relay via TURN), connectivity checks, nomination
- STUN client (RFC 5389)
- TURN client (RFC 5766) — relayed fallback behind symmetric NAT

Vendored from upstream tag `v1.7.2` (same version the Nemirtingas emulator
uses). Only the library sources are kept:

- `include/juice/juice.h` — public API (compile with `JUICE_STATIC` defined)
- `src/` — all upstream sources (`server.c` included for parity with the
  upstream build; it is not used by the emulator)
- `LICENSE` — Mozilla Public License 2.0

The library is compiled directly into the emulator projects via `premake5.lua`
(`common_files`), so no separate static lib target is needed. See `premake5.lua`
for the `JUICE_STATIC` define.
