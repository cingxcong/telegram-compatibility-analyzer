# Telegram Compatibility Analyzer

A bytecode-first compatibility analyzer for Telegram Android APKs and Morphe-style patch fingerprints.

## Goal

Given a Telegram APK and a known fingerprint/patch set, produce a machine-readable compatibility report that can distinguish:

- exact fingerprint matches
- safe structural migrations
- ambiguous candidates requiring review
- broken/missing targets

The analyzer is designed to be conservative: it should never silently rewrite a patch when confidence is insufficient.

## Architecture

```
Telegram APK URL / local APK
        |
        v
 APK intake + SHA/version metadata
        |
        v
 DEX extraction + baksmali/dexlib2 index
        |
        +--> JADX semantic view (secondary)
        |
        +--> Androguard metadata / CFG / call graph (secondary)
        |
        v
 Fingerprint candidate generation
        |
        v
 Structural similarity + anchors + call graph
        |
        v
 Compatibility report
        |
        +--> PASS
        +--> REVIEW
        +--> BROKEN
        |
        v
 Optional safe patch-build validation
```

## Design principles

1. **Bytecode is authoritative.** Decompiled Java is supporting evidence only.
2. **Exact matches first.** Structural migration is a fallback.
3. **Multiple independent signals.** Prototype, declaring class context, fields, calls, strings, opcode shape, CFG shape and neighboring methods can all contribute.
4. **Conservative automation.** Ambiguous matches are reported, not guessed.
5. **Differential history.** Known Telegram version pairs can teach obfuscation/name migrations.
6. **Policy-aware patch metadata.** The analyzer can classify patch compatibility work and keep sensitive behaviors out of automatic migration.

## Planned toolchain

- baksmali / smali + dexlib2 — authoritative DEX layer
- JADX — secondary semantic/decompiler view
- Androguard — APK/DEX metadata, disassembly, CFG/call-graph analysis
- APK parsing/signature metadata — intake and artifact validation

## First milestone

Telegram APK -> metadata -> DEX extraction -> bytecode index -> fingerprint import -> structural matching -> JSON compatibility report.

## Status

🚧 Initial repository scaffold.
