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

## CLI prototype

The analyzer now has a real APK intake and DEX indexing layer. The CLI accepts a local APK path and reports SHA-256, package/version metadata, DEX inventory, native libraries, class counts, method counts, and per-method opcode histograms in memory.

Example:

```bash
gradle :analyzer:run --args="/path/to/telegram.apk"
```

The bytecode layer uses Google's `com.android.tools.smali:smali-dexlib2:3.0.10`, which is the same major tool family used for the authoritative DEX representation. APK manifest metadata is read with `net.dongliu:apk-parser:2.6.10`. Fingerprint/report JSON is handled with Jackson Kotlin. The Google smali project documents the `smali-dexlib2` artifact as the DEX library for reading/modifying/writing DEX files.

## Differential analysis

Compare two Telegram APKs directly:

```bash
./gradlew :analyzer:run --args="--diff old.apk new.apk build/report"
```

The differential engine records:

- exact signature preservation
- structural bytecode similarity
- declaring-class migration context
- outgoing method-call prototype similarity
- top candidate migrations with independent score components
- conservative `MIGRATED`, `REVIEW`, and `BROKEN` states
- machine-readable JSON plus a Markdown summary

The migration evidence is deliberately structured rather than encoded into display strings, making it suitable for dashboards, regression tests, and future scoring models.

## GitHub Actions

The repository includes a manual URL-driven differential workflow. Provide old/new APK URLs and optional SHA-256 values; the workflow downloads both artifacts, verifies hashes when supplied, runs the analyzer tests, and uploads the generated report.

## Status

🚧 Milestone 3 in progress: differential migration intelligence now combines structural, class-context, and call-shape evidence. Next layers are caller/callee neighborhood analysis, CFG similarity, caching, and richer report visualization.
