# Security Policy

## Reporting a vulnerability

Email <security@theqrl.org>. Please do not open a public issue for a
vulnerability in this tool.

Include what you can: the version or commit, the affected file or workflow, and
what an attacker would gain. A proof of concept helps but is not required to
report something.

## What this tool protects, and what it does not

This is an offline generator for QRL XMSS wallets. Its security rests on three
assumptions, and reports that undermine any of them are in scope:

1. **The artefact you run is the code in this repository.** The published
   single-file HTML carries a SHA-256 and a signed build-provenance
   attestation; see [RELEASE.md](RELEASE.md). Anything that lets a file diverge
   from its source without detection is a serious finding.
2. **The generated seed is unpredictable.** Entropy comes from the browser
   CSPRNG through a fail-closed wrapper (`src/secure-random.js`) that refuses to
   proceed on a missing, throwing, wrong-length, or all-zero result.
3. **An encrypted wallet file resists offline attack.** scrypt (N=2^17, r=8,
   p=1) plus AES-256-GCM with the KDF parameters bound into the additional
   authenticated data. See [docs/v3-wallet-format.md](docs/v3-wallet-format.md).

Explicitly **not** defended against:

- A compromised machine. If malware is running where you generate a wallet, it
  can read the seed from the page. The documented workflow — a bootable OS with
  no network — exists for this reason.
- A weak password on an encrypted wallet. The policy refuses common passwords,
  keyboard walks and repeating patterns, but scrypt cannot rescue a password
  that appears in a wordlist.
- Anything after the wallet leaves this tool. Where you store the file, print
  the paper backup, or type the mnemonic is outside its control.

## Scope

In scope: everything in this repository, including the GitHub Actions workflows
and the release process — they are part of the trust chain.

Out of scope: QRLLIB and the underlying `qrllib` WebAssembly library (report
those to <https://github.com/theQRL/qrllib>), and the QRL web wallet.
