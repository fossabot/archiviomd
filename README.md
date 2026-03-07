# ArchivioMD

**ArchivioMD** is a document integrity and compliance plugin for WordPress built for teams and developers who need more than file storage.

At its core, ArchivioMD gives you a clean, centralized admin interface for managing site documentation, SEO files, and sitemaps. But underneath that clean surface sits a serious cryptographic engine: every document and post can be fingerprinted with SHA-256, SHA-512, BLAKE2b, or HMAC-backed hashes, signed with Ed25519, SLH-DSA (post-quantum), ECDSA P-256, or RSA, then anchored to external trust registers including RFC 3161 timestamping authorities, the Sigstore/Rekor transparency log, GitHub or GitLab repositories, and DNSSEC-protected DNS records — creating a tamper-evident, verifiable paper trail for your content.

Whether you're meeting compliance requirements, protecting against unauthorized edits, or simply building a site where document integrity actually matters, ArchivioMD gives you audit logs, checksum verification, backup and restore with dry-run previews, signed compliance exports, steganographic content fingerprinting, and an asynchronous anchoring queue with exponential backoff.

[![Version](https://img.shields.io/badge/version-1.17.4-667eea)](https://github.com/MountainViewProvisions/archiviomd/releases)
[![License](https://img.shields.io/badge/license-GPL%20v2-blue)](https://www.gnu.org/licenses/gpl-2.0.html)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4)](https://php.net)
[![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759B)](https://wordpress.org)
[![Add-on](https://img.shields.io/badge/add--on-ArchivioID-764ba2)](https://github.com/MountainViewProvisions/archivio-id)
[![Crypto](https://img.shields.io/badge/crypto-SHA256%20%7C%20SHA512%20%7C%20SHA3%20%7C%20BLAKE2b%20%7C%20BLAKE3%20%7C%20SHAKE-10b981)](https://github.com/MountainViewProvisions/archiviomd)
[![Signing](https://img.shields.io/badge/signing-Ed25519%20%7C%20SLH--DSA%20%7C%20ECDSA%20%7C%20RSA-667eea)](https://github.com/MountainViewProvisions/archiviomd)
[![Post-Quantum](https://img.shields.io/badge/post--quantum-SLH--DSA%20FIPS%20205-10b981)](https://github.com/MountainViewProvisions/archiviomd)
[![Anchoring](https://img.shields.io/badge/anchoring-GitHub%20%7C%20GitLab%20%7C%20RFC3161%20%7C%20Rekor%20%7C%20DANE-1f2937)](https://github.com/MountainViewProvisions/archiviomd)
[![Fingerprinting](https://img.shields.io/badge/fingerprinting-Canary%20Tokens-f59e0b)](https://github.com/MountainViewProvisions/archiviomd)

---

## Table of Contents

- [Features](#features)
  - [Centralized Documentation Management](#centralized-documentation-management)
  - [Custom Markdown Files](#custom-markdown-files)
  - [HTML Rendering](#html-rendering)
  - [Public Documentation Index](#public-documentation-index)
  - [Cryptographic Post & Page Verification](#-cryptographic-post--page-verification)
  - [Ed25519 Document Signing](#ed25519-document-signing)
  - [DSSE Envelope Mode](#dsse-envelope-mode)
  - [SLH-DSA Post-Quantum Signing](#slh-dsa-post-quantum-signing)
  - [ECDSA P-256 Enterprise Signing](#ecdsa-p-256-enterprise-signing)
  - [RSA Compatibility Signing](#rsa-compatibility-signing)
  - [CMS / PKCS#7 Detached Signatures](#cms--pkcs7-detached-signatures)
  - [JSON-LD / W3C Data Integrity Proofs](#json-ld--w3c-data-integrity-proofs)
  - [DANE / DNS Key Corroboration](#dane--dns-key-corroboration)
  - [External Anchoring](#external-anchoring-remote-distribution-chain)
  - [RFC 3161 Trusted Timestamps](#rfc-3161-trusted-timestamps)
  - [Sigstore / Rekor Transparency Log](#sigstore--rekor-transparency-log)
  - [Canary Tokens](#canary-tokens-steganographic-content-fingerprinting)
  - [Compliance & Audit Tools](#compliance--audit-tools)
  - [SEO & Crawling Files](#seo--crawling-files)
  - [Sitemap Management](#sitemap-management)
  - [Professional Admin Interface](#professional-admin-interface)
- [Philosophy](#philosophy)
- [Installation](#installation)
- [Requirements](#requirements)
- [Security](#security)
- [File Serving and URL Structure](#file-serving-and-url-structure)
- [WP-CLI](#wp-cli)
- [Roadmap](#roadmap)
- [License](#license)
- [Author](#author)
- [Links](#links)
- [Support](#support)

---

## Features

### Centralized Documentation Management

ArchivioMD provides a master list of Markdown (`.md`) documentation files, grouped by purpose, including:

- Project overview and development documentation
- Licensing and legal documents
- Security and vulnerability policies
- Privacy and data compliance files
- Governance, identity, and team documentation
- Supply chain and third-party service references

All documents are editable directly from the WordPress admin interface. Each category can be expanded or collapsed for easier navigation, and files display their current status (Active or Empty) along with their storage location.

---

### Custom Markdown Files

Beyond the predefined documentation templates, ArchivioMD allows you to create custom markdown files for any purpose. Custom files integrate seamlessly with the standard documentation set and support the same features, including HTML rendering and public index inclusion.

---

### HTML Rendering

ArchivioMD can automatically generate HTML versions of any markdown file with a single click. HTML files are created alongside their markdown counterparts and are served through the same URL structure with a `.html` extension instead of `.md`.

---

### Public Documentation Index

The plugin includes a dedicated public index feature that allows you to selectively publish documentation to site visitors, configurable in two ways:

**Page Mode:** Display the index on any WordPress page of your choice, rendering a structured listing of selected documents organized by category.

**Shortcode Mode:** Use the `[mdsm_public_index]` shortcode to embed the documentation index anywhere in your content.

For each included document, you can customize the public-facing description independently from the internal description.

---

### 🔒 Cryptographic Post & Page Verification

#### Verification Badge System

- **Visual badges** on posts and pages showing integrity status
- **Three states**: ✓ Verified (green), ✗ Unverified (red), − Not Signed (gray)
- **Automatic display** below titles or content
- **Manual placement** via `[hash_verify]` shortcode
- **Downloadable verification files** for offline confirmation

#### Supported Hash Algorithms

**Standard Algorithms:**

| Algorithm | Output Size | Notes |
|---|---|---|
| SHA-256 | 256 bits | Default. General use, maximum compatibility |
| SHA-224 | 224 bits | Truncated SHA-256 |
| SHA-384 | 384 bits | Truncated SHA-512 |
| SHA-512 | 512 bits | High security requirements |
| SHA-512/224 | 224 bits | SHA-512 with truncation |
| SHA-512/256 | 256 bits | SHA-512 with truncation |
| SHA3-256 | 256 bits | NIST standard, modern security |
| SHA3-512 | 512 bits | Maximum security |
| BLAKE2b-512 | 512 bits | Very fast, high security |
| BLAKE2s-256 | 256 bits | Optimized for 32-bit platforms |
| SHA-256d | 256 bits | Double SHA-256 |
| RIPEMD-160 | 160 bits | Legacy compatibility |
| Whirlpool-512 | 512 bits | ISO/IEC 10118-3 standard |

**Extended Algorithms:**

| Algorithm | Output Size | Notes |
|---|---|---|
| BLAKE3-256 | 256 bits | Fastest. Pure-PHP implementation included |
| SHAKE128-256 | 256 bits | SHA-3 XOF variant |
| SHAKE256-512 | 512 bits | SHA-3 XOF variant |
| GOST R 34.11-94 | 256 bits | Russian GOST standard |
| GOST R 34.11-94 (CryptoPro) | 256 bits | CryptoPro S-Box variant |

**Legacy Algorithms (not recommended for new installations):**

| Algorithm | Notes |
|---|---|
| MD5 | Cryptographically broken. Interoperability only |
| SHA-1 | Deprecated. Interoperability only |

#### HMAC Mode

Add authentication to content verification:

```php
// Add to wp-config.php
define('ARCHIVIOMD_HMAC_KEY', 'your-secret-key');
```

Then enable in **Cryptographic Verification → Settings → Enable HMAC Mode**.

HMAC mode provides:

- **Content integrity** — proves content hasn't changed
- **Authenticity** — proves hash was created by the key holder
- **Tamper detection** — any modification invalidates the hash
- **Key-based verification** — offline verification requires the secret key

An adversary with database access alone cannot silently update the HMAC — the key lives only in `wp-config.php`.

**Offline HMAC verification:**

```bash
echo -n "canonical_content" | openssl dgst -sha256 -hmac "YOUR_SECRET_KEY"
```

---

### Ed25519 Document Signing

Posts, pages, and media are signed automatically on save using PHP sodium (`ext-sodium`, standard since PHP 7.2).

```php
// Add to wp-config.php
define('ARCHIVIOMD_ED25519_PRIVATE_KEY', 'your-128-char-hex-private-key');
define('ARCHIVIOMD_ED25519_PUBLIC_KEY',  'your-64-char-hex-public-key');
```

- Private key never stored in the database
- Public key published at `/.well-known/ed25519-pubkey.txt` for independent third-party verification
- No WordPress dependency required to verify — standard sodium tooling works
- In-browser keypair generator included in the admin UI

**Canonical message format:**

```
mdsm-ed25519-v1\n{post_id}\n{title}\n{slug}\n{content}\n{date_gmt}
```

**Offline verification:**

```bash
# Fetch public key
curl https://yoursite.com/.well-known/ed25519-pubkey.txt

# Verify with sodium CLI or any compatible tool
```

Signatures are stored in `_mdsm_ed25519_sig` (hex) and `_mdsm_ed25519_signed_at` (Unix timestamp) post meta. Signing runs at `save_post` priority 20.

---

### DSSE Envelope Mode

Wraps Ed25519 signatures in a Dead Simple Signing Envelope per the [Sigstore DSSE specification](https://github.com/secure-systems-lab/dsse).

When enabled, every post and media signature is additionally wrapped in a structured JSON envelope stored in the `_mdsm_ed25519_dsse` post meta key. The bare hex signature in `_mdsm_ed25519_sig` is always preserved alongside — all existing verifiers continue to work without migration.

**Envelope format:**

```json
{
  "payload": "<base64(canonical_msg)>",
  "payloadType": "application/vnd.archiviomd.document",
  "signatures": [
    {
      "keyid": "<sha256_hex(pubkey_bytes)>",
      "sig": "<base64(sig_bytes)>"
    }
  ]
}
```

Signing is over the DSSE Pre-Authentication Encoding (PAE):

```
DSSEv1 {len(payloadType)} {payloadType} {len(payload)} {payload}
```

PAE binding prevents cross-protocol signature confusion attacks — a bare Ed25519 signature over a document hash cannot be replayed against the DSSE PAE and vice versa. The `keyid` field is the SHA-256 fingerprint of the raw public key bytes.

In hybrid mode with SLH-DSA, the envelope is extended with a second `signatures[]` entry — see [SLH-DSA Post-Quantum Signing](#slh-dsa-post-quantum-signing).

---

### SLH-DSA Post-Quantum Signing

Posts, pages, and media are signed automatically on save using a pure-PHP implementation of SLH-DSA (SPHINCS+), standardised as **NIST FIPS 205**.

- **Quantum-resistant:** security rests entirely on SHA-256 — not on the hardness of factoring or discrete logarithms, which Grover's and Shor's algorithms threaten
- **Pure PHP:** no extensions, no FFI, no Composer dependencies. Works on any shared host running PHP 7.4+
- Private key stored in `wp-config.php` — never in the database
- Public key published at `/.well-known/slhdsa-pubkey.txt`
- In-browser keypair generator — keys generated server-side, never transmitted

```php
// Add to wp-config.php
define('ARCHIVIOMD_SLHDSA_PRIVATE_KEY', 'your-hex-private-key');
define('ARCHIVIOMD_SLHDSA_PUBLIC_KEY',  'your-hex-public-key');
define('ARCHIVIOMD_SLHDSA_PARAM',       'SLH-DSA-SHA2-128s'); // optional
```

#### Parameter Sets

| Parameter Set | Signing Time | Signature Size | Security Level |
|---|---|---|---|
| SLH-DSA-SHA2-128s | 200–600 ms | 7,856 bytes | NIST Category 1 |
| SLH-DSA-SHA2-128f | 30–80 ms | 17,088 bytes | NIST Category 1 |
| SLH-DSA-SHA2-192s | ~1–2 s | 16,224 bytes | NIST Category 3 |
| SLH-DSA-SHA2-256s | ~2–4 s | 29,792 bytes | NIST Category 5 |

Signing overhead occurs **once per publish or update event** and has no effect on front-end page rendering. Switch to `-128f` for lower latency at the cost of larger signatures stored in post meta.

The active parameter set is recorded in `_mdsm_slhdsa_param` post meta at signing time — old signatures remain verifiable after a parameter set change.

#### Hybrid Mode with Ed25519

When both Ed25519 and SLH-DSA are enabled, the shared DSSE envelope is extended with a second `signatures[]` entry:

```json
{
  "payload": "<base64(canonical_msg)>",
  "payloadType": "application/vnd.archiviomd.document",
  "signatures": [
    { "keyid": "<sha256(ed25519_pub)>",  "sig": "...", "alg": "ed25519"           },
    { "keyid": "<sha256(slhdsa_pub)>",   "sig": "...", "alg": "slh-dsa-sha2-128s" }
  ]
}
```

Verifiers that only understand Ed25519 continue to work unchanged — they ignore the unfamiliar `alg` field.

#### Offline Verification

```python
# Python (pyspx)
from pyspx import shake_128s
ok = shake_128s.verify(message.encode(), bytes.fromhex(sig_hex), bytes.fromhex(pubkey_hex))
```

Post meta keys: `_mdsm_slhdsa_sig` (hex), `_mdsm_slhdsa_dsse` (DSSE envelope JSON), `_mdsm_slhdsa_signed_at` (Unix timestamp), `_mdsm_slhdsa_param` (parameter set name). Signing runs at `save_post` priority 25.

---

### ECDSA P-256 Enterprise Signing

> ⚠️ **Enterprise / Compliance Mode only.** Enable this when an external compliance framework explicitly mandates X.509 certificate-backed ECDSA signatures — eIDAS qualified signatures, SOC 2 Type II, HIPAA audit log mandates, or government PKI frameworks. For all other sites, Ed25519 is simpler, faster, and equally secure.

Posts, pages, and media are signed using ECDSA P-256 (secp256r1 / NIST P-256) via PHP `ext-openssl`. Nonce generation is **100% delegated to OpenSSL (libssl)** — the plugin never touches EC arithmetic or nonce generation. ECDSA is catastrophically broken by nonce reuse.

```php
// Add to wp-config.php
define('ARCHIVIOMD_ECDSA_PRIVATE_KEY_PEM', '-----BEGIN EC PRIVATE KEY-----\n...');
define('ARCHIVIOMD_ECDSA_CERTIFICATE_PEM', '-----BEGIN CERTIFICATE-----\n...');
define('ARCHIVIOMD_ECDSA_CA_BUNDLE_PEM',   '-----BEGIN CERTIFICATE-----\n...'); // optional
```

Alternatively, upload PEM files through the admin UI. Uploaded files are stored **one directory level above the webroot** (outside `DOCUMENT_ROOT`), chmod 0600, with an `.htaccess` Deny guard. Private key material is never stored in the database and never echoed in AJAX responses. On removal, files are overwritten with zeros before unlinking.

Certificate validation runs on every signing operation before `openssl_sign()` is called: notBefore/notAfter validity window, public key type (must be EC), curve identity (must be `prime256v1`), private-key/public-key match, and optional CA chain.

- Leaf certificate published at `/.well-known/ecdsa-cert.pem`
- DSSE envelope stores an `x5c` field (leaf certificate PEM) for offline chain validation without a separate network request
- `keyid` is SHA-256 of the certificate DER

#### Offline Verification

```bash
# OpenSSL CLI
curl https://yoursite.com/.well-known/ecdsa-cert.pem -o cert.pem
openssl dgst -sha256 -verify <(openssl x509 -in cert.pem -pubkey -noout) \
    -signature sig.der <<< "<canonical_message>"
```

```python
# Python (cryptography library)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
cert = load_pem_x509_certificate(open('cert.pem', 'rb').read())
cert.public_key().verify(sig_der_bytes, message_bytes, ECDSA(SHA256()))
```

Post meta keys: `_mdsm_ecdsa_sig` (hex DER), `_mdsm_ecdsa_cert` (leaf cert PEM), `_mdsm_ecdsa_signed_at`, `_mdsm_ecdsa_dsse`. Signing runs at `save_post` priority 30.

---

### RSA Compatibility Signing

> ⚠️ **Legacy compatibility mode.** Enable only when a downstream system cannot accept Ed25519, ECDSA, or SLH-DSA keys — for example, older HSMs or verification toolchains hardcoded to RSA.

```php
// Add to wp-config.php
define('ARCHIVIOMD_RSA_PRIVATE_KEY_PEM', '-----BEGIN RSA PRIVATE KEY-----\n...');
define('ARCHIVIOMD_RSA_CERTIFICATE_PEM', '-----BEGIN CERTIFICATE-----\n...'); // optional
define('ARCHIVIOMD_RSA_SCHEME', 'rsa-pss-sha256'); // or 'rsa-pkcs1v15-sha256'
```

- Two schemes: RSA-PSS/SHA-256 (recommended) and PKCS#1 v1.5/SHA-256 (legacy)
- Minimum key size enforced: 2048 bits
- Public key published at `/.well-known/rsa-pubkey.pem`
- Same secure PEM file storage pattern as ECDSA (outside webroot, chmod 0600)

#### Offline Verification

```bash
curl https://yoursite.com/.well-known/rsa-pubkey.pem -o rsa-pubkey.pem
openssl dgst -sha256 -verify rsa-pubkey.pem \
    -signature <(echo -n "{sig_hex}" | xxd -r -p) <<< "<canonical_message>"
```

Post meta keys: `_mdsm_rsa_sig`, `_mdsm_rsa_signed_at`, `_mdsm_rsa_scheme`. Signing runs at `save_post` priority 35.

---

### CMS / PKCS#7 Detached Signatures

> ⚠️ **Legacy compatibility mode.** Enable when a document management system, Adobe Acrobat workflow, or regulated-industry audit tool specifically requires `.p7s` format.

Produces a Cryptographic Message Syntax (CMS / PKCS#7, RFC 5652) detached signature on every post, page, and media save. **Reuses your configured ECDSA P-256 or RSA key** — no additional key material required. ECDSA is the primary source; RSA is the fallback.

The signature is stored as a base64-encoded DER blob in `_mdsm_cms_sig` post meta, directly importable into Adobe Acrobat, Windows Explorer, Java Bouncy Castle, and enterprise DMS platforms as a `.p7s` file.

#### Offline Verification

```bash
# Decode the base64 blob from the verification file, then:
base64 -d sig.b64 > sig.der
openssl cms -verify -inform DER -in sig.der -content message.txt -noverify
# Add -CAfile ca-bundle.pem to verify the full certificate chain
```

Signing runs at `save_post` priority 40. Requires ECDSA P-256 or RSA signing to be configured first.

---

### JSON-LD / W3C Data Integrity Proofs

Produces W3C Data Integrity proof blocks for each post and publishes a `did:web` DID document listing all active public keys as verification methods.

- **Cryptosuites:** `eddsa-rdfc-2022` (Ed25519) and `ecdsa-rdfc-2019` (ECDSA P-256), produced simultaneously when both signers are active
- **No blockchain, no external registry** — the domain is its own trust anchor
- DID document served at `/.well-known/did.json` with `publicKeyMultibase` (Ed25519) and `publicKeyJwk` (ECDSA)
- Proof set stored in `_mdsm_jsonld_proof` post meta
- Compatible with ActivityPub implementations, W3C Verifiable Credential libraries, and decentralised identity wallets
- Reuses existing Ed25519 and/or ECDSA P-256 keys — no additional key material required

#### Offline Verification

```bash
# Resolve the DID document
curl https://yoursite.com/.well-known/did.json

# Verify with any W3C Data Integrity-compatible library
# JavaScript: @digitalbazaar/jsonld-signatures
# Python:     pyld + cryptography
```

Signing runs at `save_post` priority 45. Requires Ed25519 or ECDSA P-256 to be configured first.

---

### DANE / DNS Key Corroboration

Publishes every active signing key as a DNSSEC-protected DNS record, giving verifiers a trust path entirely independent of your web server and TLS certificate chain. An attacker must compromise both your web host **and** your DNS zone simultaneously to forge a key — no trust-on-first-use required.

#### TXT Records (amd1 format)

One DNS TXT record per active algorithm, modelled on DKIM (RFC 6376) tag-value syntax:

```
_archiviomd._domainkey.example.com.         IN TXT "v=amd1; k=ed25519; p=<base64-pubkey>"
_archiviomd-slhdsa._domainkey.example.com.  IN TXT "v=amd1; k=slh-dsa; a=SLH-DSA-SHA2-128s; p=<base64-pubkey>"
_archiviomd-ecdsa._domainkey.example.com.   IN TXT "v=amd1; k=ecdsa-p256; p=<base64-cert-sha256>"
_archiviomd-rsa._domainkey.example.com.     IN TXT "v=amd1; k=rsa; p=<base64-cert-sha256>"
```

| Tag | Meaning |
|---|---|
| `v=amd1` | Format version. Records with any other version must be ignored |
| `k=` | Algorithm: `ed25519`, `slh-dsa`, `ecdsa-p256`, or `rsa` |
| `a=` | Parameter set (SLH-DSA only, e.g. `SLH-DSA-SHA2-128s`) |
| `p=` | Key material or fingerprint (base64) |

#### TLSA Record (DANE-EE, RFC 6698)

When ECDSA P-256 is configured, an optional TLSA record binds the leaf certificate to your HTTPS service:

```
_443._tcp.example.com. IN TLSA 3 1 1 <spki-sha256-hex>
```

Parameters: Usage=3 (DANE-EE), Selector=1 (SubjectPublicKeyInfo DER — survives cert renewal without a key change), Matching-type=1 (SHA-256).

#### Discovery & Specification Endpoints

```
GET /.well-known/archiviomd-dns.json       # active records, expected TXT values, key fingerprints
GET /.well-known/archiviomd-dns-spec.json  # machine-readable amd1 format specification
```

`archiviomd-dns.json` returns `{"enabled":false}` when DANE is disabled — verifiers can distinguish module-off from a wrong URL. `archiviomd-dns-spec.json` is always served regardless of DANE state.

#### Key Rotation

DNS TTL caching means there is always a window between updating a key constant and the old TXT record expiring from resolver caches. Rotation mode suppresses false-positive mismatch warnings during this window:

1. Click **Start Key Rotation** (or `wp archiviomd dane-check --rotation`)
2. Publish the new TXT record alongside the old one in DNS
3. Wait one TTL (default 3600 s)
4. Update `wp-config.php` with the new keypair constants
5. Click **Finish Rotation** (or `wp archiviomd dane-check --finish-rotation`)
6. Remove the old TXT record after one more TTL

#### Configuration Constants

```php
define('ARCHIVIOMD_DOH_URL',       'https://8.8.8.8/resolve'); // DoH resolver (default: 1.1.1.1)
define('ARCHIVIOMD_DANE_TTL',      300);                        // DNS TTL (default: 3600)
define('ARCHIVIOMD_TLSA_PORT',     '443');                      // TLSA port (default: 443)
define('ARCHIVIOMD_TLSA_PROTOCOL', 'tcp');                      // tcp, udp, or sctp (default: tcp)
```

#### WP-CLI

```bash
wp archiviomd dane-check                    # health check all active algorithms
wp archiviomd dane-check --algo=ed25519     # single algorithm
wp archiviomd dane-check --tlsa             # also run TLSA check
wp archiviomd dane-check --porcelain        # machine-readable; exit 1 on failure
wp archiviomd dane-check --enable           # enable DANE Corroboration
wp archiviomd dane-check --disable          # disable DANE Corroboration
wp archiviomd dane-check --rotation         # start rotation mode
wp archiviomd dane-check --finish-rotation  # end rotation mode
```

Weekly passive health checks via wp-cron surface failures as dismissible admin notices. DNSSEC is required — without a validating resolver confirming the `AD` flag, DNS responses are unauthenticated and the records provide no additional trust.

---

### External Anchoring (Remote Distribution Chain)

Distribute cryptographic integrity records to Git repositories for tamper-evident audit trails.

#### Supported Providers

- **GitHub** (public and private repositories)
- **GitLab** (public and private repositories, including self-hosted)

#### How It Works

1. Content is published or updated
2. Cryptographic hash (and any active signatures) is generated
3. JSON anchor record is created and queued
4. WP-Cron pushes to GitHub/GitLab every 5 minutes
5. Git commit provides an immutable, independently verifiable timestamp

Multiple providers can run simultaneously on every anchor job. Failure or rate-limiting of one does not block the others.

#### Anchor Record Format

```json
{
  "document_id": "security.txt.md",
  "post_id": 123,
  "post_type": "post",
  "hash_algorithm": "sha256",
  "hash_value": "a3f5b8c2d9e1f4a7...",
  "hmac_value": "b7c6d8e2f1a4b7c6...",
  "ed25519_sig": "...",
  "ed25519_pubkey": "...",
  "slhdsa_sig": "...",
  "slhdsa_param": "SLH-DSA-SHA2-128s",
  "slhdsa_pubkey": "...",
  "ecdsa_sig": "...",
  "ecdsa_cert_url": "https://yoursite.com/.well-known/ecdsa-cert.pem",
  "author_id": 1,
  "timestamp": "2026-02-15T12:05:30Z",
  "plugin_version": "1.17.4",
  "integrity_mode": "hmac"
}
```

#### Git Chain Verification

```bash
git clone https://github.com/username/anchors.git && cd anchors
git log --oneline
cat document_20260215_120530.json
git log --follow document_20260215_120530.json
```

---

### RFC 3161 Trusted Timestamps

Every anchor job can submit the content hash to an RFC 3161-compliant Time Stamp Authority (TSA). The TSA returns a signed `.tsr` token binding the hash to a specific point in time — independently verifiable offline without trusting the plugin or the site.

#### Built-in TSA Providers

| Provider | Notes |
|---|---|
| FreeTSA.org | Free public TSA |
| DigiCert | Commercial |
| GlobalSign | Commercial |
| Sectigo | Commercial |

Custom TSA endpoints are supported.

#### Storage & Access

- `.tsr` and `.tsq` files stored in `uploads/meta-docs/tsr-timestamps/`
- Blocked from direct HTTP access via `.htaccess`
- Served via authenticated download handler
- Manifests included in Compliance JSON exports

#### Offline Verification

```bash
openssl ts -verify -in response.tsr -queryfile request.tsq -CAfile tsa.crt
```

RFC 3161, Git, and Rekor anchoring can all run simultaneously on every anchor job.

---

### Sigstore / Rekor Transparency Log

Every anchor job can simultaneously submit a `hashedrekord v0.0.1` entry to the public Sigstore Rekor append-only transparency log (`rekor.sigstore.dev`). Entries are immutable and publicly verifiable by anyone without pre-trusting the signer's key. No account or API key required.

#### Signing Behaviour

- With `ARCHIVIOMD_ED25519_PRIVATE_KEY` configured: entries are signed with the long-lived site key. The public key fingerprint links to `/.well-known/ed25519-pubkey.txt`.
- Without site keys: a per-submission ephemeral keypair is generated automatically via PHP Sodium. The content hash is still immutably logged.

#### Embedded Provenance Metadata

| Field | Value |
|---|---|
| `archiviomd.site_url` | Publishing site URL |
| `archiviomd.document_id` | Post/document ID |
| `archiviomd.post_type` | WordPress post type |
| `archiviomd.hash_algorithm` | Algorithm used |
| `archiviomd.plugin_version` | ArchivioMD version |
| `archiviomd.pubkey_fingerprint` | SHA-256 of public key bytes (or `ephemeral`) |
| `archiviomd.key_type` | `site-longterm` or `ephemeral` |
| `archiviomd.pubkey_url` | `/.well-known/ed25519-pubkey.txt` URL |

#### Independent Verification

```bash
# Via rekor-cli
rekor-cli get --log-index <INDEX>
rekor-cli verify --artifact-hash sha256:<HASH> --log-index <INDEX>

# Via REST API
curl https://rekor.sigstore.dev/api/v1/log/entries?logIndex=<INDEX>
```

Or browse entries at [search.sigstore.dev](https://search.sigstore.dev).

The Rekor Activity Log in the admin includes a live **Verify** button — fetches the inclusion proof directly from the Rekor API without leaving the admin.

#### Requirements

- PHP Sodium (`ext-sodium`) — standard since PHP 7.2
- PHP OpenSSL (`ext-openssl`)
- Outbound HTTPS to `rekor.sigstore.dev:443`

---

### Canary Tokens (Steganographic Content Fingerprinting)

> **Entirely opt-in. Nothing is injected into your content unless you explicitly enable it.**

Embeds an invisible, HMAC-authenticated fingerprint into published post content **at render time** — stored content is never modified. The fingerprint encodes the post ID, a timestamp, and a 48-bit HMAC, allowing you to identify the original source of content that has been copied or scraped without attribution.

#### Payload

```
[0-3]   post_id    uint32 big-endian
[4-7]   timestamp  uint32 big-endian (Unix epoch)
[8-13]  HMAC-SHA256(key, header)[0:6]  — 48-bit MAC
```

Each bit is encoded **three times** per active channel with majority-vote redundancy, providing resilience against partial stripping.

#### Encoding Channels

**Unicode layer** — survives copy-paste; stripped by OCR or retyping:

| Channel | Mechanism |
|---|---|
| Ch.1 | Zero-width characters (U+200B / U+200C) at word boundaries — sequentially decodable without a key |
| Ch.2 | Thin-space variants (U+2009) at key-derived positions |
| Ch.3 | Typographic apostrophe variants (U+2019) at key-derived positions |
| Ch.4 | Soft hyphens (U+00AD) inserted within longer words |

**Semantic layer** — survives OCR, retyping, and Unicode normalisation; each opt-in:

| Channel | Mechanism |
|---|---|
| Ch.5 | Contraction encoding — "don't" ↔ "do not" |
| Ch.6 | Synonym substitution — "start" ↔ "begin" |
| Ch.7 | Punctuation choice — Oxford comma; em-dash ↔ parentheses |
| Ch.8 | Spelling variants — "organise" ↔ "organize", "colour" ↔ "color" |
| Ch.9 | Hyphenation choices — "email" ↔ "e-mail", "online" ↔ "on-line" |
| Ch.10 | Number/date style — "1,000" ↔ "1000"; "10 percent" ↔ "10%"; "first" ↔ "1st" |
| Ch.11 | Punctuation style II — em-dash spacing; comma-before-too; introductory-clause comma |
| Ch.12 | Citation/title style — attribution colon; title italics ↔ quotation marks |

**Structural layer** — CDN-proof; survives Unicode normalisation and HTML minification:

| Channel | Mechanism |
|---|---|
| Ch.13 | Sentence-count parity — appends/removes a short filler clause from a 50-entry key-derived pool |
| Ch.14 | Word-count parity — inserts/removes a filler word from a 44-entry key-derived pool |

Channel dictionaries for Ch.5/6/8/9 use **key-derived pair selection** — an HMAC-PRNG selects a stable 70% subset of each dictionary, where the active subset is determined by your HMAC key. Knowing the full dictionary does not allow systematic reversal without the key.

#### Key Configuration

```php
// Strongly recommended — add to wp-config.php
define('ARCHIVIOMD_HMAC_KEY', 'your-secret-key'); // minimum 16 chars
```

Without this constant, the key falls back to `wp_salt('auth')`. If WordPress secret keys are ever regenerated or the site is migrated, that fallback key changes silently — invalidating all previously embedded fingerprints. A persistent admin notice is shown whenever the constant is absent.

#### Cache Compatibility

A Cache Compatibility Layer (`class-cache-compat.php`) uses `ob_start` at `template_redirect` priority 1 to wrap the entire page render. If an HTML-minifying caching plugin (WP Super Cache, W3 Total Cache, LiteSpeed Cache, WP Rocket) strips the Ch.1–4 Unicode characters before writing to the cache store, the layer re-encodes the article body and splices the fingerprint back into the full page before the cache copy is written — no caching plugin configuration required.

Additionally, a `Cache-Control: no-transform` header is sent on all fingerprinted responses (RFC 7230 §5.7.2), instructing compliant proxies and CDNs not to modify the body.

Semantic and structural channels (Ch.5–Ch.14) are not affected by caching or minification.

#### Decoding & Evidence

Navigate to **ArchivioMD → Canary Tokens → Decoder** and paste copied content or enter a remote URL. The URL decoder uses `dns_get_record()` to resolve the hostname and rejects any IP in a private, loopback, or reserved range before making the outbound request — preventing SSRF against internal services. cURL IP pinning (CURLOPT_RESOLVE) prevents TOCTOU between the DNS check and the connection.

After a successful decode:

- **DMCA Notice Generator** pre-fills a takedown letter using the decoded post metadata
- **Signed Evidence Package** downloads a `.sig.json` receipt containing the full decode result, a SHA-256 integrity hash over canonical JSON, and (when Ed25519 is configured) a detached signature over the same canonical string. The receipt is generated from the server-written Discovery Log row — not from user-submitted data — so it cannot be fabricated.

#### Discovery Log

Every decode attempt writes a timestamped entry to `wp_archivio_canary_log`, recording: wall time (UTC), source type, URL checked, post ID, fingerprint timestamp, payload version, HMAC validity, verifier user ID, and channel count. The log includes pagination, one-click CSV export for evidentiary use, and a per-receipt audit trail.

#### REST API

```
POST /wp-json/content/v1/verify
Body: { "content": "<text or HTML to check>" }
```

Returns: `found`, `valid`, `post_id`, `timestamp`, `post_title`, `post_url`. Rate-limited to 60 requests/60 s per IP (HTTP 429). An authenticated endpoint at `/wp-json/content/v1/verify/full` (requires `manage_options`) returns the full channel-by-channel breakdown with no rate limit.

The REST namespace is intentionally generic (`content/v1`) to avoid advertising the plugin's presence to parties probing the API.

#### WP-Options Obfuscation

All Canary Token settings are stored under 8-character hex keys derived from the site URL (`ac_3f7a2b1c` etc.), computed by `MDSM_Canary_Token::opt()`. A database dump does not reveal that steganographic fingerprinting is in use.

---

### Compliance & Audit Tools

Located at **Tools → ArchivioMD**.

#### Signed Export Receipts

Every CSV, Compliance JSON, and Backup ZIP generates a companion `.sig.json` integrity receipt containing:

- SHA-256 hash of the exported file
- Export type, filename, generation timestamp (UTC)
- Site URL, plugin version, generating user ID
- Detached signatures from all configured algorithms (Ed25519, SLH-DSA, ECDSA P-256)

#### Metadata Export (CSV)

Exports all document metadata: UUID, filename, path, last-modified timestamp (UTC), SHA-256 checksum, changelog count, and full changelog entries.

#### Compliance JSON Export

Structured export of the complete evidence package as a single JSON file. Preserves full relationships between posts, hash history, anchor log entries, and inlined RFC 3161 TSR manifests. Suitable for legal evidence packages, compliance audits, and SIEM ingestion.

#### Backup & Restore

Portable ZIP archives of all metadata and files. Restore requires a mandatory dry-run analysis before execution. Restore is explicit and admin-confirmed.

#### Metadata Verification

Manual checksum verification against stored SHA-256 values. Reports ✓ VERIFIED, ✗ MISMATCH, or ⚠ MISSING FILE. Read-only — does not modify files or metadata.

#### Metadata Cleanup on Uninstall

Opt-in, disabled by default. Requires typing `DELETE METADATA` to confirm. Markdown files are never deleted regardless of this setting.

---

### SEO & Crawling Files

Manage essential crawling and indexing files from the same admin page:

- `robots.txt`
- `llms.txt` (AI and LLM crawling instructions)
- `ads.txt`
- `app-ads.txt`
- `sellers.json`
- `ai.txt`

---

### Sitemap Management

**Small sites:** Single `sitemap.xml` containing all URLs.

**Large sites:** Multiple sitemaps organized by content type with a `sitemap_index.xml`. Optional automatic regeneration on publish/delete.

---

### Professional Admin Interface

Tab-based navigation, collapsible category organization, inline search, modal editing, status indicators, and link management. Fully responsive.

---

## Philosophy

ArchivioMD is intentionally **document-first**.

It does not attempt to replace full SEO suites or marketing tools. Instead, it focuses on providing a clear, maintainable, and transparent way to manage the files and documentation that define how a site operates, communicates, and is indexed — with a cryptographic proof layer that lets any third party independently verify that the content they see today is the content that was published.

---

## Installation

1. Download or clone this repository
2. Upload the plugin folder to `/wp-content/plugins/`
3. Activate **ArchivioMD** from the WordPress Plugins menu
4. Navigate to **Meta Documentation & SEO** in the WordPress admin dashboard
5. Go to **Settings → Permalinks** and click **Save Changes** to flush rewrite rules and enable `.well-known/` file serving

> **Important:** The permalink flush is critical. Without it, requests for markdown files, HTML files, and `.well-known/` endpoints will return 404 errors.

---

## Requirements

| Requirement | Minimum |
|---|---|
| WordPress | 6.0 |
| PHP | 7.4 |
| ext-sodium | Required for Ed25519 signing and Rekor (standard since PHP 7.2) |
| ext-openssl | Required for ECDSA P-256, RSA, CMS/PKCS#7, and Rekor |
| File permissions | Root-level write access (optional, recommended for `robots.txt`) |
| Capability | `manage_options` |

SLH-DSA post-quantum signing requires no extensions — pure PHP only.

---

## Security

- All AJAX requests are protected with WordPress nonces
- All plugin functionality requires `manage_options` capability
- All user input is sanitized; all output is escaped
- File operations validate filenames against directory traversal
- All private keys stored exclusively in `wp-config.php` — never in the database
- ECDSA and RSA PEM files stored outside `DOCUMENT_ROOT`, chmod 0600, with `.htaccess` Deny guard; overwritten with zeros on removal
- `.tsr` and `.tsq` files blocked from direct HTTP access
- SSRF prevention in the Canary Token URL decoder: hostname resolved via `dns_get_record()` with private/loopback/reserved range rejection and cURL IP pinning (CURLOPT_RESOLVE) to prevent TOCTOU
- Rate limiter on the public REST endpoint uses the rightmost `X-Forwarded-For` IP with private-range validation, falling back to `REMOTE_ADDR`
- Canary Token evidence receipts are generated from server-written log rows — not from POST data — preventing fabrication of signed receipts
- REST endpoint namespace (`content/v1`) is generic to avoid plugin enumeration via API probing

If you discover a security issue, please report it responsibly. See [`SECURITY.md`](SECURITY.md) for reporting guidelines.

---

## File Serving and URL Structure

| File | URL |
|---|---|
| Markdown | `https://yoursite.com/filename.md` |
| HTML | `https://yoursite.com/filename.html` |
| robots.txt | `https://yoursite.com/robots.txt` |
| llms.txt | `https://yoursite.com/llms.txt` |
| ads.txt | `https://yoursite.com/ads.txt` |
| sellers.json | `https://yoursite.com/sellers.json` |
| Ed25519 public key | `https://yoursite.com/.well-known/ed25519-pubkey.txt` |
| SLH-DSA public key | `https://yoursite.com/.well-known/slhdsa-pubkey.txt` |
| ECDSA certificate | `https://yoursite.com/.well-known/ecdsa-cert.pem` |
| RSA public key | `https://yoursite.com/.well-known/rsa-pubkey.pem` |
| DID document | `https://yoursite.com/.well-known/did.json` |
| DANE discovery | `https://yoursite.com/.well-known/archiviomd-dns.json` |
| DANE format spec | `https://yoursite.com/.well-known/archiviomd-dns-spec.json` |
| Sitemap (small) | `https://yoursite.com/sitemap.xml` |
| Sitemap (large) | `https://yoursite.com/sitemap_index.xml` |

---

## WP-CLI

```bash
# Anchoring
wp archiviomd process-queue        # process anchor queue immediately (bypasses cron)
wp archiviomd anchor-post <id>     # anchor a specific post by ID
wp archiviomd verify <id>          # verify a post's hash and all active signatures
wp archiviomd prune-log            # prune old anchor log entries

# DANE
wp archiviomd dane-check                    # health check all active algorithms
wp archiviomd dane-check --algo=ed25519     # single algorithm
wp archiviomd dane-check --tlsa             # also run TLSA check
wp archiviomd dane-check --porcelain        # machine-readable; exit 1 on failure
wp archiviomd dane-check --enable           # enable DANE Corroboration
wp archiviomd dane-check --disable          # disable DANE Corroboration
wp archiviomd dane-check --rotation         # start key rotation mode
wp archiviomd dane-check --finish-rotation  # end key rotation mode
```

---

## Roadmap

- Additional document types and templates
- Enhanced sitemap controls (priority, change frequency)
- UI refinements and accessibility improvements
- Bulk import for migrating existing documentation
- Version history UI for documentation changes
- Collaborative editing features for team workflows

---

## License

Licensed under the **GNU General Public License v2.0 (GPL-2.0)** — the same license used by WordPress.

See [`LICENSE`](LICENSE) for full license text.

---

## Author

**Mountain View Provisions LLC**

---

## Links

- Plugin website: [mountainviewprovisions.com/ArchivioMD](https://mountainviewprovisions.com/ArchivioMD)
- GitHub: [github.com/mountainviewprovisions/archiviomd](https://github.com/mountainviewprovisions/archiviomd)
- WordPress.org: [wordpress.org/plugins/archiviomd](https://wordpress.org/plugins/archiviomd)

---

## Support

For questions, feature requests, or bug reports, please use the [GitHub issue tracker](https://github.com/MountainViewProvisions/archiviomd/issues).
