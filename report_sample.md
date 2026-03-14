# Forensic Report: e21de28d-a5a3-400f-b7db-e7187c3ba334.pdf

**Engine:** PDF Shadow Attack Forensic Engine v2  
**Scan:** 2026-03-14T01:20:55.491078  
**File size:** 397,443 bytes  

> **🔴 VERDICT: DOCUMENT INTEGRITY COMPROMISED**

## ⛔ Attacks Performed

The following attack classes are not theoretical vulnerabilities — the attack artifacts are structurally present in the document, meaning the attacks were actually carried out:

- **ISA** on `JobTitle`
- **SHADOW** on `JobTitle`

## ⚠️ Vulnerabilities Present (Not Exploited)

The following vulnerabilities exist in the document's cryptographic infrastructure but show no evidence of exploitation:

- **PKCS** on `JobTitle`
- **USF** on `HRWet`

## Signature Analysis

### `JobTitle`

**Signed:** 2024-08-19 18:21:53 UTC  
**Certificate:** Common Name: eStaff365 Digital Signature  
**Self-signed:** True  
**Certificate validity:** 26 years (until 2039-12-31 23:59:59+00:00)  
**ByteRange:** `[0, 361493, 367639, 20608]`  
**Covers entire file:** False  
**Hash valid:** True (SHA-1)  
**Appearance:** `BITMAP-ONLY [RED]`  
**Bitmap:** 400x230 with alpha transparency  

| Attack Class | Status | Evidence |
|---|---|---|
| **ISA** | ⛔ EXPLOITED | ByteRange ends before the file ends and 8 objects were redefined in the incremental update. Content was appended and objects were changed after this signature was applied. This is not a theoretical... |
| **PKCS** | ⚠️ SUSCEPTIBLE |  |
| **SHADOW** | ⛔ EXPLOITED | Appearance stream contains ONLY a bitmap image with zero text operators. Standard "Digitally signed by [Name]" text is completely absent. This is not a vulnerability — it is the artifact of a perfo... |

### `HRWet`


| Attack Class | Status | Evidence |
|---|---|---|
| **USF** | ⚠️ SUSCEPTIBLE |  |

### `HRWet`

**Signed:** 2024-08-20 23:49:33 UTC  
**Signer:** Kelli Bates  
**Certificate:** Common Name: eStaff365 Digital Signature  
**Self-signed:** True  
**Certificate validity:** 26 years (until 2039-12-31 23:59:59+00:00)  
**ByteRange:** `[0, 390707, 396853, 590]`  
**Covers entire file:** True  
**Hash valid:** True (SHA-1)  
**Appearance:** `TEXT-ESIG [GREEN]`  

| Attack Class | Status | Evidence |
|---|---|---|
| **PKCS** | ⚠️ SUSCEPTIBLE |  |

### `SigObj_246`


| Attack Class | Status | Evidence |
|---|---|---|
| **USF** | ⚠️ SUSCEPTIBLE |  |

## All Findings

### 🔴 [CRITICAL] [SHADOW] Mixed appearances: bitmap-only and proper e-sig on same document

RED: ['JobTitle']. GREEN: ['HRWet']. Same platform, different rendering. One field has a picture, the other has proper signature text.

### 🔴 [CRITICAL] [SHADOW] ATTACKS PERFORMED (not merely susceptible): ISA, SHADOW

The following attack classes show evidence of actual exploitation, not just theoretical vulnerability. The attack artifacts are present in the document structure: ISA: JobTitle; SHADOW: JobTitle. Compare against fields where the same platform produced proper signatures without these artifacts — proving the platform is capable of correct output and chose not to produce it for the affected fields.

### 🔴 [CRITICAL] [ISA] ByteRange does not cover entire file (9,196 unsigned bytes)

CCS 2019 Line 20: c+d must equal file size. ByteRange ends at 388,247, file is 397,443 bytes. The last 9,196 bytes are unsigned. ISA: anyone could have appended content after signing.

### 🔴 [CRITICAL] [ISA] Incremental update redefines 8 objects outside signed range

Objects [103, 243, 244, 119, 245, 246, 247, 187] were redefined after first %%EOF. These modifications are not covered by the signature and alter the document's content.

### 🟠 [HIGH] [PKCS] Deprecated PKCS#1 v1.5 RSA padding

RFC 8017 recommends PSS. v1.5 is deterministic, no salt, exploitable by lazy validators. Enables parser-confusion attacks.

### 🟡 [MEDIUM] [PKCS] No signed attributes in PKCS#7

SignerInfo has zero authenticated attributes. RSA signature is computed directly over content hash with no binding metadata.

### 🟠 [HIGH] [PKCS] Hash algorithm mismatch: declares SHA-256, hash is 20 bytes (SHA-1)

Digest algorithm field says SHA-256 but embedded hash length is 20 bytes, consistent with SHA-1. Algorithm confusion.

### 🔴 [CRITICAL] [SHADOW] SHADOW ATTACK: hash intact but document modified via incremental update

Content hash matches ByteRange (SHA-1) but ByteRange does not cover the entire file. Objects were redefined outside the signed range. Adobe Reader post-2021 detects this and reports RED/INVALID.

**Reproduce:** `Adobe Reader: click signature -> RED/INVALID`

### 🟠 [HIGH] [PKCS] Self-signed certificate: 'Common Name: eStaff365 Digital Signature'

Subject equals issuer. No CA chain. Only the issuer can validate. Adobe shows YELLOW. Not in any trusted root store.

### 🟠 [HIGH] [PKCS] Certificate validity: 26 years (industry standard: 1-3)

Valid until 2039-12-31 23:59:59+00:00. 26 years without key rotation. If the private key is compromised at any point, every document ever signed with it is retroactively untrustworthy.

### 🟡 [MEDIUM] [PKCS] Certificate signed with SHA-1 (sha1_rsa)

SHA-1 broken for collision resistance since 2017. Deprecated by all major CAs.

### 🔴 [CRITICAL] [SHADOW] BITMAP-ONLY signature appearance — no text operators

Appearance stream has image (Do) but ZERO text (TJ/Tj). Standard 'Digitally signed by' text is absent. A picture was pasted where a cryptographic identity should be.

**Reproduce:** `pdfimages -list e21de28d-a5a3-400f-b7db-e7187c3ba334.pdf`

### 🔴 [CRITICAL] [SHADOW] Alpha transparency on signature bitmap

Bitmap has /SMask. Background-free overlay. Digital equivalent of cut-and-paste forgery.

### 🔴 [CRITICAL] [USF] No signature value reference

Field exists but /V is missing. Nothing to validate.

### 🟠 [HIGH] [PKCS] Deprecated PKCS#1 v1.5 RSA padding

RFC 8017 recommends PSS. v1.5 is deterministic, no salt, exploitable by lazy validators. Enables parser-confusion attacks.

### 🟡 [MEDIUM] [PKCS] No signed attributes in PKCS#7

SignerInfo has zero authenticated attributes. RSA signature is computed directly over content hash with no binding metadata.

### 🟠 [HIGH] [PKCS] Hash algorithm mismatch: declares SHA-256, hash is 20 bytes (SHA-1)

Digest algorithm field says SHA-256 but embedded hash length is 20 bytes, consistent with SHA-1. Algorithm confusion.

### 🟠 [HIGH] [PKCS] Self-signed certificate: 'Common Name: eStaff365 Digital Signature'

Subject equals issuer. No CA chain. Only the issuer can validate. Adobe shows YELLOW. Not in any trusted root store.

### 🟠 [HIGH] [PKCS] Certificate validity: 26 years (industry standard: 1-3)

Valid until 2039-12-31 23:59:59+00:00. 26 years without key rotation. If the private key is compromised at any point, every document ever signed with it is retroactively untrustworthy.

### 🟡 [MEDIUM] [PKCS] Certificate signed with SHA-1 (sha1_rsa)

SHA-1 broken for collision resistance since 2017. Deprecated by all major CAs.

### 🔴 [CRITICAL] [USF] ByteRange missing

USF Variant 1: no ByteRange at all. No bytes declared as signed.

## Attack Class Reference

### Incremental Saving Attack (ISA)

PDF allows appending new content to the end of a file without touching the original bytes. The signature protects a specific byte range, but the appended content falls outside that range. It is like signing page 1 of a contract and then someone staples a new page 2 with different terms. The signature on page 1 is still technically valid, but it does not cover what was added after. If the signature's ByteRange does not extend to the last byte of the file, anything beyond it is unsigned and could have been added by anyone.
Reference: Mladenov et al., CCS 2019, section 4.2. CVE-2018-18688.

### PKCS-based Attack

The PKCS#7 cryptographic container that holds the signature value, certificates, and hash is itself malformed or uses deprecated cryptography. This includes self-signed certificates with no trusted authority chain, excessively long certificate validity periods meaning no key rotation, deprecated PKCS#1 v1.5 padding that is deterministic and exploitable, and hash algorithm mismatches. A self-signed certificate is like a notary who notarized their own notary license. You have to take their word for it that they are who they say they are, and there is no one else to ask.
Reference: Mladenov et al., CCS 2019, section 8. NDSS 2021.

### Hide-and-Replace Shadow Attack

A combination attack that uses Incremental Saving to modify the visual appearance of a signed document after the first signature is applied, then seals the modification with a second signature. The first signature's hash may still match its original ByteRange, but Adobe Reader's post-2021 countermeasures detect that objects were redefined after signing and report the signature as INVALID. The content hash is intact but the document's visual presentation has been changed. Think of it as replacing the photograph in a signed passport. The signature on the cover is still valid, but the face inside is someone else's.
Reference: Mainka, Mladenov, Rohlmann, NDSS 2021. CVE-2020-9592, CVE-2020-9596.

### Universal Signature Forgery (USF)

The signature exists in the document, but critical information needed to validate it is missing, null, or malformed. The document says 'I am signed' but when asked to prove it, hands over a blank check. A viewer that treats missing data as 'no problem' instead of 'no signature' will display a green checkmark on a document that was never actually verified.
Reference: Mladenov et al., CCS 2019, section 4.1. CVE-2018-16042.

---

*Generated by [PDF Shadow Attack Forensic Engine v2](https://github.com/your-repo/pdf-shadow-engine) — implementing Mladenov et al., CCS 2019 and Mainka et al., NDSS 2021.*