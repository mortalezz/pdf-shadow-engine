# PDF Shadow Attack Forensic Engine

A single-file forensic tool that answers a question no other PDF analyzer asks: **was this document attacked, or is it merely vulnerable?**

Every signed PDF has some theoretical attack surface — deprecated padding, self-signed certificates, incremental update mechanisms — and these vulnerabilities exist in millions of documents, most of them harmless. This engine ignores that noise and instead looks for the artifacts of attacks that were actually carried out: signature appearances stripped of text and replaced with bitmaps, documents modified after signing via incremental saves that redefine objects outside the signed byte range, and the telltale combination of both on the same page where one signature was tampered with and another wasn't.

The distinction between EXPLOITED and SUSCEPTIBLE is the entire point of this tool. If the same platform, in the same signing session, produces a proper text-based signature for one signer and a bitmap-only image with alpha transparency for another, that is not a vulnerability scan finding — that is a crime scene.

## Live Demo

**Web app:** [sigcheck-app.leapcell.app](https://sigcheck-app.leapcell.app) — drag and drop a signed PDF, get a forensic report in your browser.

**API + Swagger UI:** [sigcheck.leapcell.app/docs](https://sigcheck.leapcell.app/docs) — upload via interactive docs or call the endpoints directly from code.

No installation required for either. Just a browser and a signed PDF.

### View report in the browser (HTML)

The HTML endpoint returns a fully styled forensic report. From a terminal:

```bash
curl -X POST https://sigcheck.leapcell.app/report/html -F file=@document.pdf -o report.html
open report.html   # macOS
start report.html  # Windows
```

In Swagger UI, the HTML renders as text in the response body — use the PDF or Markdown endpoints for the best Swagger experience, or use the curl command above for HTML.

### Download a PDF report

1. Expand **POST /report/pdf**
2. Click **Try it out**, upload your PDF, click **Execute**
3. Click **Download file** when the response appears

### Other formats

The **POST /analyze** endpoint returns raw JSON for programmatic consumption, and **POST /report/md** returns a Markdown file that renders natively on GitHub.

No documents are stored — uploaded files are deleted from memory immediately after processing and the serverless container retains no persistent storage between requests.

## The Research

This engine implements the verification algorithm published by researchers at Ruhr University Bochum in two landmark papers on PDF signature security.

The first paper, presented at ACM CCS 2019 in London, introduced three attack classes — Universal Signature Forgery (USF), Incremental Saving Attack (ISA), and Signature Wrapping Attack (SWA) — and systematically tested them against 22 PDF viewers, finding 21 of them vulnerable, including Adobe Reader DC and Foxit. The paper also proposed a concrete verification algorithm (Listing 2) that would prevent all three classes, and that algorithm serves as the primary gate in this engine.

The second paper, presented at NDSS 2021, introduced the Hide-and-Replace Shadow Attack, where an attacker modifies the visual appearance of a signed document via incremental update and then seals the modification with a second signature. Adobe patched Reader to detect this pattern, which is why clicking a tampered signature now shows RED/INVALID — but the patch is a UI warning, not a structural fix, and the attack still works at the file level.

A fourth class, PKCS-based attacks targeting the cryptographic container itself, was proposed as future research in the CCS 2019 conclusions, and this engine checks for it as well: self-signed certificates, deprecated PKCS#1 v1.5 padding, excessive certificate validity periods, and hash algorithm mismatches.

### References

- Mladenov, V., Mainka, C., Meyer zu Selhausen, K., Grothe, M., Schwenk, J. "1 Trillion Dollar Refund — How To Spoof PDF Signatures." ACM CCS 2019. CVE-2018-16042, CVE-2018-18688, CVE-2018-18689. DOI: [10.1145/3319535.3339812](https://doi.org/10.1145/3319535.3339812)
- Mainka, C., Mladenov, V., Rohlmann, S. "Shadow Attacks: Hiding and Replacing Content in Signed PDFs." NDSS 2021. CVE-2020-9592, CVE-2020-9596.
- PDF Insecurity Project: [https://www.pdf-insecurity.org/](https://www.pdf-insecurity.org/)

## Attack Classes

The engine classifies findings against five attack classes drawn from both Bochum papers:

| Class | Paper | What It Means |
|-------|-------|---------------|
| **USF** | CCS 2019 §4.1 | Universal Signature Forgery — signature metadata is missing, null, or malformed, so the viewer finds a signature but cannot actually validate it and may incorrectly report it as valid |
| **ISA** | CCS 2019 §4.2 | Incremental Saving Attack — content was appended beyond the signed ByteRange, meaning the signature is technically valid over its declared range but does not cover the entire file |
| **SWA** | CCS 2019 §4.3 | Signature Wrapping Attack — signed content has been relocated and malicious objects injected into the gap between the two signed byte blocks or into the PKCS#7 zero-padding |
| **PKCS** | CCS 2019 §8 | PKCS-based Attack — the cryptographic container uses deprecated algorithms, self-signed certificates without a trusted authority chain, or mismatched hash algorithms |
| **SHADOW** | NDSS 2021 | Hide-and-Replace Shadow Attack — the visual appearance of a signed field was modified after signing and sealed by a subsequent incremental update or countersignature |

## EXPLOITED vs SUSCEPTIBLE

Every finding is classified as one of two states, and this distinction is the core contribution of the engine:

- **⛔ EXPLOITED** — The attack artifact is present in the document, meaning the attack was actually performed and the evidence is structurally embedded in the PDF
- **⚠️ SUSCEPTIBLE** — The vulnerability exists in the document's cryptographic infrastructure but there is no evidence it was exploited, so the attack surface is present but the attack was not performed

### Example Output

From a real document analysis where two signatures from the same platform appear on the same page:

```
Signature: [Employee Field]
  ISA:    ⛔ EXPLOITED    — 9,196 unsigned bytes, 8 objects redefined
  SHADOW: ⛔ EXPLOITED    — bitmap-only appearance, alpha transparency, zero text
  PKCS:   ⚠️  SUSCEPTIBLE — self-signed cert, v1.5 padding (not exploited)

Signature: [HR Countersignature]
  PKCS:   ⚠️  SUSCEPTIBLE — same cert, same padding (not exploited)
  appearance: TEXT-ESIG [GREEN] — "Digitally signed by [HR Signer]"
```

Same platform, same session, same certificate — one field was attacked and the other was not, which proves both that the platform is capable of correct output and that it selectively did not produce correct output for the affected field.

## Scope and Greenlighting

This engine checks documents that use **AcroForm-based digital signatures** — the PDF signing mechanism defined in the Adobe PDF specification where signature fields (`/FT /Sig`), signature dictionaries (`/Type /Sig`), ByteRange arrays, and PKCS#7 cryptographic containers are embedded in the document structure. All five attack classes (USF, ISA, SWA, PKCS, SHADOW) target specifically this infrastructure and cannot exist in documents that don't use it.

The engine greenlights a document — stops analysis and reports no attack surface — in two cases:

**DocuSign envelopes:** DocuSign uses CA-issued certificates, RFC 3161 timestamps, and containers validated by Adobe's Approved Trust List (AATL). The Bochum researchers tested their attacks against documents with weaker infrastructure. DocuSign's signing pipeline does not produce the vulnerabilities that enable those attacks.

**No AcroForm signatures detected:** If the engine finds no `/FT /Sig` form fields, no `/Type /Sig` dictionaries, no ByteRange arrays, and no PKCS#7 containers, the document was not signed using AcroForm infrastructure. Platforms like ApproveMe, HelloSign, PandaDoc, and similar e-signature services that use visual image stamps rather than AcroForm certificate infrastructure produce documents that are outside the scope of this engine. A simple visual check can still validate any electronic signature: look for the signer's identity linked to a timestamp in the same signature block — what Adobe identifies as the most critical component of digital signature compliance.

The engine is not here to validate every freestyle PDF signature in the world — that would be an incredibly tall order. It is here to check documents where the AcroForm signing infrastructure creates the specific attack surface that the Bochum papers describe. If the engine greenlights a document, that document is free from that attack surface.

## How It Works

### Gate 1: AcroForm Detection and Greenlight

The engine first checks for DocuSign envelope markers and, if absent, searches for AcroForm signature infrastructure (`/FT /Sig`, `/Type /Sig`, ByteRange, PKCS#7). If none is found, the document is greenlighted immediately. If AcroForm signatures are present, analysis proceeds through the full verification pipeline.

### Gate 2: CCS 2019 Listing 2 Verification Algorithm

The primary gate implements the exact verification pseudocode from CCS 2019 (page 11), checking whether the ByteRange is present, parseable, and contains four well-formed integers satisfying `a=0, b>0, c>b, d>0`. The most critical check is whether `c+d == filesize`, because if the ByteRange does not extend to the last byte of the file then everything beyond the signed range is unsigned and anyone could have appended content after signing — which is the definition of the ISA attack.

### Gate 3: PKCS#7 Deep Analysis

Parses the ASN.1 structure inside the signature's cryptographic container to extract and independently verify the content hash against the ByteRange bytes, check whether the certificate is self-signed (subject equals issuer), flag certificate validity periods exceeding 10 years that indicate no key rotation, detect deprecated PKCS#1 v1.5 padding, identify hash algorithm mismatches where the container declares SHA-256 but the embedded hash is 20 bytes (SHA-1), and examine trailing bytes in the PKCS#7 zero-padding for non-zero data that would indicate SWA injection.

### Gate 4: Appearance Stream Analysis

Decompresses the signature field's appearance stream and classifies it based on the presence or absence of PDF text rendering operators versus image rendering operators:

- **BITMAP-ONLY [RED]** — Contains an image `Do` operator but zero text `TJ/Tj` operators, meaning the standard "Digitally signed by [Name]" text has been entirely replaced with a picture
- **TEXT-ESIG [GREEN]** — Contains text operators rendering signer name plus at least one additional identity element (email, timestamp, or hash), which is the standard output of a properly functioning e-signature platform
- **DECORATED-ESIG [GREEN]** — Contains both a bitmap and text with signer identity, which is standard DocuSign/Adobe Sign behavior where the bitmap is cosmetic decoration on top of proper cryptographic infrastructure
- **YELLOW variants** — Ambiguous cases such as text without identifiable PII, a single text string only, or mixed image-and-text without signer identity

### Gate 5: Cross-Signature Comparison

If the same document contains both RED (bitmap-only) and GREEN (text-based) signature appearances, the engine flags the inconsistency as the comparative proof that the platform produced different output for different fields within a single document.

### Gate 6: EXPLOITED / SUSCEPTIBLE Classification

The final classifier maps structural evidence to the distinction between performed attacks and theoretical vulnerabilities — a bitmap-only appearance with alpha transparency on a field where the same platform demonstrably produces text for other signers is classified as EXPLOITED because the bitmap is the attack artifact and the absent text is the replaced content.

## API

The engine is served via [FastAPI](https://fastapi.tiangolo.com) with four endpoints:

| Endpoint | Format | Description |
|----------|--------|-------------|
| `POST /analyze` | JSON | Structured forensic data for programmatic consumption |
| `POST /report/html` | HTML | Styled report viewable in a browser |
| `POST /report/md` | Markdown | GitHub-renderable report |
| `POST /report/pdf` | PDF | Downloadable report for court filings and sharing |

Interactive documentation is auto-generated at `/docs` via Swagger UI. The source is in [`api.py`](api.py) — 120 lines wrapping the engine with file upload handling, CORS, and response formatting.

The frontend ([sigcheck-frontend](https://github.com/mortalezz/sigcheck-frontend)) is a separate React app that calls these endpoints.

## Architecture

```
pdf_forensic_engine.py    (single file, no framework dependencies)
├── DocuSign greenlight   (trusted platform bypass)
├── CCS 2019 Listing 2    (ByteRange verification — USF/ISA/SWA gate)
├── PKCS#7 analysis       (hash verification, cert chain, padding)
├── Appearance analysis   (TJ/Tj vs Do — bitmap detection)
├── Cross-sig comparison  (RED vs GREEN on same document)
└── EXPLOITED classifier  (artifact-based attack confirmation)

api.py                    (FastAPI wrapper)
├── POST /analyze         (JSON)
├── POST /report/html     (HTML)
├── POST /report/md       (Markdown)
└── POST /report/pdf      (PDF)
```

## Installation

```bash
git clone https://github.com/mortalezz/pdf-shadow-engine.git
cd pdf-shadow-engine
pip install -r requirements.txt
```

Python 3.8 or later required. Dependencies: `asn1crypto` for PKCS#7 parsing, `reportlab` for PDF report generation.

## Usage

```bash
python3 pdf_forensic_engine.py document.pdf                          # terminal report
python3 pdf_forensic_engine.py document.pdf --json                   # JSON output
python3 pdf_forensic_engine.py document.pdf --json -o report.json    # JSON to file
python3 pdf_forensic_engine.py document.pdf --report findings.md     # Markdown report
python3 pdf_forensic_engine.py document.pdf --pdf-report report.pdf  # PDF report
python3 pdf_forensic_engine.py document.pdf --html-report report.html # HTML report
python3 pdf_forensic_engine.py suspect.pdf --compare control.pdf     # compare two docs
```

Yes, the tool that forensically dismantles PDF signature fraud outputs its findings as a PDF. The format is not the problem. The implementation is.

For an example of the engine's output, see [`examples/sample_report.md`](examples/sample_report.md).

Exit codes: `0` for clean, `1` for HIGH findings (susceptible), `2` for CRITICAL findings (exploited).

## Responsible Disclosure

If this tool detects EXPLOITED findings on documents produced by an electronic signature platform, we recommend a 90-day responsible disclosure to the platform operator before public release of findings, consistent with the Bochum team's own disclosure process via BSI-CERT.

## License

MIT. See [LICENSE](LICENSE).
