"""
PDF Shadow Attack Forensic Engine — FastAPI Interface

    uvicorn api:app --host 0.0.0.0 --port 8000
"""

import os
import uuid
import tempfile
import shutil
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse, PlainTextResponse, HTMLResponse, RedirectResponse
from pdf_forensic_engine import analyze

RESPONSES = {200: {"description": "Success"}, 422: {"description": "Invalid file"}}

# In-memory cache for HTML reports (auto-expire would be nice, but for now simple dict)
_html_cache = {}

app = FastAPI(
    title="SigCheck — PDF Signature Forensic Engine",
    description=(
        "Upload a signed PDF and get back a forensic report that classifies every "
        "digital signature against five attack classes from two peer-reviewed papers "
        "by Ruhr University Bochum:\n\n"
        "- **USF** — Universal Signature Forgery (CCS 2019)\n"
        "- **ISA** — Incremental Saving Attack (CCS 2019)\n"
        "- **SWA** — Signature Wrapping Attack (CCS 2019)\n"
        "- **PKCS** — PKCS-based Attack (CCS 2019)\n"
        "- **SHADOW** — Hide-and-Replace Shadow Attack (NDSS 2021)\n\n"
        "Each finding is classified as **⛔ EXPLOITED** (attack was performed, "
        "artifact is in the document) or **⚠️ SUSCEPTIBLE** (vulnerability exists, "
        "no evidence of exploitation).\n\n"
        "DocuSign envelopes with trusted CA infrastructure are automatically "
        "greenlighted.\n\n"
        "*Mladenov et al., ACM CCS 2019 — Mainka et al., NDSS 2021*"
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url=None,
    swagger_ui_parameters={
        "defaultModelsExpandDepth": -1,
        "defaultModelRendering": "example",
    },
)


def _save_upload(upload: UploadFile) -> str:
    if not upload.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="File must be a PDF.")
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    try:
        shutil.copyfileobj(upload.file, tmp)
        tmp.close()
        return tmp.name
    except Exception:
        tmp.close()
        os.unlink(tmp.name)
        raise


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok", "engine": "SigCheck v2"}


@app.get("/view/{report_id}", include_in_schema=False)
async def view_report(report_id: str):
    """Serve a cached HTML report by ID."""
    html = _html_cache.pop(report_id, None)
    if html is None:
        raise HTTPException(status_code=404, detail="Report expired or not found.")
    return HTMLResponse(content=html)


@app.post("/analyze", tags=["Analyze"],
          summary="JSON forensic report",
          responses=RESPONSES)
async def analyze_json(file: UploadFile = File(..., description="Signed PDF to analyze")):
    """Upload a signed PDF and receive a structured JSON forensic report."""
    path = _save_upload(file)
    try:
        report = analyze(path)
        return JSONResponse(content=report.to_dict())
    finally:
        os.unlink(path)


@app.post("/report/html", tags=["Reports"],
          summary="HTML forensic report (opens in new tab)",
          responses=RESPONSES)
async def report_html(request: Request, file: UploadFile = File(..., description="Signed PDF to analyze")):
    """Upload a signed PDF and get a link to view the forensic report in the browser.

    The response is a redirect to a temporary page that renders the full
    HTML report. Open the URL from the response headers in a new tab."""
    path = _save_upload(file)
    try:
        report = analyze(path)
        html = report.to_html()
        report_id = uuid.uuid4().hex[:12]
        _html_cache[report_id] = html
        # Keep cache bounded
        if len(_html_cache) > 100:
            oldest = next(iter(_html_cache))
            _html_cache.pop(oldest, None)
        view_url = f"/view/{report_id}"
        return JSONResponse(
            content={
                "report_url": str(request.base_url).rstrip('/') + view_url,
                "message": "Open the report_url in your browser to view the HTML report.",
            },
            headers={"Location": view_url},
        )
    finally:
        os.unlink(path)


@app.post("/report/md", tags=["Reports"],
          summary="Markdown forensic report",
          responses=RESPONSES)
async def report_markdown(file: UploadFile = File(..., description="Signed PDF to analyze")):
    """Upload a signed PDF and download a Markdown forensic report."""
    path = _save_upload(file)
    try:
        report = analyze(path)
        md = report.to_markdown()
        return PlainTextResponse(
            content=md,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename={file.filename}_report.md"},
        )
    finally:
        os.unlink(path)


@app.post("/report/pdf", tags=["Reports"],
          summary="PDF forensic report",
          responses=RESPONSES)
async def report_pdf(file: UploadFile = File(..., description="Signed PDF to analyze")):
    """Upload a signed PDF and download a PDF forensic report.

    Yes, the tool that forensically dismantles PDF signature fraud
    outputs its findings as a PDF. The format is not the problem.
    The implementation is."""
    path = _save_upload(file)
    out_path = path.replace('.pdf', '_report.pdf')
    try:
        report = analyze(path)
        report.to_pdf(out_path)
        return FileResponse(
            out_path,
            media_type="application/pdf",
            filename=f"{file.filename}_report.pdf",
            background=None,
        )
    finally:
        os.unlink(path)
        if os.path.exists(out_path):
            import atexit
            atexit.register(lambda p=out_path: os.path.exists(p) and os.unlink(p))
