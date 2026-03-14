"""
PDF Shadow Attack Forensic Engine — FastAPI Interface

Wraps the forensic engine in three endpoints that do exactly
what the CLI does, but over HTTP.

    uvicorn api:app --host 0.0.0.0 --port 8000
"""

import os
import tempfile
import shutil
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse, FileResponse, PlainTextResponse
from pdf_forensic_engine import analyze

app = FastAPI(
    title="PDF Shadow Attack Forensic Engine",
    description=(
        "Upload a signed PDF, get back a forensic report classifying every "
        "signature against five attack classes (USF, ISA, SWA, PKCS, SHADOW) "
        "with EXPLOITED vs SUSCEPTIBLE distinction. "
        "Implements Mladenov et al., CCS 2019 and Mainka et al., NDSS 2021."
    ),
    version="2.0.0",
)


def _save_upload(upload: UploadFile) -> str:
    """Save uploaded file to a temp path, return the path."""
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


@app.get("/health")
def health():
    return {"status": "ok", "engine": "PDF Shadow Attack Forensic Engine v2"}


@app.post("/analyze")
async def analyze_json(file: UploadFile = File(...)):
    """Upload a signed PDF, get JSON forensic report."""
    path = _save_upload(file)
    try:
        report = analyze(path)
        return JSONResponse(content=report.to_dict())
    finally:
        os.unlink(path)


@app.post("/report/md")
async def report_markdown(file: UploadFile = File(...)):
    """Upload a signed PDF, get Markdown forensic report."""
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


@app.post("/report/pdf")
async def report_pdf(file: UploadFile = File(...)):
    """Upload a signed PDF, get PDF forensic report.

    Yes, the tool that forensically dismantles PDF signature fraud
    outputs its findings as a PDF. The format is not the problem.
    The implementation is.
    """
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
            # FileResponse reads it before this fires — schedule cleanup
            import atexit
            atexit.register(lambda p=out_path: os.path.exists(p) and os.unlink(p))
