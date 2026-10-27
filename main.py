import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select

from .ai import analyze_with_ollama
from .db import Base, Finding, Scan, SessionLocal, engine
from .scanner import EXTENSIONS, static_scan

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = int(os.getenv("MAX_CODE_BYTES", "150000"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="Secure Code Agent", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


class CodeInput(BaseModel):
    filename: str = Field(default="sample.py", max_length=255)
    code: str = Field(min_length=1, max_length=150000)


def serialize_scan(scan: Scan, include_code: bool = False) -> dict:
    result = {"id": scan.id, "filename": scan.filename, "language": scan.language, "summary": scan.summary, "ai_status": scan.ai_status, "created_at": scan.created_at.isoformat(), "findings": [{"id": f.id, "title": f.title, "severity": f.severity, "line": f.line, "description": f.description, "recommendation": f.recommendation, "source": f.source} for f in scan.findings]}
    if include_code:
        result.update(source_code=scan.source_code, fixed_code=scan.fixed_code)
    return result


async def perform_scan(filename: str, code: str) -> dict:
    name = Path(filename.replace("\\", "/")).name[:255] or "sample.py"
    language = EXTENSIONS.get(Path(name).suffix.lower())
    if language is None:
        raise HTTPException(415, f"Unsupported extension. Allowed: {', '.join(sorted(EXTENSIONS))}")
    if len(code.encode("utf-8")) > MAX_BYTES:
        raise HTTPException(413, "Source is too large")
    findings = static_scan(code, language)
    summary = "Static pattern scan complete. Review findings manually; absence of findings does not mean code is secure."
    fixed_code = ""
    status = "disabled"
    if os.getenv("ENABLE_AI", "true").lower() in {"true", "1", "yes"}:
        try:
            ai = await analyze_with_ollama(code, language)
            findings.extend(ai["findings"])
            summary = ai["summary"] or summary
            fixed_code = ai["fixed_code"]
            status = "complete"
        except Exception as exc:
            # No source code or model output is included in error.
            status = "unavailable"
            summary += " Ollama analysis unavailable; check Ollama is running and the model is installed."
    with SessionLocal() as session:
        scan = Scan(filename=name, language=language, source_code=code, summary=summary, fixed_code=fixed_code, ai_status=status)
        session.add(scan)
        session.flush()
        scan.findings = [Finding(**f) for f in findings]
        session.commit()
        session.refresh(scan)
        return serialize_scan(scan, include_code=True)


@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze(data: CodeInput):
    return await perform_scan(data.filename, data.code)


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "File too large")
    try:
        code = data.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "Upload must be UTF-8 text")
    if not code.strip():
        raise HTTPException(400, "File is empty")
    return await perform_scan(file.filename or "sample.py", code)


@app.get("/api/scans")
def scans():
    with SessionLocal() as session:
        records = session.scalars(select(Scan).order_by(Scan.id.desc()).limit(100)).all()
        return [{"id": s.id, "filename": s.filename, "language": s.language, "created_at": s.created_at.isoformat(), "ai_status": s.ai_status} for s in records]


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int):
    with SessionLocal() as session:
        record = session.get(Scan, scan_id)
        if not record:
            raise HTTPException(404, "Scan not found")
        return serialize_scan(record, include_code=True)


@app.get("/api/scans/{scan_id}/fixed", response_class=PlainTextResponse)
def download_fixed(scan_id: int):
    with SessionLocal() as session:
        record = session.get(Scan, scan_id)
        if not record:
            raise HTTPException(404, "Scan not found")
        if not record.fixed_code:
            raise HTTPException(404, "No suggested fix available")
        return PlainTextResponse(record.fixed_code, headers={"Content-Disposition": f'attachment; filename="suggested_fix_{scan_id}.txt"'})
