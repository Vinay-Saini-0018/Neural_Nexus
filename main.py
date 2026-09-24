"""
FastAPI Industry-Standard REST API Server for APISentinel AI.
Provides RESTful endpoints for API schema ingestion, static security diagnostic analysis, and status checks.
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any

from core.ingestion import parse_spec_from_url_or_json, check_api_reachability
from core.rules_engine import analyze_endpoint_url, evaluate_openapi_schema

app = FastAPI(
    title="APISentinel AI Backend API",
    description="Industry-standard REST API for static OpenAPI schema security audit & URL parameter evaluation.",
    version="1.0.0"
)

# Enable CORS for local frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalysisRequest(BaseModel):
    url: str

class IssueItem(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    where: str
    why: str
    hint: str
    codeSnippet: Optional[str] = None

class AnalysisResponse(BaseModel):
    url: str
    sanitizedUrl: str
    score: int
    status: str
    issues: List[IssueItem]
    anatomy: Optional[Dict[str, Any]] = None


@app.get("/")
def health_check():
    """Service health verification endpoint."""
    return {
        "service": "APISentinel AI Backend",
        "status": "online",
        "version": "1.0.0"
    }


@app.post("/analyze", response_model=AnalysisResponse)
def analyze_api(request: AnalysisRequest):
    """
    Main diagnostic endpoint. Receives target API URL or spec reference and returns
    structured security health score, OWASP category risk, and remediation hints.
    """
    if not request.url or not request.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL or specification input cannot be empty."
        )

    target_url = request.url.strip()
    
    # Run static rule evaluation engine
    result = analyze_endpoint_url(target_url)
    
    return result
