from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanConfig(BaseModel):
    """
    Configuration for an authorized API security scan.
    """

    # The target must be explicitly provided by the user.
    authorized: bool = False

    # Optional bearer credentials.
    bearer_token: Optional[str] = None

    # Optional second authorized identity for BOLA testing.
    second_bearer_token: Optional[str] = None

    # Optional object identifiers supplied by the tester.
    object_ids: List[str] = Field(default_factory=list)

    # HTTP behavior controls.
    timeout_seconds: float = 8.0
    rate_test_requests: int = 6
    rate_test_delay_seconds: float = 0.25

    # Never allow an uncontrolled high-volume scan.
    max_endpoints: int = 30


class AnalysisRequest(BaseModel):
    url: str

    scan: ScanConfig = Field(default_factory=ScanConfig)


class Evidence(BaseModel):
    method: str
    url: str
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_excerpt: Optional[Any] = None
    request_headers: Dict[str, str] = Field(default_factory=dict)


class IssueItem(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    where: str
    why: str
    hint: str
    codeSnippet: Optional[str] = None
    evidence: Optional[Evidence] = None


class AnalysisResponse(BaseModel):
    url: str
    sanitizedUrl: str
    score: int
    status: str
    issues: List[IssueItem]
    anatomy: Optional[Dict[str, Any]] = None

    scan_type: str = "live"
    endpoints_scanned: int = 0
    requests_made: int = 0