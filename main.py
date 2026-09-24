"""
Neural Nexus API Security Scanner.

The API accepts:
- a normal API endpoint
- an OpenAPI JSON URL

The scanner performs bounded, authorized HTTP checks.

IMPORTANT:
Only scan systems you own or have explicit permission to test.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from core.ingestion import (
    extract_endpoints,
    fetch_document,
    is_openapi_document,
    looks_like_openapi_url,
)

from core.models import (
    AnalysisRequest,
    AnalysisResponse,
    IssueItem,
)

from core.rules_engine import (
    calculate_score,
    calculate_status,
    evaluate_openapi_schema,
    evaluate_runtime_result,
)

from core.scanner import (
    check_response_exposure,
    check_rate_limit,
    check_security_headers,
    make_request,
)


app = FastAPI(
    title="Neural Nexus API Security Scanner",
    description=(
        "Authorized API security testing and OpenAPI analysis platform."
    ),
    version="2.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def validate_target_url(url: str) -> None:

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="Target must use HTTP or HTTPS.",
        )

    if not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="Target URL must contain a hostname.",
        )


def anatomy(url: str) -> Dict[str, Any]:

    parsed = urlparse(url)

    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname or "",
        "port": parsed.port or (
            443 if parsed.scheme == "https" else 80
        ),
        "path": parsed.path or "/",
        "query": parsed.query or "(none)",
        "hash": parsed.fragment or "(none)",
    }


def convert_issues(
    findings: List[Dict[str, Any]]
) -> List[IssueItem]:

    return [
        IssueItem(**finding)
        for finding in findings
    ]


@app.get("/")
def health_check():

    return {
        "service": "Neural Nexus",
        "status": "online",
        "version": "2.0.0",
    }


@app.get("/health")
def health():

    return {
        "status": "healthy",
    }


@app.post(
    "/analyze",
    response_model=AnalysisResponse,
)
def analyze_api(request: AnalysisRequest):

    target = request.url.strip()

    if not target:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL cannot be empty.",
        )

    validate_target_url(target)

    # ---------------------------------------------------------
    # SAFETY GATE
    # ---------------------------------------------------------

    if not request.scan.authorized:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Active scanning requires authorized=true. "
                "Only scan systems you own or are explicitly "
                "authorized to test."
            ),
        )

    findings: List[Dict[str, Any]] = []

    requests_made = 0
    endpoints_scanned = 0

    # ---------------------------------------------------------
    # OPENAPI MODE
    # ---------------------------------------------------------

    if looks_like_openapi_url(target):

        try:

            spec = fetch_document(
                target,
                timeout=request.scan.timeout_seconds,
            )

        except Exception as exc:

            raise HTTPException(
                status_code=400,
                detail=f"Unable to fetch OpenAPI document: {exc}",
            )

        if not is_openapi_document(spec):

            raise HTTPException(
                status_code=400,
                detail=(
                    "The supplied URL did not return a valid "
                    "OpenAPI/Swagger JSON document."
                ),
            )

        # Static specification findings.
        findings.extend(
            evaluate_openapi_schema(spec)
        )

        endpoints = extract_endpoints(
            spec,
            target,
            request.scan.max_endpoints,
        )

        for endpoint in endpoints:

            method = endpoint["method"]
            endpoint_url = endpoint["url"]

            # -------------------------------------------------
            # Skip unresolved template parameters.
            # -------------------------------------------------

            if "{" in endpoint_url or "}" in endpoint_url:

                findings.append(
                    {
                        "id": "endpoint_requires_parameters",
                        "severity": "info",
                        "category": "coverage",
                        "title": "Endpoint requires explicit parameter values",
                        "where": f"{method} {endpoint_url}",
                        "why": (
                            "The OpenAPI path contains template parameters, "
                            "so the scanner did not invent values."
                        ),
                        "hint": (
                            "Supply authorized test object IDs before "
                            "running runtime authorization tests."
                        ),
                        "codeSnippet": None,
                        "evidence": None,
                    }
                )

                continue

            # -------------------------------------------------
            # Baseline request
            # -------------------------------------------------

            baseline = make_request(
                method=method,
                url=endpoint_url,
                token=request.scan.bearer_token,
                timeout=request.scan.timeout_seconds,
            )

            requests_made += 1
            endpoints_scanned += 1

            # -------------------------------------------------
            # Response data exposure
            # -------------------------------------------------

            exposure = check_response_exposure(
                baseline
            )

            sensitive_fields = (
                exposure["fields"]
                if exposure
                else []
            )

            # -------------------------------------------------
            # Authentication behavior
            # -------------------------------------------------

            unauthenticated = None

            if request.scan.bearer_token:

                unauthenticated = make_request(
                    method=method,
                    url=endpoint_url,
                    token=None,
                    timeout=request.scan.timeout_seconds,
                )

                requests_made += 1

            # -------------------------------------------------
            # Rate limit
            # -------------------------------------------------

            rate_results = []

            if method in {
                "GET",
                "HEAD",
                "OPTIONS",
            }:

                rate_results = check_rate_limit(
                    url=endpoint_url,
                    method=method,
                    token=request.scan.bearer_token,
                    timeout=request.scan.timeout_seconds,
                    request_count=request.scan.rate_test_requests,
                    delay=request.scan.rate_test_delay_seconds,
                )

                requests_made += len(rate_results)

            # -------------------------------------------------
            # Runtime rule evaluation
            # -------------------------------------------------

            runtime_findings = evaluate_runtime_result(
                target_url=endpoint_url,
                method=method,
                baseline=baseline,
                unauthenticated=unauthenticated,
                rate_results=rate_results,
                sensitive_fields=sensitive_fields,
            )

            findings.extend(runtime_findings)

            # -------------------------------------------------
            # Security headers
            # -------------------------------------------------

            missing_headers = check_security_headers(
                baseline
            )

            if missing_headers:

                findings.append(
                    {
                        "id": "missing_security_headers",
                        "severity": "info",
                        "category": "security",
                        "title": "Recommended security headers not observed",
                        "where": f"{method} {endpoint_url}",
                        "why": (
                            "The response did not include one or more "
                            "recommended security headers."
                        ),
                        "hint": (
                            "Review whether these headers are appropriate "
                            "for the API and deployment architecture."
                        ),
                        "codeSnippet": None,
                        "evidence": {
                            "method": method,
                            "url": endpoint_url,
                            "status_code": baseline.status_code,
                            "missing_headers": missing_headers,
                        },
                    }
                )

    # ---------------------------------------------------------
    # SINGLE ENDPOINT MODE
    # ---------------------------------------------------------

    else:

        method = "GET"

        baseline = make_request(
            method=method,
            url=target,
            token=request.scan.bearer_token,
            timeout=request.scan.timeout_seconds,
        )

        requests_made += 1
        endpoints_scanned = 1

        exposure = check_response_exposure(
            baseline
        )

        sensitive_fields = (
            exposure["fields"]
            if exposure
            else []
        )

        unauthenticated = None

        if request.scan.bearer_token:

            unauthenticated = make_request(
                method=method,
                url=target,
                token=None,
                timeout=request.scan.timeout_seconds,
            )

            requests_made += 1

        rate_results = check_rate_limit(
            url=target,
            method=method,
            token=request.scan.bearer_token,
            timeout=request.scan.timeout_seconds,
            request_count=request.scan.rate_test_requests,
            delay=request.scan.rate_test_delay_seconds,
        )

        requests_made += len(rate_results)

        findings.extend(
            evaluate_runtime_result(
                target_url=target,
                method=method,
                baseline=baseline,
                unauthenticated=unauthenticated,
                rate_results=rate_results,
                sensitive_fields=sensitive_fields,
            )
        )

        missing_headers = check_security_headers(
            baseline
        )

        if missing_headers:

            findings.append(
                {
                    "id": "missing_security_headers",
                    "severity": "info",
                    "category": "security",
                    "title": "Recommended security headers not observed",
                    "where": target,
                    "why": (
                        "The response did not include one or more "
                        "recommended security headers."
                    ),
                    "hint": (
                        "Review the API's security-header configuration."
                    ),
                    "codeSnippet": None,
                    "evidence": {
                        "method": method,
                        "url": target,
                        "status_code": baseline.status_code,
                        "missing_headers": missing_headers,
                    },
                }
            )

    # ---------------------------------------------------------
    # SCORE
    # ---------------------------------------------------------

    score = calculate_score(
        findings
    )

    result_status = calculate_status(
        score,
        findings,
    )

    return AnalysisResponse(
        url=target,
        sanitizedUrl=target,
        score=score,
        status=result_status,
        issues=convert_issues(findings),
        anatomy=anatomy(target),
        scan_type=(
            "openapi-runtime"
            if looks_like_openapi_url(target)
            else "endpoint-runtime"
        ),
        endpoints_scanned=endpoints_scanned,
        requests_made=requests_made,
    )