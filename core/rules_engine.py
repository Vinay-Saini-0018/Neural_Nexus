"""
Runtime security rules.

Important:
A rule should distinguish between:

1. Evidence observed during an HTTP test.
2. A heuristic / informational observation.

We do not label a vulnerability as confirmed unless runtime evidence
supports it.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


SEVERITY_WEIGHT = {
    "critical": 35,
    "high": 25,
    "medium": 15,
    "warning": 8,
    "info": 3,
}


def issue(
    issue_id: str,
    severity: str,
    category: str,
    title: str,
    where: str,
    why: str,
    hint: str,
    evidence: Optional[Dict[str, Any]] = None,
    code_snippet: Optional[str] = None,
) -> Dict[str, Any]:

    return {
        "id": issue_id,
        "severity": severity,
        "category": category,
        "title": title,
        "where": where,
        "why": why,
        "hint": hint,
        "codeSnippet": code_snippet,
        "evidence": evidence,
    }


def evaluate_runtime_result(
    target_url: str,
    method: str,
    baseline: Any,
    unauthenticated: Any = None,
    rate_results: Optional[List[Any]] = None,
    sensitive_fields: Optional[List[str]] = None,
    bola_result: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:

    findings = []

    # ---------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------

    if unauthenticated:

        status = unauthenticated.status_code

        if status is not None and 200 <= status < 300:

            findings.append(
                issue(
                    issue_id="auth_runtime_exposure",
                    severity="high",
                    category="authentication",
                    title="Protected-resource access succeeded without credentials",
                    where=f"{method} {target_url}",
                    why=(
                        "A request without an Authorization header received "
                        "a successful HTTP response."
                    ),
                    hint=(
                        "Verify that this endpoint is intentionally public. "
                        "If it is protected, enforce authentication server-side."
                    ),
                    evidence={
                        "method": method,
                        "url": target_url,
                        "status_code": status,
                        "response_excerpt": str(
                            unauthenticated.body
                        )[:1000],
                    },
                )
            )

    # ---------------------------------------------------------
    # Excessive / sensitive response data
    # ---------------------------------------------------------

    if sensitive_fields:

        findings.append(
            issue(
                issue_id="runtime_sensitive_response_fields",
                severity="high",
                category="data_exposure",
                title="Sensitive fields observed in API response",
                where=f"{method} {target_url}",
                why=(
                    "The live API response contained field names commonly "
                    "associated with secrets, credentials, tokens, or sensitive data."
                ),
                hint=(
                    "Return only fields required by the API contract and "
                    "remove secrets/internal fields from public response DTOs."
                ),
                evidence={
                    "method": method,
                    "url": target_url,
                    "status_code": getattr(
                        baseline,
                        "status_code",
                        None,
                    ),
                    "sensitive_fields": sensitive_fields,
                    "response_excerpt": str(
                        getattr(baseline, "body", "")
                    )[:1000],
                },
                code_snippet=(
                    "class PublicResponse(BaseModel):\n"
                    "    id: str\n"
                    "    name: str\n"
                    "    # Do not expose internal secrets"
                ),
            )
        )

    # ---------------------------------------------------------
    # Rate limiting
    # ---------------------------------------------------------

    if rate_results:

        statuses = [
            result.status_code
            for result in rate_results
            if result.status_code is not None
        ]

        if statuses and 429 not in statuses:

            findings.append(
                issue(
                    issue_id="rate_limit_not_observed",
                    severity="warning",
                    category="rate_limit",
                    title="Rate limiting was not observed during bounded test",
                    where=f"{method} {target_url}",
                    why=(
                        f"{len(statuses)} sequential requests were made "
                        "without receiving HTTP 429."
                    ),
                    hint=(
                        "Confirm the endpoint's documented rate limits and "
                        "consider server-side throttling for sensitive operations."
                    ),
                    evidence={
                        "method": method,
                        "url": target_url,
                        "requests_tested": len(statuses),
                        "status_codes": statuses,
                    },
                )
            )

    # ---------------------------------------------------------
    # BOLA
    # ---------------------------------------------------------

    if bola_result:

        first = bola_result.get("first")
        second = bola_result.get("second")

        if first and second:

            first_success = (
                first.status_code is not None
                and 200 <= first.status_code < 300
            )

            second_success = (
                second.status_code is not None
                and 200 <= second.status_code < 300
            )

            if first_success and second_success:

                findings.append(
                    issue(
                        issue_id="bola_cross_identity_access",
                        severity="critical",
                        category="bola",
                        title="Potential BOLA: both authorized identities received successful access",
                        where=f"{method} {target_url}",
                        why=(
                            "The same object request returned a successful response "
                            "for both supplied authorized identities. This is evidence "
                            "that object-level authorization requires review."
                        ),
                        hint=(
                            "Verify object ownership/authorization on the server "
                            "using the authenticated identity before returning the object."
                        ),
                        evidence={
                            "method": method,
                            "url": target_url,
                            "identity_a_status": first.status_code,
                            "identity_b_status": second.status_code,
                        },
                        code_snippet=(
                            "if resource.owner_id != current_user.id:\n"
                            "    raise HTTPException(status_code=403)\n"
                        ),
                    )
                )

    return findings


def evaluate_openapi_schema(spec: dict) -> list:

    """
    Static OpenAPI checks remain useful, but findings are explicitly
    marked as specification observations rather than confirmed runtime
    vulnerabilities.
    """

    findings = []

    paths = spec.get("paths", {})

    if not paths:
        return findings

    for path, methods in paths.items():

        if not isinstance(methods, dict):
            continue

        for method, details in methods.items():

            if method.lower() not in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
            }:
                continue

            if not isinstance(details, dict):
                continue

            security = details.get(
                "security",
                spec.get("security", None),
            )

            if security == []:

                findings.append(
                    issue(
                        issue_id="openapi_explicit_public_operation",
                        severity="info",
                        category="authentication",
                        title="OpenAPI operation explicitly declares no security",
                        where=f"{method.upper()} {path}",
                        why=(
                            "The OpenAPI document explicitly declares an empty "
                            "security requirement for this operation."
                        ),
                        hint=(
                            "Confirm that this endpoint is intentionally public."
                        ),
                    )
                )

            parameters = details.get("parameters", [])

            for parameter in parameters:

                if not isinstance(parameter, dict):
                    continue

                name = str(parameter.get("name", "")).lower()

                if name in {
                    "id",
                    "user_id",
                    "account_id",
                    "owner_id",
                    "order_id",
                }:

                    findings.append(
                        issue(
                            issue_id="object_identifier_requires_runtime_test",
                            severity="info",
                            category="bola",
                            title="Object identifier requires authorization test",
                            where=f"{method.upper()} {path}",
                            why=(
                                f"Parameter '{name}' identifies an object. "
                                "The OpenAPI document alone cannot prove BOLA."
                            ),
                            hint=(
                                "Run the authorized cross-identity test with "
                                "two test identities and explicit object IDs."
                            ),
                        )
                    )

    return findings


def calculate_score(findings: List[Dict[str, Any]]) -> int:

    score = 100

    for finding in findings:

        severity = finding.get("severity", "info")

        score -= SEVERITY_WEIGHT.get(
            severity,
            3,
        )

    return max(0, min(100, score))


def calculate_status(
    score: int,
    findings: List[Dict[str, Any]],
) -> str:

    if any(
        finding.get("severity") == "critical"
        for finding in findings
    ):
        return "critical"

    if any(
        finding.get("severity") == "high"
        for finding in findings
    ):
        return "critical"

    if score < 90:
        return "warning"

    return "clean"


def analyze_endpoint_url(url: str) -> Dict[str, Any]:

    """
    Compatibility wrapper.

    This function no longer claims that URL patterns prove
    vulnerabilities. It only validates the URL structure.
    """

    parsed = urlparse(url.strip())

    findings = []

    if parsed.scheme not in {"http", "https"}:

        findings.append(
            issue(
                issue_id="invalid_scheme",
                severity="critical",
                category="structure",
                title="Invalid URL scheme",
                where=url,
                why="Only HTTP and HTTPS targets are supported.",
                hint="Use an http:// or https:// URL.",
            )
        )

    score = calculate_score(findings)

    return {
        "url": url,
        "sanitizedUrl": url.strip(),
        "score": score,
        "status": calculate_status(score, findings),
        "issues": findings,
        "anatomy": {
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "port": parsed.port or (
                443 if parsed.scheme == "https" else 80
            ),
            "path": parsed.path or "/",
            "query": parsed.query or "(none)",
            "hash": parsed.fragment or "(none)",
        },
    }