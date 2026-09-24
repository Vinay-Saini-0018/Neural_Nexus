"""
Static Schema Rule Inspector for OpenAPI Specs & Route Configurations.
Evaluates static security policies: BOLA parameter patterns, excessive data flags, and rate limiting setup.
"""

import urllib.parse

def evaluate_openapi_schema(spec: dict) -> list:
    """
    Evaluates an OpenAPI spec dict for static security declarations.
    """
    findings = []
    
    paths = spec.get("paths", {})
    if not paths:
        return findings

    for path, methods in paths.items():
        for method, details in methods.items():
            if not isinstance(details, dict):
                continue
            
            # Check 1: Missing authentication scope declarations
            security = details.get("security", spec.get("security", []))
            if not security:
                findings.append({
                    "id": "missing_auth_scheme",
                    "severity": "warning",
                    "category": "security",
                    "title": f"Missing Explicit Security Scheme on {method.upper()} {path}",
                    "where": f"Path '{path}' [{method.upper()}]",
                    "why": "Endpoint path operation does not explicitly enforce a security requirement (e.g., Bearer/OAuth2).",
                    "hint": "Add 'security' requirements block in OpenAPI specification for this path."
                })

            # Check 2: Potential BOLA / IDOR path parameters
            parameters = details.get("parameters", [])
            has_id_param = any(p.get("name", "").endswith("_id") or p.get("name") == "id" for p in parameters if isinstance(p, dict))
            if has_id_param and not security:
                findings.append({
                    "id": "unprotected_bola_route",
                    "severity": "critical",
                    "category": "bola",
                    "title": f"Unauthenticated Resource Identifier on {path}",
                    "where": f"Path parameter in '{path}'",
                    "why": "Path contains object identifier parameters without enforcing authentication, creating high risk for Broken Object-Level Authorization (BOLA).",
                    "hint": "Enforce server-side JWT ownership verification and add authorization policies.",
                    "codeSnippet": "@app.get('/api/resource/{id}')\ndef get_res(id: str, user = Depends(get_current_user)):\n    if res.owner_id != user.id:\n        raise HTTPException(403)"
                })

    return findings


def analyze_endpoint_url(url: str) -> dict:
    """
    Performs static structural audit on an API URL string.
    """
    findings = []
    score = 100
    sanitized_url = url.strip()

    if not sanitized_url:
        return {
            "url": url,
            "sanitizedUrl": "",
            "score": 0,
            "status": "critical",
            "issues": [{
                "id": "empty_url",
                "severity": "critical",
                "category": "structure",
                "title": "Empty Target URL",
                "where": "Input parameter",
                "why": "No URL string provided to analyze.",
                "hint": "Provide a valid HTTP/HTTPS API URL."
            }]
        }

    try:
        parsed = urllib.parse.urlparse(sanitized_url)
    except Exception as e:
        return {
            "url": url,
            "sanitizedUrl": sanitized_url,
            "score": 0,
            "status": "critical",
            "issues": [{
                "id": "malformed_url",
                "severity": "critical",
                "category": "structure",
                "title": "Malformed URL Format",
                "where": "URL String",
                "why": f"Failed to parse URL: {str(e)}",
                "hint": "Check URL syntax rules."
            }]
        }

    # BOLA Parameter Check
    if any(res in parsed.path.lower() for res in ['/orders/', '/users/', '/accounts/', '/invoices/']) and ('user_id' in parsed.query.lower() or 'account_id' in parsed.query.lower()):
        score -= 40
        findings.append({
            "id": "bola_vulnerability",
            "severity": "critical",
            "category": "bola",
            "title": "Broken Object-Level Authorization Pattern (BOLA / IDOR)",
            "where": f"Path '{parsed.path}' & Query '{parsed.query}'",
            "why": "Endpoint exposes object identifiers while accepting client-supplied user_id parameters.",
            "hint": "Verify object ownership server-side using session JWT token claims instead of query parameters.",
            "codeSnippet": "# FastAPI Authorization Guard:\nif order.owner_id != current_user.id:\n    raise HTTPException(status_code=403, detail='Access Forbidden')"
        })

    # Excessive Data Exposure Check
    if any(param in parsed.query.lower() for param in ['include_private', 'full_profile', 'debug=true', 'all_fields']):
        score -= 30
        findings.append({
            "id": "excessive_data_exposure",
            "severity": "critical",
            "category": "data_exposure",
            "title": "Excessive Data Exposure Parameter Flag",
            "where": f"Query parameters '{parsed.query}'",
            "why": "Passing parameters that request unredacted or full database records exposes sensitive PII fields.",
            "hint": "Use explicit Pydantic / DTO response schemas to filter sensitive properties on the server.",
            "codeSnippet": "class PublicUserDTO(BaseModel):\n    id: str\n    username: str\n    # Exclude password_hash or internal secrets"
        })

    # Rate Limiting & Auth Check
    if any(auth_path in parsed.path.lower() for auth_path in ['/auth', '/login', '/otp-verify', '/token']):
        score -= 20
        findings.append({
            "id": "auth_rate_limit_check",
            "severity": "warning",
            "category": "rate_limit",
            "title": "Sensitive Authentication Endpoint - Rate Limiting Recommended",
            "where": f"Auth Path '{parsed.path}'",
            "why": "Authentication endpoints require strict sliding-window rate limiting to prevent brute-force attacks.",
            "hint": "Enforce Redis-backed rate limiting middleware on auth routes.",
            "codeSnippet": "# Redis Rate Limit Middleware:\nif await redis.incr(ip) > 5:\n    return JSONResponse({'error': 'Too Many Requests'}, status_code=429)"
        })

    # Insecure Transport Scheme
    if parsed.scheme == "http":
        score -= 15
        findings.append({
            "id": "insecure_transport",
            "severity": "warning",
            "category": "security",
            "title": "Insecure HTTP Protocol",
            "where": "Scheme prefix 'http://'",
            "why": "Unencrypted HTTP transport exposes API tokens and headers to network eavesdropping.",
            "hint": "Upgrade endpoint to HTTPS and enforce HSTS headers."
        })

    score = max(0, min(100, score))
    status = "critical" if score < 60 or any(f["severity"] == "critical" for f in findings) else ("warning" if score < 90 or len(findings) > 0 else "clean")

    return {
        "url": url,
        "sanitizedUrl": sanitized_url,
        "score": score,
        "status": status,
        "issues": findings,
        "anatomy": {
            "scheme": parsed.scheme or "http",
            "host": parsed.netloc or "unknown",
            "port": parsed.port or ("443" if parsed.scheme == "https" else "80"),
            "path": parsed.path or "/",
            "query": parsed.query or "(none)",
            "hash": parsed.fragment or "(none)"
        }
    }
