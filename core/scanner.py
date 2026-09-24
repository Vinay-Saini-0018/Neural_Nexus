"""
Authorized API runtime security scanner.

This module performs low-volume HTTP checks against a target that the
operator explicitly confirms they are authorized to test.

Checks:
- HTTP reachability
- authentication behavior
- response-data exposure
- security headers
- rate-limit behavior
- controlled BOLA comparison when two authorized identities
  and explicit object IDs are supplied
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


SENSITIVE_FIELD_NAMES = {
    "password",
    "password_hash",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "client_secret",
    "authorization",
    "ssn",
    "social_security_number",
    "credit_card",
    "card_number",
    "cvv",
    "internal_token",
}


@dataclass
class RequestResult:
    method: str
    url: str
    status_code: Optional[int]
    headers: Dict[str, str]
    body: Any
    elapsed_ms: float
    error: Optional[str] = None


def build_headers(token: Optional[str]) -> Dict[str, str]:

    headers = {
        "Accept": "application/json",
        "User-Agent": "Neural-Nexus-Authorized-Scanner/1.0",
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    return headers


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:

    result = {}

    sensitive = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
    }

    for key, value in headers.items():

        if key.lower() in sensitive:
            result[key] = "<REDACTED>"
        else:
            result[key] = value

    return result


def redact_body(value: Any) -> Any:

    if isinstance(value, dict):

        result = {}

        for key, item in value.items():

            if str(key).lower() in SENSITIVE_FIELD_NAMES:
                result[key] = "<REDACTED>"
            else:
                result[key] = redact_body(item)

        return result

    if isinstance(value, list):

        return [redact_body(item) for item in value[:20]]

    if isinstance(value, str):

        return value[:2000]

    return value


def parse_response_body(response: requests.Response) -> Any:

    content_type = response.headers.get("content-type", "").lower()

    if "json" in content_type:

        try:
            return response.json()
        except ValueError:
            return response.text[:2000]

    text = response.text[:2000]

    return text


def make_request(
    method: str,
    url: str,
    token: Optional[str],
    timeout: float,
) -> RequestResult:

    headers = build_headers(token)

    started = time.perf_counter()

    try:

        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
        )

        elapsed_ms = (time.perf_counter() - started) * 1000

        return RequestResult(
            method=method,
            url=url,
            status_code=response.status_code,
            headers=dict(response.headers),
            body=parse_response_body(response),
            elapsed_ms=elapsed_ms,
        )

    except requests.RequestException as exc:

        elapsed_ms = (time.perf_counter() - started) * 1000

        return RequestResult(
            method=method,
            url=url,
            status_code=None,
            headers={},
            body=None,
            elapsed_ms=elapsed_ms,
            error=str(exc),
        )


def detect_sensitive_fields(value: Any, path: str = "$") -> List[str]:

    findings = []

    if isinstance(value, dict):

        for key, child in value.items():

            current_path = f"{path}.{key}"

            if str(key).lower() in SENSITIVE_FIELD_NAMES:

                findings.append(current_path)

            findings.extend(
                detect_sensitive_fields(
                    child,
                    current_path,
                )
            )

    elif isinstance(value, list):

        for index, child in enumerate(value[:20]):

            findings.extend(
                detect_sensitive_fields(
                    child,
                    f"{path}[{index}]",
                )
            )

    return findings


def check_response_exposure(
    result: RequestResult,
) -> Optional[Dict[str, Any]]:

    if result.error:
        return None

    if result.status_code is None:
        return None

    if not (200 <= result.status_code < 300):
        return None

    fields = detect_sensitive_fields(result.body)

    if not fields:
        return None

    return {
        "fields": fields[:30],
        "status_code": result.status_code,
    }


def check_authentication_behavior(
    url: str,
    method: str,
    timeout: float,
) -> Optional[RequestResult]:

    result = make_request(
        method=method,
        url=url,
        token=None,
        timeout=timeout,
    )

    return result


def check_security_headers(
    result: RequestResult,
) -> List[str]:

    missing = []

    headers = {
        key.lower(): value
        for key, value in result.headers.items()
    }

    if result.url.lower().startswith("https://"):

        if "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security")

    if "x-content-type-options" not in headers:
        missing.append("X-Content-Type-Options")

    return missing


def check_rate_limit(
    url: str,
    method: str,
    token: Optional[str],
    timeout: float,
    request_count: int,
    delay: float,
) -> List[RequestResult]:

    results = []

    # Small bounded test only.
    request_count = max(1, min(request_count, 10))

    for _ in range(request_count):

        result = make_request(
            method=method,
            url=url,
            token=token,
            timeout=timeout,
        )

        results.append(result)

        if result.status_code == 429:
            break

        time.sleep(max(0.0, min(delay, 2.0)))

    return results


def replace_object_id(
    url: str,
    object_id: str,
) -> str:

    # Used only with explicit object IDs supplied by the operator.
    #
    # If the caller has an endpoint such as:
    # /orders/{id}
    # or a concrete URL containing an ID,
    # they should provide a complete target URL in their OpenAPI
    # operation configuration.
    #
    # This simple replacement supports the common placeholder form.

    return (
        url.replace("{id}", object_id)
        .replace("{object_id}", object_id)
        .replace("{order_id}", object_id)
        .replace("{user_id}", object_id)
        .replace("{account_id}", object_id)
    )


def compare_authorized_identities(
    url: str,
    method: str,
    first_token: str,
    second_token: str,
    timeout: float,
) -> Dict[str, RequestResult]:

    first = make_request(
        method=method,
        url=url,
        token=first_token,
        timeout=timeout,
    )

    second = make_request(
        method=method,
        url=url,
        token=second_token,
        timeout=timeout,
    )

    return {
        "first": first,
        "second": second,
    }