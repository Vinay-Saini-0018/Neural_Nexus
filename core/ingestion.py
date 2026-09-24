"""
OpenAPI / Swagger ingestion.

This module:
1. Fetches an OpenAPI/Swagger document.
2. Parses JSON.
3. Extracts HTTP operations.
4. Resolves server/base URLs.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import requests


HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
}


def fetch_document(source: str, timeout: float = 8.0) -> Dict[str, Any]:
    source = source.strip()

    if not source:
        raise ValueError("Empty OpenAPI source.")

    response = requests.get(
        source,
        timeout=timeout,
        headers={
            "Accept": "application/json, application/yaml, text/yaml, */*"
        },
    )

    response.raise_for_status()

    try:
        data = response.json()
    except ValueError as exc:
        raise ValueError(
            "The supplied document is not valid JSON. "
            "YAML support can be added separately."
        ) from exc

    if not isinstance(data, dict):
        raise ValueError("OpenAPI document must be a JSON object.")

    return data


def is_openapi_document(data: Dict[str, Any]) -> bool:
    return (
        isinstance(data.get("openapi"), str)
        or isinstance(data.get("swagger"), str)
    )


def resolve_base_url(spec: Dict[str, Any], source_url: str) -> str:
    """
    OpenAPI 3:
        servers[0].url

    Swagger 2:
        schemes + host + basePath
    """

    servers = spec.get("servers")

    if isinstance(servers, list) and servers:
        first = servers[0]

        if isinstance(first, dict):
            server_url = first.get("url")

            if isinstance(server_url, str) and server_url:
                return server_url.rstrip("/") + "/"

    # Swagger 2
    host = spec.get("host")
    base_path = spec.get("basePath", "")
    schemes = spec.get("schemes") or ["https"]

    if host:
        return f"{schemes[0]}://{host}{base_path}".rstrip("/") + "/"

    # Fallback: same origin as specification URL.
    parsed = urlparse(source_url)

    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/"

    return ""


def extract_endpoints(
    spec: Dict[str, Any],
    source_url: str,
    max_endpoints: int = 30,
) -> List[Dict[str, Any]]:

    paths = spec.get("paths", {})

    if not isinstance(paths, dict):
        return []

    base_url = resolve_base_url(spec, source_url)

    endpoints: List[Dict[str, Any]] = []

    for path, path_item in paths.items():

        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():

            if method.lower() not in HTTP_METHODS:
                continue

            if not isinstance(operation, dict):
                operation = {}

            # OpenAPI may use server URLs containing relative paths.
            full_url = urljoin(base_url, str(path).lstrip("/"))

            endpoints.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "url": full_url,
                    "operation": operation,
                }
            )

            if len(endpoints) >= max_endpoints:
                return endpoints

    return endpoints


def looks_like_openapi_url(url: str) -> bool:
    lowered = url.lower()

    return any(
        marker in lowered
        for marker in [
            "openapi.json",
            "swagger.json",
            "openapi.yaml",
            "openapi.yml",
            "swagger.yaml",
            "swagger.yml",
            "/docs/openapi",
            "/openapi",
        ]
    )