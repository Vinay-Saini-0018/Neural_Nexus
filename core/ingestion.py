"""
OpenAPI Specification & Schema Ingestion Engine.
Parses OpenAPI JSON/YAML specs or fetches endpoint definitions for static compliance auditing.
"""

import json
import urllib.parse
import requests

def parse_spec_from_url_or_json(source: str) -> dict:
    """
    Ingests and parses an OpenAPI spec JSON/YAML string or fetches it from a URL.
    """
    source = source.strip() if isinstance(source, str) else source
    if not source:
        return {"error": "Empty source provided"}

    # If it's a URL, fetch content
    if source.startswith("http://") or source.startswith("https://"):
        try:
            resp = requests.get(source, timeout=5)
            if resp.status_code == 200:
                try:
                    return resp.json()
                except Exception:
                    return {"raw_url": source, "content": resp.text}
            return {"error": f"Failed to fetch spec from URL: HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": f"Connection error: {str(e)}"}

    # If it's raw JSON
    try:
        return json.loads(source)
    except Exception:
        pass

    # Basic URL structure parsing fallback
    try:
        parsed = urllib.parse.urlparse(source)
        return {
            "url": source,
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query
        }
    except Exception as e:
        return {"error": f"Parsing failed: {str(e)}"}

def check_api_reachability(url: str) -> dict:
    """
    Checks basic HTTP reachability for a target endpoint URL.
    """
    if not url:
        return {"status": "error", "message": "No URL provided"}

    try:
        resp = requests.get(url, timeout=5)
        return {
            "status": "valid" if resp.status_code < 500 else "server_error",
            "status_code": resp.status_code,
            "headers": dict(resp.headers)
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}