# APISentinel AI — Autonomous API Vulnerability & BOLA Auditor 🛡️🤖

> **Hackathon MVP Frontend Solution** designed for AppSec and Backend Engineering Teams.

APISentinel AI is an autonomous, AI/ML-inspired security frontend built to continuously audit API endpoints and OpenAPI/Swagger specs for broken object-level authorization (BOLA/IDOR), excessive data exposure, and authentication flaws.

---

## Key Capabilities ✨

1. **Input Vector Column**: Ingests API routes, OpenAPI spec URLs, or backend paths.
2. **AI Agentic Reasoner Trace**: Simulates multi-step reasoning steps (ingesting spec, evaluating BOLA logic, checking data exposure vectors).
3. **Structured Diagnostic Findings**:
   - **📍 Where is the Vulnerability**: Pinpoints exact path parameters (`/orders/{id}`) and query parameters (`user_id`).
   - **🔍 Why is this Happening**: Deep OWASP API Security Top 10 root cause explanation.
   - **💡 Fix Hints & Code Remedies**: Actionable server-side fix recommendations with copyable FastAPI / Python Pydantic / Redis middleware code snippets.
4. **Anatomy Inspector**: Visual decomposition of API Scheme, Domain, Port, Path, and Parameters.
5. **Dual Mode Execution**:
   - **Client AI Neural Simulator**: Operates 100% locally out-of-the-box for rapid demo testing.
   - **Python Backend Integration**: Click **Backend Config** to direct requests to your custom Python API endpoint (`http://localhost:8000/analyze`).

---

## How to Run the Frontend 🚀

Run the built-in HTTP server using Python:

```bash
python -m http.server 3000 --directory frontend
```

Open `http://localhost:3000` in your web browser!

---

## Python Backend Contract (for `main.py`) 🐍

When you build your Python backend (using FastAPI or Flask), configure your route to handle `POST` requests:

### Request Payload:
```json
{
  "url": "https://api.acmeshop.com/v1/orders/109482?user_id=884"
}
```

### Expected Response JSON:
```json
{
  "url": "https://api.acmeshop.com/v1/orders/109482?user_id=884",
  "sanitizedUrl": "https://api.acmeshop.com/v1/orders/109482?user_id=884",
  "score": 45,
  "status": "critical",
  "issues": [
    {
      "id": "bola_vulnerability",
      "severity": "critical",
      "category": "bola",
      "title": "Broken Object-Level Authorization (BOLA / IDOR)",
      "where": "Path parameter `/orders/{order_id}` & query `user_id`",
      "why": "Endpoint accepts user_id from query without enforcing session ownership verification.",
      "hint": "Validate order ownership server-side using authenticated JWT claims: req.user.id == order.user_id",
      "codeSnippet": "@app.get('/v1/orders/{order_id}')\ndef get_order(order_id: str, current_user = Depends(get_current_user)):\n    order = db.get_order(order_id)\n    if order.user_id != current_user.id:\n        raise HTTPException(status_code=403, detail='Access Forbidden')"
    }
  ]
}
```
