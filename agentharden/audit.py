"""The security audit in FIX_PROMPT.md: an attack-surface map, and instructions for the flaws a scanner cannot see.

Pattern rules find injection, secrets and vulnerable packages. They cannot tell whether a route checks that the
caller owns the record it returns, whether a state-changing request needs a CSRF token, or whether an endpoint
that calls a paid AI API can be run in a loop. Those need someone to read the code, so the prompt asks the AI
tool to do it, with rules that keep the result checkable:

- surface() lists the routes and sensitive areas agentharden can see, with file and line, so the audit starts
  from a concrete list and the report must give a verdict on every route.
- section() writes the audit instructions: a core checklist built on OWASP ASVS 5.0 and the CWE Top 25, plus
  notes for each detected framework. Every issue must cite file:line and the request an attacker would send,
  and every fix must come with a test that sends that request.

Everything taken from the repository (paths, route strings, marker text) goes into `agentharden-data` blocks,
like the rest of the prompt. The instruction text here is static.
"""
from __future__ import annotations

import os
import re

from . import context

MAX_ROUTES = 120
MAX_PER_AREA = 8
_STRINGS = re.compile(r"(\"\"\"|'''|[\"'`])(?:\\.|(?!\1).)*?\1")
_PY_ROUTE = re.compile(r"^\s*@([A-Za-z_][\w.]*)\.(get|post|put|patch|delete|head|options|route|api_route|websocket)"
                       r"\(\s*(?:path\s*=\s*)?[rRuU]?[\"']([^\"']*)[\"']")
_PY_PREFIX = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(?:APIRouter|Blueprint)\((.*)")
_PY_PREFIX_ARG = re.compile(r"(?:prefix|url_prefix)\s*=\s*[\"']([^\"']*)[\"']")
_PY_METHODS = re.compile(r"methods\s*=\s*[\[(]([^\])]*)")
_DJANGO = re.compile(r"\b(?:re_)?path\(\s*r?[\"']([^\"']*)[\"']\s*,\s*([\w.]+)")
_JS_ROUTE = re.compile(r"\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|all)\(\s*([\"'`])(/[^\"'`]*)\3")
_JS_RECEIVER = re.compile(r"^(app|server|router|routes?|fastify|hono|[a-z]\w*(Router|Routes|App|Server))$", re.IGNORECASE)
_JS_CLIENT = re.compile(r"^(axios|http|https|client|fetcher|request|instance|ky|got|superagent|\$http|api\w*)$")
# A file defines server routes only if it loads a server framework; browser code calling `api.get("/x")` does not.
_JS_SERVER = re.compile(r"(?:require\(\s*|from\s+)[\"'](?:express|fastify|koa|@koa/router|koa-router|hono|hono/[\w-]+"
                        r"|restify|polka|elysia|h3|@hapi/hapi)[\"']|\bexpress\.Router\(|\bRouter\(\s*\)")
_NEXT_APP = re.compile(r"(^|/)app/(?:(.*)/)?route\.[cm]?[jt]sx?$")
_NEXT_PAGES = re.compile(r"(^|/)pages/api/(.+)\.[cm]?[jt]sx?$")
_NEXT_METHOD = re.compile(r"^\s*export\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
_SERVER_ACTION = re.compile(r"^\s*export\s+async\s+function\s+([A-Za-z_$][\w$]*)")
_NEST_CTRL = re.compile(r"@Controller\(\s*(?:[\"'`]([^\"'`]*)[\"'`])?")
_NEST_ROUTE = re.compile(r"^\s*@(Get|Post|Put|Patch|Delete|All)\(\s*(?:[\"'`]([^\"'`]*)[\"'`])?\s*\)")
_SPRING = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:(?:value|path)\s*=\s*)?\{?\s*\"([^\"]*)\"")
_RAILS = re.compile(r"^\s*(get|post|put|patch|delete|resources|resource)\s+[:\"']?([\w/:\-{}.]+)")
_LARAVEL = re.compile(r"Route::(get|post|put|patch|delete|any|match|resource|apiResource)\(\s*[\"']([^\"']*)[\"']")
_GO = re.compile(r"\.(GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete|Handle|HandleFunc)\(\s*\"((?:[A-Z]+ )?/[^\"]*)\"")
_ANY_ROUTE = re.compile(r"\.(?:get|post|put|patch|delete|all|GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle)\(\s*[\"'`]"
                        r"|@(?:Get|Post|Put|Patch|Delete|Request|All)(?:Mapping)?\(|Route::|^\s*export\s")
_AUTH_PY = re.compile(
    r"(?:Depends|Security)\(\s*[\w.]*(?:current_user|get_user|_user|auth|verify|require|token|login|admin|permission"
    r"|jwt|session)[\w.]*\)?|login_required|permission_required|user_passes_test|jwt_required|auth_required"
    r"|requires_auth|fresh_login_required|IsAuthenticated|permission_classes|roles_required|admin_required")
_AUTH_OTHER = re.compile(
    r"passport\.authenticate|UseGuards|PreAuthorize|Secured|RolesAllowed|before_action|authenticate_user"
    r"|->middleware\(\s*\[?\s*[\"']?auth|\b(?:requireAuth|isAuthenticated|ensureAuthenticated|ensureLoggedIn"
    r"|isLoggedIn|requireUser|requireLogin|verifyToken|verifyJWT|verifyJwt|checkJwt|withAuth|withSession"
    r"|authenticate|authenticateToken|authenticateJWT|authMiddleware|auth|protect|protected|authorize|requireRole"
    r"|requireAdmin|isAdmin|jwtAuth|getServerSession|currentUser|auth\(\))\b"
    r"|\b\w*(?:Auth|auth)(?:Middleware|Guard|enticate\w*|orize\w*|Required)\b")
_FILE_AUTH = re.compile(r"(?:\.use\(\s*([\w.]*(?:auth|Auth|protect|jwt|Jwt|session|passport)[\w.()]*)"
                        r"|APIRouter\([^)]*dependencies\s*=|@UseGuards|before_action\s+:authenticate"
                        r"|->middleware\(\s*[\"']auth)")
_URL_ID = re.compile(r"\{[^}]+\}|<[^>]+>|(?:^|/):[A-Za-z_]\w*|\[[^\]]+\]|\(\?P<")

AREAS = {  # area -> pattern, matched against app code with string literals blanked
    "file upload": re.compile(r"\bUploadFile\b|request\.files\b|\bmulter\b|formidable|busboy|MultipartFile"
                              r"|->file\(|\bFileField\b"),
    "file download or serving": re.compile(r"\bFileResponse\b|\bsend_file\b|send_from_directory|\.sendFile\("
                                           r"|res\.download\(|StreamingResponse|serve_static|http\.ServeFile"),
    "outbound request from a variable": re.compile(
        r"\b(?:requests|httpx)\.(?:get|post|put|request)\(\s*[A-Za-z_]"
        r"|urlopen\(\s*[A-Za-z_]|\bfetch\(\s*[A-Za-z_$]|axios(?:\.(?:get|post|request))?\(\s*[A-Za-z_$]"
        r"|http\.(?:Get|Post)\(\s*[A-Za-z_]"),
    "AI or LLM API call": re.compile(r"chat\.completions\.create|messages\.create|responses\.create|generate_content"
                                     r"|ChatOpenAI|ChatAnthropic|\bGroq\(|\bOpenAI\(|\bAnthropic\("
                                     r"|GoogleGenerativeAI|\bgenai\.|\blitellm\.completion"),
    "CORS setup": re.compile(r"CORSMiddleware|\bCORS\(|\bcors\(|allow_origins|Access-Control-Allow-Origin"
                             r"|CORS_ALLOW|@CrossOrigin|AllowOrigins"),
    "token or session handling": re.compile(r"\bjwt\.(?:encode|decode|sign|verify)\b|jsonwebtoken|create_access_token"
                                            r"|OAuth2PasswordBearer|SESSION_COOKIE|cookie-session|express-session"
                                            r"|set_cookie|\.cookie\("),
    "password storage": re.compile(r"\bbcrypt\b|passlib|argon2|scrypt|pbkdf2|make_password|check_password"
                                   r"|password_hash|hashpw|CryptContext"),
}
_IMPORT = re.compile(r"^\s*(?:import\b|from\s+\S+\s+import\b|(?:const|let|var)\s+[^=]+=\s*require\(|require\(|use\s"
                     r"|#include|package\s)")
_CODE_EXT = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".rb", ".php", ".go"}


def _blank(text: str) -> str:
    return _STRINGS.sub('""', text)


def _auth_near(lines: list, i: int, py: bool) -> str:
    """The first auth marker in the route's definition: stacked decorators and the signature (Python) or the
    route call's own line and the next two (other languages). String literals are ignored."""
    if py:
        lo = i
        while lo > 0 and lines[lo - 1].lstrip().startswith("@"):
            lo -= 1
        hi = i
        while hi < min(len(lines) - 1, i + 16) and not re.search(r"\)\s*(?:->[^:]*)?:\s*(?:#.*)?$", lines[hi]):
            hi += 1
        span = lines[lo:hi + 1]
    else:
        lo = i
        while lo > 0 and i - lo < 4 and lines[lo - 1].lstrip().startswith("@"):
            lo -= 1
        hi = i
        while hi < min(len(lines) - 1, i + 2) and lines[hi + 1].strip() and not _ANY_ROUTE.search(lines[hi + 1]):
            hi += 1
        span = lines[lo:hi + 1]
    m = (_AUTH_PY if py else _AUTH_OTHER).search(_blank("\n".join(span)))
    return m.group(0)[:60] if m else ""


def _route(method, path, rel, line, auth, file_auth):
    return {"method": method.upper(), "path": path or "/", "file": rel, "line": line,
            "auth": auth or (f"file: {file_auth}" if file_auth else ""), "url_id": bool(_URL_ID.search(path or ""))}


def _python_routes(rel: str, text: str, lines: list) -> list:
    out = []
    fa = re.search(r"APIRouter\([^)]*dependencies\s*=", text)
    file_auth = "APIRouter(dependencies=...)" if fa else ""
    prefixes = {}
    for ln in lines:
        m = _PY_PREFIX.match(ln)
        if m:
            p = _PY_PREFIX_ARG.search(m.group(2))
            prefixes[m.group(1)] = p.group(1) if p else ""
    for i, ln in enumerate(lines):
        m = _PY_ROUTE.match(ln)
        if m:
            verb = m.group(2)
            if verb in ("route", "api_route"):
                ms = _PY_METHODS.search(ln)
                verb = "/".join(re.findall(r"[A-Za-z]+", ms.group(1))) if ms else "GET"
            path = prefixes.get(m.group(1).split(".")[-1], "") + m.group(3)
            out.append(_route(verb, path, rel, i + 1, _auth_near(lines, i, True), file_auth))
    if rel.rsplit("/", 1)[-1] == "urls.py":
        for i, ln in enumerate(lines):
            m = _DJANGO.search(ln)
            if m and not ln.lstrip().startswith("#"):
                out.append(_route("ANY", "/" + m.group(1).lstrip("^/"), rel, i + 1, "", ""))
    return out


def _js_routes(rel: str, text: str, lines: list, file_auth: str) -> list:
    out = []
    m = _NEXT_APP.search(rel)
    if m:
        path = "/" + m.group(2) if m.group(2) else "/"
        for i, ln in enumerate(lines):
            mm = _NEXT_METHOD.match(ln)
            if mm:
                out.append(_route(mm.group(1), path, rel, i + 1, _auth_near(lines, i, False), file_auth))
        return out
    m = _NEXT_PAGES.search(rel)
    if m:
        return [_route("ANY", "/api/" + re.sub(r"/?index$", "", m.group(2)), rel, 1, "", file_auth)]
    if re.match(r"^\s*[\"']use server[\"']", text):
        for i, ln in enumerate(lines):
            mm = _SERVER_ACTION.match(ln)
            if mm:
                out.append(_route("ACTION", f"server action {mm.group(1)}", rel, i + 1,
                                  _auth_near(lines, i + 1, False), file_auth))
        return out
    ctrl = _NEST_CTRL.search(text)
    if ctrl:
        prefix = "/" + (ctrl.group(1) or "").strip("/")
        for i, ln in enumerate(lines):
            mm = _NEST_ROUTE.match(ln)
            if mm:
                path = (prefix.rstrip("/") + "/" + (mm.group(2) or "").strip("/")).rstrip("/") or "/"
                out.append(_route(mm.group(1), path, rel, i + 1, _auth_near(lines, i, False), file_auth))
        return out
    if not _JS_SERVER.search(text):
        return out
    for i, ln in enumerate(lines):
        for mm in _JS_ROUTE.finditer(ln):
            recv = mm.group(1)
            if _JS_CLIENT.match(recv) or not _JS_RECEIVER.match(recv):
                continue
            out.append(_route(mm.group(2), mm.group(4), rel, i + 1, _auth_near(lines, i, False), file_auth))
    return out


def _routes_in(rel: str, text: str, blanked: str) -> list:
    ext = os.path.splitext(rel)[1].lower()
    lines = text.splitlines()
    if ext == ".py":
        return _python_routes(rel, text, lines)
    fa = _FILE_AUTH.search(blanked)
    file_auth = (fa.group(1) or fa.group(0)).strip()[:60] if fa else ""
    if ext in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"):
        return _js_routes(rel, text, lines, file_auth)
    pattern = {".java": _SPRING, ".kt": _SPRING, ".php": _LARAVEL, ".go": _GO}.get(ext)
    if ext == ".rb" and rel.rsplit("/", 1)[-1] == "routes.rb":
        pattern = _RAILS
    out = []
    if pattern is None:
        return out
    for i, ln in enumerate(lines):
        m = pattern.search(ln)
        if not m or ln.lstrip().startswith(("#", "//")):
            continue
        verb, path = m.group(1), m.group(2)
        if ext == ".go" and " " in path:
            verb, path = path.split(" ", 1)
        if verb.lower() in ("request", "handle", "handlefunc", "any", "match", "resource", "resources", "apiresource"):
            verb = "ANY"
        if ext == ".rb" and not path.startswith("/"):
            path = "/" + path.lstrip(":")
        out.append(_route(verb, path, rel, i + 1, _auth_near(lines, i, False), file_auth))
    return out


_AREA_WORDS = {  # area -> literal strings, at least one of which a matching file must contain (a fast prefilter)
    "file upload": ("UploadFile", "request.files", "multer", "formidable", "busboy", "MultipartFile", "->file(",
                    "FileField"),
    "file download or serving": ("FileResponse", "send_file", "send_from_directory", ".sendFile(", ".download(",
                                 "StreamingResponse", "serve_static", "ServeFile"),
    "outbound request from a variable": ("requests.", "httpx.", "urlopen(", "fetch(", "axios", "http.Get(",
                                         "http.Post("),
    "AI or LLM API call": ("completions.create", "messages.create", "responses.create", "generate_content",
                           "ChatOpenAI", "ChatAnthropic", "Groq(", "OpenAI(", "Anthropic(", "GoogleGenerativeAI",
                           "genai.", "litellm."),
    "CORS setup": ("CORS", "cors(", "allow_origins", "Access-Control-Allow-Origin", "CrossOrigin", "AllowOrigins"),
    "token or session handling": ("jwt.", "jsonwebtoken", "create_access_token", "OAuth2PasswordBearer",
                                  "SESSION_COOKIE", "cookie-session", "express-session", "set_cookie", ".cookie("),
    "password storage": ("bcrypt", "passlib", "argon2", "scrypt", "pbkdf2", "make_password", "check_password",
                         "password_hash", "hashpw", "CryptContext"),
}


def _areas_in(rel: str, blanked: str, areas: dict) -> None:
    """Add up to MAX_PER_AREA 'file:line' hits per area, skipping import lines. Full areas are not searched."""
    for area, pattern in AREAS.items():
        hits = areas.setdefault(area, [])
        if len(hits) >= MAX_PER_AREA or not any(w in blanked for w in _AREA_WORDS[area]):
            continue
        for m in pattern.finditer(blanked):
            start = blanked.rfind("\n", 0, m.start()) + 1
            end = blanked.find("\n", m.start())
            if _IMPORT.match(blanked[start:end if end >= 0 else len(blanked)]):
                continue
            where = f"{rel}:{blanked.count(chr(10), 0, m.start()) + 1}"
            if not hits or hits[-1] != where:
                hits.append(where)
            if len(hits) >= MAX_PER_AREA:
                break


def surface(files: list) -> dict:
    """{'routes': [...], 'more_routes': n, 'areas': {area: ['file:line', ...]}} for app code only."""
    routes, areas = [], {}
    for f in files:
        rel = f.path
        if os.path.splitext(rel)[1].lower() not in _CODE_EXT or context.classify(rel) != context.APP:
            continue
        blanked = _blank(f.text)
        routes.extend(_routes_in(rel, f.text, blanked))
        _areas_in(rel, blanked, areas)
    # Routes with no visible auth and routes that take an id from the URL come first: that is where
    # access-control bugs are.
    routes.sort(key=lambda r: (bool(r["auth"]), not r["url_id"], r["file"], r["line"]))
    return {"routes": routes[:MAX_ROUTES], "more_routes": max(0, len(routes) - MAX_ROUTES),
            "areas": {k: v for k, v in areas.items() if v}}


# ------------------------------------------------------------------ prompt section (static text)

CORE = [
    ("Access control", "CWE-862, CWE-863, CWE-639",
     "For every route in the `routes` block, find where the server checks (1) that the caller is logged in and "
     "(2) that the caller may act on this record. A query that loads a record by an id from the URL or body "
     "without also filtering on the current user, team or tenant is an IDOR: user A can read or change user B's "
     "data by changing the id. Admin and staff routes must check the role on the server. Checks in the frontend "
     "do not count."),
    ("Authentication", "CWE-287, CWE-307, CWE-521, CWE-640",
     "Passwords are hashed with bcrypt, scrypt or Argon2, never a plain or fast hash. Login and password reset are "
     "rate limited. Tokens are signed, verified with a fixed algorithm, expire, and use a secret read from the "
     "environment. Reset tokens are random, single-use and expire, and the reset and login responses do not reveal "
     "whether an email is registered."),
    ("Sessions and CSRF", "CWE-352, CWE-614, CWE-1004",
     "If authentication uses cookies, every state-changing route needs CSRF protection or SameSite=Lax/Strict "
     "cookies, and the cookies are Secure and HttpOnly. If tokens live in localStorage, any XSS can steal them, "
     "so XSS findings weigh more."),
    ("Input handling", "CWE-915, CWE-434, CWE-22, CWE-20",
     "Request bodies are not bound straight onto database models (mass assignment of fields like `role`, "
     "`is_admin`, `owner_id`, `credits`). Uploads check type by content, cap size, get a server-chosen name and "
     "are stored outside any served folder. File paths built from input stay inside their base folder."),
    ("Outbound requests", "CWE-918",
     "A URL or host that comes from the user and is fetched by the server is SSRF unless it is checked against an "
     "allowlist. Look at every entry in the `outbound request from a variable` area."),
    ("Data exposure", "CWE-200, CWE-209, CWE-532, CWE-942",
     "Responses do not include password hashes, tokens, other users' data or internal fields; use an explicit "
     "response schema. Errors in production do not return stack traces. Logs do not contain passwords, tokens or "
     "personal data. CORS does not allow every origin together with credentials."),
    ("Abuse and business logic", "CWE-770, CWE-840, CWE-362",
     "Expensive operations (AI calls, email, SMS, PDF or image generation, exports) have per-user rate limits or "
     "quotas, so one account cannot run up the bill. Limits, credits and balances cannot go negative and are "
     "updated atomically, so two parallel requests cannot both spend the same credit. Each step of a multi-step "
     "flow checks the state on the server, not a value the client sends."),
]
FRAMEWORK_NOTES = {
    "FastAPI": "FastAPI: protected routes need `Depends(...)` on the current user, on the route or on its router "
               "(`APIRouter(dependencies=[...])`). Check that every route that touches user data has one and then "
               "filters its queries by that user. Use `response_model` so ORM fields do not leak. "
               "`CORSMiddleware(allow_origins=[\"*\"], allow_credentials=True)` is a finding.",
    "Starlette": "Starlette: check the authentication middleware covers every mount, and that endpoints check "
                 "`request.user.is_authenticated` themselves where it does not.",
    "Flask": "Flask: look for routes missing `@login_required` or an equivalent check, `SECRET_KEY` set in code, "
             "`debug=True`, and forms without CSRF protection (Flask-WTF `CSRFProtect`).",
    "Django": "Django: views need `@login_required`, `LoginRequiredMixin` or DRF `permission_classes`, and object "
              "lookups need the owner, e.g. `get_object_or_404(Model, pk=pk, owner=request.user)`. Every "
              "`@csrf_exempt`, a `DEBUG` that is on in production and a wildcard in `ALLOWED_HOSTS` needs a reason.",
    "Express": "Express: check the order of `app.use(...)`: routes registered before the auth middleware are "
               "public. Look for `req.params.id` or `req.body.id` used in a query without the current user. "
               "Expect `helmet` and a rate limiter on login and expensive routes.",
    "Fastify": "Fastify: check that `onRequest` or `preHandler` auth hooks are registered in the scope of every "
               "protected route, since plugins are encapsulated.",
    "Koa": "Koa: check the auth middleware is mounted before the routers that need it.",
    "Hono": "Hono: check auth middleware is applied to every protected path pattern.",
    "NestJS": "NestJS: every controller or route that needs a user has `@UseGuards(...)`, or a global guard is "
              "registered and public routes opt out explicitly. DTOs use `class-validator` with `whitelist: true`.",
    "Next.js": "Next.js: route handlers (`app/**/route.ts`), `pages/api` and server actions are public HTTP "
               "endpoints. Each must check the session itself, because `middleware.ts` matchers often miss "
               "paths. Nothing secret may use the `NEXT_PUBLIC_` prefix.",
    "Nuxt": "Nuxt: `server/api` handlers are public endpoints and must check the session themselves.",
    "SvelteKit": "SvelteKit: `+server.ts` endpoints and form actions must check `locals.user` themselves.",
    "React": "React (browser code): every check in the UI is cosmetic, so confirm each one is repeated on the "
             "server. Look for API keys or secrets in frontend code or in `VITE_` and `REACT_APP_` variables, "
             "tokens in localStorage, and `dangerouslySetInnerHTML` with server or user data.",
    "Vue": "Vue (browser code): checks in the UI are cosmetic; confirm the server repeats them. Look for `v-html` "
           "with user data and secrets in `VITE_` variables.",
    "Angular": "Angular (browser code): checks in the UI are cosmetic; confirm the server repeats them. Look for "
               "`bypassSecurityTrust*` calls.",
    "Electron": "Electron: windows need `contextIsolation: true` and `nodeIntegration: false`, and IPC handlers "
                "must validate what the renderer sends.",
    "Spring Boot": "Spring Boot: read the `SecurityFilterChain`: what does `permitAll()` cover, and is CSRF "
                   "disabled for cookie sessions? Methods that touch user data need `@PreAuthorize` or an owner "
                   "check in the query.",
    "Rails": "Rails: controllers need `before_action :authenticate_user!` (watch for `skip_before_action`), "
             "lookups should go through the user (`current_user.posts.find(params[:id])`), and `permit` lists "
             "must not include `role` or `admin`.",
    "Laravel": "Laravel: routes need the `auth` middleware, and models need policies or `$this->authorize()`. "
               "Check `$fillable` and `$guarded` for mass assignment.",
    "Gin": "Gin: check auth middleware is attached to every protected router group.",
    "Echo": "Echo: check auth middleware is attached to every protected group.",
    "Fiber": "Fiber: check auth middleware is attached to every protected group.",
}
AI_DEPS = ("openai", "anthropic", "@anthropic-ai/sdk", "groq", "groq-sdk", "google-generativeai", "google-genai",
           "@google/generative-ai", "@google/genai", "cohere", "mistralai", "langchain", "langchain-openai",
           "@langchain/core", "litellm", "ollama", "together")
AI_NOTE = ("AI features: text from users or uploaded files that reaches the model is untrusted. Check that it "
           "cannot make the model call tools, read other users' data or reveal the system prompt or keys, that "
           "model output is escaped before it is rendered as HTML, and that AI endpoints have per-user rate limits "
           "and quotas.")


def section(result, data_block, one_line) -> list:
    """Markdown lines for the audit section. data_block and one_line are prompt.py's fencing and cleaning helpers."""
    surf = getattr(result, "surface", None) or {}
    stack = getattr(result, "stack", None) or {}
    routes, areas = surf.get("routes", []), surf.get("areas", {})
    frameworks = [f for f in FRAMEWORK_NOTES if f in (stack.get("frameworks") or [])]
    deps = set(stack.get("node_deps") or []) | set(stack.get("python_deps") or [])
    L = []
    w = L.append
    w("## Security audit\n")
    w("The scanner finds code patterns. It cannot see flaws that depend on what the code is for: missing access "
      "checks, IDOR, CSRF, abuse of expensive endpoints, broken business rules. After the tasks above, audit the "
      "application for these yourself.\n")
    w("Rules for the audit:\n")
    w("- Report only issues you can show in the code: the file and line, the request an attacker sends, and what "
      "they get. No general advice and no \"consider adding\" items.")
    w("- Give each issue an ID (A1, A2, ...) and a severity on the same scale as the tasks.")
    w("- Fix an issue when the fix is local and clear: add the missing check, filter the query by the current user, "
      "add the limit. Add a test that sends the attack request and expects it to be refused. If a fix needs a "
      "design decision, mark it needs human and say why.")
    w("- The ground rules above apply to audit fixes too.\n")

    if routes:
        more = surf.get("more_routes", 0)
        w(f"agentharden found {len(routes) + more} route(s). Routes with no auth marker in their definition and "
          "routes that take an id from the URL are listed first. The `auth` column is a pattern match, so confirm "
          "it in the code. Prefixes added where a router is mounted are not shown.\n")
        rows = []
        for r in routes:
            auth = one_line(r.get("auth") or "none seen", 80)
            flag = "  url-id" if r.get("url_id") else ""
            rows.append(f"{one_line(r.get('method'), 20):<7} {one_line(r.get('path'), 160)}  "
                        f"{one_line(r.get('file'), 200)}:{int(r.get('line') or 0)}  auth: {auth}{flag}")
        if more:
            rows.append(f"...and {more} more")
        w(data_block("routes", "\n".join(rows)))
        w("")
    else:
        w("agentharden found no route definitions it recognises. List the application's entry points yourself "
          "(HTTP routes, RPC handlers, queue consumers, CLI commands) before you start.\n")
    if areas:
        w("Places that need a closer look, by area:\n")
        w(data_block("areas", "\n".join(f"{one_line(a, 60)}: {', '.join(one_line(x, 200) for x in hits)}"
                                        for a, hits in areas.items())))
        w("")

    w("Check each of these:\n")
    for n, (name, cwes, text) in enumerate(CORE, 1):
        w(f"{n}. **{name}** ({cwes}). {text}")
    w("")
    notes = [FRAMEWORK_NOTES[f] for f in frameworks]
    if deps & set(AI_DEPS) or "AI or LLM API call" in areas:
        notes.append(AI_NOTE)
    if notes:
        w("For this stack:\n")
        for note in notes:
            w(f"- {note}")
        w("")
    return L
