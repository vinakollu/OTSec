"""The site controller's REST API — the modern way into an OT network.

Every current site controller ships an HTTP API for dispatch, configuration and
diagnostics, and it is usually the *newest* attack surface on a site that is
otherwise running twenty-year-old protocols. It is also the one an attacker is
most likely to reach, because it is the interface that has been deliberately
exposed to schedulers, market systems and vendor support.

The interesting property is that REST is *better* authenticated than Modbus or
DNP3 — there is a bearer token, there is TLS, there are roles — and that this
does not help as much as it looks. Three reasons, each of which shows up as an
attack in the evaluation:

*Valid credentials are stolen credentials.* A token lifted from a jump server or
a CI pipeline produces requests that are authentic by every check the API makes.
Authentication answers "who sent this", never "is this a sane thing to do".

*Configuration endpoints bypass the dispatch limits.* ``PUT /site/setpoint`` is
usually validated against the export limit. ``PUT /site/limits`` is what *sets*
the export limit, and is often validated against nothing but its own type. An
attacker does not need to exceed the limit if they can raise it.

*The API is a different path to the same actuator.* Rules enforced in the
dispatch loop are not automatically enforced on the REST handler, so the two
paths disagree about what is allowed.

The guard's answer to all three is to treat a REST write exactly like a register
write: same rules, same physics, same provenance check. A limit is checkable
against the transformer nameplate, which no token can raise.

This models the API rather than serving it — requests are objects, not sockets.
The authentication and role logic is real enough to express the attacks; it is
not a hardened HTTP stack and should not be read as one.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from enum import Enum


class Method(str, Enum):
    GET = "GET"
    PUT = "PUT"
    POST = "POST"


class Role(str, Enum):
    """API roles, coarsest-first."""

    VIEWER = "viewer"          # read telemetry
    OPERATOR = "operator"      # dispatch set-points
    ENGINEER = "engineer"      # limits and configuration
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return {"viewer": 0, "operator": 1, "engineer": 2, "admin": 3}[self.value]

    def can(self, required: "Role") -> bool:
        return self.rank >= required.rank


@dataclass(frozen=True)
class Token:
    """A bearer token with a role, an origin zone and an expiry."""

    value: str
    role: Role
    zone: str
    issued_t: float = 0.0
    lifetime_s: float = 3600.0
    subject: str = ""

    def valid_at(self, t: float) -> bool:
        return t - self.issued_t <= self.lifetime_s


@dataclass(frozen=True)
class Request:
    """One API call."""

    t: float
    method: Method
    path: str
    body: dict = field(default_factory=dict)
    token: str = ""
    source_zone: str = "supervisory"
    via: str = ""


@dataclass(frozen=True)
class Response:
    status: int
    body: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


@dataclass(frozen=True)
class Endpoint:
    """What an endpoint needs and what it touches."""

    method: Method
    path: str
    required_role: Role
    # Whether this endpoint changes a *limit* rather than a set-point. The
    # distinction is the whole point of this module: the two are equally
    # authenticated and are not equally dangerous.
    is_limit_change: bool = False


ENDPOINTS: tuple[Endpoint, ...] = (
    Endpoint(Method.GET, "/api/v1/site/telemetry", Role.VIEWER),
    Endpoint(Method.GET, "/api/v1/site/limits", Role.VIEWER),
    Endpoint(Method.PUT, "/api/v1/site/setpoint", Role.OPERATOR),
    Endpoint(Method.PUT, "/api/v1/megapacks/setpoint", Role.OPERATOR),
    Endpoint(Method.PUT, "/api/v1/site/limits", Role.ENGINEER, is_limit_change=True),
    Endpoint(Method.PUT, "/api/v1/site/ramp", Role.ENGINEER, is_limit_change=True),
    Endpoint(Method.POST, "/api/v1/breaker/close", Role.ENGINEER),
    Endpoint(Method.POST, "/api/v1/megapacks/cooling", Role.ENGINEER),
)


def issue_token(secret: bytes, subject: str, role: Role, zone: str, t: float = 0.0) -> Token:
    """Mint a token. The digest is decorative — the role and zone are the payload."""
    material = f"{subject}:{role.value}:{zone}:{t}".encode()
    digest = hmac.new(secret, material, hashlib.sha256).hexdigest()[:32]
    return Token(value=digest, role=role, zone=zone, issued_t=t, subject=subject)


@dataclass
class ApiCall:
    """A decoded, authenticated request ready for the guard to judge."""

    request: Request
    endpoint: Endpoint | None
    token: Token | None
    authenticated: bool
    authorised: bool
    reason: str = ""


class SiteControllerApi:
    """The site controller's HTTP surface.

    Deliberately permissive in one specific way: once a request authenticates
    and carries a sufficient role, this API applies it. It does *not*
    second-guess whether raising the export limit to 40 MW is sensible. That is
    the realistic behaviour — and it is why the guard has to see these calls
    rather than trusting the controller to police itself.
    """

    def __init__(self, secret: bytes = b"site-controller-dev-secret") -> None:
        self.secret = secret
        self.tokens: dict[str, Token] = {}
        self.log: list[ApiCall] = []
        # Mutable site configuration reachable through the API.
        self.state: dict[str, float] = {
            "poi_limit_mw": 20.0,
            "ramp_limit_mw_s": 2.0,
            "site_setpoint_mw": 0.0,
        }

    def register(self, token: Token) -> Token:
        self.tokens[token.value] = token
        return token

    def endpoint_for(self, method: Method, path: str) -> Endpoint | None:
        for ep in ENDPOINTS:
            if ep.method is method and ep.path == path:
                return ep
        return None

    def decode(self, request: Request) -> ApiCall:
        """Authenticate and authorise, without applying anything."""
        endpoint = self.endpoint_for(request.method, request.path)
        token = self.tokens.get(request.token)

        if endpoint is None:
            return ApiCall(request, None, token, False, False, "no such endpoint")
        if token is None:
            return ApiCall(request, endpoint, None, False, False, "unknown bearer token")
        if not token.valid_at(request.t):
            return ApiCall(request, endpoint, token, False, False, "token expired")
        if not token.role.can(endpoint.required_role):
            return ApiCall(
                request,
                endpoint,
                token,
                True,
                False,
                f"role {token.role.value} below required {endpoint.required_role.value}",
            )
        return ApiCall(request, endpoint, token, True, True)

    def apply(self, call: ApiCall) -> Response:
        """Apply an authorised call. No plausibility checking — see class docs."""
        self.log.append(call)
        if not call.authenticated:
            return Response(401, {"error": call.reason})
        if not call.authorised:
            return Response(403, {"error": call.reason})

        request, endpoint = call.request, call.endpoint
        assert endpoint is not None
        if endpoint.method is Method.GET:
            return Response(200, dict(self.state))

        for key, value in request.body.items():
            if key in self.state and isinstance(value, (int, float)):
                self.state[key] = float(value)
        return Response(200, {"applied": request.body})

    def handle(self, request: Request) -> Response:
        return self.apply(self.decode(request))
