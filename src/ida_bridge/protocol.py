import os
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    model_validator,
)
from pydantic_core import PydanticCustomError

# NOTE: This is a strict protocol sketch (lean) intended for local comms.
#
# Design goals:
# - strict validation (extra="forbid")
# - "src" and "dst" are always present on requests/responses (client_id strings)
# - single discriminator: "type" (no req/resp envelope)
# - bridge is authoritative: only the bridge emits MSG_ERROR/ProtocolError; clients
#   should close the websocket (1002/1008) on protocol violations.

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_URL = f"ws://{DEFAULT_HOST}:{DEFAULT_PORT}"
PROTO_VERSION = 5

# WebSocket close codes
WS_CLOSE_PROTOCOL_ERROR = 1002
WS_CLOSE_POLICY_VIOLATION = 1008

# Roles
ROLE_AGENT = "agent"
ROLE_IDA = "ida"
ROLE_BRIDGE = "bridge"  # Used for dst routing; not a valid client role.

type ClientRole = Literal[ROLE_AGENT, ROLE_IDA]

# Message types
MSG_ERROR = "error"  # fatal, protocol-level
MSG_HELLO = "hello"
MSG_HELLO_ACK = "hello_ack"

MSG_LIST = "list"
MSG_LIST_RESPONSE = "list_response"

MSG_EXEC = "exec"
MSG_EXEC_RESPONSE = "exec_response"

MSG_RESET = "reset"
MSG_RESET_RESPONSE = "reset_response"
MSG_QUIT = "quit"
MSG_QUIT_RESPONSE = "quit_response"
MSG_START_IDALIB = "start_idalib"
MSG_START_IDALIB_RESPONSE = "start_idalib_response"
MSG_STOP_IDALIB = "stop_idalib"
MSG_STOP_IDALIB_RESPONSE = "stop_idalib_response"

MessageType = Literal[
    MSG_ERROR,
    MSG_HELLO,
    MSG_HELLO_ACK,
    MSG_LIST,
    MSG_LIST_RESPONSE,
    MSG_EXEC,
    MSG_EXEC_RESPONSE,
    MSG_RESET,
    MSG_RESET_RESPONSE,
    MSG_QUIT,
    MSG_QUIT_RESPONSE,
    MSG_START_IDALIB,
    MSG_START_IDALIB_RESPONSE,
    MSG_STOP_IDALIB,
    MSG_STOP_IDALIB_RESPONSE,
]

# List filters
LIST_KIND_IDA = "ida"
LIST_KIND_ALL = "all"

type ListKind = Literal[LIST_KIND_IDA, LIST_KIND_ALL]

# Protocol error codes (fatal, connection-level)
ERR_INVALID_JSON = "INVALID_JSON"
ERR_HANDSHAKE_REQUIRED = "HANDSHAKE_REQUIRED"
ERR_DUPLICATE_HELLO = "DUPLICATE_HELLO"
ERR_INVALID_ROLE = "INVALID_ROLE"
ERR_INVALID_CLIENT_ID = "INVALID_CLIENT_ID"
ERR_DUPLICATE_CLIENT_ID = "DUPLICATE_CLIENT_ID"
ERR_UNSUPPORTED_MESSAGE = "UNSUPPORTED_MESSAGE"
ERR_INVALID_STATE = "INVALID_STATE"
ERR_INVALID_MESSAGE = "INVALID_MESSAGE"
ERR_INVALID_REQUEST_ID = "INVALID_REQUEST_ID"

# More specific connection-level codes (still fatal).
ERR_UNSUPPORTED_FRAME = "UNSUPPORTED_FRAME"
ERR_MISSING_VERSION = "MISSING_VERSION"
ERR_UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
ERR_SRC_MISMATCH = "SRC_MISMATCH"
ERR_DUPLICATE_REQUEST_ID = "DUPLICATE_REQUEST_ID"
ERR_RESPONSE_MISMATCH = "RESPONSE_MISMATCH"

# Request-level error codes (typically non-fatal, response-level)
ERR_TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
ERR_TARGET_DISCONNECTED = "TARGET_DISCONNECTED"
ERR_TARGET_PING_TIMEOUT = "TARGET_PING_TIMEOUT"
ERR_TIMEOUT = "TIMEOUT"
ERR_QUEUE_FULL = "QUEUE_FULL"
ERR_INVALID_TARGET_ROLE = "INVALID_TARGET_ROLE"
ERR_SESSION_CONFLICT = "SESSION_CONFLICT"
ERR_TAKEOVER_PENDING = "TAKEOVER_PENDING"
ERR_RELEASE_PENDING = "RELEASE_PENDING"
ERR_SESSION_LOCKED = "SESSION_LOCKED"
ERR_START_FAILED = "START_FAILED"
ERR_STOP_FAILED = "STOP_FAILED"


class BaseMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    # Defaulted for ergonomic programmatic construction, but required on the wire.
    v: int = PROTO_VERSION
    type: MessageType

    @model_validator(mode="before")
    @classmethod
    def _wire_require_version(cls, data: Any, info: ValidationInfo) -> Any:
        """Enforce that `v` is present and correct on wire parsing.

        We want clients to always send `v`, but we also want server/client code to be able
        to construct messages without repeating `v=PROTO_VERSION` everywhere.

        This validator only enforces presence when validation is run with
        `context={"wire": True}`.
        """

        if info.context and info.context.get("wire") is True:
            if not isinstance(data, dict):
                raise PydanticCustomError("invalid_message", "invalid message")

            if "v" not in data:
                raise PydanticCustomError("missing_version", "missing protocol version")

            if data.get("v") != PROTO_VERSION:
                raise PydanticCustomError(
                    "unsupported_version",
                    "unsupported protocol version",
                    {"expected": PROTO_VERSION, "got": data.get("v")},
                )

        return data


NonBlankStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

ClientId = NonBlankStr


def _validate_request_id(v: Any) -> str:
    if not isinstance(v, str):
        raise PydanticCustomError("invalid_request_id", "invalid request id")

    try:
        u = UUID(v)
    except Exception as exc:
        raise PydanticCustomError("invalid_request_id", "invalid request id") from exc

    # Strict: require canonical UUID string form and UUIDv4.
    if str(u) != v or u.version != 4:
        raise PydanticCustomError("invalid_request_id", "invalid request id")

    return v


RequestId = Annotated[str, BeforeValidator(_validate_request_id)]


def new_req_id() -> str:
    """Return a canonical UUIDv4 string suitable for `RequestId`."""

    return str(uuid4())


# -----------------
# Handshake
# -----------------


class Hello(BaseMessage):
    type: Literal[MSG_HELLO] = MSG_HELLO

    role: ClientRole
    client_id: ClientId
    meta: dict[str, Any] = Field(default_factory=dict)


class HelloAck(BaseMessage):
    type: Literal[MSG_HELLO_ACK] = MSG_HELLO_ACK

    client_id: ClientId
    bridge_id: ClientId
    meta: dict[str, Any] = Field(default_factory=dict)


class ProtocolError(BaseMessage):
    """Fatal, connection-level protocol error.

    Bridge-only: clients should never emit this message. On protocol violations,
    clients should close the websocket (typically with 1002/1008).

    """

    type: Literal[MSG_ERROR] = MSG_ERROR

    code: NonBlankStr
    message: NonBlankStr
    trace: dict[str, Any] | None = None


class RoutedBase(BaseMessage):
    """Base for all post-handshake routed messages."""

    id: RequestId
    src: ClientId
    dst: ClientId


class RequestBase(RoutedBase):
    # Timeout in seconds (integer) for bridge-routed requests.
    # - null/absent: use bridge default
    # - 0: no timeout
    # - >0: explicit timeout
    timeout_s: int | None = Field(default=None, ge=0)


class ResponseBase(RoutedBase):
    ok: bool

    code: NonBlankStr | None = None
    message: NonBlankStr | None = None
    trace: dict[str, Any] | None = None

    def _enforce_ok(self, field: str, *, require_when_ok: bool) -> None:
        """Enforce a field's presence/absence on both ok branches.

        If require_when_ok=True:
        - ok=true  => field must be present (not None)
        - ok=false => field must be absent (None)

        If require_when_ok=False:
        - ok=true  => field must be absent (None)
        - ok=false => field must be present (not None)
        """

        val = getattr(self, field)
        if self.ok:
            if require_when_ok and val is None:
                raise ValueError(f"{self.type}: {field} is required when ok=true")
            if (not require_when_ok) and val is not None:
                raise ValueError(f"{self.type}: {field} must be absent when ok=true")
        else:
            if require_when_ok and val is not None:
                raise ValueError(f"{self.type}: {field} must be absent when ok=false")
            if (not require_when_ok) and val is None:
                raise ValueError(f"{self.type}: {field} is required when ok=false")

    def _enforce_ok_only(self, field: str, *, require: bool) -> None:
        """Enforce a field's presence/absence only for ok=true responses."""

        if not self.ok:
            return

        val = getattr(self, field)
        if require and val is None:
            raise ValueError(f"{self.type}: {field} is required when ok=true")
        if (not require) and val is not None:
            raise ValueError(f"{self.type}: {field} must be absent when ok=true")

    def _enforce_err_only(self, field: str, *, require: bool) -> None:
        """Enforce a field's presence/absence only for ok=false responses."""

        if self.ok:
            return

        val = getattr(self, field)
        if require and val is None:
            raise ValueError(f"{self.type}: {field} is required when ok=false")
        if (not require) and val is not None:
            raise ValueError(f"{self.type}: {field} must be absent when ok=false")

    @model_validator(mode="after")
    def _validate_ok_error(self):
        # code is forbidden on ok=true and required on ok=false
        self._enforce_ok("code", require_when_ok=False)

        # message/trace are forbidden on ok=true
        self._enforce_ok_only("message", require=False)
        self._enforce_ok_only("trace", require=False)

        return self


# -----------------
# list
# -----------------


class ListRequest(RequestBase):
    type: Literal[MSG_LIST] = MSG_LIST
    kind: ListKind


class ClientInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: ClientId
    role: Literal[ROLE_IDA, ROLE_AGENT]
    meta: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None


class ListResponse(ResponseBase):
    type: Literal[MSG_LIST_RESPONSE] = MSG_LIST_RESPONSE

    kind: ListKind

    clients: list[ClientInfo] | None = None

    @model_validator(mode="after")
    def _validate_clients(self):
        self._enforce_ok("clients", require_when_ok=True)
        return self


# -----------------
# exec
# -----------------


class ExecRequest(RequestBase):
    type: Literal[MSG_EXEC] = MSG_EXEC

    session_id: NonBlankStr | None = None
    persist: bool = False
    reset_env: bool = True
    code: str

    @model_validator(mode="after")
    def _validate_stateful_fields(self):
        if self.persist:
            if self.session_id is None:
                raise ValueError("exec: session_id is required when persist=true")
        elif self.session_id is not None:
            raise ValueError("exec: session_id is only valid when persist=true")

        return self


class ExecResponse(ResponseBase):
    type: Literal[MSG_EXEC_RESPONSE] = MSG_EXEC_RESPONSE

    result: Any = None
    stdout: str | None = None
    stderr: str | None = None

    traceback: str | None = None

    @model_validator(mode="after")
    def _validate_exec_fields(self):
        self._enforce_ok_only("traceback", require=False)
        self._enforce_err_only("result", require=False)
        return self


# -----------------
# reset
# -----------------


class ResetRequest(RequestBase):
    type: Literal[MSG_RESET] = MSG_RESET

    session_id: NonBlankStr
    takeover: bool = False
    release: bool = False

    @model_validator(mode="after")
    def _validate_reset_fields(self):
        if self.takeover and self.release:
            raise ValueError("reset: takeover and release are mutually exclusive")
        return self


class ResetResponse(ResponseBase):
    type: Literal[MSG_RESET_RESPONSE] = MSG_RESET_RESPONSE


# -----------------
# quit
# -----------------


class QuitRequest(RequestBase):
    type: Literal[MSG_QUIT] = MSG_QUIT


class QuitResponse(ResponseBase):
    type: Literal[MSG_QUIT_RESPONSE] = MSG_QUIT_RESPONSE


# -----------------
# remote idalib lifecycle
# -----------------


class StartIdalibRequest(RequestBase):
    type: Literal[MSG_START_IDALIB] = MSG_START_IDALIB

    idb: NonBlankStr | None = None
    input: NonBlankStr | None = None
    out_idb: NonBlankStr | None = None
    force: bool = False
    arch: NonBlankStr | None = None
    dyld_module: NonBlankStr | None = None
    python: NonBlankStr | None = None
    wait_s: float = Field(default=300.0, ge=0)

    @model_validator(mode="after")
    def _validate_start_fields(self):
        if (self.idb is None) == (self.input is None):
            raise ValueError("start_idalib: exactly one of --idb or --input is required")

        if self.idb is not None:
            if self.out_idb is not None or self.force or self.arch is not None or self.dyld_module is not None:
                raise ValueError("start_idalib: input options are only valid with --input")
            return self

        if self.out_idb is None:
            raise ValueError("start_idalib: --out-idb is required with --input")
        if self.arch is not None and self.dyld_module is not None:
            raise ValueError("start_idalib: --arch and --dyld-module are mutually exclusive")
        return self


class StartIdalibResponse(ResponseBase):
    type: Literal[MSG_START_IDALIB_RESPONSE] = MSG_START_IDALIB_RESPONSE

    status: Literal["connected", "waiting"] | None = None
    client_id: ClientId | None = None
    pid: int | None = Field(default=None, gt=0)
    idb_path: NonBlankStr | None = None
    log: NonBlankStr | None = None

    @model_validator(mode="after")
    def _validate_start_result(self):
        for field in ("status", "pid", "idb_path", "log"):
            self._enforce_ok(field, require_when_ok=True)

        if not self.ok:
            self._enforce_err_only("client_id", require=False)
        elif self.status == "connected":
            self._enforce_ok_only("client_id", require=True)
        else:
            self._enforce_ok_only("client_id", require=False)
        return self


class StopIdalibRequest(RequestBase):
    type: Literal[MSG_STOP_IDALIB] = MSG_STOP_IDALIB

    target: NonBlankStr


class StopIdalibResponse(ResponseBase):
    type: Literal[MSG_STOP_IDALIB_RESPONSE] = MSG_STOP_IDALIB_RESPONSE

    method: Literal["quit", "already_dead", "sigterm", "sigkill"] | None = None
    client_id: ClientId | None = None
    pid: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _validate_stop_result(self):
        self._enforce_ok("method", require_when_ok=True)
        self._enforce_ok("pid", require_when_ok=True)
        self._enforce_err_only("client_id", require=False)
        return self


Message = Annotated[
    Hello
    | HelloAck
    | ListRequest
    | ListResponse
    | ExecRequest
    | ExecResponse
    | ResetRequest
    | ResetResponse
    | QuitRequest
    | QuitResponse
    | StartIdalibRequest
    | StartIdalibResponse
    | StopIdalibRequest
    | StopIdalibResponse
    | ProtocolError,
    Field(discriminator="type"),
]

_message_adapter = TypeAdapter(Message)


def parse_message_json(raw: str) -> Message:
    """Parse and validate a JSON-encoded message.

    Raises pydantic.ValidationError for both JSON parse errors and schema errors.
    Callers can inspect `exc.errors()` entries (notably their `type` fields).
    """

    return _message_adapter.validate_json(raw, context={"wire": True})


def dump_message_json(msg: Message) -> str:
    return msg.model_dump_json(exclude_none=True, ensure_ascii=True)


DEFAULT_WS_MAX_SIZE = 64 * 1024 * 1024  # 64 MiB


def ws_max_size() -> int:
    """Max inbound websocket message size.

    Note: This is a per-message (per frame reassembly) limit enforced by the websocket
    implementation, not a cumulative session limit.
    """

    raw = os.getenv("IDA_BRIDGE_WS_MAX_SIZE", str(DEFAULT_WS_MAX_SIZE))
    size = int(raw)
    if size <= 0:
        raise ValueError("IDA_BRIDGE_WS_MAX_SIZE must be > 0")
    return size


def bridge_host() -> str:
    return os.getenv("IDA_BRIDGE_HOST", DEFAULT_HOST)


def bridge_port() -> int:
    raw = os.getenv("IDA_BRIDGE_PORT", str(DEFAULT_PORT))
    port = int(raw)
    if port <= 0:
        raise ValueError("IDA_BRIDGE_PORT must be > 0")
    return port


def bridge_url() -> str:
    return f"ws://{bridge_host()}:{bridge_port()}"


# ---------------------------------------------------------------------------
# Validation-error classification
# ---------------------------------------------------------------------------


def classify_validation_error(exc: ValidationError) -> tuple[str, str, dict[str, Any]]:
    """Map pydantic validation errors to stable protocol error codes."""

    errors = exc.errors()

    # JSON parse errors are reported by pydantic with type="json_invalid".
    if any(e.get("type") == "json_invalid" for e in errors):
        return ERR_INVALID_JSON, "invalid json", {"errors": errors}

    # Typed custom errors from protocol models.
    if any(e.get("type") == "missing_version" for e in errors):
        return ERR_MISSING_VERSION, "missing protocol version", {"errors": errors}

    if any(e.get("type") == "unsupported_version" for e in errors):
        return ERR_UNSUPPORTED_VERSION, "unsupported protocol version", {"errors": errors}

    if any(e.get("type") == "invalid_request_id" for e in errors):
        return ERR_INVALID_REQUEST_ID, "invalid request id", {"errors": errors}

    # Discriminator errors (unknown type).
    if any(e.get("type") == "union_tag_invalid" for e in errors):
        return ERR_UNSUPPORTED_MESSAGE, "unsupported message type", {"errors": errors}

    # Handshake-level specifics.
    def _loc_endswith(err: dict[str, Any], field: str) -> bool:
        loc = err.get("loc", ())
        if isinstance(loc, list):
            loc = tuple(loc)
        return bool(loc) and loc[-1] == field

    if any(e.get("type") == "literal_error" and _loc_endswith(e, "role") for e in errors):
        return ERR_INVALID_ROLE, "invalid role", {"errors": errors}

    if any(e.get("type") == "missing" and _loc_endswith(e, "client_id") for e in errors):
        return ERR_INVALID_CLIENT_ID, "client_id is required", {"errors": errors}

    if any(e.get("type") == "string_too_short" and _loc_endswith(e, "client_id") for e in errors):
        return ERR_INVALID_CLIENT_ID, "client_id must be non-empty", {"errors": errors}

    # Fallback.
    return ERR_INVALID_MESSAGE, "invalid message", {"errors": errors}
