"""Declarative predicate-complete suite recipes for the Level-5 dataset.

Predicate identifiers come from the dependency-aware rule model, so a recipe can
be checked against the rule it claims to cover.  Coverage is never fabricated: a
predicate is either exercised by an isolated negative case or declared
unsupported with an explicit reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from hardening_game.suricata.rule_model import ParsedRule, parse_suricata_rule


_OPTION_PREDICATE_KINDS: dict[str, str] = {
    "pcre": "pcre",
    "byte_test": "byte_test",
    "byte_jump": "byte_jump",
    "isdataat": "isdataat",
    "bsize": "length",
    "dsize": "length",
    "urilen": "length",
    "flowbits": "state",
    "threshold": "throttle",
    "base64_decode": "transform",
}
_MODIFIER_KINDS: dict[str, str] = {
    "startswith": "boundary",
    "endswith": "boundary",
    "offset": "position",
    "depth": "position",
    "distance": "position",
    "within": "position",
    "nocase": "case",
    "fast_pattern": "performance",
    "rawbytes": "representation",
}


@dataclass(frozen=True)
class PredicateRef:
    id: str
    buffer: str
    kind: str
    description: str


@dataclass(frozen=True)
class UnsupportedPredicate:
    id: str
    reason: str


@dataclass(frozen=True)
class SuiteCaseSpec:
    name: str
    expected_alert: bool
    reason: str
    predicate_id: str | None
    mutation: dict[str, object] = field(default_factory=dict)
    segment_sizes: tuple[int, ...] | None = None
    retransmit_segment: int | None = None
    established: bool = True
    split_after: tuple[bytes, ...] | None = None
    uniform_segment_size: int | None = None


@dataclass(frozen=True)
class RuleRecipe:
    sid: int
    suite_type: Literal["http", "raw_tcp"]
    port: int
    direction: Literal["to_server", "to_client"]
    canonical: dict[str, object]
    predicates: tuple[PredicateRef, ...]
    cases: tuple[SuiteCaseSpec, ...]
    unsupported: tuple[UnsupportedPredicate, ...] = ()
    reason: str = "predicate-complete synthetic suite derived from the rule model"


def _buffer_map(parsed: ParsedRule) -> dict[int, str]:
    buffers: dict[int, str] = {}
    for group in parsed.sticky_groups:
        for predicate in group.predicates:
            buffers[predicate.option_index] = group.buffer
            for consumer in predicate.relative_consumers:
                buffers[consumer.option_index] = group.buffer
        for option in group.scoped_options:
            buffers[option.option_index] = group.buffer
    return buffers


def _content_description(value: bytes | None, negated: bool) -> str:
    rendered = "unparsed content" if value is None else repr(value)
    return f"{'negated ' if negated else ''}content match on {rendered}"


def predicate_refs(rule: str) -> tuple[PredicateRef, ...]:
    """Derive the stable, testable predicate catalog for one Suricata rule."""
    parsed = parse_suricata_rule(rule)
    refs: list[PredicateRef] = []
    header = parsed.header
    for label, expression in (
        ("src", header.source_address),
        ("dst", header.destination_address),
    ):
        if expression.casefold() != "any":
            refs.append(
                PredicateRef(
                    id=f"header-{label}-address",
                    buffer="header",
                    kind="address",
                    description=f"{label} address must match {expression}",
                )
            )
    for label, expression in (
        ("src", header.source_port),
        ("dst", header.destination_port),
    ):
        if expression.casefold() != "any":
            refs.append(
                PredicateRef(
                    id=f"header-{label}-port",
                    buffer="header",
                    kind="port",
                    description=f"{label} port must match {expression}",
                )
            )
    for token in (parsed.flow or "").split(","):
        token = token.strip()
        if token:
            refs.append(
                PredicateRef(
                    id=f"flow-{token}",
                    buffer="flow",
                    kind="flow",
                    description=f"flow must satisfy {token}",
                )
            )

    contents = {
        predicate.option_index: predicate
        for group in parsed.sticky_groups
        for predicate in group.predicates
    }
    buffers = _buffer_map(parsed)
    counters: dict[str, int] = {}
    for option in parsed.options:
        predicate = contents.get(option.option_index)
        if predicate is not None:
            refs.append(
                PredicateRef(
                    id=predicate.predicate_id,
                    buffer=predicate.buffer,
                    kind="negated_content" if predicate.negated else "content",
                    description=_content_description(
                        predicate.value, predicate.negated
                    ),
                )
            )
            for modifier in predicate.modifiers:
                refs.append(
                    PredicateRef(
                        id=f"{predicate.predicate_id}-{modifier.name}",
                        buffer=predicate.buffer,
                        kind=_MODIFIER_KINDS.get(modifier.name, "modifier"),
                        description=(
                            f"{modifier.name}"
                            + (f":{modifier.value}" if modifier.value else "")
                            + f" constrains {predicate.predicate_id}"
                        ),
                    )
                )
            continue
        kind = _OPTION_PREDICATE_KINDS.get(option.name)
        if kind is None:
            continue
        ordinal = counters.get(option.name, 0)
        counters[option.name] = ordinal + 1
        refs.append(
            PredicateRef(
                id=f"{option.name}-{ordinal}",
                buffer=buffers.get(option.option_index, "rule"),
                kind=kind,
                description=f"{option.name}:{option.value}" if option.value else option.name,
            )
        )
    refs.append(
        PredicateRef(
            id="rule-baseline",
            buffer="rule",
            kind="whole_signature",
            description="the signature as a whole must stay silent on unrelated traffic",
        )
    )
    return tuple(refs)


OUTSIDE_SERVER_IP = "203.0.113.5"
INSIDE_CLIENT_IP = "10.0.0.9"

_FAST_PATTERN_REASON = (
    "fast_pattern only selects the multi-pattern anchor; no traffic can violate it "
    "without violating the content it annotates"
)
_NOCASE_REASON = (
    "nocase relaxes matching, so no traffic can violate it; a signature-positive case with "
    "alternate casing demonstrates it instead"
)
_FLOWBITS_REASON = (
    "flowbits:set only records state for other signatures and has no detection "
    "effect on this rule"
)
_THRESHOLD_REASON = (
    "threshold throttles alert output rather than deciding whether the signature "
    "matches, so a single-flow case cannot isolate it"
)


def _positive(name: str, reason: str, **kwargs: object) -> SuiteCaseSpec:
    return SuiteCaseSpec(
        name=name, expected_alert=True, reason=reason, predicate_id=None, **kwargs
    )


def _negative(
    name: str, predicate_id: str, reason: str, **kwargs: object
) -> SuiteCaseSpec:
    return SuiteCaseSpec(
        name=name,
        expected_alert=False,
        reason=reason,
        predicate_id=predicate_id,
        **kwargs,
    )


def _stream_positives(
    *,
    split_after: tuple[bytes, ...],
    uniform_segment_size: int = 8,
    retransmit_segment_size: int = 16,
) -> tuple[SuiteCaseSpec, ...]:
    """Standard canonical, boundary, segmented signature-positive cases."""
    return (
        _positive(
            "P0-canonical",
            "canonical signature-positive payload in a single TCP segment",
        ),
        _positive(
            "P1-boundary-segments",
            "signature-positive canonical payload split at parser and required-content boundaries",
            split_after=split_after,
        ),
        _positive(
            "P2-many-small-segments",
            "signature-positive canonical payload split into many small TCP segments",
            uniform_segment_size=uniform_segment_size,
        ),
        _positive(
            "P3-retransmission",
            "signature-positive canonical payload with one byte-identical retransmitted data segment",
            uniform_segment_size=retransmit_segment_size,
            retransmit_segment=1,
        ),
    )


def _not_established(predicate_id: str = "flow-established") -> SuiteCaseSpec:
    return _negative(
        "N-flow-not-established",
        predicate_id,
        "canonical payload is sent without a completed TCP handshake",
        established=False,
    )


def _reversed_stream(predicate_id: str, direction: str, *, note: str) -> SuiteCaseSpec:
    flipped = "to_client" if direction == "to_server" else "to_server"
    return _negative(
        "N-wrong-direction",
        predicate_id,
        f"canonical payload is replayed {flipped.replace('_', ' ')}; {note}",
        mutation={"direction": flipped},
    )


def _wrong_destination_address() -> SuiteCaseSpec:
    return _negative(
        "N-wrong-destination-address",
        "header-dst-address",
        "canonical payload is sent to a server outside the monitored network",
        mutation={"server_ip": OUTSIDE_SERVER_IP},
    )


def _internal_source_address() -> SuiteCaseSpec:
    return _negative(
        "N-internal-source-address",
        "header-src-address",
        "canonical payload originates inside the monitored network",
        mutation={"client_ip": INSIDE_CLIENT_IP},
    )


def _external_response_source() -> SuiteCaseSpec:
    return _negative(
        "N-external-response-source",
        "header-src-address",
        "response is served by a host outside the monitored network",
        mutation={"server_ip": OUTSIDE_SERVER_IP},
    )


_RANDOM_REQUEST = (
    "GET /metrics/v2/nodes?window=15m&format=json HTTP/1.1\r\n"
    "Host: target.local\r\n"
    "User-Agent: curl/8.5.0\r\n"
    "Accept: application/json\r\n"
    "\r\n"
).encode()
_RANDOM_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 74\r\n"
    "\r\n"
    "<html><head><title>Node status</title></head><body><p>ok</p></body></html>"
).encode()


def _random_http_request() -> SuiteCaseSpec:
    return _negative(
        "N-random-http-request",
        "rule-baseline",
        "protocol-valid HTTP request that satisfies no combination of rule predicates",
        mutation={"raw_payload": _RANDOM_REQUEST},
    )


def _random_http_response() -> SuiteCaseSpec:
    return _negative(
        "N-random-http-response",
        "rule-baseline",
        "protocol-valid HTTP response that satisfies no combination of rule predicates",
        mutation={"raw_payload": _RANDOM_RESPONSE},
    )


def _rsync_payload(
    *,
    banner: bytes = b"@RSYNCD:",
    server: bytes = b"--server",
    sender: bytes = b"--sender",
    marker: bytes = b"\x00\x00\x07",
    tag: bytes = b"\x0e",
    flag: bytes = b"\x80",
    length: int = 32,
    tag_before_marker: bool = False,
) -> bytes:
    """Assemble one rsync daemon greeting plus argument/checksum-seed layout."""
    head = banner + b" " + server + b" " + sender
    framing = tag + marker if tag_before_marker else marker + tag
    return head + framing + flag + (b"\x00" * 8) + length.to_bytes(4, "little")


def _pgsql_query(query: bytes) -> bytes:
    """Wrap a query in a PostgreSQL simple-query frontend message."""
    body = query + b"\x00"
    return b"Q" + (len(body) + 4).to_bytes(4, "big") + body


_MICROS_URI = (
    "/Operajserv/webarchive/FileReceiver?filename=C:\\MICROS\\x"
    "&jndiname=x&username=x"
)
_CONFLUENCE_META = '<meta name="ajs-version-number" content="{version}">'


def _recipe_2044143() -> RuleRecipe:
    return RuleRecipe(
        sid=2044143,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "POST",
            "target": "/goanywhere/lic/accept?bundle=x",
            "headers": {},
            "body": "",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.method", "content", "method must be POST"),
            PredicateRef("content-1", "http.uri", "content", "licence-accept endpoint literal"),
            PredicateRef("content-1-fast_pattern", "http.uri", "performance", "URI literal is the fast pattern"),
            PredicateRef("content-1-startswith", "http.uri", "boundary", "URI literal must start the buffer"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"POST ", b"bundle=", b"\r\n")),
            _negative("N-wrong-method", "content-0", "GET replaces the required POST method", mutation={"method": "GET"}),
            _negative("N-uri-endpoint-changed", "content-1", "licence endpoint rejects instead of accepts, removing the required URI literal", mutation={"target": "/goanywhere/lic/reject?bundle=x"}),
            _negative("N-uri-not-at-start", "content-1-startswith", "required URI literal is present but preceded by a proxy prefix", mutation={"target": "/proxy/goanywhere/lic/accept?bundle=x"}),
            _negative("N-uri-literal-in-header", "content-1", "URI literal appears in a request header instead of http.uri", mutation={"target": "/", "headers": {"X-Requested-Path": "/goanywhere/lic/accept?bundle=x"}}),
            _negative("N-uri-parameter-changed", "content-1", "URI keeps the licence-accept endpoint but carries a different parameter than the required bundle", mutation={"target": "/goanywhere/lic/accept?token=x"}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="request buffers stay empty in the response direction"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2044585() -> RuleRecipe:
    return RuleRecipe(
        sid=2044585,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "POST",
            "target": "/cgi-bin;stok=/locale?form=country",
            "headers": {},
            "body": "operation=write&country=$(x)",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("content-0", "http.method", "content", "method must be POST"),
            PredicateRef("content-1", "http.uri", "content", "CGI prefix literal"),
            PredicateRef("content-1-startswith", "http.uri", "boundary", "CGI prefix must start the URI"),
            PredicateRef("content-2", "http.uri", "content", "locale form parameter literal"),
            PredicateRef("content-2-fast_pattern", "http.uri", "performance", "locale literal is the fast pattern"),
            PredicateRef("content-3", "http.request_body", "content", "write operation literal"),
            PredicateRef("content-4", "http.request_body", "content", "command-substitution country value"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"POST ", b";stok=", b"\r\n\r\n")),
            _negative("N-wrong-method", "content-0", "GET replaces the required POST method", mutation={"method": "GET"}),
            _negative("N-uri-not-at-start", "content-1-startswith", "CGI prefix is present but preceded by a proxy path", mutation={"target": "/proxy/cgi-bin;stok=/locale?form=country"}),
            _negative("N-uri-cgi-prefix-changed", "content-1", "URI no longer contains the required CGI prefix", mutation={"target": "/cgi-bi;stok=/locale?form=country"}),
            _negative("N-uri-locale-parameter-absent", "content-2", "URI drops the stok/locale form parameter literal", mutation={"target": "/cgi-bin/locale?form=country"}),
            _negative("N-uri-locale-form-changed", "content-2", "URI keeps the stok locale form but selects a different form than country", mutation={"target": "/cgi-bin;stok=/locale?form=timezone"}),
            _negative("N-body-operation-read", "content-3", "body requests a read instead of the required write operation", mutation={"body": "operation=read&country=$(x)"}),
            _negative("N-body-country-not-command", "content-4", "country value is percent-encoded, removing the literal command substitution", mutation={"body": "operation=write&country=%24(x)"}),
            _negative("N-wrong-direction", "header-dst-address", "canonical request bytes replayed to client, so the destination is external and request buffers stay empty", mutation={"direction": "to_client"}),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(UnsupportedPredicate("content-2-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2050434() -> RuleRecipe:
    return RuleRecipe(
        sid=2050434,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "GET",
            "target": "/goanywhere/%2e%3b/R/wizard/InitialAccountSetup.xhtml",
            "headers": {},
            "body": "",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.request_line", "content", "GET request line prefix"),
            PredicateRef("content-0-startswith", "http.request_line", "boundary", "prefix must start the request line"),
            PredicateRef("pcre-0", "http.request_line", "pcre", "encoded dot-semicolon traversal within ten bytes"),
            PredicateRef("content-1", "http.request_line", "content", "account setup page literal"),
            PredicateRef("content-1-within", "http.request_line", "position", "setup page must follow the traversal within 60 bytes"),
            PredicateRef("content-1-fast_pattern", "http.request_line", "performance", "setup page literal is the fast pattern"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"GET /goanywhere/", b"/wizard/", b"\r\n")),
            _negative("N-wrong-method", "content-0", "POST replaces the GET request-line prefix", mutation={"method": "POST"}),
            _negative("N-pcre-no-encoded-traversal", "pcre-0", "traversal characters are replaced so the relative PCRE cannot match", mutation={"target": "/goanywhere/xx%3b/R/wizard/InitialAccountSetup.xhtml"}),
            _negative("N-pcre-beyond-offset-bound", "pcre-0", "encoded traversal starts past the PCRE's ten-byte bound", mutation={"target": "/goanywhere/aaaaaaaaaaa%2e%3b/R/wizard/InitialAccountSetup.xhtml"}),
            _negative("N-setup-page-absent", "content-1", "request targets another wizard page, dropping the required literal", mutation={"target": "/goanywhere/%2e%3b/R/wizard/Other.xhtml"}),
            _negative("N-setup-page-beyond-within", "content-1-within", "setup page literal appears more than 60 bytes after the traversal", mutation={"target": "/goanywhere/%2e%3b/" + "a" * 70 + "/wizard/InitialAccountSetup.xhtml"}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="http.request_line is only populated for requests"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(
            UnsupportedPredicate("content-0-startswith", "http.request_line always begins with the method and target, so the required prefix can only ever appear at the buffer start"),
            UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),
        ),
    )


def _recipe_2055723() -> RuleRecipe:
    return RuleRecipe(
        sid=2055723,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "POST",
            "target": "/hedwig.cgi",
            "headers": {},
            "body": "/htdocs/webinc/getcfg.xml",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.method", "content", "method must be POST"),
            PredicateRef("bsize-0", "http.uri", "length", "URI must be exactly 11 bytes"),
            PredicateRef("content-1", "http.uri", "content", "hedwig CGI endpoint literal"),
            PredicateRef("content-1-fast_pattern", "http.uri", "performance", "endpoint literal is the fast pattern"),
            PredicateRef("content-2", "http.request_body", "content", "getcfg configuration path"),
            PredicateRef("content-3", "http.request_body", "content", "xml extension literal"),
            PredicateRef("content-3-within", "http.request_body", "position", "extension must follow the path within 50 bytes"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"POST ", b"\r\n\r\n", b"getcfg")),
            _negative("N-wrong-method", "content-0", "GET replaces the required POST method", mutation={"method": "GET"}),
            _negative("N-uri-length-exceeds-bsize", "bsize-0", "URI keeps the endpoint literal but is 13 bytes instead of the required 11", mutation={"target": "/hedwig.cgi?x"}),
            _negative("N-uri-endpoint-changed", "content-1", "URI keeps the required 11-byte length but not the endpoint literal", mutation={"target": "/hedwig.cg1"}),
            _negative("N-body-config-path-changed", "content-2", "body drops the getcfg configuration path", mutation={"body": "/htdocs/webinc/getcf.xml"}),
            _negative("N-body-config-directory-changed", "content-2", "body keeps the getcfg leaf and the xml extension but reaches them through a different directory than the htdocs webinc path", mutation={"body": "/var/tmp/getcfg.xml"}),
            _negative("N-body-extension-changed", "content-3", "body requests a text file instead of the required xml extension", mutation={"body": "/htdocs/webinc/getcfg.txt"}),
            _negative("N-body-extension-beyond-within", "content-3-within", "xml extension appears more than 50 bytes after the configuration path", mutation={"body": "/htdocs/webinc/getcfg" + "A" * 51 + ".xml"}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="request buffers stay empty in the response direction"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2057330() -> RuleRecipe:
    return RuleRecipe(
        sid=2057330,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "GET",
            "target": "/cgi-bin/account_mgr.cgi?cmd=cgi_user_add&name=%3b",
            "headers": {},
            "body": "",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.method", "content", "method must be GET"),
            PredicateRef("content-1", "http.uri", "content", "account manager CGI literal"),
            PredicateRef("content-1-fast_pattern", "http.uri", "performance", "CGI literal is the fast pattern"),
            PredicateRef("content-2", "http.uri", "content", "cgi_user_add command literal"),
            PredicateRef("content-3", "http.uri", "content", "name parameter literal"),
            PredicateRef("pcre-0", "http.uri", "pcre", "shell metacharacter in the name parameter"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"GET ", b"account_mgr.cgi?", b"\r\n")),
            _negative("N-wrong-method", "content-0", "POST replaces the required GET method", mutation={"method": "POST"}),
            _negative("N-cgi-endpoint-changed", "content-1", "URI targets a different CGI endpoint", mutation={"target": "/cgi-bin/account_mgr2.cgi?cmd=cgi_user_add&name=%3b"}),
            _negative("N-command-changed", "content-2", "URI deletes a user instead of the required add command", mutation={"target": "/cgi-bin/account_mgr.cgi?cmd=cgi_user_del&name=%3b"}),
            _negative("N-name-parameter-absent", "content-3", "URI carries the command but not the name parameter literal", mutation={"target": "/cgi-bin/account_mgr.cgi?cmd=cgi_user_add&user=%3b"}),
            _negative("N-pcre-no-shell-metacharacter", "pcre-0", "name parameter holds a plain value with no injectable metacharacter", mutation={"target": "/cgi-bin/account_mgr.cgi?cmd=cgi_user_add&name=safeuser"}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="http.uri is only populated for requests"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2057705() -> RuleRecipe:
    return RuleRecipe(
        sid=2057705,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "GET",
            "target": "/",
            "headers": {"X-PAN-AUTHCHECK": "off"},
            "body": "",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.header", "content", "authentication-check bypass header"),
            PredicateRef("content-0-fast_pattern", "http.header", "performance", "header literal is the fast pattern"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"GET / HTTP/1.1\r\n", b"X-PAN-AUTHCHECK: ")),
            _negative("N-authcheck-enabled", "content-0", "bypass header requests authentication instead of disabling it", mutation={"headers": {"X-PAN-AUTHCHECK": "on"}}),
            _negative("N-authcheck-literal-in-body", "content-0", "bypass literal appears in the request body instead of a header", mutation={"method": "POST", "headers": {"X-PAN-AUTHCHECK": None}, "body": "X-PAN-AUTHCHECK: off"}),
            _negative("N-other-header-value-off", "content-0", "an unrelated header is set to off, so the header buffer ends a value the same way without carrying the vendor header name", mutation={"headers": {"X-PAN-AUTHCHECK": None, "X-Debug-Mode": "off"}}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="request headers stay empty in the response direction"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(UnsupportedPredicate("content-0-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2059741() -> RuleRecipe:
    return RuleRecipe(
        sid=2059741,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "POST",
            "target": "/options.php",
            "headers": {},
            "body": "csrf_token=x&section=general&this_install_title=x",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.method", "content", "method must be POST"),
            PredicateRef("bsize-0", "http.uri", "length", "URI must be exactly 12 bytes"),
            PredicateRef("content-1", "http.uri", "content", "options endpoint literal"),
            PredicateRef("content-2", "http.request_body", "content", "CSRF token parameter"),
            PredicateRef("content-3", "http.request_body", "content", "general settings section"),
            PredicateRef("content-4", "http.request_body", "content", "install title option name"),
            PredicateRef("content-4-fast_pattern", "http.request_body", "performance", "install title literal is the fast pattern"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"POST ", b"\r\n\r\n", b"section=")),
            _negative("N-wrong-method", "content-0", "GET replaces the required POST method", mutation={"method": "GET"}),
            _negative("N-uri-length-exceeds-bsize", "bsize-0", "URI keeps the endpoint literal but is 14 bytes instead of the required 12", mutation={"target": "/options.php?x"}),
            _negative("N-uri-endpoint-changed", "content-1", "URI keeps the required 12-byte length but not the endpoint literal", mutation={"target": "/options.ph1"}),
            _negative("N-body-csrf-token-absent", "content-2", "body drops the CSRF token parameter name", mutation={"body": "xsrf_token=x&section=general&this_install_title=x"}),
            _negative("N-body-section-changed", "content-3", "body posts a different settings section", mutation={"body": "csrf_token=x&section=other&this_install_title=x"}),
            _negative("N-body-option-name-changed", "content-4", "body writes the unprefixed option name", mutation={"body": "csrf_token=x&section=general&install_title=x"}),
            _negative("N-option-name-in-header", "content-4", "install title option name appears in a header instead of the request body", mutation={"body": "csrf_token=x&section=general", "headers": {"X-Option": "this_install_title=x"}}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="request body stays empty in the response direction"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(UnsupportedPredicate("content-4-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2060086() -> RuleRecipe:
    return RuleRecipe(
        sid=2060086,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "GET",
            "target": "/unauth/a%252e%252e/PAN_help/x.css",
            "headers": {},
            "body": "",
        },
        predicates=(
            PredicateRef("header-src-address", "header", "address", "source must be external"),
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.method", "content", "method must be GET"),
            PredicateRef("content-1", "http.uri", "content", "unauthenticated path prefix"),
            PredicateRef("content-1-fast_pattern", "http.uri", "performance", "prefix literal is the fast pattern"),
            PredicateRef("content-1-startswith", "http.uri", "boundary", "prefix must start the URI"),
            PredicateRef("content-2", "http.uri", "content", "help directory literal"),
            PredicateRef("pcre-0", "http.uri", "pcre", "double-encoded traversal into a static help asset"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"GET ", b"/unauth/", b"/PAN_help/")),
            _negative("N-wrong-method", "content-0", "POST replaces the required GET method", mutation={"method": "POST"}),
            _negative("N-pcre-single-encoded-traversal", "pcre-0", "URI carries one double-encoded dot instead of the required pair", mutation={"target": "/unauth/a%252e/PAN_help/x.css"}),
            _negative("N-pcre-non-static-extension", "pcre-0", "URI requests a non-static extension the PCRE does not accept", mutation={"target": "/unauth/a%252e%252e/PAN_help/x.txt"}),
            _negative("N-pcre-help-path-relocated", "pcre-0", "help directory literal is present but before the traversal, so the traversal lands in a different eight-byte directory", mutation={"target": "/unauth/PAN_help/a%252e%252e/OTHERDIR/x.css"}),
            _internal_source_address(),
            _wrong_destination_address(),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="http.uri is only populated for requests"),
            _random_http_request(),
        ),
        unsupported=(
            UnsupportedPredicate("content-1", "pcre-0 independently anchors the same /unauth/ prefix, so no traffic can drop this content while the PCRE still matches"),
            UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),
            UnsupportedPredicate("content-1-startswith", "pcre-0 is anchored at the start of http.uri with the same prefix, so relocating the content cannot be isolated from the PCRE"),
            UnsupportedPredicate("content-2", "pcre-0 independently requires the same /PAN_help/ path element, so this content cannot be violated in isolation"),
        ),
    )


def _recipe_2067354() -> RuleRecipe:
    return RuleRecipe(
        sid=2067354,
        suite_type="raw_tcp",
        port=873,
        direction="to_server",
        canonical={"payload": _rsync_payload()},
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("header-dst-port", "header", "port", "rsync daemon port 873"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "payload", "content", "rsync daemon banner"),
            PredicateRef("content-0-fast_pattern", "payload", "performance", "banner is the fast pattern"),
            PredicateRef("content-1", "payload", "content", "server argument"),
            PredicateRef("content-2", "payload", "content", "sender argument"),
            PredicateRef("content-3", "payload", "content", "message framing marker"),
            PredicateRef("content-4", "payload", "content", "checksum negotiation tag"),
            PredicateRef("content-4-distance", "payload", "position", "tag must follow the framing marker"),
            PredicateRef("byte_test-0", "payload", "byte_test", "high bit set in the flag byte"),
            PredicateRef("byte_test-1", "payload", "byte_test", "seed length above 16"),
            PredicateRef("byte_test-2", "payload", "byte_test", "seed length below 65"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"@RSYNCD:", b"--sender", b"\x00\x00\x07"), uniform_segment_size=6, retransmit_segment_size=12),
            _negative("N-banner-changed", "content-0", "greeting no longer carries the rsync daemon banner", mutation={"payload": _rsync_payload(banner=b"@RSYNCX:")}),
            _negative("N-server-argument-changed", "content-1", "server argument literal is altered", mutation={"payload": _rsync_payload(server=b"--serve1")}),
            _negative("N-sender-argument-changed", "content-2", "sender argument literal is altered", mutation={"payload": _rsync_payload(sender=b"--sende1")}),
            _negative("N-framing-marker-changed", "content-3", "message framing marker bytes are altered", mutation={"payload": _rsync_payload(marker=b"\x00\x01\x07")}),
            _negative("N-negotiation-tag-changed", "content-4", "checksum negotiation tag byte is altered", mutation={"payload": _rsync_payload(tag=b"\x0f")}),
            _negative("N-tag-before-framing-marker", "content-4-distance", "negotiation tag appears before the framing marker it must follow", mutation={"payload": _rsync_payload(tag_before_marker=True)}),
            _negative("N-flag-high-bit-clear", "byte_test-0", "flag byte after the tag has its high bit clear", mutation={"payload": _rsync_payload(flag=b"\x00")}),
            _negative("N-seed-length-at-lower-bound", "byte_test-1", "seed length is exactly 16, which the greater-than test rejects", mutation={"payload": _rsync_payload(length=16)}),
            _negative("N-seed-length-at-upper-bound", "byte_test-2", "seed length is exactly 65, which the less-than test rejects", mutation={"payload": _rsync_payload(length=65)}),
            _negative("N-wrong-port", "header-dst-port", "canonical payload is sent to an adjacent non-rsync port", mutation={"port": 874}),
            _wrong_destination_address(),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="the rule only inspects client-to-server data"),
            _negative("N-random-rsync-handshake", "rule-baseline", "protocol-valid rsync version handshake and module listing with no exploit layout", mutation={"payload": b"@RSYNCD: 31.0\nbackup\tnightly backups\n@RSYNCD: EXIT\n"}),
        ),
        unsupported=(UnsupportedPredicate("content-0-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2045307() -> RuleRecipe:
    return RuleRecipe(
        sid=2045307,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "POST",
            "target": _MICROS_URI,
            "headers": {"Content-Type": "multipart/form-data; boundary=x"},
            "body": "",
        },
        predicates=(
            PredicateRef("header-src-address", "header", "address", "source must be external"),
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("content-0", "http.method", "content", "method must be POST"),
            PredicateRef("content-1", "http.uri", "content", "file receiver endpoint literal"),
            PredicateRef("content-1-fast_pattern", "http.uri", "performance", "endpoint literal is the fast pattern"),
            PredicateRef("content-1-nocase", "http.uri", "case", "endpoint literal matches case-insensitively"),
            PredicateRef("content-1-startswith", "http.uri", "boundary", "endpoint literal must start the URI"),
            PredicateRef("pcre-0", "http.uri", "pcre", "Windows MICROS install path in the filename parameter"),
            PredicateRef("content-2", "http.uri", "content", "jndiname parameter"),
            PredicateRef("content-2-distance", "http.uri", "position", "jndiname must follow the filename path"),
            PredicateRef("content-3", "http.uri", "content", "username parameter"),
            PredicateRef("content-3-distance", "http.uri", "position", "username must follow jndiname"),
            PredicateRef("content-4", "http.content_type", "content", "multipart upload content type"),
            PredicateRef("content-4-startswith", "http.content_type", "boundary", "content type must start the buffer"),
            PredicateRef("content-5", "http.header_names", "negated_content", "no Referer header may be present"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"POST ", b"filename=", b"\r\n")),
            _positive("P4-lowercase-uri", "signature-positive endpoint literal replayed in lower case, which nocase accepts", mutation={"target": "/operajserv/webarchive/filereceiver?filename=C:\\MICROS\\x&jndiname=x&username=x"}),
            _negative("N-wrong-method", "content-0", "GET replaces the required POST method", mutation={"method": "GET"}),
            _negative("N-uri-endpoint-changed", "content-1", "URI targets a different receiver endpoint", mutation={"target": "/Operajserv/webarchive/FileReceiver1?filename=C:\\MICROS\\x&jndiname=x&username=x"}),
            _negative("N-uri-not-at-start", "content-1-startswith", "endpoint literal is present but preceded by a proxy path", mutation={"target": "/proxy/Operajserv/webarchive/FileReceiver?filename=C:\\MICROS\\x&jndiname=x&username=x"}),
            _negative("N-pcre-not-micros-path", "pcre-0", "filename parameter points outside the MICROS install path", mutation={"target": "/Operajserv/webarchive/FileReceiver?filename=C:\\OTHER\\x&jndiname=x&username=x"}),
            _negative("N-pcre-other-six-byte-install-path", "pcre-0", "filename parameter keeps the Windows drive path shape and a six-byte directory, but the directory is not MICROS", mutation={"target": "/Operajserv/webarchive/FileReceiver?filename=C:\\ORACLE\\x&jndiname=x&username=x"}),
            _negative("N-jndiname-parameter-absent", "content-2", "URI carries a differently named jndi parameter", mutation={"target": "/Operajserv/webarchive/FileReceiver?filename=C:\\MICROS\\x&jndiname1=x&username=x"}),
            _negative("N-username-parameter-absent", "content-3", "URI carries a differently named user parameter", mutation={"target": "/Operajserv/webarchive/FileReceiver?filename=C:\\MICROS\\x&jndiname=x&user_name=x"}),
            _negative("N-parameters-out-of-order", "content-3-distance", "username precedes jndiname, so the ordered distance constraint fails", mutation={"target": "/Operajserv/webarchive/FileReceiver?filename=C:\\MICROS\\x&username=x&jndiname=y"}),
            _negative("N-content-type-changed", "content-4", "upload is form-urlencoded instead of multipart", mutation={"headers": {"Content-Type": "application/x-www-form-urlencoded"}}),
            _negative("N-content-type-not-at-start", "content-4-startswith", "multipart literal is present but not at the start of http.content_type", mutation={"headers": {"Content-Type": "text/plain, multipart/form-data; boundary=x"}}),
            _negative("N-referer-header-present", "content-5", "a Referer header is present, which the negated predicate forbids", mutation={"headers": {"Referer": "http://target.local/"}}),
            _internal_source_address(),
            _wrong_destination_address(),
            _not_established(),
            _negative("N-wrong-direction", "header-src-address", "canonical request bytes replayed to client, so the source is internal and request buffers stay empty", mutation={"direction": "to_client"}),
            _random_http_request(),
        ),
        unsupported=(
            UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),
            UnsupportedPredicate("content-1-nocase", _NOCASE_REASON),
            UnsupportedPredicate("content-2-distance", "startswith pins the endpoint literal to the URI start and pcre-0 immediately follows it, so no protocol-valid URI can place jndiname before that anchor"),
        ),
    )


def _recipe_2048541() -> RuleRecipe:
    return RuleRecipe(
        sid=2048541,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "GET",
            "target": "/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false",
            "headers": {},
            "body": "",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("flowbits-0", "rule", "state", "sets a cross-signature flowbit"),
            PredicateRef("content-0", "http.uri", "content", "server-info action endpoint"),
            PredicateRef("content-1", "http.uri", "content", "setup-complete reset parameter"),
            PredicateRef("content-1-distance", "http.uri", "position", "parameter must follow the endpoint"),
            PredicateRef("content-1-fast_pattern", "http.uri", "performance", "parameter literal is the fast pattern"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"GET ", b"/server-info.action?", b"\r\n")),
            _negative("N-action-endpoint-changed", "content-0", "URI targets a different server-info action", mutation={"target": "/server-info2.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"}),
            _negative("N-setup-complete-true", "content-1", "setup-complete parameter is true, so the reset literal is absent", mutation={"target": "/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=true"}),
            _negative("N-parameter-before-endpoint", "content-1-distance", "reset parameter appears only before the endpoint literal it must follow", mutation={"target": "/status?bootstrapStatusProvider.applicationConfig.setupComplete=false&next=/server-info.action?"}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="http.uri is only populated for requests"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(
            UnsupportedPredicate("flowbits-0", _FLOWBITS_REASON),
            UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),
        ),
    )


def _recipe_2049007() -> RuleRecipe:
    return RuleRecipe(
        sid=2049007,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "POST",
            "target": "/webui/rest/softwareMgmt/installAdd",
            "headers": {"Cookie": "Auth=x", "X-Csrf-Token": "x"},
            "body": '"ipaddress":"a:a:a:a;"',
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.method", "content", "method must be POST"),
            PredicateRef("content-1", "http.uri", "content", "software install endpoint"),
            PredicateRef("content-1-startswith", "http.uri", "boundary", "endpoint must start the URI"),
            PredicateRef("content-1-nocase", "http.uri", "case", "endpoint matches case-insensitively"),
            PredicateRef("content-1-fast_pattern", "http.uri", "performance", "endpoint literal is the fast pattern"),
            PredicateRef("content-2", "http.cookie", "content", "authenticated session cookie name"),
            PredicateRef("content-2-startswith", "http.cookie", "boundary", "cookie name must start the buffer"),
            PredicateRef("content-3", "http.header_names", "content", "CSRF token header must be present"),
            PredicateRef("content-3-nocase", "http.header_names", "case", "header name matches case-insensitively"),
            PredicateRef("content-4", "http.request_body", "content", "ipaddress JSON key"),
            PredicateRef("content-4-nocase", "http.request_body", "case", "JSON key matches case-insensitively"),
            PredicateRef("content-5", "http.request_body", "content", "opening quote of the value"),
            PredicateRef("content-5-within", "http.request_body", "position", "quote must follow the key within 5 bytes"),
            PredicateRef("content-6", "http.request_body", "content", "first address separator"),
            PredicateRef("content-6-within", "http.request_body", "position", "first separator within 5 bytes"),
            PredicateRef("content-7", "http.request_body", "content", "second address separator"),
            PredicateRef("content-7-within", "http.request_body", "position", "second separator within 5 bytes"),
            PredicateRef("content-8", "http.request_body", "content", "third address separator"),
            PredicateRef("content-8-within", "http.request_body", "position", "third separator within 5 bytes"),
            PredicateRef("pcre-0", "http.request_body", "pcre", "command injection metacharacter after the address"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"POST ", b"\r\n\r\n", b'"ipaddress"')),
            _positive("P4-lowercase-uri", "signature-positive install endpoint replayed in lower case, which nocase accepts", mutation={"target": "/webui/rest/softwaremgmt/installadd"}),
            _positive("P5-lowercase-csrf-header", "signature-positive CSRF header name replayed in lower case, which nocase accepts", mutation={"headers": {"x-csrf-token": "x"}}),
            _positive("P6-uppercase-ipaddress-key", "signature-positive JSON key replayed in upper case, which nocase accepts", mutation={"body": '"IPADDRESS":"a:a:a:a;"'}),
            _negative("N-wrong-method", "content-0", "GET replaces the required POST method", mutation={"method": "GET"}),
            _negative("N-uri-endpoint-changed", "content-1", "URI stops short of the install endpoint literal", mutation={"target": "/webui/rest/softwareMgmt/install"}),
            _negative("N-uri-not-at-start", "content-1-startswith", "endpoint literal is present but preceded by a proxy path", mutation={"target": "/proxy/webui/rest/softwareMgmt/installAdd"}),
            _negative("N-cookie-name-changed", "content-2", "request carries a different session cookie name", mutation={"headers": {"Cookie": "Session=x"}}),
            _negative("N-cookie-not-at-start", "content-2-startswith", "authentication cookie is present but not first in http.cookie", mutation={"headers": {"Cookie": "Session=y; Auth=x"}}),
            _negative("N-csrf-header-absent", "content-3", "request omits the CSRF token header name", mutation={"headers": {"X-Csrf-Token": None}}),
            _negative("N-body-json-key-changed", "content-4", "body uses a different JSON key", mutation={"body": '"ipaddres":"a:a:a:a;"'}),
            _negative("N-body-value-quote-absent", "content-5", "body value is unquoted, so the required quote never follows the key", mutation={"body": '"ipaddress":a:a:a:a;'}),
            _negative("N-body-value-quote-beyond-within", "content-5-within", "quote appears more than 5 bytes after the JSON key", mutation={"body": '"ipaddress":aaaaaa"a:a:a:a;'}),
            _negative("N-body-first-separator-beyond-within", "content-6-within", "first separator appears more than 5 bytes after the opening quote", mutation={"body": '"ipaddress":"aaaaaa:a:a;'}),
            _negative("N-body-second-separator-beyond-within", "content-7-within", "second separator appears more than 5 bytes after the first", mutation={"body": '"ipaddress":"a:aaaaaa:a;'}),
            _negative("N-body-third-separator-absent", "content-8", "address carries only two separators instead of the required three", mutation={"body": '"ipaddress":"a:a:aa;"'}),
            _negative("N-body-third-separator-beyond-within", "content-8-within", "third separator appears more than 5 bytes after the second", mutation={"body": '"ipaddress":"a:a:aaaaaa:x;"'}),
            _negative("N-body-no-injection-metacharacter", "pcre-0", "address value ends with a benign assignment instead of an injectable metacharacter", mutation={"body": '"ipaddress":"a:a:a:a=x"'}),
            _negative("N-body-metacharacter-beyond-pcre-bound", "pcre-0", "injectable metacharacter appears past the PCRE's five-byte bound", mutation={"body": '"ipaddress":"a:a:a:aaaaaaa;"'}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="request buffers stay empty in the response direction"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(
            UnsupportedPredicate("content-1-nocase", "nocase cannot be isolated by a negative; signature-positive P4-lowercase-uri verifies its alternate URI casing"),
            UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),
            UnsupportedPredicate("content-3-nocase", "nocase cannot be isolated by a negative; signature-positive P5-lowercase-csrf-header verifies its alternate header-name casing"),
            UnsupportedPredicate("content-4-nocase", "nocase cannot be isolated by a negative; signature-positive P6-uppercase-ipaddress-key verifies its alternate JSON-key casing"),
            UnsupportedPredicate("content-6", "content-6, content-7, and content-8 are identical single-byte separators chained by within:5; only the final link can be isolated by shortening the separator count"),
            UnsupportedPredicate("content-7", "content-6, content-7, and content-8 are identical single-byte separators chained by within:5; only the final link can be isolated by shortening the separator count"),
        ),
    )


def _confluence_recipe(sid: int, *, out_of_range: str, unsupported_note: str) -> RuleRecipe:
    return RuleRecipe(
        sid=sid,
        suite_type="http",
        port=80,
        direction="to_client",
        canonical={
            "request_target": "/",
            "status": "200 OK",
            "headers": {},
            "body": _CONFLUENCE_META.format(version="5.0"),
        },
        predicates=(
            PredicateRef("header-src-address", "header", "address", "response must come from an internal server"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_client", "flow", "flow", "response direction only"),
            PredicateRef("content-0", "http.response_body", "content", "version meta tag prefix"),
            PredicateRef("content-0-fast_pattern", "http.response_body", "performance", "meta tag literal is the fast pattern"),
            PredicateRef("pcre-0", "http.response_body", "pcre", "affected major version range"),
            PredicateRef("threshold-0", "rule", "throttle", "one alert per source per hour"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"HTTP/1.1 200 OK\r\n", b'content="')),
            _negative("N-meta-tag-changed", "content-0", "response advertises a different meta tag name", mutation={"body": '<meta name="ajs-version" content="5.0">'}),
            _negative("N-version-out-of-range", "pcre-0", f"advertised major version {out_of_range} is outside the affected range", mutation={"body": _CONFLUENCE_META.format(version=f"{out_of_range}.0")}),
            _negative("N-version-without-minor-separator", "pcre-0", "advertised version omits the minor-version separator the PCRE requires", mutation={"body": _CONFLUENCE_META.format(version="59")}),
            _external_response_source(),
            _not_established(),
            _reversed_stream("flow-to_client", "to_client", note="http.response_body is only populated for responses"),
            _random_http_response(),
        ),
        unsupported=(
            UnsupportedPredicate("content-0-fast_pattern", _FAST_PATTERN_REASON),
            UnsupportedPredicate("threshold-0", unsupported_note),
        ),
    )


def _recipe_2050340() -> RuleRecipe:
    return RuleRecipe(
        sid=2050340,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "POST",
            "target": "/x.vm",
            "headers": {},
            "body": ".KEY_velocity.struts2{}",
        },
        predicates=(
            PredicateRef("header-src-address", "header", "address", "source must be external"),
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.method", "content", "method must be POST"),
            PredicateRef("content-1", "http.uri", "content", "velocity template extension"),
            PredicateRef("content-1-endswith", "http.uri", "boundary", "extension must end the URI"),
            PredicateRef("content-2", "http.request_body", "content", "velocity struts key"),
            PredicateRef("content-2-fast_pattern", "http.request_body", "performance", "velocity key is the fast pattern"),
            PredicateRef("content-3", "http.request_body", "content", "opening template brace"),
            PredicateRef("content-3-distance", "http.request_body", "position", "opening brace must follow the key"),
            PredicateRef("content-4", "http.request_body", "content", "closing template brace"),
            PredicateRef("content-4-distance", "http.request_body", "position", "closing brace must follow the opening brace"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"POST ", b"\r\n\r\n", b".KEY_velocity")),
            _negative("N-wrong-method", "content-0", "GET replaces the required POST method", mutation={"method": "GET"}),
            _negative("N-uri-extension-changed", "content-1", "URI requests a text file instead of a velocity template", mutation={"target": "/x.txt"}),
            _negative("N-uri-extension-not-at-end", "content-1-endswith", "template extension is present but followed by a query string", mutation={"target": "/x.vm?a=1"}),
            _negative("N-body-velocity-key-changed", "content-2", "body posts a different velocity key", mutation={"body": ".KEY_velocity.struts3{}"}),
            _negative("N-body-open-brace-absent", "content-3", "body replaces the opening template brace", mutation={"body": ".KEY_velocity.struts2[}"}),
            _negative("N-body-open-brace-before-key", "content-3-distance", "opening brace appears only before the velocity key it must follow", mutation={"body": "{.KEY_velocity.struts2}"}),
            _negative("N-body-close-brace-absent", "content-4", "body replaces the closing template brace", mutation={"body": ".KEY_velocity.struts2{]"}),
            _negative("N-body-close-brace-before-braces", "content-4-distance", "closing brace appears only before the opening brace it must follow", mutation={"body": "}.KEY_velocity.struts2{"}),
            _internal_source_address(),
            _wrong_destination_address(),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="request body stays empty in the response direction"),
            _random_http_request(),
        ),
        unsupported=(UnsupportedPredicate("content-2-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2050988() -> RuleRecipe:
    return RuleRecipe(
        sid=2050988,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={"method": "GET", "target": "/SetupWizard.aspx/", "headers": {}, "body": ""},
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("flowbits-0", "rule", "state", "sets a cross-signature flowbit"),
            PredicateRef("content-0", "http.uri", "content", "setup wizard path literal"),
            PredicateRef("content-0-startswith", "http.uri", "boundary", "literal must start the URI"),
            PredicateRef("content-0-fast_pattern", "http.uri", "performance", "path literal is the fast pattern"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"GET ", b"/SetupWizard", b"\r\n")),
            _negative("N-uri-lowercased", "content-0", "path is lower case, which the case-sensitive literal rejects", mutation={"target": "/setupwizard.aspx/"}),
            _negative("N-uri-not-at-start", "content-0-startswith", "path literal is present but preceded by a proxy prefix", mutation={"target": "/proxy/SetupWizard.aspx/"}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="http.uri is only populated for requests"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(
            UnsupportedPredicate("flowbits-0", _FLOWBITS_REASON),
            UnsupportedPredicate("content-0-fast_pattern", _FAST_PATTERN_REASON),
        ),
    )


def _recipe_2052951() -> RuleRecipe:
    return RuleRecipe(
        sid=2052951,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "GET",
            "target": "/api/index.php/v1/config/application?public=true",
            "headers": {},
            "body": "",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.method", "content", "method must be GET"),
            PredicateRef("content-1", "http.uri", "content", "public configuration endpoint"),
            PredicateRef("content-1-fast_pattern", "http.uri", "performance", "endpoint literal is the fast pattern"),
            PredicateRef("content-1-endswith", "http.uri", "boundary", "endpoint literal must end the URI"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"GET ", b"/api/index.php/", b"\r\n")),
            _negative("N-wrong-method", "content-0", "POST replaces the required GET method", mutation={"method": "POST"}),
            _negative("N-public-parameter-false", "content-1", "configuration request asks for non-public data", mutation={"target": "/api/index.php/v1/config/application?public=false"}),
            _negative("N-uri-not-at-end", "content-1-endswith", "endpoint literal is present but followed by another parameter", mutation={"target": "/api/index.php/v1/config/application?public=true&x=1"}),
            _negative("N-uri-prefix-changed", "content-1", "URI ends with the public configuration endpoint but reaches it through a different prefix than the API route", mutation={"target": "/administrator/index.php/v1/config/application?public=true"}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="http.uri is only populated for requests"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2056147() -> RuleRecipe:
    credentials = "Basic Y3NsdS13aW5kb3dzLWNsaWVudDpMaWJyYXJ5NEMkTFU="
    return RuleRecipe(
        sid=2056147,
        suite_type="http",
        port=80,
        direction="to_server",
        canonical={
            "method": "GET",
            "target": "/cslu/",
            "headers": {"Authorization": credentials},
            "body": "",
        },
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "http.uri", "content", "licensing utility path"),
            PredicateRef("content-0-startswith", "http.uri", "boundary", "path must start the URI"),
            PredicateRef("content-1", "http.header", "content", "hardcoded backdoor credentials"),
            PredicateRef("content-1-fast_pattern", "http.header", "performance", "credential literal is the fast pattern"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"GET ", b"Authorization: ", b"Basic ")),
            _negative("N-uri-path-changed", "content-0", "request targets a different application path", mutation={"target": "/other/"}),
            _negative("N-uri-not-at-start", "content-0-startswith", "licensing path is present but preceded by a proxy prefix", mutation={"target": "/proxy/cslu/"}),
            _negative("N-credentials-changed", "content-1", "Authorization header carries different credentials", mutation={"headers": {"Authorization": "Basic bad"}}),
            _negative("N-credentials-in-body", "content-1", "credential literal appears in the request body instead of a header", mutation={"method": "POST", "headers": {"Authorization": None}, "body": f"Authorization: {credentials}"}),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="request headers stay empty in the response direction"),
            _wrong_destination_address(),
            _random_http_request(),
        ),
        unsupported=(UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),),
    )


def _recipe_2060144() -> RuleRecipe:
    return RuleRecipe(
        sid=2060144,
        suite_type="raw_tcp",
        port=5432,
        direction="to_server",
        canonical={"payload": _pgsql_query(b"SELECT 1;\x5c\x5c\x21\x20id")},
        predicates=(
            PredicateRef("header-dst-address", "header", "address", "destination must be internal"),
            PredicateRef("header-dst-port", "header", "port", "PostgreSQL or HTTP proxy ports"),
            PredicateRef("flow-established", "flow", "flow", "TCP flow must be established"),
            PredicateRef("flow-to_server", "flow", "flow", "request direction only"),
            PredicateRef("content-0", "payload", "content", "statement separator"),
            PredicateRef("content-1", "payload", "content", "psql meta-command shell escape"),
            PredicateRef("content-1-fast_pattern", "payload", "performance", "shell escape is the fast pattern"),
            PredicateRef("content-1-distance", "payload", "position", "shell escape must follow the separator"),
            PredicateRef("rule-baseline", "rule", "whole_signature", "signature must stay silent otherwise"),
        ),
        cases=(
            *_stream_positives(split_after=(b"Q", b"SELECT 1;"), uniform_segment_size=4, retransmit_segment_size=8),
            _negative("N-statement-separator-absent", "content-0", "query drops the statement separator the rule requires", mutation={"payload": _pgsql_query(b"SELECT 1\x5c\x5c\x21\x20id")}),
            _negative("N-shell-escape-changed", "content-1", "meta-command bytes no longer form the shell escape", mutation={"payload": _pgsql_query(b"SELECT 1;\x5c\x78\x21\x20id")}),
            _negative("N-shell-escape-before-separator", "content-1-distance", "shell escape appears only before the separator it must follow", mutation={"payload": _pgsql_query(b"\x5c\x5c\x21\x20SELECT 1;")}),
            _negative("N-wrong-port", "header-dst-port", "query is sent to a port outside the monitored PostgreSQL and HTTP port set", mutation={"port": 5433}),
            _wrong_destination_address(),
            _not_established(),
            _reversed_stream("flow-to_server", "to_server", note="the rule only inspects client-to-server data"),
            _negative("N-random-pgsql-query", "rule-baseline", "protocol-valid PostgreSQL simple query with no shell escape", mutation={"payload": _pgsql_query(b"SELECT version();")}),
        ),
        unsupported=(UnsupportedPredicate("content-1-fast_pattern", _FAST_PATTERN_REASON),),
    )


def recipes() -> dict[int, RuleRecipe]:
    """Return the declarative suite recipe for every retained dataset rule."""
    catalog = (
        _recipe_2044143(),
        _recipe_2044585(),
        _recipe_2045307(),
        _recipe_2048541(),
        _recipe_2049007(),
        _confluence_recipe(2049080, out_of_range="9", unsupported_note=_THRESHOLD_REASON),
        _confluence_recipe(2049623, out_of_range="3", unsupported_note=_THRESHOLD_REASON),
        _recipe_2050340(),
        _recipe_2050434(),
        _recipe_2050988(),
        _recipe_2052951(),
        _recipe_2055723(),
        _recipe_2056147(),
        _recipe_2057330(),
        _recipe_2057705(),
        _recipe_2059741(),
        _recipe_2060086(),
        _recipe_2060144(),
        _recipe_2067354(),
    )
    return {recipe.sid: recipe for recipe in catalog}
