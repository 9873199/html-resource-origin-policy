"""Optional origin-based policy for URI attribute values.

This implements an additional, opt-in layer on top of Bleach's
protocol-based URI filtering. When enabled, every attribute Bleach treats
as a URI (``a[href]``, ``img[src]``, ``form[action]``, ``xlink:href``, ...)
is resolved against a fixed, trusted HTTPS base URL and then checked
against a set of allowed http(s) origins.

Origin comparison is done on the parsed ``(scheme, host, effective port)``
triple--never with string prefix matching--so domain case, IDNA and
default-port equivalences hold, while subdomains and look-alike suffixes
("help.example.com.evil.com", "help-example.com") do not.

"""

import re

from bleach import html5lib_shim
from bleach import parse_shim


#: Default ports for the http and https schemes
SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443}

#: Characters that are never allowed in a URI handled by the origin policy:
#: ASCII control characters, DEL and backslash. Browsers strip or reinterpret
#: these in surprising ways, so values containing them are dropped outright.
INVALID_URI_CHARACTERS_RE = re.compile(r"[\x00-\x1f\x7f\\]")


def normalize_host(host):
    """Normalizes a host for origin comparison

    Domain names are compared case-insensitively and IDNA-encoded so that
    unicode names and their punycode forms are equivalent. IP literals
    (which contain ":") are compared case-insensitively as-is.

    :arg host: the host to normalize; may be None

    :returns: normalized host or None if the host is missing or malformed

    """
    if not host:
        return None

    if ":" in host:
        # IPv6 literal--not a domain name, so no IDNA
        return host.lower()

    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None


def origin_for_parsed(parsed):
    """Computes the (scheme, host, effective port) origin triple

    :arg parsed: result of parsing a url with ``parse_shim.urlparse``

    :returns: ``(scheme, normalized_host, effective_port)`` tuple

    :raises ValueError: if the parsed url can't be an http(s) origin: wrong
        scheme, username or password, malformed host or invalid port

    """
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"origin scheme must be http or https, not {scheme!r}")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("origin must not contain a username or password")

    host = normalize_host(parsed.hostname)
    if host is None:
        raise ValueError(f"origin has a missing or malformed host: {parsed.netloc!r}")

    try:
        port = parsed.port
    except ValueError:
        raise ValueError(f"origin has an invalid port: {parsed.netloc!r}")

    if port is not None and port == 0:
        raise ValueError("origin has an invalid port: 0")

    effective_port = port if port is not None else SCHEME_DEFAULT_PORTS[scheme]
    return (scheme, host, effective_port)


class URIOriginPolicy:
    """Policy restricting URI attribute values to a set of allowed origins

    Relative URIs are resolved against the trusted ``base_url`` first and
    the resulting absolute URL is what gets returned. Pure fragment
    references (``#section``) are kept as-is. Cross-origin URIs,
    protocol-relative URIs, URIs with a username or password, and values
    containing backslashes or control characters are dropped.

    """

    def __init__(self, base_url, allowed_origins):
        """Initializes a URIOriginPolicy

        :arg str base_url: fixed HTTPS base url that relative URIs are
            resolved against; must not contain a username or password

        :arg allowed_origins: collection of allowed http(s) origins, e.g.
            ``{"https://help.example.com", "https://static.example.com:8443"}``;
            the origin of ``base_url`` is always allowed

        :raises ValueError: if the base url or any of the origins is invalid

        """
        try:
            parsed_base = parse_shim.urlparse(base_url)
        except ValueError:
            raise ValueError(f"base_url is malformed: {base_url!r}")

        if parsed_base.scheme.lower() != "https":
            raise ValueError("base_url must use the https scheme")

        try:
            base_origin = origin_for_parsed(parsed_base)
        except ValueError as exc:
            raise ValueError(f"base_url is invalid: {exc}")

        origins = set()
        for origin in allowed_origins:
            try:
                parsed_origin = parse_shim.urlparse(origin)
                origin_triple = origin_for_parsed(parsed_origin)
            except ValueError as exc:
                raise ValueError(f"allowed origin {origin!r} is invalid: {exc}")

            if (
                parsed_origin.path not in ("", "/")
                or parsed_origin.query
                or parsed_origin.fragment
            ):
                raise ValueError(
                    f"allowed origin {origin!r} must not have a path, query or "
                    "fragment"
                )

            origins.add(origin_triple)

        # The trusted base is always an allowed origin
        origins.add(base_origin)

        self.base_url = base_url
        self.base_origin = base_origin
        self.allowed_origins = frozenset(origins)

    def sanitize_uri(self, value):
        """Checks a uri value against this policy

        :arg value: the uri value to check

        :returns: the value to keep--relative uris come back as absolute
            urls resolved against the base url--or None if the value is
            not allowed

        """
        # Judge the real value with HTML entities resolved--this is the same
        # normalization the protocol check does, so entity-obfuscated values
        # can't sneak past either check
        decoded = html5lib_shim.convert_entities(value)

        # Drop values with control characters or backslashes--browsers
        # reinterpret these in ways that make parsing ambiguous
        if INVALID_URI_CHARACTERS_RE.search(decoded):
            return None

        candidate = decoded.strip()

        # Pure fragment references are local to the page--keep them as-is
        if candidate.startswith("#"):
            return value

        try:
            parsed = parse_shim.urlparse(candidate)
        except ValueError:
            return None

        absolute = None
        if parsed.scheme:
            # Absolute URI--only http(s) URIs have an origin to check; this
            # also keeps dangerous schemes like javascript: from riding
            # through on top of the protocol check
            if parsed.scheme.lower() not in ("http", "https"):
                return None

        elif parsed.netloc:
            # Protocol-relative URIs inherit whatever scheme the page was
            # loaded with, so they're not allowed
            return None

        else:
            # Relative URI--resolve it against the trusted base url
            try:
                absolute = parse_shim.urljoin(self.base_url, candidate)
                parsed = parse_shim.urlparse(absolute)
            except ValueError:
                return None

        try:
            origin = origin_for_parsed(parsed)
        except ValueError:
            return None

        if origin not in self.allowed_origins:
            return None

        if absolute is not None:
            return absolute

        return value
