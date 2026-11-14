import pytest

import bleach
from bleach.css_sanitizer import CSSSanitizer
from bleach.origin_policy import URIOriginPolicy
from bleach.sanitizer import Cleaner


BASE_URL = "https://help.example.com/docs/"
ALLOWED_ORIGINS = {
    "https://help.example.com",
    "https://static.example.com",
    "https://xn--exmple-cua.com",
    "http://intranet.example.com:8080",
}

TAGS = {"a", "img", "form", "svg", "use", "pattern", "p"}
ATTRIBUTES = {
    "a": ["href", "title"],
    "img": ["src", "alt"],
    "form": ["action"],
    "use": ["href"],
    "pattern": ["id", "href"],
    "p": ["style"],
}


def clean_with_policy(text, **kwargs):
    kwargs.setdefault("tags", TAGS)
    kwargs.setdefault("attributes", ATTRIBUTES)
    kwargs.setdefault("base_url", BASE_URL)
    kwargs.setdefault("allowed_origins", ALLOWED_ORIGINS)
    return bleach.clean(text, **kwargs)


@pytest.mark.parametrize(
    "text, expected",
    [
        # Relative paths are resolved against the trusted base url and
        # rewritten to absolute urls
        (
            '<a href="/docs/start">站内文档</a>',
            '<a href="https://help.example.com/docs/start">站内文档</a>',
        ),
        (
            '<a href="guide">rel</a>',
            '<a href="https://help.example.com/docs/guide">rel</a>',
        ),
        (
            '<a href="../index">up</a>',
            '<a href="https://help.example.com/index">up</a>',
        ),
        # Query strings and fragments on relative urls survive
        (
            '<a href="/search?q=bleach#top">q</a>',
            '<a href="https://help.example.com/search?q=bleach#top">q</a>',
        ),
        # Pure fragment references are kept as-is
        ('<a href="#part">页内定位</a>', '<a href="#part">页内定位</a>'),
        ('<a href="#">top</a>', '<a href="#">top</a>'),
        # Allowed origins pass through
        (
            '<a href="https://help.example.com/a">same</a>',
            '<a href="https://help.example.com/a">same</a>',
        ),
        (
            '<img src="https://static.example.com/logo.png">',
            '<img src="https://static.example.com/logo.png">',
        ),
        # Explicit default port is equivalent to no port
        (
            '<a href="https://help.example.com:443/a">port</a>',
            '<a href="https://help.example.com:443/a">port</a>',
        ),
        # Non-default ports must match exactly
        (
            '<a href="http://intranet.example.com:8080/a">intra</a>',
            '<a href="http://intranet.example.com:8080/a">intra</a>',
        ),
        # Scheme and host case don't matter
        (
            '<a href="HTTPS://HELP.EXAMPLE.COM/a">case</a>',
            '<a href="HTTPS://HELP.EXAMPLE.COM/a">case</a>',
        ),
        # IDNA and unicode forms of the same domain are equivalent
        (
            '<a href="https://exämple.com/x">idn</a>',
            '<a href="https://exämple.com/x">idn</a>',
        ),
        (
            '<a href="https://XN--EXMPLE-CUA.COM/x">idn</a>',
            '<a href="https://XN--EXMPLE-CUA.COM/x">idn</a>',
        ),
    ],
)
def test_origin_policy_allowed(text, expected):
    assert clean_with_policy(text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        # Cross-origin links and tracking pixels lose the attribute
        ('<a href="https://outside.invalid/">跳走</a>', "<a>跳走</a>"),
        ('<img src="https://outside.invalid/pixel">', "<img>"),
        # Protocol-relative urls are dropped even for allowed hosts
        ('<a href="//outside.invalid/">跳走</a>', "<a>跳走</a>"),
        ('<a href="//help.example.com/x">pr</a>', "<a>pr</a>"),
        # Username and password in the url
        ('<a href="https://user:pw@help.example.com/">ui</a>', "<a>ui</a>"),
        ('<a href="https://user@help.example.com/">ui</a>', "<a>ui</a>"),
        # Backslashes
        ('<a href="https:\\\\help.example.com/x">bs</a>', "<a>bs</a>"),
        ('<a href="/a\\b">bs</a>', "<a>bs</a>"),
        # Control characters
        ('<a href="https://help.example.com/a\x0bb">cc</a>', "<a>cc</a>"),
        ('<a href="\thttps://help.example.com/a">cc</a>', "<a>cc</a>"),
        # Malformed hosts and ports
        ('<a href="https://help.example.com:bad/">mp</a>', "<a>mp</a>"),
        ('<a href="https://help.example.com:99999/">mp</a>', "<a>mp</a>"),
        ('<a href="https://help.example.com:0/">mp</a>', "<a>mp</a>"),
        ('<a href="https://[::1/x">mh</a>', "<a>mh</a>"),
        # Subdomains and look-alike suffixes don't match
        ('<a href="https://sub.help.example.com/">sub</a>', "<a>sub</a>"),
        ('<a href="https://help.example.com.evil.com/">suf</a>', "<a>suf</a>"),
        ('<a href="https://help-example.com/">suf</a>', "<a>suf</a>"),
        ('<a href="https://static.example.com.evilhelp.example.com/">s</a>', "<a>s</a>"),
        # Wrong port doesn't match
        ('<a href="https://help.example.com:8443/">wp</a>', "<a>wp</a>"),
        ('<a href="http://intranet.example.com/">wp</a>', "<a>wp</a>"),
        # Wrong scheme doesn't match
        ('<a href="http://help.example.com/">ws</a>', "<a>ws</a>"),
        # Non-http(s) schemes have no origin to check
        ('<a href="mailto:me@example.com">m</a>', "<a>m</a>"),
        ('<a href="ftp://help.example.com/x">f</a>', "<a>f</a>"),
    ],
)
def test_origin_policy_dropped(text, expected):
    assert clean_with_policy(text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        # Entity-obfuscated dangerous schemes are still caught by the
        # protocol check--the origin policy doesn't weaken it
        ('<a href="&#106;avascript:alert(1)">js</a>', "<a>js</a>"),
        ('<a href="java&#115;cript:alert(1)">js</a>', "<a>js</a>"),
        ('<a href="&#106;&#97;vascript:alert(1)">js</a>', "<a>js</a>"),
        # Entity-obfuscated control characters are dropped
        ('<a href="&#9;https://help.example.com/x">tab</a>', "<a>tab</a>"),
        ('<a href="https://help.example.com/a&#11;b">vt</a>', "<a>vt</a>"),
        # Entity-obfuscated legitimate urls are judged on the decoded value
        (
            '<a href="https&#58;//help.example.com/y">ent</a>',
            '<a href="https&#58;//help.example.com/y">ent</a>',
        ),
        ('<a href="&#35;frag">frag</a>', '<a href="&#35;frag">frag</a>'),
        (
            '<a href="&#47;docs&#47;start">rel</a>',
            '<a href="https://help.example.com/docs/start">rel</a>',
        ),
    ],
)
def test_origin_policy_entities(text, expected):
    assert clean_with_policy(text) == expected


def test_origin_policy_applies_to_all_uri_attributes():
    """The policy applies to every attribute bleach treats as a uri"""
    # img src
    assert clean_with_policy('<img src="https://outside.invalid/pixel">') == "<img>"
    assert (
        clean_with_policy('<img src="img/pic.png">')
        == '<img src="https://help.example.com/docs/img/pic.png">'
    )
    # form action
    assert (
        clean_with_policy('<form action="https://outside.invalid/post">f</form>')
        == "<form>f</form>"
    )
    assert (
        clean_with_policy('<form action="/search">f</form>')
        == '<form action="https://help.example.com/search">f</form>'
    )


def test_origin_policy_xlink_href():
    """xlink:href goes through the same origin policy entry"""
    # Cross-origin xlink:href is dropped
    text = '<svg><a xlink:href="https://outside.invalid/p">x</a></svg>'
    assert clean_with_policy(text) == "<svg><a>x</a></svg>"

    # Relative xlink:href is resolved against the base url
    # NOTE(willkg): html5lib serializer drops the xlink part
    text = '<svg><a xlink:href="/p">x</a></svg>'
    assert (
        clean_with_policy(text)
        == '<svg><a href="https://help.example.com/p">x</a></svg>'
    )


def test_origin_policy_svg_local_href_stays_stricter():
    """SVG elements that only allow local refs keep the stricter limit"""
    # Local fragment is fine
    text = '<svg><use xlink:href="#icon"></use></svg>'
    assert clean_with_policy(text) == '<svg><use href="#icon"></use></svg>'

    # Even a same-origin absolute url is dropped--use only allows local refs
    text = '<svg><use xlink:href="https://help.example.com/i.svg#x"></use></svg>'
    assert clean_with_policy(text) == "<svg><use></use></svg>"


def test_origin_policy_does_not_affect_css_sanitizing():
    """CSS url() values are not part of the origin policy"""
    css_sanitizer = CSSSanitizer()
    text = '<p style="fill: url(https://outside.invalid/x)">t</p>'
    with_policy = clean_with_policy(text, css_sanitizer=css_sanitizer)
    without_policy = bleach.clean(
        text, tags=TAGS, attributes=ATTRIBUTES, css_sanitizer=css_sanitizer
    )
    assert with_policy == without_policy


def test_origin_policy_disabled_keeps_protocol_filtering():
    """Without base_url/allowed_origins, behavior is unchanged"""
    # Protocol-relative urls pass the default protocol check
    assert (
        bleach.clean('<a href="//outside.invalid/">x</a>')
        == '<a href="//outside.invalid/">x</a>'
    )
    # Relative urls are not rewritten
    assert (
        bleach.clean('<a href="/docs/start">x</a>')
        == '<a href="/docs/start">x</a>'
    )
    # Dangerous protocols are still dropped
    assert bleach.clean('<a href="javascript:alert(1)">x</a>') == "<a>x</a>"


def test_origin_policy_reusable_cleaner():
    """A Cleaner with an origin policy can be reused"""
    cleaner = Cleaner(
        tags=TAGS,
        attributes=ATTRIBUTES,
        base_url=BASE_URL,
        allowed_origins=ALLOWED_ORIGINS,
    )
    assert (
        cleaner.clean('<a href="/a">1</a>')
        == '<a href="https://help.example.com/a">1</a>'
    )
    assert cleaner.clean('<a href="https://outside.invalid/">2</a>') == "<a>2</a>"
    assert (
        cleaner.clean('<img src="b.png">')
        == '<img src="https://help.example.com/docs/b.png">'
    )


def test_origin_policy_clean_is_idempotent():
    """Cleaning cleaned text doesn't change it"""
    cleaner = Cleaner(
        tags=TAGS,
        attributes=ATTRIBUTES,
        base_url=BASE_URL,
        allowed_origins=ALLOWED_ORIGINS,
    )
    text = (
        '<a href="/docs/start">站内文档</a>'
        '<img src="https://outside.invalid/pixel">'
        '<a href="//outside.invalid/">跳走</a>'
        '<a href="#part">页内定位</a>'
    )
    once = cleaner.clean(text)
    assert cleaner.clean(once) == once
    assert cleaner.clean(cleaner.clean(once)) == once


@pytest.mark.parametrize(
    "kwargs",
    [
        # base_url without allowed_origins and vice versa
        {"base_url": BASE_URL},
        {"allowed_origins": ALLOWED_ORIGINS},
    ],
)
def test_origin_policy_requires_both_arguments(kwargs):
    with pytest.raises(ValueError):
        Cleaner(**kwargs)

    with pytest.raises(ValueError):
        bleach.clean("text", **kwargs)


@pytest.mark.parametrize(
    "base_url",
    [
        # base url must be https
        "http://help.example.com/",
        # no username or password
        "https://user:pw@help.example.com/",
        # malformed host or port
        "https:///missing-host/",
        "https://help.example.com:bad/",
    ],
)
def test_origin_policy_invalid_base_url(base_url):
    with pytest.raises(ValueError):
        URIOriginPolicy(base_url, ALLOWED_ORIGINS)


@pytest.mark.parametrize(
    "origin",
    [
        # origins must be http(s)
        "ftp://static.example.com",
        "static.example.com",
        # no username or password
        "https://user@static.example.com",
        # no path, query or fragment
        "https://static.example.com/path",
        "https://static.example.com/?q=1",
        "https://static.example.com/#frag",
        # malformed port
        "https://static.example.com:bad",
    ],
)
def test_origin_policy_invalid_allowed_origin(origin):
    with pytest.raises(ValueError):
        URIOriginPolicy(BASE_URL, {origin})


def test_origin_policy_base_origin_is_always_allowed():
    """The base url origin is allowed even if not listed"""
    policy = URIOriginPolicy("https://help.example.com/", {"https://static.example.com"})
    assert policy.sanitize_uri("https://help.example.com/x") == (
        "https://help.example.com/x"
    )
    assert policy.sanitize_uri("/x") == "https://help.example.com/x"
    assert policy.sanitize_uri("https://other.invalid/") is None
