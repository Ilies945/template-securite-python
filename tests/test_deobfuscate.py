import helpers
from tp2 import deobfuscate as d


def test_extract_strings_ascii_and_wide():
    data = b"\x00\x01hello world\x00" + "wide text".encode("utf-16-le") + b"\x00\x00"
    found = d.extract_strings(data)
    assert "hello world" in found
    assert "wide text" in found


def test_extract_strings_drops_ascii_tail_before_wide():
    data = b"185.10.20.30\x00" + "evil.example.test".encode("utf-16-le")
    assert "evil.example.test" in d.extract_strings(data)


def test_printable_ratio():
    assert d._printable_ratio(b"abcd") == 1.0
    assert d._printable_ratio(b"\x00\x01\x02\x03") == 0.0
    assert d._printable_ratio(b"") == 0.0


def test_wide_ratio():
    assert d._wide_ratio("hello world".encode("utf-16-le")) > 0.9
    assert d._wide_ratio(b"plain ascii data") == 0.0
    assert d._wide_ratio(b"ab") == 0.0


def test_is_texty():
    assert d._is_texty(b"http://example.test/")
    assert not d._is_texty(bytes(range(200, 256)))


def test_decode_blobs_base64_and_hex():
    b64_text = helpers.b64(b"http://hidden.example.test/x").decode()
    hex_text = b"Global\\mutex_name".hex()
    blobs = d.decode_blobs([f"data={b64_text}", f"h={hex_text}"])
    assert b"http://hidden.example.test/x" in blobs
    assert b"Global\\mutex_name" in blobs
    assert d.decode_blobs(["short"]) == []


def test_xor_views_finds_key():
    data = b"\x00" * 16 + helpers.xor_bytes(b"https://x.example.test/a", 0x42) + b"\x00" * 8
    keys = [k for k, _view in d.xor_views(data)]
    assert 0x42 in keys
    view = dict(d.xor_views(data))[0x42]
    assert b"https://x.example.test/a" in view


def test_xor_views_ignores_plain_data():
    assert d.xor_views(b"nothing interesting here, just prose") == []


def test_collect_texts_layers():
    data = (b"plain.example.test\x00" + helpers.b64(b"http://b64.example.test/z") + b"\x00"
            + helpers.xor_bytes(b"ESGI{k}\x00", 0x11))
    texts = d.collect_texts(data)
    assert any("plain.example.test" in t for t in texts.plain)
    assert any("http://b64.example.test/z" in t for t in texts.plain)
    assert any("ESGI{k}" in t for t in texts.strict)
