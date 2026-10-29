import helpers
from tp2 import iocs as m
from tp2.deobfuscate import Texts, collect_texts


def sample_blob() -> bytes:
    return (
        b"MZ\x00\x00"
        b"GET http://c2.example.test:8080/gate.php?id=1 HTTP/1.1\x00"
        b"185.10.20.30\x00"
        + "evil-cdn.example.test".encode("utf-16-le") + b"\x00\x00"
        + b"Global\\abc123\x00HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc\x00"
        b"C:\\Users\\Public\\svc.exe\x00kernel32.dll\x00System.Net.Sockets\x00/tmp/.hidden/x.sh\x00"
        b"1.2.3.4.5\x00version 10.0.19041.1\x00"
        + helpers.b64(b"http://b64.example.test/a") + b"\x00"
        + helpers.xor_bytes(b"ESGI{x0r_fl4g} https://xor.example.test/z\x00", 0x5A) + b"\x00" * 4
    )


def test_extract_iocs_complete():
    found = m.extract_iocs(sample_blob())
    assert "c2.example.test" in found["domains"]
    assert "evil-cdn.example.test" in found["domains"]
    assert "b64.example.test" in found["domains"]
    assert "xor.example.test" in found["domains"]
    assert found["ips"] == ["185.10.20.30"]
    assert "http://c2.example.test:8080/gate.php?id=1" in found["urls"]
    assert found["mutex"] == ["Global\\abc123"]
    assert found["registry"] == ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc"]
    assert "C:\\Users\\Public\\svc.exe" in found["paths"]
    assert "/tmp/.hidden/x.sh" in found["paths"]


def test_extract_iocs_rejects_false_positives():
    found = m.extract_iocs(sample_blob())
    assert not any(d.endswith(".dll") for d in found["domains"])
    assert "System.Net.Sockets" not in found["domains"]
    assert "1.2.3.4.5" not in found["ips"]
    assert all(not ip.startswith("10.0.19041") for ip in found["ips"])


def test_extract_iocs_is_sorted_and_unique():
    data = b"http://b.example.test/x\x00http://a.example.test/y\x00http://a.example.test/y\x00"
    found = m.extract_iocs(data)
    assert found["urls"] == sorted(set(found["urls"]))
    assert len(found["urls"]) == 2


def test_extract_iocs_from_texts_strict_vs_loose():
    texts = Texts(plain=["host loose.example.test"], strict=["loose2.example.test http://u.example.test/p"])
    found = m.extract_iocs_from_texts(texts)
    assert "loose.example.test" in found["domains"]
    assert "u.example.test" in found["domains"]
    assert "loose2.example.test" not in found["domains"]  # domaine nu : refusé dans une vue XOR


def test_clean_strips_trailing_punctuation():
    assert m._clean("http://a.test/x).") == "http://a.test/x"


def test_valid_ip():
    assert m._valid_ip("185.10.20.30")
    assert not m._valid_ip("999.1.1.1")
    assert not m._valid_ip("0.0.0.0")


def test_valid_domain():
    assert m._valid_domain("c2.example.test")
    assert m._valid_domain("evil.ru")
    assert not m._valid_domain("kernel32.dll")
    assert not m._valid_domain("System.Net")
    assert not m._valid_domain("schemas.microsoft.com")
    assert not m._valid_domain("localhost")
    assert not m._valid_domain("u.uh")  # faux ccTLD
    assert not m._valid_domain("1.2.3.com.notatld")


def test_host_of():
    assert m._host_of("http://c2.example.test:8080/a") == "c2.example.test"
    assert m._host_of("https://user@1.2.3.4/x") == "1.2.3.4"
    assert m._host_of("http://[::1]/x") == ""


def test_scan_strict_collects_ip_hosts_separately():
    found = {k: set() for k in ("domains", "ips", "urls", "mutex", "registry", "paths")}
    m._scan_strict("see http://10.1.2.3/payload and Local\\mtx_01", found)
    assert found["ips"] == {"10.1.2.3"}
    assert found["mutex"] == {"Local\\mtx_01"}
    assert not found["domains"]


def test_scan_loose_finds_bare_ip_and_domain():
    found = {k: set() for k in ("domains", "ips", "urls", "mutex", "registry", "paths")}
    m._scan_loose("beacon to 8.8.4.4 via dns.example.test", found)
    assert found["ips"] == {"8.8.4.4"}
    assert found["domains"] == {"dns.example.test"}


def test_find_flag_in_every_encoding():
    assert m.find_flag(b"..ESGI{plain}..") == "ESGI{plain}"
    assert m.find_flag("ESGI{wide}".encode("utf-16-le")) == "ESGI{wide}"
    assert m.find_flag(helpers.b64(b"ESGI{b64_flag}")) == "ESGI{b64_flag}"
    assert m.find_flag(b"junk" + helpers.xor_bytes(b"ESGI{xor}\x00", 0x21)) == "ESGI{xor}"
    assert m.find_flag(b"}esrever{IGSE") == "ESGI{reverse}"
    assert m.find_flag(b"RFTV{ebg13}") == "ESGI{rot13}"
    assert m.find_flag(b"no flag here") == ""


def test_find_flag_reuses_precomputed_texts():
    data = b"..ESGI{cached}.."
    assert m.find_flag(data, collect_texts(data)) == "ESGI{cached}"
