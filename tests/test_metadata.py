import hashlib

from tp2.metadata import detect_file_type, get_file_metadata, shannon_entropy


def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9


def test_detect_file_type_recognises_pe_and_text(pe_bytes):
    assert "PE32" in detect_file_type(pe_bytes)
    assert "text" in detect_file_type(b"hello world\n").lower()


def test_get_file_metadata_hashes_and_size(pe_bytes):
    meta = get_file_metadata(pe_bytes)
    assert meta["sha256"] == hashlib.sha256(pe_bytes).hexdigest()
    assert meta["md5"] == hashlib.md5(pe_bytes).hexdigest()
    assert meta["size"] == len(pe_bytes)
    assert "PE32" in meta["file_type"]
    assert 0 < meta["entropy"] < 8
    assert set(meta) == {"sha256", "md5", "size", "file_type", "entropy"}
