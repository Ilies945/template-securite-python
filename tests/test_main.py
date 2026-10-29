import json

import helpers
from tp2 import main as m

CONTRACT_KEYS = ["sha256", "md5", "size", "entropy", "file_type", "iocs", "imports", "yara_matches",
                 "family_guess", "mitre_attack", "llm_summary", "score", "flag"]


def make_samples(tmp_path, pe_bytes):
    samples = tmp_path / "samples"
    (samples / "nested").mkdir(parents=True)
    (samples / "a.exe").write_bytes(pe_bytes)
    (samples / "nested" / "b.txt").write_text("rien à signaler\n")
    (samples / ".hidden").write_text("ignoré")
    return samples


def test_list_samples_recursive_sorted_and_skips_hidden(tmp_path, pe_bytes):
    samples = make_samples(tmp_path, pe_bytes)
    assert [p.name for p in m.list_samples(samples)] == ["a.exe", "b.txt"]
    assert m.list_samples(samples / "a.exe") == [samples / "a.exe"]


def test_build_parser_requires_three_options(tmp_path):
    args = m.build_parser().parse_args(["--samples", "s", "--rules", "r", "--out", "o"])
    assert (str(args.samples), str(args.rules), str(args.out)) == ("s", "r", "o")


def test_run_writes_one_json_per_sample(tmp_path, pe_bytes):
    samples, out = make_samples(tmp_path, pe_bytes), tmp_path / "out"
    assert m.run(samples, tmp_path / 'rules', out) == 2
    files = sorted(out.glob("*.json"))
    assert len(files) == 2
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        assert list(data) == CONTRACT_KEYS
        assert f.name == data["sha256"] + ".json"
        assert list(data["iocs"]) == ["domains", "ips", "urls", "mutex", "registry"]
        assert isinstance(data["score"], int) and 0 <= data["score"] <= 10


def test_run_is_deterministic(tmp_path, pe_bytes):
    samples = make_samples(tmp_path, pe_bytes)
    m.run(samples, tmp_path / 'rules', tmp_path / "o1")
    m.run(samples, tmp_path / 'rules', tmp_path / "o2")
    for f in (tmp_path / "o1").glob("*.json"):
        assert f.read_bytes() == (tmp_path / "o2" / f.name).read_bytes()


def test_run_survives_unreadable_sample(tmp_path, pe_bytes, monkeypatch):
    samples = make_samples(tmp_path, pe_bytes)
    real = m.analyze_file

    def flaky(path, rules, client):
        if path.name == "a.exe":
            raise OSError("illisible")
        return real(path, rules, client)

    monkeypatch.setattr(m, "analyze_file", flaky)
    assert m.run(samples, tmp_path / 'rules', tmp_path / "out") == 1


def test_run_with_empty_rules_dir_still_works(tmp_path, pe_bytes):
    samples, empty = make_samples(tmp_path, pe_bytes), tmp_path / "norules"
    empty.mkdir()
    assert m.run(samples, empty, tmp_path / "out") == 2


def test_main_cli(tmp_path, pe_bytes):
    samples = make_samples(tmp_path, pe_bytes)
    argv = ["--samples", str(samples), "--rules", str(tmp_path / 'rules'), "--out", str(tmp_path / "out")]
    assert m.main(argv) == 0
    assert len(list((tmp_path / "out").glob("*.json"))) == 2
    assert m.main(["--samples", str(tmp_path / "absent"), "--rules", "r", "--out", str(tmp_path / "o")]) == 2
