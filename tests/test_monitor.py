import datetime as dt
import json
from pathlib import Path
import pytest
from monitor.core import AdvisoryUnavailable, normalize, update_report

DEP = {"ecosystem": "PyPI", "name": "sample", "version": "1.0"}

def test_normalizes_and_distinguishes_empty_response():
    empty = normalize(DEP, {})
    assert empty["observation"] == "no_advisory_returned"
    assert empty["advisories"] == []
    result = normalize(DEP, {"vulns": [{"id": "OSV-2", "aliases": ["CVE-2"], "references": [{"url": "https://osv.dev/vulnerability/OSV-2"}]}]})
    assert result["observation"] == "advisories_returned"
    assert result["advisories"][0]["id"] == "OSV-2"

def test_timestamp_only_does_not_rewrite(tmp_path):
    source = tmp_path / "deps.json"; output = tmp_path / "report.json"
    source.write_text(json.dumps([DEP]), encoding="utf-8")
    fetch = lambda dep: {}
    assert update_report(source, output, fetch, dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
    before = output.read_text()
    assert not update_report(source, output, fetch, dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc))
    assert output.read_text() == before

def test_failure_preserves_previous_report(tmp_path):
    source = tmp_path / "deps.json"; output = tmp_path / "report.json"
    source.write_text(json.dumps([DEP]), encoding="utf-8")
    output.write_text('{"preserved": true}\n', encoding="utf-8")
    def fail(dep): raise AdvisoryUnavailable("offline")
    with pytest.raises(AdvisoryUnavailable): update_report(source, output, fail)
    assert json.loads(output.read_text()) == {"preserved": True}
