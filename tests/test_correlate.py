from ghostsoc.correlate import chain, dedupe
from ghostsoc.findings import Finding, Severity


def _f(tool, rule, sev, asset, category):
    return Finding(tool=tool, rule_id=rule, title=rule, severity=sev, asset=asset, category=category)


def test_dedupe_collapses_same_fingerprint_keeping_loudest():
    findings = [
        _f("ghostdlp", "dlp.credential", Severity.MEDIUM, "api.example.com", "data-leak"),
        _f("ghostdlp", "dlp.credential", Severity.HIGH, "api.example.com", "data-leak"),
    ]
    out = dedupe(findings)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_dedupe_keeps_distinct_findings():
    findings = [
        _f("ghostrecon", "recon.host", Severity.INFO, "a.example.com", "recon"),
        _f("ghostrecon", "recon.host", Severity.INFO, "b.example.com", "recon"),
    ]
    assert len(dedupe(findings)) == 2


def test_chain_lifts_exposure_plus_secret_on_same_host():
    findings = [
        _f("ghostrecon", "recon.open_service", Severity.MEDIUM, "api.example.com:8080", "attack-surface"),
        _f("ghostdlp", "dlp.credential", Severity.HIGH, "api.example.com", "data-leak"),
    ]
    chains = chain(findings)
    assert len(chains) == 1
    c = chains[0]
    assert c.asset == "api.example.com"
    assert c.severity == Severity.CRITICAL
    assert set(c.tools) == {"ghostrecon", "ghostdlp"}


def test_chain_leaves_a_lone_finding_at_its_own_severity():
    findings = [_f("ghostmap", "xss.reflected", Severity.MEDIUM, "http://x/y:1", "dast")]
    chains = chain(findings)
    assert len(chains) == 1
    assert chains[0].severity == Severity.MEDIUM


def test_chain_does_not_lift_two_findings_of_the_same_role():
    findings = [
        _f("ghostrecon", "recon.host", Severity.LOW, "api.example.com", "recon"),
        _f("ghostrecon", "recon.subdomain", Severity.LOW, "api.example.com", "attack-surface"),
    ]
    chains = chain(findings)
    assert chains[0].severity == Severity.LOW
