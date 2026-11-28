"""Confianza (Confidence) en el score de postura: TENTATIVE pesa la mitad,
CERTAIN y FIRM pesan igual que antes (= no cambia el comportamiento previo
a esta feature, donde todo era implícitamente FIRM)."""
from __future__ import annotations

from nexrecon.models import Confidence, HostResult, Severity


def _host_with_finding(severity, confidence):
    host = HostResult(hostname="t.example")
    host.add_finding("algo", severity, module="x", confidence=confidence)
    return host


def test_tentative_medium_gives_half_the_penalty_of_firm_medium():
    from nexrecon.modules import posture

    firm = _host_with_finding(Severity.MEDIUM, Confidence.FIRM)
    tentative = _host_with_finding(Severity.MEDIUM, Confidence.TENTATIVE)

    posture.compute_score(firm)
    posture.compute_score(tentative)

    firm_penalty = firm.score - 60
    tentative_penalty = tentative.score - 60
    assert firm_penalty == -6
    assert tentative_penalty == -3
    assert tentative_penalty == round(firm_penalty / 2)


def test_certain_and_firm_score_identically():
    from nexrecon.modules import posture

    certain = _host_with_finding(Severity.HIGH, Confidence.CERTAIN)
    firm = _host_with_finding(Severity.HIGH, Confidence.FIRM)

    posture.compute_score(certain)
    posture.compute_score(firm)

    assert certain.score == firm.score


def test_add_finding_defaults_to_firm_confidence():
    host = HostResult(hostname="t.example")
    host.add_finding("algo", Severity.LOW, module="x")
    assert host.findings[0].confidence == Confidence.FIRM


def test_finding_without_confidence_arg_defaults_to_firm():
    from nexrecon.models import Finding

    f = Finding(title="t", severity=Severity.LOW)
    assert f.confidence == Confidence.FIRM


def test_vulnmatch_defaults_source_vuln_db_and_confidence_firm():
    from nexrecon.models import VulnMatch

    v = VulnMatch(technology="jQuery", detected_version="1.0", fixed_in="3.5.0",
                  cve="CVE-X", description="d", reference="r")
    assert v.source == "vuln_db"
    assert v.confidence == Confidence.FIRM
    assert v.cvss == ""
