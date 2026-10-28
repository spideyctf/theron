"""OSV identity grouping and severity interpretation; no vulnerability data is hardcoded."""

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from scanner.models import Severity


def group_advisories(records):
    groups = []
    for record in records:
        if record.get("withdrawn"):
            continue
        identities = {record["id"]} | {alias for alias in record.get("aliases", []) if isinstance(alias, str)}
        matching = [group for group in groups if group[0] & identities]
        members = [record]
        for group in matching:
            identities |= group[0]
            members.extend(group[1])
            groups.remove(group)
        groups.append((identities, members))
    for identities, members in sorted(groups, key=lambda group: sorted(group[0])):
        members.sort(key=lambda record: (not record["id"].startswith("GHSA-"), record["id"]))
        canonical = next((value for value in sorted(identities) if value.startswith("CVE-")), members[0]["id"])
        yield canonical, sorted(identities), members


def advisory_severity(record):
    metadata = [record.get("database_specific") or {}]
    metadata += [affected.get("ecosystem_specific") or {} for affected in record.get("affected", [])]
    names = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    for entry in metadata:
        name = entry.get("severity") if isinstance(entry, dict) else None
        if isinstance(name, str) and name.upper() in names:
            return names[name.upper()], "advisory-metadata"
    scores = []
    for entry in record.get("severity", []):
        try:
            vector = entry["score"]
            parser = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}.get(entry.get("type"))
            if parser:
                scores.append(float(parser(vector).scores()[0]))
        except (ValueError, TypeError, KeyError, CVSSError):
            continue
    if scores:
        score = max(scores)
        return (Severity.CRITICAL if score >= 9 else Severity.HIGH if score >= 7 else Severity.MEDIUM if score >= 4 else Severity.LOW), "cvss-base-score"
    return Severity.MEDIUM, "provisional-unknown"


def group_severity(members):
    for record in members:
        severity, source = advisory_severity(record)
        if source != "provisional-unknown":
            return severity, source
    return Severity.MEDIUM, "provisional-unknown"
