"""
OSCAL (Open Security Controls Assessment Language) Exporter
Generates NIST OSCAL Assessment Results (AR) documents from cATO assessment data.

OSCAL version: 1.1.2
Reference: https://pages.nist.gov/OSCAL/
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _new_uuid() -> str:
    return str(uuid.uuid4())


def _oscal_datetime(dt: Optional[datetime] = None) -> str:
    """Return an OSCAL-compliant RFC 3339 datetime string."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _control_id_to_oscal(control_id: str) -> str:
    """Convert 'AC-2' → 'ac-2' (OSCAL uses lowercase)."""
    return control_id.lower()


def _status_to_oscal_state(status: str) -> str:
    """Map cATO ComplianceStatus values to OSCAL finding target states."""
    mapping = {
        "Implemented": "satisfied",
        "Partially Implemented": "not-satisfied",
        "Not Implemented": "not-satisfied",
        "Not Assessed": "not-satisfied",
    }
    return mapping.get(status, "not-satisfied")


def _risk_score_to_likelihood(risk_score: int) -> str:
    """Map numeric risk score (0–100) to OSCAL likelihood facet value."""
    if risk_score <= 30:
        return "low"
    if risk_score <= 60:
        return "moderate"
    return "high"


def _risk_score_to_impact(risk_score: int) -> str:
    """Map numeric risk score (0–100) to OSCAL impact facet value."""
    if risk_score <= 25:
        return "low"
    if risk_score <= 55:
        return "moderate"
    return "high"


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

def build_oscal_assessment_results(
    assessments: List[Dict],
    metadata: Optional[Dict] = None,
    system_name: str = "AKS Cluster",
) -> Dict:
    """
    Build a complete OSCAL Assessment Results (AR) document from cATO
    assessment data.

    Parameters
    ----------
    assessments:
        List of serialized ControlAssessment dicts (as returned by the API).
    metadata:
        Optional dict with keys: cluster_name, framework, assessment_type,
        generated_date, ai_enhanced.
    system_name:
        Human-readable name of the assessed system.

    Returns
    -------
    dict
        Full OSCAL AR document ready for JSON serialisation.
    """
    meta = metadata or {}
    now = _oscal_datetime()
    doc_uuid = _new_uuid()
    result_uuid = _new_uuid()
    tool_party_uuid = _new_uuid()
    assessor_role_uuid = _new_uuid()

    # ---- Per-control OSCAL objects ----------------------------------------
    observations: List[Dict] = []
    findings: List[Dict] = []
    risks: List[Dict] = []

    # Track which observation UUIDs belong to each control for cross-linking
    control_observation_map: Dict[str, List[str]] = {}
    control_risk_map: Dict[str, List[str]] = {}

    for assessment in assessments:
        ctrl_id = assessment.get("control_id", "UNKNOWN")
        oscal_ctrl_id = _control_id_to_oscal(ctrl_id)
        status = assessment.get("status", "Not Assessed")
        risk_score = assessment.get("risk_score", 50)
        narrative = assessment.get("implementation_narrative", "")
        gaps = assessment.get("gaps", [])
        recommendations = assessment.get("recommendations", [])
        last_assessed_raw = assessment.get("last_assessed")
        evidence_ids = assessment.get("evidence_ids", [])

        try:
            assessed_dt = datetime.fromisoformat(last_assessed_raw)
        except (TypeError, ValueError):
            assessed_dt = None

        # -- Observation (one per control, summarises evidence) --------------
        obs_uuid = _new_uuid()
        relevant_evidence = [
            {"description": eid} for eid in evidence_ids
        ]
        if not relevant_evidence:
            relevant_evidence = [{"description": "No specific evidence references recorded."}]

        observation = {
            "uuid": obs_uuid,
            "title": f"Observation for {ctrl_id}: {assessment.get('control_name', '')}",
            "description": narrative or f"Assessment observation for control {ctrl_id}.",
            "methods": ["EXAMINE", "INTERVIEW"],
            "types": ["finding"],
            "collected": _oscal_datetime(assessed_dt),
            "relevant-evidence": relevant_evidence,
            "remarks": f"Control family: {assessment.get('family', 'N/A')}. "
                       f"Risk score: {risk_score}/100.",
        }
        observations.append(observation)
        control_observation_map[ctrl_id] = [obs_uuid]

        # -- Risks (one per gap, or one summary risk if no gaps) -------------
        gap_risk_uuids: List[str] = []
        items_to_risk = gaps if gaps else (
            [] if status == "Implemented" else [f"Control {ctrl_id} is not fully implemented."]
        )
        for gap in items_to_risk:
            risk_uuid = _new_uuid()
            risk_entry = {
                "uuid": risk_uuid,
                "title": f"Risk: {ctrl_id} – {gap[:80]}",
                "description": gap,
                "statement": gap,
                "status": "open",
                "characterizations": [
                    {
                        "origin": {
                            "actors": [
                                {
                                    "type": "tool",
                                    "actor-uuid": tool_party_uuid,
                                }
                            ]
                        },
                        "facets": [
                            {
                                "name": "likelihood",
                                "system": "http://csrc.nist.gov/ns/oscal/assessment-common/risk-metric",
                                "value": _risk_score_to_likelihood(risk_score),
                            },
                            {
                                "name": "impact",
                                "system": "http://csrc.nist.gov/ns/oscal/assessment-common/risk-metric",
                                "value": _risk_score_to_impact(risk_score),
                            },
                        ],
                    }
                ],
                "mitigating-factors": [
                    {"description": rec}
                    for rec in recommendations
                ] or [{"description": "No specific mitigations recorded."}],
            }
            risks.append(risk_entry)
            gap_risk_uuids.append(risk_uuid)

        control_risk_map[ctrl_id] = gap_risk_uuids

        # -- Finding (one per control) ---------------------------------------
        finding_uuid = _new_uuid()
        oscal_state = _status_to_oscal_state(status)
        finding = {
            "uuid": finding_uuid,
            "title": f"Finding: {ctrl_id} – {assessment.get('control_name', '')}",
            "description": (
                f"Control {ctrl_id} assessed as '{status}'. "
                + (f"Risk score: {risk_score}/100. " if risk_score else "")
                + (narrative[:300] if narrative else "")
            ),
            "target": {
                "type": "statement-id",
                "target-id": f"{oscal_ctrl_id}_smt",
                "title": assessment.get("control_name", ctrl_id),
                "description": narrative or f"Implementation status: {status}.",
                "status": {
                    "state": oscal_state,
                    "reason": status,
                    "remarks": "; ".join(gaps) if gaps else "No gaps identified.",
                },
            },
            "related-observations": [
                {"observation-uuid": obs_uuid}
                for obs_uuid in control_observation_map[ctrl_id]
            ],
        }
        if gap_risk_uuids:
            finding["related-risks"] = [
                {"risk-uuid": ruuid} for ruuid in gap_risk_uuids
            ]

        findings.append(finding)

    # ---- Reviewed controls list -------------------------------------------
    include_controls = [
        {"control-id": _control_id_to_oscal(a.get("control_id", ""))}
        for a in assessments
        if a.get("control_id")
    ]

    # ---- Assemble the full OSCAL AR document ------------------------------
    framework = meta.get("framework", "NIST 800-53 Rev 5")
    cluster_name = meta.get("cluster_name", system_name)

    oscal_doc = {
        "assessment-results": {
            "uuid": doc_uuid,
            "metadata": {
                "title": f"cATO Assessment Results – {cluster_name}",
                "last-modified": now,
                "version": "1.0",
                "oscal-version": "1.1.2",
                "remarks": (
                    f"Generated by gataisha-ai Continuous ATO Agent. "
                    f"Framework: {framework}. "
                    f"AI-enhanced: {meta.get('ai_enhanced', False)}."
                ),
                "roles": [
                    {
                        "id": "assessor",
                        "title": "Assessor",
                    },
                    {
                        "id": "assessment-tool",
                        "title": "Assessment Tool",
                    },
                ],
                "parties": [
                    {
                        "uuid": tool_party_uuid,
                        "type": "organization",
                        "name": "gataisha-ai cATO Agent",
                        "remarks": "Automated continuous compliance assessment tool.",
                    }
                ],
                "responsible-parties": [
                    {
                        "role-id": "assessment-tool",
                        "party-uuids": [tool_party_uuid],
                    }
                ],
            },
            "import-ap": {
                "href": "#",
                "remarks": "Assessment plan is embedded within this document.",
            },
            "results": [
                {
                    "uuid": result_uuid,
                    "title": f"Assessment Results – {cluster_name}",
                    "description": (
                        f"Continuous ATO assessment of {cluster_name} against "
                        f"{framework}. {len(assessments)} controls evaluated."
                    ),
                    "start": meta.get("generated_date", now),
                    "end": now,
                    "reviewed-controls": {
                        "description": f"Controls reviewed against {framework}.",
                        "control-selections": [
                            {
                                "description": "All assessed NIST 800-53 Rev 5 controls.",
                                "include-controls": include_controls,
                            }
                        ],
                    },
                    "observations": observations,
                    "findings": findings,
                    "risks": risks,
                    "remarks": (
                        f"Assessment generated on {now}. "
                        f"Total controls: {len(assessments)}."
                    ),
                }
            ],
        }
    }

    return oscal_doc
