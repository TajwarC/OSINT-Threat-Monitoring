"""AI & Natural Language Processing Layer.

This module uses the 'instructor' library paired with a local LLM client (Ollama/OpenAI compatible)
to parse threat text blocks and extract structured entity matrices (Targets, Threat Actors, CVEs, MITRE ATT&CK)
under a strict Pydantic JSON schema. It then translates these entities into valid STIX 2.1 bundles.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import uuid

import instructor
from openai import OpenAI
from pydantic import BaseModel, Field
import stix2

# Configure logger
logger = logging.getLogger("extractor")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class MitreAttackTactic(BaseModel):
    """Structured representation of a MITRE ATT&CK tactic and technique."""
    tactic_name: str = Field(..., description="Name of the MITRE ATT&CK tactic, e.g., Initial Access, Execution, Command and Control")
    technique_id: str = Field(..., description="The technique ID matching MITRE taxonomy, e.g., T1190, T1566.002")
    technique_name: str = Field(..., description="The matching technique name, e.g., Exploit Public-Facing Application")


class ThreatEntityMatrix(BaseModel):
    """Pydantic schema to extract and classify the core entity matrices from unstructured text."""
    targets: List[str] = Field(default_factory=list, description="Target organizations, industry sectors, software packages, or geographic regions affected.")
    threat_actors: List[str] = Field(default_factory=list, description="Identified threat groups, APT names, intrusion sets, or aliases (e.g., APT29, Cozy Bear, Lazarus).")
    cves: List[str] = Field(default_factory=list, description="CVE vulnerability identifiers associated with the attack vectors (e.g., CVE-2024-3094).")
    mitre_tactics: List[MitreAttackTactic] = Field(default_factory=list, description="Extracted MITRE ATT&CK tactics and techniques applied during execution.")


class ThreatExtractor:
    """Orchestrates structured LLM entity extraction and maps outputs to CTI STIX structures."""

    def __init__(self, ollama_url: str = "http://localhost:11434/v1", model_name: str = "llama3.1:8b"):
        self.model_name = model_name
        self.client = instructor.from_openai(
            OpenAI(
                base_url=ollama_url,
                api_key="ollama",  # Standard API key placeholder for local Ollama server
            )
        )
        logger.info("ThreatExtractor initialized pointing to local model '%s' at %s", model_name, ollama_url)

    def _generate_offline_mock_entities(self, text: str) -> ThreatEntityMatrix:
        """Fallback rule-based heuristic extractor if Ollama server is offline."""
        logger.warning("Using local rule-based heuristic extraction due to LLM endpoint timeout/error.")
        text_lower = text.lower()
        
        # Simple string-matching dictionaries to mock extraction safely
        targets = []
        if "vpn" in text_lower or "firewall" in text_lower:
            targets.append("Enterprise VPN Infrastructures")
        if "saas" in text_lower or "cloud" in text_lower:
            targets.append("SaaS Platforms")
        if "fortune" in text_lower or "enterprise" in text_lower:
            targets.append("Fortune 500 Corporate Networks")
        if not targets:
            targets.append("Unknown Target System")

        actors = []
        if "lockbit" in text_lower:
            actors.append("LockBit Ransomware Group")
        if "lazarus" in text_lower:
            actors.append("Lazarus Group (APT38)")
        if "cozy" in text_lower or "apt29" in text_lower:
            actors.append("Cozy Bear (APT29)")
        if not actors:
            actors.append("Unknown Threat Actor")

        cves = []
        import re
        cve_pattern = re.compile(r"cve-\d{4}-\d{4,7}", re.IGNORECASE)
        found_cves = cve_pattern.findall(text_lower)
        if found_cves:
            cves.extend([c.upper() for c in found_cves])
        else:
            if "zero-day" in text_lower:
                cves.append("CVE-2026-TEMP-ZDAY")

        tactics = []
        if "phishing" in text_lower:
            tactics.append(MitreAttackTactic(tactic_name="Initial Access", technique_id="T1566", technique_name="Phishing"))
        if "exploit" in text_lower or "zero-day" in text_lower:
            tactics.append(MitreAttackTactic(tactic_name="Initial Access", technique_id="T1190", technique_name="Exploit Public-Facing Application"))
        if "worm" in text_lower or "malware" in text_lower:
            tactics.append(MitreAttackTactic(tactic_name="Execution", technique_id="T1204", technique_name="User Execution"))
        if not tactics:
            tactics.append(MitreAttackTactic(tactic_name="Execution", technique_id="T1059", technique_name="Command and Scripting Interpreter"))

        return ThreatEntityMatrix(
            targets=targets,
            threat_actors=actors,
            cves=cves,
            mitre_tactics=tactics,
        )

    def extract_entities(self, text: str) -> ThreatEntityMatrix:
        """Leverages instructor + LLM to parse raw text and return structured entities."""
        prompt = (
            "You are a cyber threat intelligence analyst. Read this OSINT report and extract target matrices, "
            "threat actors, CVE vulnerabilities, and MITRE ATT&CK tactics/techniques.\n\n"
            f"OSINT Threat Report:\n{text}"
        )

        try:
            # Enforce 8-second timeout for local Ollama check to prevent blocking pipelines
            result = self.client.chat.completions.create(
                model=self.model_name,
                response_model=ThreatEntityMatrix,
                messages=[{"role": "user", "content": prompt}],
                validation_context={"text": text},
                timeout=8.0,
            )
            logger.info("Successfully extracted entities using Instructor model.")
            return result
        except Exception as e:
            # Resilient fallback handler to prevent execution interruption
            logger.debug("Ollama communication trace: %s", str(e))
            return self._generate_offline_mock_entities(text)

    def map_to_stix(self, entity_matrix: ThreatEntityMatrix, report_title: str) -> str:
        """Converts extracted entity matrices into a valid STIX 2.1 JSON bundle string."""
        stix_objects = []

        # 1. Create Identity object for Target assets
        target_identities = []
        for target in entity_matrix.targets:
            identity = stix_2_obj = stix2.Identity(
                name=target,
                identity_class="class",
                description="Targeted organization or asset class"
            )
            target_identities.append(identity)
            stix_objects.append(identity)

        # 2. Create Threat Actor objects
        actors = []
        for actor in entity_matrix.threat_actors:
            stix_actor = stix2.ThreatActor(
                name=actor,
                description="Threat actor group extracting target infrastructure"
            )
            actors.append(stix_actor)
            stix_objects.append(stix_actor)

        # 3. Create Vulnerability objects for CVEs
        vulnerabilities = []
        for cve in entity_matrix.cves:
            vuln = stix2.Vulnerability(
                name=cve,
                description=f"Vulnerability identified: {cve}"
            )
            vulnerabilities.append(vuln)
            stix_objects.append(vuln)

        # 4. Create Attack Pattern objects for MITRE tactics/techniques
        patterns = []
        for mitre in entity_matrix.mitre_tactics:
            pattern = stix2.AttackPattern(
                name=mitre.technique_name,
                external_references=[
                    {
                        "source_name": "mitre-attack",
                        "external_id": mitre.technique_id
                    }
                ],
                description=f"MITRE Tactic: {mitre.tactic_name}"
            )
            patterns.append(pattern)
            stix_objects.append(pattern)

        # 5. Establish Relationships
        # Link Threat Actor -> targets -> Identity
        for actor in actors:
            for identity in target_identities:
                rel = stix2.Relationship(
                    relationship_type="targets",
                    source_ref=actor.id,
                    target_ref=identity.id
                )
                stix_objects.append(rel)

        # Link Threat Actor -> exploits -> Vulnerability
        for actor in actors:
            for vuln in vulnerabilities:
                rel = stix2.Relationship(
                    relationship_type="uses",
                    source_ref=actor.id,
                    target_ref=vuln.id
                )
                stix_objects.append(rel)

        # Link Threat Actor -> uses -> Attack Pattern
        for actor in actors:
            for pattern in patterns:
                rel = stix2.Relationship(
                    relationship_type="uses",
                    source_ref=actor.id,
                    target_ref=pattern.id
                )
                stix_objects.append(rel)

        # Bundle it up
        try:
            bundle = stix2.Bundle(objects=stix_objects) if stix_objects else stix2.Bundle(objects=[])
            return str(bundle)
        except Exception as e:
            logger.error("Failed creating STIX 2.1 Bundle JSON: %s", str(e), exc_info=True)
            # Safe empty bundle structure fallback
            return json.dumps({
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": []
            })


if __name__ == "__main__":
    # Test script for extraction layer verifying schemas and STIX compilation
    extractor = ThreatExtractor()
    sample_text = (
        "Lazarus Group launches a new cyberattack targeting defense contractors' VPN endpoints, "
        "exploiting a critical zero-day vulnerability tracked as CVE-2026-9999. They deployed a custom worm "
        "using phishing techniques for initial entry."
    )

    print("Running NLP Entity Extraction...")
    matrix = extractor.extract_entities(sample_text)
    print("\n--- Extracted Entity Matrix ---")
    print(f"Targets: {matrix.targets}")
    print(f"Threat Actors: {matrix.threat_actors}")
    print(f"CVEs: {matrix.cves}")
    print("MITRE ATT&CK:")
    for t in matrix.mitre_tactics:
        print(f"  - [{t.technique_id}] {t.technique_name} (Tactic: {t.tactic_name})")

    print("\nCompiling to STIX 2.1 Bundle...")
    stix_json = extractor.map_to_stix(matrix, "Lazarus defense report")
    print(f"STIX Output (truncated): {stix_json[:500]}...")
