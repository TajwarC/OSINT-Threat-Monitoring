"""Threat Reporting & Presentation Layer.

This module implements a Streamlit dashboard visualizing prioritized OSINT threat alerts.
It allows security operators to dynamically adjust priority weights, review extracted entities,
inspect STIX 2.1 configurations, and generate offline PDF intelligence reports using fpdf2.
"""

from datetime import datetime, timezone, timedelta
import json
import logging
import os
import sys
from typing import Any, Dict, List

from fpdf import FPDF
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import streamlit as st

# Setup paths to import project packages
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ingestion.ingestion import RawThreatReport, IngestionMetadata
from storage.database import RelationalThreatMetadata, HybridStorageManager
from nlp.extractor import ThreatExtractor, ThreatEntityMatrix, MitreAttackTactic
from risk.risk_engine import RiskEngine

# Configure logger
logger = logging.getLogger("ui_app")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class ThreatPDFReport(FPDF):
    """Custom FPDF generator for styling PDF threat summaries."""

    def header(self):
        # Draw premium header styling
        self.set_fill_color(22, 28, 45)  # Dark blue banner
        self.rect(0, 0, 210, 35, "F")
        self.set_text_color(255, 255, 255)
        self.set_font("Arial", "B", 18)
        self.cell(0, 15, "OSINT THREAT INTELLIGENCE SUMMARY", ln=True, align="C")
        self.set_font("Arial", "", 10)
        self.cell(0, 5, f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()} | OSINT Threat Monitoring Prototype", align="C")


def get_db_manager() -> HybridStorageManager:
    """Instantiates and returns the DB manager."""
    return HybridStorageManager(db_url="sqlite:///osint_threats.db", qdrant_path="./data/qdrant")


def populate_mock_data_if_empty(manager: HybridStorageManager):
    """Seed DB with high-quality mock threat payloads if DB is empty to demonstrate the dashboard."""
    db_session = manager.SessionLocal()
    count = db_session.query(RelationalThreatMetadata).count()
    if count == 0:
        logger.info("Database empty. Seeding mock intelligence reports for demo purposes...")
        
        extractor = ThreatExtractor()
        
        mock_reports = [
            {
                "title": "APT29 initiates spear-phishing campaign leveraging zero-day in Microsoft Outlook",
                "summary": "Russian state-sponsored actors targeting European government officials with credential harvesting attachments.",
                "content": "European diplomatic entities were targeted in a new campaign attribute to APT29. The threat actor used a zero-day exploit (CVE-2026-1020) to bypass authentication protocols.",
                "source": "CISA TAXII",
                "published_offset_days": 1,
            },
            {
                "title": "New LockBit 4.0 ransomware variant targets enterprise Linux server networks",
                "summary": "Security logs show LockBit decrypting file structures on cloud database clusters.",
                "content": "LockBit has upgraded its execution binary to attack Linux environments, utilizing malicious scripting to terminate recovery routines.",
                "source": "Google News RSS",
                "published_offset_days": 3,
            },
            {
                "title": "Critical RCE vulnerability discovered in widely used open-source VPN controller",
                "summary": "An unauthenticated remote code execution vulnerability tracked as CVE-2026-8843 affects edge systems.",
                "content": "Multiple manufacturers report scanning traffic searching for open VPN controllers. A public POC has been released on GitHub.",
                "source": "NewsAPI",
                "published_offset_days": 5,
            },
            {
                "title": "Lazarus Group executes supply chain attack on critical infrastructure provider",
                "summary": "Intruders tampered with code signing certificates for industrial automation firmware updates.",
                "content": "A supply chain incident allowed threat actors to distribute backdoored utility software, compromising critical distribution routers.",
                "source": "CISA TAXII",
                "published_offset_days": 7,
            },
            {
                "title": "Minor software update released for simple local office network printer drivers",
                "summary": "Driver update resolves paper jam reporting errors on printer dashboards.",
                "content": "A minor patch was pushed to resolve print queue errors and network handshake logs.",
                "source": "Google News RSS",
                "published_offset_days": 2,
            }
        ]

        now = datetime.now(timezone.utc)
        reports_to_store = []
        for index, r in enumerate(mock_reports):
            pub_date = now - timedelta(days=r["published_offset_days"])
            
            # Form raw threat report
            metadata = IngestionMetadata(
                source_name=r["source"],
                source_url=f"https://threats-feed.example.com/{index}",  # type: ignore
                raw_payload_hash=f"mock_hash_{index}",
            )
            
            report = RawThreatReport(
                title=r["title"],
                summary=r["summary"],
                content=r["content"],
                published_at=pub_date,
                metadata=metadata,
                raw_payload={"source_details": r["source"]},
            )
            reports_to_store.append(report)

        # Apply semantic filtering and storage automatically
        manager.filter_and_store(reports_to_store)
        logger.info("Successfully seeded database with %d items.", len(reports_to_store))
    db_session.close()


def generate_pdf(reports: List[Dict[str, Any]], weights: np.ndarray) -> bytes:
    """Compiles list of threats and parameters into a premium PDF document."""
    pdf = ThreatPDFReport()
    pdf.add_page()
    
    # Weights configuration section
    pdf.set_font("Arial", "B", 12)
    pdf.set_text_color(22, 28, 45)
    pdf.cell(0, 8, "1. ACTIVE RISK MATRIX CONFIGURATION", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 6, f"Confidentiality Weight: {weights[0]:.2f}", ln=True)
    pdf.cell(0, 6, f"Integrity Weight: {weights[1]:.2f}", ln=True)
    pdf.cell(0, 6, f"Availability Weight: {weights[2]:.2f}", ln=True)
    pdf.cell(0, 6, f"Asset Criticality Weight: {weights[3]:.2f}", ln=True)
    pdf.ln(10)

    # Threats list section
    pdf.set_font("Arial", "B", 12)
    pdf.set_text_color(22, 28, 45)
    pdf.cell(0, 8, "2. PRIORITIZED SECURITY THREATS", ln=True)
    pdf.ln(2)

    for idx, r in enumerate(reports):
        # Card style header
        pdf.set_fill_color(240, 242, 246)
        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 7, f" #{idx+1} | SCORE: {r['priority_score']:.1f} | {r['title']}", ln=True, fill=True)
        
        # Details body
        pdf.set_font("Arial", "", 9)
        pdf.cell(0, 5, f"Source: {r['source']} | Published: {r['published']}", ln=True)
        pdf.cell(0, 5, f"Max Semantic Cosine Match: {r['semantic_score']:.3f}", ln=True)
        pdf.set_font("Arial", "I", 9)
        pdf.multi_cell(0, 5, f"Summary: {r['summary']}")
        pdf.ln(5)

    return bytes(pdf.output())


def main():
    # Streamlit Config
    st.set_page_config(
        page_title="OSINT AI Threat Monitor",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # CSS Injection for Premium styling
    st.markdown("""
        <style>
        .main { background-color: #0e1117; }
        h1, h2, h3 { color: #f0f2f6 !important; font-family: 'Outfit', 'Inter', sans-serif; }
        .metric-card {
            background-color: #1a1e29;
            border-radius: 8px;
            padding: 15px;
            border: 1px solid #2d313f;
        }
        </style>
    """, unsafe_allow_key_html=True)

    st.title("🛡️ AI-Driven OSINT Threat Monitoring Dashboard")
    st.subheader("Prototype Operator Console")

    # Initialize Backend
    manager = get_db_manager()
    populate_mock_data_if_empty(manager)
    risk_engine = RiskEngine()
    extractor = ThreatExtractor()

    # Sidebar: Model Config and Dynamic Weights tuning
    st.sidebar.header("🔧 Parameters & Weights")
    
    st.sidebar.markdown("### Risk Priority Weights (W_a)")
    w_conf = st.sidebar.slider("Confidentiality weight", 0.0, 1.0, 0.4, 0.05)
    w_integ = st.sidebar.slider("Integrity weight", 0.0, 1.0, 0.3, 0.05)
    w_avail = st.sidebar.slider("Availability weight", 0.0, 1.0, 0.1, 0.05)
    w_asset = st.sidebar.slider("Asset Criticality weight", 0.0, 1.0, 0.2, 0.05)
    
    weights = np.array([w_conf, w_integ, w_avail, w_asset])
    # Normalize weights to sum up to 1.0
    weight_sum = np.sum(weights)
    if weight_sum > 0:
        weights = weights / weight_sum

    st.sidebar.markdown("### Temporal Decay Rate (λ)")
    decay_rate = st.sidebar.slider("Decay Rate (Days)", 0.01, 0.20, 0.05, 0.01)
    risk_engine.decay_rate = decay_rate

    st.sidebar.info(
        f"**Active W_a (Normalized):**\n"
        f"• Conf: {weights[0]:.2f}\n"
        f"• Integ: {weights[1]:.2f}\n"
        f"• Avail: {weights[2]:.2f}\n"
        f"• Asset: {weights[3]:.2f}"
    )

    # Load threat list from SQL DB
    db_session = manager.SessionLocal()
    db_threats = db_session.query(RelationalThreatMetadata).all()
    
    # Calculate priority score on the fly using active weights and decay rates
    processed_threats = []
    now = datetime.now(timezone.utc)

    for db_t in db_threats:
        # Re-fetch vector payload from Qdrant to build accurate threat vectors
        try:
            point = manager.qdrant.retrieve(
                collection_name=manager.collection_name,
                ids=[db_t.id]
            )
            if point:
                payload = point[0].payload
                # Extract entities locally using rule-based/cached parsing if available
                # or pass text block directly to extractor
                summary_text = payload.get("summary", "")
                title_text = payload.get("title", "")
                full_text = f"{title_text} {summary_text}"
                
                # Retrieve structured entities
                entities = extractor.extract_entities(full_text)
                
                # Build vector continuously
                t_vector = risk_engine.calculate_impact_vector(
                    num_targets=len(entities.targets),
                    num_actors=len(entities.threat_actors),
                    num_cves=len(entities.cves),
                    num_tactics=len(entities.mitre_tactics)
                )
                
                # Determine source credibility factor (Rs)
                cred_map = {"CISA TAXII": 1.0, "NewsAPI": 0.8, "Google News RSS": 0.7}
                credibility = cred_map.get(db_t.source_name, 0.6)

                # Calculate priority score
                pub_utc = db_t.published_at.replace(tzinfo=timezone.utc)
                p_score = risk_engine.calculate_priority(
                    impact_vector=t_vector,
                    weights=weights,
                    source_credibility=credibility,
                    published_at=pub_utc,
                    current_time=now
                )
                
                # Update DB score
                db_t.risk_score = p_score
                
                processed_threats.append({
                    "id": db_t.id,
                    "title": db_t.title,
                    "source": db_t.source_name,
                    "published": pub_utc.strftime("%Y-%m-%d %H:%M:%S"),
                    "semantic_score": db_t.max_semantic_score,
                    "priority_score": p_score,
                    "summary": summary_text,
                    "entities": entities,
                    "raw_payload": payload.get("raw_payload", {})
                })
        except Exception as e:
            logger.error("Failed calculating priority for threat %s: %s", db_t.title, str(e))

    # Commit any updated risk scores
    db_session.commit()
    db_session.close()

    # Sort reports by priority score descending
    processed_threats = sorted(processed_threats, key=lambda x: x["priority_score"], reverse=True)

    # Render Dashboard metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="Total Ingested Alerts", value=len(db_threats))
    with col2:
        high_critical = sum(1 for t in processed_threats if t["priority_score"] >= 70.0)
        st.metric(label="High/Critical Risk Alerts (Score >= 70)", value=high_critical)
    with col3:
        avg_score = np.mean([t["priority_score"] for t in processed_threats]) if processed_threats else 0.0
        st.metric(label="Average Priority Score", value=f"{avg_score:.1f}")

    st.markdown("---")

    # Threat Intelligence Feed Table
    st.subheader("🗂️ Prioritized Threat Intelligence Feed")
    if not processed_threats:
        st.info("No threat intelligence data matches current filters.")
    else:
        # Table data representation
        table_data = []
        for idx, t in enumerate(processed_threats):
            table_data.append({
                "Rank": idx + 1,
                "Priority Score": round(t["priority_score"], 1),
                "Title": t["title"],
                "Source": t["source"],
                "Published Date": t["published"],
                "Semantic Similarity": round(t["semantic_score"], 3),
            })
        st.table(table_data)

    st.markdown("---")

    # Detailed Inspection Section
    st.subheader("🔍 Deep Threat Entity & STIX 2.1 Inspection")
    if processed_threats:
        threat_titles = [f"#{t['Rank']} - {t['Title']} (Score: {t['Priority Score']})" for t in table_data]
        selected_index = st.selectbox("Select threat report to inspect details & STIX schema", range(len(threat_titles)), format_func=lambda i: threat_titles[i])
        
        target_threat = processed_threats[selected_index]
        entities = target_threat["entities"]

        det_col1, det_col2 = st.columns(2)
        with det_col1:
            st.markdown("#### Extracted Entity Matrices")
            st.markdown(f"**Targets:** {', '.join(entities.targets) if entities.targets else 'None'}")
            st.markdown(f"**Threat Actors:** {', '.join(entities.threat_actors) if entities.threat_actors else 'None'}")
            st.markdown(f"**CVE Vulnerabilities:** {', '.join(entities.cves) if entities.cves else 'None'}")
            
            st.markdown("**MITRE ATT&CK Tactics:**")
            if entities.mitre_tactics:
                for mt in entities.mitre_tactics:
                    st.markdown(f"- **[{mt.technique_id}]** {mt.technique_name} *(Tactic: {mt.tactic_name})*")
            else:
                st.markdown("*No MITRE tactics extracted*")

        with det_col2:
            st.markdown("#### STIX 2.1 CTI Graph Representation")
            stix_bundle_json = extractor.map_to_stix(entities, target_threat["title"])
            st.code(stix_bundle_json, language="json")

        st.markdown("---")

        # Exporter Section
        st.subheader("📄 Report Exporting")
        pdf_bytes = generate_pdf(processed_threats, weights)
        st.download_button(
            label="Download Dashboard Threat Summary (PDF)",
            data=pdf_bytes,
            file_name="OSINT_Threat_Summary_Report.pdf",
            mime="application/pdf"
        )


if __name__ == "__main__":
    main()
