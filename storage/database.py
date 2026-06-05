"""Storage & Data Management Layer.

This module implements the hybrid database layer:
1. Relational database management using SQLAlchemy + SQLite to track operational logs, configuration, and threat metadata.
2. Vector database collection using Qdrant (local/in-memory) with sentence-transformers ('all-MiniLM-L6-v2') embeddings.
3. Semantic Filter to calculate cosine similarity against predefined threat seed concepts to discard noise.
"""

from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels
from sentence_transformers import SentenceTransformer
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, JSON, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Set up logging
logger = logging.getLogger("storage")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# SQLAlchemy base and model definitions
Base = declarative_base()


class IngestionLog(Base):
    """Relational table to log ingestion pipeline executions and statistics."""
    __tablename__ = "ingestion_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    source = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False)  # 'SUCCESS', 'FAILED'
    items_received = Column(Integer, default=0, nullable=False)
    items_filtered = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)


class RelationalThreatMetadata(Base):
    """Relational table to track structured threat record metadata, logs, and computed risk metrics."""
    __tablename__ = "threat_metadata"

    id = Column(String(36), primary_key=True, comment="Maps to the UUID report_id")
    title = Column(String(255), nullable=False)
    source_name = Column(String(100), nullable=False)
    source_url = Column(Text, nullable=False)
    published_at = Column(DateTime, nullable=False)
    ingested_at = Column(DateTime, nullable=False)
    max_semantic_score = Column(Float, nullable=False)
    risk_score = Column(Float, nullable=True, comment="Populated later by Risk Engine")
    operational_status = Column(String(50), default="INGESTED", nullable=False)  # e.g., 'INGESTED', 'PROCESSED', 'FAILED'


class FallbackEncoder:
    """Fallback text encoder using keyword hashing for deterministic unit-vector embeddings when offline."""

    def __init__(self, vector_dim: int = 384):
        self.vector_dim = vector_dim

    def encode(self, texts: List[str], normalize_embeddings: bool = True) -> np.ndarray:
        embeddings = []
        for text in texts:
            words = text.lower().split()
            vec = np.zeros(self.vector_dim)
            for word in words:
                # Use standard hash to map words deterministically
                idx = hash(word) % self.vector_dim
                vec[idx] += 1.0
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec = vec / norm
            else:
                vec = np.ones(self.vector_dim) / np.sqrt(self.vector_dim)
            embeddings.append(vec)
        return np.array(embeddings)


class HybridStorageManager:
    """Manages the lifecycle and operations of both Qdrant and SQLite databases."""

    def __init__(
        self,
        db_url: str = "sqlite:///osint_threats.db",
        qdrant_path: Optional[str] = "./data/qdrant",
        embedding_model_name: str = "all-MiniLM-L6-v2",
        similarity_threshold: float = 0.35,
    ):
        # Initialize SQLite database
        self.engine = create_engine(db_url, echo=False)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

        # Initialize Qdrant Client
        if qdrant_path:
            os.makedirs(qdrant_path, exist_ok=True)
            self.qdrant = QdrantClient(path=qdrant_path)
            logger.info("Qdrant initialized locally at %s", qdrant_path)
        else:
            self.qdrant = QdrantClient(":memory:")
            logger.info("Qdrant initialized in-memory")

        # Initialize Semantic Embedding model
        logger.info("Loading SentenceTransformer model: %s", embedding_model_name)
        self.vector_dim = 384  # Dimension for all-MiniLM-L6-v2
        try:
            self.encoder = SentenceTransformer(embedding_model_name)
            logger.info("SentenceTransformer loaded successfully.")
        except Exception as e:
            logger.warning(
                "Failed to load sentence-transformers model due to network/dependency error: %s. "
                "Falling back to local keyword hash encoder.", str(e)
            )
            self.encoder = FallbackEncoder(self.vector_dim)

        self.collection_name = "threat_reports"
        self._setup_vector_collection()

        # Seed concepts for Semantic Filtering
        self.similarity_threshold = similarity_threshold
        self.seed_concepts = [
            "Ransomware threat cyberattack",
            "Zero-Day vulnerability exploit software patch",
            "Phishing campaign credential harvesting scam",
            "Data breach database leak unauthorized access",
            "Spyware trojan backdoor malware infection",
            "Advanced Persistent Threat APT actor cyber espionage",
            "Denial of Service DDoS server outage traffic flooding",
            "Supply chain attack dependency injection compromise",
        ]
        # Precompute seed embeddings
        self.seed_embeddings = self.encoder.encode(self.seed_concepts, normalize_embeddings=True)

    def _setup_vector_collection(self) -> None:
        """Sets up the Qdrant collection if it doesn't already exist."""
        try:
            collections = self.qdrant.get_collections().collections
            exists = any(c.name == self.collection_name for c in collections)
            if not exists:
                self.qdrant.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=qmodels.VectorParams(
                        size=self.vector_dim,
                        distance=qmodels.Distance.COSINE,
                    ),
                )
                logger.info("Created Qdrant collection '%s'", self.collection_name)
        except Exception as e:
            logger.error("Failed to initialize Qdrant vector collection: %s", str(e), exc_info=True)

    def compute_similarity(self, text: str) -> float:
        """Computes the maximum cosine similarity of input text against seed threat concepts."""
        text_embedding = self.encoder.encode([text], normalize_embeddings=True)[0]
        # Calculate cosine similarity (dot product of normalized vectors)
        similarities = np.dot(self.seed_embeddings, text_embedding)
        return float(np.max(similarities))

    def filter_and_store(self, raw_reports: List[Any]) -> List[Any]:
        """Filters out reports below semantic threshold and stores matching ones in SQL and Vector DBs.

        Arguments:
            raw_reports: List of RawThreatReport model instances.

        Returns:
            List of successfully matching RawThreatReport model instances.
        """
        filtered_reports = []
        db_session = self.SessionLocal()

        for report in raw_reports:
            # Analyze title and summary combined for richer context
            text_to_analyze = f"{report.title} {report.summary}"
            max_score = self.compute_similarity(text_to_analyze)

            if max_score < self.similarity_threshold:
                logger.info(
                    "Report '%s' filtered out. Semantic similarity (%f) < threshold (%f)",
                    report.title, max_score, self.similarity_threshold
                )
                # Log filtered item in Relational Log
                log_entry = IngestionLog(
                    source=report.metadata.source_name,
                    status="FILTERED",
                    items_received=1,
                    items_filtered=1,
                    error_message=f"Similarity score {max_score:.4f} too low.",
                )
                db_session.add(log_entry)
                continue

            filtered_reports.append(report)
            logger.info("Report '%s' passed semantic filter (Score: %f)", report.title, max_score)

            try:
                # 1. Relational Database Insert
                meta_entry = RelationalThreatMetadata(
                    id=str(report.report_id),
                    title=report.title,
                    source_name=report.metadata.source_name,
                    source_url=str(report.metadata.source_url),
                    published_at=report.published_at.replace(tzinfo=None),
                    ingested_at=report.metadata.ingested_at.replace(tzinfo=None),
                    max_semantic_score=max_score,
                    operational_status="INGESTED",
                )
                db_session.add(meta_entry)

                # 2. Vector Database Insert
                embedding = self.encoder.encode([report.content or report.summary])[0].tolist()
                payload = {
                    "report_id": str(report.report_id),
                    "title": report.title,
                    "summary": report.summary,
                    "source_name": report.metadata.source_name,
                    "published_at": report.published_at.isoformat(),
                    "raw_payload": report.raw_payload,
                }
                self.qdrant.upsert(
                    collection_name=self.collection_name,
                    points=[
                        qmodels.PointStruct(
                            id=str(report.report_id),
                            vector=embedding,
                            payload=payload,
                        )
                    ],
                )

                log_entry = IngestionLog(
                    source=report.metadata.source_name,
                    status="SUCCESS",
                    items_received=1,
                    items_filtered=0,
                )
                db_session.add(log_entry)

            except Exception as e:
                db_session.rollback()
                logger.error("Failed storing report '%s' in hybrid database: %s", report.title, str(e), exc_info=True)
                error_log = IngestionLog(
                    source=report.metadata.source_name,
                    status="FAILED",
                    items_received=1,
                    items_filtered=0,
                    error_message=str(e),
                )
                db_session.add(error_log)

        db_session.commit()
        db_session.close()
        return filtered_reports


if __name__ == "__main__":
    # Standard test runner to verify database connections and semantic filtering
    class MockMetadata(BaseModel):
        source_name: str
        source_url: str
        ingested_at: datetime

    class MockReport(BaseModel):
        report_id: Any
        title: str
        summary: str
        content: str
        published_at: datetime
        metadata: MockMetadata
        raw_payload: Dict[str, Any]

    manager = HybridStorageManager(db_url="sqlite:///test_osint_threats.db", qdrant_path="./test_data/qdrant")

    # Sample threat report (Should pass)
    threat_report = MockReport(
        report_id="11111111-2222-3333-4444-555555555555",
        title="New LockBit Ransomware strain spreads via zero-day exploits in VPN servers",
        summary="Security researchers detected a spike in LockBit deployment bypassing enterprise firewalls.",
        content="LockBit ransomware attacks have escalated, utilizing a zero-day exploit targeting network appliances.",
        published_at=datetime.now(timezone.utc),
        metadata=MockMetadata(
            source_name="Mock OSINT",
            source_url="https://mockthreat.example.com/lockbit",
            ingested_at=datetime.now(timezone.utc),
        ),
        raw_payload={"details": "dummy_payload"},
    )

    # Sample noise report (Should be filtered out)
    noise_report = MockReport(
        report_id="66666666-7777-8888-9999-000000000000",
        title="Local company introduces new premium custom coffee maker app with Bluetooth connectivity",
        summary="A local espresso startup launched a mobile app to brew coffee using smart home systems.",
        content="Our smart coffee maker has a simple web interface and bluetooth interface.",
        published_at=datetime.now(timezone.utc),
        metadata=MockMetadata(
            source_name="Mock OSINT",
            source_url="https://mockthreat.example.com/coffee",
            ingested_at=datetime.now(timezone.utc),
        ),
        raw_payload={"details": "dummy_coffee_payload"},
    )

    print("Running filter on mock items...")
    results = manager.filter_and_store([threat_report, noise_report])
    print(f"Filter processing done. Successfully kept: {[r.title for r in results]}")
