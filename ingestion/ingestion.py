"""Data Ingestion & Collection Layer.

This module implements asynchronous workers to poll and ingest unstructured threat reports
and Cyber Threat Intelligence (CTI) feeds from NewsAPI, Google News RSS, and CISA TAXII servers.
It defines a strict Pydantic model to enforce runtime payload safety and unify data fields.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from feedparser import FeedParserDict
import feedparser
import httpx
from pydantic import BaseModel, Field, HttpUrl
from taxii2client.v21 import Collection, Server

# Configure logger
logger = logging.getLogger("ingestion")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class IngestionMetadata(BaseModel):
    """Source validation metadata for tracking ingestion provenance."""
    source_name: str = Field(..., description="Name of the source provider (e.g., NewsAPI, Google News RSS, CISA TAXII)")
    source_url: HttpUrl = Field(..., description="The original URL of the article or feed endpoint")
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of when ingestion occurred")
    raw_payload_hash: str = Field(..., description="MD5/SHA256 or UUID based hash of raw payload for deduplication")


class RawThreatReport(BaseModel):
    """Unified data contract representing raw unstructured threat data from external feeds."""
    report_id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique identifier for the report")
    title: str = Field(..., description="Title or headline of the threat report")
    summary: str = Field(..., description="Short summary or abstract of the raw text content")
    content: str = Field(..., description="Full text block or raw content details")
    published_at: datetime = Field(..., description="Publishing datetime from the source feed")
    metadata: IngestionMetadata = Field(..., description="Provenance and source metadata")
    raw_payload: Dict[str, Any] = Field(..., description="The raw, unmapped payload dictionary for debugging and extraction stage")


class NewsApiWorker:
    """Asynchronous worker to scrape cybersecurity news using NewsAPI."""

    def __init__(self, api_key: str, query: str = "cybersecurity OR vulnerability OR cyberattack", page_size: int = 20):
        self.api_key = api_key
        self.query = query
        self.page_size = page_size
        self.url = "https://newsapi.org/v2/everything"

    async def fetch_reports(self) -> List[RawThreatReport]:
        """Polls NewsAPI asynchronously and maps results into RawThreatReport models."""
        if not self.api_key or self.api_key == "PLACEHOLDER":
            logger.warning("NewsAPI key not configured. Skipping NewsAPI worker.")
            return []

        params = {
            "q": self.query,
            "pageSize": self.page_size,
            "sortBy": "publishedAt",
            "apiKey": self.api_key,
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(self.url, params=params)
                response.raise_for_status()
                data = response.json()

            articles = data.get("articles", [])
            reports: List[RawThreatReport] = []

            for art in articles:
                # Basic validation: ensure essential fields exist
                title = art.get("title")
                url_str = art.get("url")
                if not title or not url_str:
                    continue

                # Parse publication date
                published_str = art.get("publishedAt")
                published_at = (
                    datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                    if published_str
                    else datetime.now(timezone.utc)
                )

                # Generate a unique hash for metadata validation
                payload_hash = str(uuid.uuid5(uuid.NAMESPACE_URL, url_str))

                meta = IngestionMetadata(
                    source_name="NewsAPI",
                    source_url=url_str,  # type: ignore (Pydantic auto-coerces to HttpUrl)
                    raw_payload_hash=payload_hash,
                )

                report = RawThreatReport(
                    title=title,
                    summary=art.get("description") or "",
                    content=art.get("content") or "",
                    published_at=published_at,
                    metadata=meta,
                    raw_payload=art,
                )
                reports.append(report)

            logger.info("Successfully ingested %d articles from NewsAPI", len(reports))
            return reports

        except Exception as e:
            logger.error("Failed fetching articles from NewsAPI: %s", str(e), exc_info=True)
            return []


class GoogleNewsRssWorker:
    """Asynchronous worker to poll Google News RSS feeds using feedparser."""

    def __init__(self, query: str = "cybersecurity"):
        # Google News RSS URL with search query
        self.feed_url = f"https://news.google.com/rss/search?q={query}&hl=en-US&gl=US&ceid=US:en"

    async def fetch_reports(self) -> List[RawThreatReport]:
        """Polls Google News RSS asynchronously, parses contents, and maps to data contract."""
        try:
            # Fetch XML feed over async HTTP
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(self.feed_url)
                response.raise_for_status()
                xml_content = response.text

            # Parse the XML structure using feedparser in an executor to avoid blocking the event loop
            feed: FeedParserDict = await asyncio.to_thread(feedparser.parse, xml_content)
            reports: List[RawThreatReport] = []

            for entry in feed.entries:
                title = entry.get("title", "")
                link = entry.get("link", "")
                if not title or not link:
                    continue

                summary = entry.get("summary", "")
                
                # Parse publication date from RSS tuple format
                published_struct = entry.get("published_parsed")
                if published_struct:
                    published_at = datetime(*published_struct[:6], tzinfo=timezone.utc)
                else:
                    published_at = datetime.now(timezone.utc)

                payload_hash = str(uuid.uuid5(uuid.NAMESPACE_URL, link))

                meta = IngestionMetadata(
                    source_name="Google News RSS",
                    source_url=link,  # type: ignore
                    raw_payload_hash=payload_hash,
                )

                # Feed entries often put description in summary; content is raw entry representation
                report = RawThreatReport(
                    title=title,
                    summary=summary,
                    content=summary,  # RSS entries usually contain snippet in summary
                    published_at=published_at,
                    metadata=meta,
                    raw_payload=dict(entry),
                )
                reports.append(report)

            logger.info("Successfully ingested %d entries from Google News RSS", len(reports))
            return reports

        except Exception as e:
            logger.error("Failed fetching Google News RSS feed: %s", str(e), exc_info=True)
            return []


class CisaTaxiiWorker:
    """Asynchronous worker fetching CTI graphs from CISA feeds using taxii2client."""

    def __init__(
        self,
        server_url: str = "https://limo.anomali.com/api/v1/taxii2/server/",
        collection_id: str = "107",  # Default guest Limo collections
        username: str = "guest",
        password: str = "guest",
    ):
        self.server_url = server_url
        self.collection_id = collection_id
        self.username = username
        self.password = password

    def _poll_taxii_sync(self) -> List[Dict[str, Any]]:
        """Synchronous connection logic for TAXII 2.1 client."""
        server = Server(url=self.server_url, user=self.username, password=self.password)
        api_root = server.api_roots[0]  # Get the primary api root
        
        # Get target collection
        collection = Collection(
            f"{api_root.url}collections/{self.collection_id}/",
            user=self.username,
            password=self.password,
        )
        
        # Retrieve objects from CTI feed (limit to 10 latest objects for performance)
        response = collection.get_objects(limit=10)
        return response.get("objects", []) if response else []

    async def fetch_reports(self) -> List[RawThreatReport]:
        """Polls TAXII 2.1 feed, converting STIX objects to RawThreatReport formats."""
        try:
            # Run the synchronous taxii client call in a background thread to prevent blockages
            objects = await asyncio.to_thread(self._poll_taxii_sync)
            reports: List[RawThreatReport] = []

            for obj in objects:
                obj_id = obj.get("id")
                obj_type = obj.get("type", "unknown")
                if not obj_id:
                    continue

                # Generate a title and content block based on STIX schema format
                title = obj.get("name") or obj.get("description") or f"STIX Object: {obj_type}"
                summary = obj.get("description") or f"CTI payload representing {obj_type}"
                content = str(obj)

                # Parse created time or default
                created_str = obj.get("created")
                if created_str:
                    try:
                        # Clean Z to UTC offset
                        created_str = created_str.replace("Z", "+00:00")
                        published_at = datetime.fromisoformat(created_str)
                    except ValueError:
                        published_at = datetime.now(timezone.utc)
                else:
                    published_at = datetime.now(timezone.utc)

                payload_hash = str(uuid.uuid5(uuid.NAMESPACE_DNS, obj_id))

                # Build source URI reference
                source_url = f"{self.server_url}collections/{self.collection_id}/objects/{obj_id}"

                meta = IngestionMetadata(
                    source_name="CISA TAXII",
                    source_url=source_url,  # type: ignore
                    raw_payload_hash=payload_hash,
                )

                report = RawThreatReport(
                    title=title,
                    summary=summary,
                    content=content,
                    published_at=published_at,
                    metadata=meta,
                    raw_payload=obj,
                )
                reports.append(report)

            logger.info("Successfully ingested %d threat reports from CISA TAXII", len(reports))
            return reports

        except Exception as e:
            logger.error("Failed fetching threat objects from CISA TAXII: %s", str(e), exc_info=True)
            return []


class IngestionPipeline:
    """Orchestrator to run all collection workers concurrently."""

    def __init__(self, news_api_key: Optional[str] = None):
        self.workers = [
            GoogleNewsRssWorker(),
            CisaTaxiiWorker(),
        ]
        if news_api_key:
            self.workers.append(NewsApiWorker(api_key=news_api_key))

    async def run(self) -> List[RawThreatReport]:
        """Runs all ingestion workers concurrently and returns a aggregated list of RawThreatReports."""
        logger.info("Starting OSINT Threat Ingestion Pipeline...")
        tasks = [worker.fetch_reports() for worker in self.workers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_reports: List[RawThreatReport] = []
        for worker_result in results:
            if isinstance(worker_result, Exception):
                logger.error("Ingestion worker failed with exception: %s", str(worker_result))
            elif isinstance(worker_result, list):
                all_reports.extend(worker_result)

        logger.info("Pipeline execution complete. Total ingested reports: %d", len(all_reports))
        return all_reports


if __name__ == "__main__":
    # Test runner for standalone verification
    async def main():
        pipeline = IngestionPipeline()
        reports = await pipeline.run()
        for idx, report in enumerate(reports[:3]):
            print(f"\n--- Ingested Report #{idx+1} ---")
            print(f"Title: {report.title}")
            print(f"Source: {report.metadata.source_name} ({report.metadata.source_url})")
            print(f"Published At: {report.published_at}")
            print(f"Payload Preview: {str(report.raw_payload)[:150]}...")

    asyncio.run(main())
