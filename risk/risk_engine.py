"""Risk Engine & Prioritization Layer.

This module implements the core mathematical risk engine for prioritizing OSINT threat signals.
It avoids qualitative branches and lookup matrices, relying instead on continuous vector calculus
and exponential time-decay modeling.

Mathematical formulation:
    1. Threat Impact Vector (I_i): Constructed using continuous exponential saturation functions:
       I_i = [1 - e^(-alpha * N_targets), 1 - e^(-beta * N_actors), 1 - e^(-gamma * N_cves), 1 - e^(-delta * N_tactics)]
    2. Inner Product: W_a^T * I_i
    3. Decay factor P(T_i) = R_s * e^(-lambda * dt)
    4. Combined Priority Score = (W_a^T * I_i) * R_s * e^(-lambda * dt)
"""

from datetime import datetime, timezone
import logging
from typing import List

import numpy as np
import scipy.stats

# Configure logger
logger = logging.getLogger("risk_engine")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class RiskEngine:
    """Prioritizes threat reports based on vector inner products and temporal decay."""

    def __init__(self, decay_rate: float = 0.05):
        """Initializes the Risk Engine.

        Arguments:
            decay_rate: Temporal urgency decay factor (lambda).
        """
        self.decay_rate = decay_rate
        # Default W_a (Asset Configuration Weight Vector)
        # Normalized weight layout: [Confidentiality, Integrity, Availability, AssetCriticality]
        self.default_weights = np.array([0.4, 0.3, 0.1, 0.2], dtype=float)

    def calculate_impact_vector(
        self,
        num_targets: int,
        num_actors: int,
        num_cves: int,
        num_tactics: int,
        alpha: float = 0.5,
        beta: float = 0.6,
        gamma: float = 0.7,
        delta: float = 0.4,
    ) -> np.ndarray:
        """Computes the continuous, multi-dimensional Impact Vector (I_i) using saturation curves.

        This avoids qualitative conditional branches. Instead, it models impact via
        continuous asymptotic growth curves: f(x) = 1 - e^(-k * x)

        Arguments:
            num_targets: Number of target assets extracted.
            num_actors: Number of threat actors identified.
            num_cves: Number of CVE vulnerabilities extracted.
            num_tactics: Number of MITRE ATT&CK tactics/techniques identified.
            alpha, beta, gamma, delta: Scaling saturation constants for each dimension.

        Returns:
            A 4D numpy array representing the Impact Vector (I_i).
        """
        i_target = 1.0 - np.exp(-alpha * num_targets)
        i_actor = 1.0 - np.exp(-beta * num_actors)
        i_cve = 1.0 - np.exp(-gamma * num_cves)
        i_mitre = 1.0 - np.exp(-delta * num_tactics)

        return np.array([i_target, i_actor, i_cve, i_mitre], dtype=float)

    def calculate_priority(
        self,
        impact_vector: np.ndarray,
        weights: np.ndarray,
        source_credibility: float,
        published_at: datetime,
        current_time: datetime,
    ) -> float:
        """Computes the dynamic priority score using vector inner products and credibility-weighted time decay.

        Formula:
            Score = (W_a^T * I_i) * P(T_i)
            where P(T_i) = R_s * e^(-lambda * dt)

        Arguments:
            impact_vector: The multi-dimensional Impact Vector (I_i).
            weights: The Asset Configuration Weight Vector (W_a).
            source_credibility: The credibility coefficient (R_s) of the source (range [0.0, 1.0]).
            published_at: datetime when the report was published.
            current_time: The comparison time (e.g. now).

        Returns:
            Priority score in the range [0.0, 100.0].
        """
        # Calculate time delta dt in days
        dt_seconds = (current_time - published_at).total_seconds()
        dt_days = max(0.0, dt_seconds / 86400.0)

        # Inner product of asset weights and threat impacts: W_a^T * I_i
        inner_product = np.dot(weights, impact_vector)

        # Decay function: P(T_i) = R_s * e^(-lambda * dt)
        decay_factor = source_credibility * np.exp(-self.decay_rate * dt_days)

        # Final Priority score mapped to standard 0-100 scale
        priority_score = inner_product * decay_factor * 100.0
        return float(priority_score)


if __name__ == "__main__":
    # Test execution illustrating dynamic decay calculations
    engine = RiskEngine()
    now = datetime.now(timezone.utc)
    
    # Target counts: 2 targets, 1 actor, 2 CVEs, 3 tactics
    impact = engine.calculate_impact_vector(num_targets=2, num_actors=1, num_cves=2, num_tactics=3)
    
    # Credibility scores: CISA TAXII (1.0) vs RSS Feed (0.7)
    cisa_credibility = 1.0
    rss_credibility = 0.7

    print("\n--- Core Risk Calculus Validation ---")
    print(f"Asset Weights (W_a): {engine.default_weights}")
    print(f"Computed Impact Vector (I_i): {impact}")
    print(f"Inner Product (W_a^T * I_i): {np.dot(engine.default_weights, impact):.4f}")

    # Priority score for CISA report published today
    score_cisa_today = engine.calculate_priority(
        impact_vector=impact,
        weights=engine.default_weights,
        source_credibility=cisa_credibility,
        published_at=now,
        current_time=now
    )

    # Priority score for CISA report published 5 days ago
    from datetime import timedelta
    five_days_ago = now - timedelta(days=5)
    score_cisa_old = engine.calculate_priority(
        impact_vector=impact,
        weights=engine.default_weights,
        source_credibility=cisa_credibility,
        published_at=five_days_ago,
        current_time=now
    )

    # Priority score for RSS report published today
    score_rss_today = engine.calculate_priority(
        impact_vector=impact,
        weights=engine.default_weights,
        source_credibility=rss_credibility,
        published_at=now,
        current_time=now
    )

    print(f"CISA (Credibility 1.0) - Today: {score_cisa_today:.2f}")
    print(f"CISA (Credibility 1.0) - 5 Days Ago (Decayed): {score_cisa_old:.2f}")
    print(f"RSS  (Credibility 0.7) - Today: {score_rss_today:.2f}")
