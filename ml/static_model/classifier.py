"""
classifier.py — XGBoost Static Gatekeeper inference wrapper.
Stubbed for Phase 2; uses simple heuristics for now.
Copyright (c) 2026 SentinelCore Project. All rights reserved.
"""

import sys
import os
import json
import lief
import numpy as np

# Add parent to path for config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from ml.static_model.feature_extractor import PeFeatureExtractor

class StaticGatekeeper:
    def __init__(self, model_path=None):
        self.model_path = model_path
        self.extractor = PeFeatureExtractor()
        # In Phase 3, this would load xgb_gatekeeper.ubj
        self.model_loaded = False if not model_path else True
        if self.model_loaded:
             print(f"[*] Static Gatekeeper: Loaded model from {model_path}")

    def predict(self, features_or_path):
        """Returns malware probability 0.0 - 1.0."""
        # If it's a file path, extract features first
        if isinstance(features_or_path, str):
            features = self.extractor.extract(features_or_path)
            if "error" in features:
                return 0.5  # Neutral score on error
        else:
            features = features_or_path

        # Phase 2 Heuristic Proxy (Mock ML Model):
        # 1. Check sections (legit code usually has predictable section names)
        suspicious_sections = [".pack", ".UPX", ".themida", "PROTECT"]
        section_score = 0.0
        for s in features.get("sections", []):
            if any(p in s["name"] for p in suspicious_sections):
                section_score += 0.2
            if s["entropy"] > config.ENTROPY_SUSPICIOUS_THRESHOLD:
                section_score += 0.3

        # 2. Check general info
        # Very small executables with high entropy sections are suspicious
        size_score = 0.0
        if features.get("general_info", {}).get("size", 100000) < 10000:
             size_score += 0.1

        # 3. Final Mock Score (capped at 1.0)
        final_probability = min(0.1 + section_score + size_score, 1.0)

        # Print detailed decision for logs
        verdict = self.get_verdict(final_probability)
        print(f"[XGBoost] Analysis: Score={final_probability:.2f} -> {verdict.name}")

        return final_probability

    def get_verdict(self, probability):
        """Converts probability to a Verdict enum."""
        if probability >= config.STATIC_BLOCK_THRESHOLD:
            return config.Verdict.BLOCK
        if probability >= config.STATIC_MONITOR_THRESHOLD:
            return config.Verdict.MONITOR
        return config.Verdict.ALLOW

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: py classifier.py <file_path>")
        sys.exit(1)

    gatekeeper = StaticGatekeeper()
    score = gatekeeper.predict(sys.argv[1])
    verdict = gatekeeper.get_verdict(score)
    print(f"Final Verdict: {verdict.name} ({score:.2f})")
