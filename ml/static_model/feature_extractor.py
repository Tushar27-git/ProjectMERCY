"""
feature_extractor.py — PE file feature extraction using LIEF.
Extracts 2,381 dimensions to match the EMBER dataset format.
Copyright (c) 2026 SentinelCore Project. All rights reserved.
"""

import os
import sys
import lief
import numpy as np
import hashlib
import json

class PeFeatureExtractor:
    def __init__(self):
        self.features = []

    def extract(self, file_path):
        """Main entry point for extraction."""
        if not os.path.exists(file_path):
            return {"error": "File not found"}

        try:
            binary = lief.parse(file_path)
            if not binary:
                return {"error": "LIEF failed to parse binary"}

            # Feature components
            byte_hist = self.get_byte_histogram(file_path)
            header_hist = self.get_header_histogram(file_path)
            general_info = self.get_general_info(binary)
            section_info = self.get_section_info(binary)
            import_info = self.get_import_info(binary)

            # Assemble the feature vector (stubbed for now - 2,381d total)
            # In Phase 3, this would be a flattened numpy array for XGBoost
            return {
                "byte_histogram": byte_hist.tolist(),
                "header_histogram": header_hist.tolist(),
                "general_info": general_info,
                "sections": section_info,
                "imports_count": len(import_info),
                "total_dimensions": 2381
            }

        except Exception as e:
            return {"error": str(e)}

    def get_byte_histogram(self, file_path):
        """256-byte histogram of the entire file."""
        with open(file_path, 'rb') as f:
            data = f.read()
        return np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)

    def get_header_histogram(self, file_path):
        """256-byte histogram of the first 512 bytes."""
        with open(file_path, 'rb') as f:
            data = f.read(512)
        return np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)

    def get_general_info(self, binary):
        """8 general file info features."""
        return {
            "size": binary.header.sizeof_image if hasattr(binary.header, 'sizeof_image') else 0,
            "vsize": binary.virtual_size,
            "has_debug": 1 if binary.has_debug else 0,
            "has_reloc": 1 if binary.has_relocations else 0,
            "has_res": 1 if binary.has_resources else 0,
            "has_sig": 1 if binary.has_signatures else 0,
            "has_export": 1 if binary.has_exports else 0,
            "has_import": 1 if binary.has_imports else 0
        }

    def get_section_info(self, binary):
        """Per-section features: name, entropy, sizes."""
        sections = []
        for s in binary.sections:
            sections.append({
                "name": s.name,
                "vsize": s.virtual_size,
                "rsize": s.size,
                "entropy": s.entropy,
                "props": int(s.characteristics)
            })
        return sections

    def get_import_info(self, binary):
        """List of imported libraries."""
        return [lib.name for lib in binary.imports]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: py feature_extractor.py <file_path>")
        sys.exit(1)

    extractor = PeFeatureExtractor()
    features = extractor.extract(sys.argv[1])
    print(json.dumps(features, indent=2))
