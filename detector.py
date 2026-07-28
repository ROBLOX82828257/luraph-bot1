"""
Luraph Obfuscation Detector
Identifies Luraph-protected Lua scripts and classifies the variant.
"""
import re
from enum import Enum
from dataclasses import dataclass
from typing import Optional


class LuraphVariant(Enum):
    LPH_PLUS = "LPH+"
    LPH_TURBO = "LPH+TURBO"
    LPH_NORMAL = "LPH"
    UNKNOWN = "UNKNOWN"


@dataclass
class DetectionResult:
    is_luraph: bool
    variant: LuraphVariant
    version_string: str
    confidence: float
    signatures_matched: list


class LuraphDetector:
    """Detects and classifies Luraph obfuscation in Lua bytecode/source."""

    # Static signatures — byte patterns that appear in every Luraph build
    SIGNATURES = [
        # Watermark / header strings
        (rb'LPH\s*[+\.]?', "watermark", 1.0),
        (rb'lph_\w+', "lph_identifier", 0.9),
        (rb'Il1lIl1l', "confused_names", 0.7),
        (rb'll1ll1l1', "confused_names_alt", 0.7),
        # VM dispatch structures
        (rb'while\s+true\s+do\s*if\s+\w+\s*==\s*\d+', "dispatch_loop", 0.95),
        (rb'local\s+function\s+l_[A-Za-z0-9_]+', "handler_funcs", 0.6),
        # String protection
        (rb'string\.char$\s*\d+(?:\s*,\s*\d+){2,}\s*$', "char_table", 0.5),
        (rb'bit32\.bxor|bit\.bxor', "bit_ops", 0.4),
        (rb'getfenv$\s*["\']?\x00?', "env_lock", 0.5),
        # Anti-tamper
        (rb'string\.dump', "dump_check", 0.3),
        (rb'debug\.', "debug_anti", 0.3),
    ]

    VM_PATTERNS = {
        LuraphVariant.LPH_PLUS: [
            rb'local\s+v\d+\s*=\s*\{',
            rb'if\s+v\d+\s*==\s*\d+\s+then',
            rb'local\s+function\s+l_[A-Za-z0-9]+',
        ],
        LuraphVariant.LPH_TURBO: [
            rb'local\s+[A-Za-z0-9_]+\s*=\s*string\.reverse',
            rb'bit\.bnot|bit\.bxor|bit\.band',
            rb'local\s+[Il1]+\s*=\s*\{',
            rb'loadstring|load\(',
        ],
        LuraphVariant.LPH_NORMAL: [
            rb'LPH\s*=\s*',
            rb'lph_encode|lph_decode',
        ],
    }

    def detect(self, data: bytes) -> DetectionResult:
        """Full detection — returns variant, confidence, matched signatures."""
        matched = []
        confidence = 0.0

        for pattern, name, weight in self.SIGNATURES:
            if re.search(pattern, data):
                matched.append(name)
                confidence += weight

        if not matched:
            # Heuristic fallback: dense numeric tables
            if self._has_dense_numeric_table(data):
                matched.append("dense_numeric_table")
                confidence += 0.4

        if confidence < 0.3:
            return DetectionResult(
                is_luraph=False,
                variant=LuraphVariant.UNKNOWN,
                version_string="",
                confidence=0.0,
                signatures_matched=matched,
            )

        variant = self._classify_variant(data, matched)
        version = self._extract_version(data)

        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)

        return DetectionResult(
            is_luraph=True,
            variant=variant,
            version_string=version,
            confidence=confidence,
            signatures_matched=matched,
        )

    def _classify_variant(self, data: bytes, matched: list) -> LuraphVariant:
        """Classify the Luraph variant by checking VM pattern clusters."""
        best_variant = LuraphVariant.UNKNOWN
        best_score = 0

        for variant, patterns in self.VM_PATTERNS.items():
            score = sum(1 for p in patterns if re.search(p, data))
            if score > best_score:
                best_score = score
                best_variant = variant

        if best_score == 0 and "watermark" in matched:
            return LuraphVariant.LPH_NORMAL

        return best_variant

    def _has_dense_numeric_table(self, data: bytes) -> bool:
        """Detect large arrays of integers — Luraph VM bytecode tables."""
        dense_table = rb'\{[\d,\s]{200,}\}'
        return bool(re.search(dense_table, data))

    def _extract_version(self, data: bytes) -> str:
        """Attempt to extract Luraph version watermark."""
        match = re.search(rb'LPH[\+\.]?[\s\S]{0,30}', data[:512])
        if match:
            raw = match.group(0)
            return raw.decode('utf-8', errors='replace').strip()
        return "unknown"

    def is_luraph(self, data: bytes) -> bool:
        """Quick boolean check."""
        return self.detect(data).is_luraph
