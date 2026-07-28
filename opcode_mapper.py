"""
Maps Luraph VM opcodes back to standard Lua 5.1 bytecode opcodes.
Uses behavioral fingerprinting of each VM handler.
"""
import re
import logging
from typing import Dict, Optional, Any, List

logger = logging.getLogger(__name__)

# Lua 5.1 standard opcode set
LUA51_OPCODES = [
    "OP_MOVE", "OP_LOADK", "OP_LOADBOOL", "OP_LOADNIL", "OP_GETUPVAL",
    "OP_GETGLOBAL", "OP_GETTABLE", "OP_SETGLOBAL", "OP_SETUPVAL", "OP_SETTABLE",
    "OP_NEWTABLE", "OP_SELF", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV",
    "OP_MOD", "OP_POW", "OP_UNM", "OP_NOT", "OP_LEN", "OP_CONCAT",
    "OP_JMP", "OP_EQ", "OP_LT", "OP_LE", "OP_TEST", "OP_TESTSET",
    "OP_CALL", "OP_TAILCALL", "OP_RETURN", "OP_FORLOOP", "OP_FORPREP",
    "OP_TFORLOOP", "OP_SETLIST", "OP_CLOSE", "OP_CLOSURE", "OP_VARARG",
]

# Behavioral signatures - patterns that identify what a VM handler does
BEHAVIORAL_SIGNATURES = {
    "OP_MOVE": [
        r"virtual\s*

$$
\s*\w+\s*
$$

\s*=\s*virtual\s*

$$
\s*\w+\s*
$$

",
        r"regs?\s*

$$
\s*A\s*
$$

\s*=\s*regs?\s*

$$
\s*B\s*
$$

",
    ],
    "OP_LOADK": [
        r"constants\s*

$$
",
        r"k\s*\[\s*\w+\s*
$$

",
        r"consts\s*

$$
",
    ],
    "OP_LOADBOOL": [
        r"(?:B\s*~=?\s*0|B\s*==\s*0).*?(?:C\s*~=?\s*0|pc\s*\+)",
        r"bool",
    ],
    "OP_LOADNIL": [
        r"=\s*nil",
        r"nil",
    ],
    "OP_GETGLOBAL": [
        r"globals\s*\[",
        r"_G\s*\[",
        r"environment\s*\[",
        r"env\s*\[",
    ],
    "OP_GETTABLE": [
        r"\[\s*virtual\s*\[",
        r"regs?\s*\[\s*A\s*
$$

\s*=\s*regs?\s*

$$
\s*B\s*
$$

\s*

$$
",
    ],
    "OP_SETGLOBAL": [
        r"globals\s*\[\s*\w+\s*
$$

\s*=",
        r"_G\s*

$$
",
    ],
    "OP_SETTABLE": [
        r"regs?\s*\[\s*B\s*
$$

\s*

$$
\s*C\s*
$$

\s*=\s*regs?\s*

$$
\s*A\s*
$$

",
    ],
    "OP_NEWTABLE": [
        r"table\.(?:new|create|insert)\b",
        r"\{\s*\}",
        r"newtable",
    ],
    "OP_SELF": [
        r"self",
        r":\s*call",
        r"function\s*call\s*method",
    ],
    "OP_ADD": [r"\+", r"add"],
    "OP_SUB": [r"-", r"sub"],
    "OP_MUL": [r"\*", r"mul"],
    "OP_DIV": [r"/", r"div"],
    "OP_MOD": [r"%", r"mod"],
    "OP_POW": [r"\^", r"pow"],
    "OP_UNM": [r"-\s*-?\s*virtual", r"unary\s*minus", r"negate"],
    "OP_NOT": [r"\bnot\b", r"negate\s*bool"],
    "OP_LEN": [r"#", r"length", r"\blen\b"],
    "OP_CONCAT": [r"\.\.", r"concat"],
    "OP_JMP": [
        r"pc\s*=\s*pc\s*[\+\-]",
        r"goto\s",
        r"ip\s*[\+\-]=",
        r"instruction_pointer\s*[\+\-]=",
    ],
    "OP_EQ": [r"==", r"\bEQ\b", r"equal"],
    "OP_LT": [r"<(?! =)", r"\bLT\b", r"less"],
    "OP_LE": [r"<=", r"\bLE\b", r"less.*equal"],
    "OP_TEST": [r"test\s", r"(?:B|C)\s*~=?\s*0.*?pc"],
    "OP_CALL": [
        r"call\s*$",
        r"pcall",
        r"function\s*call",
        r"regs?\s*

$$
\s*A\s*
$$

\s*\(",
    ],
    "OP_RETURN": [
        r"return\b",
        r"exit\s",
        r"break\s*loop",
        r"unpack\s*\(",
    ],
    "OP_FORLOOP": [r"for\s*loop", r"OP_FORLOOP"],
    "OP_FORPREP": [r"for\s*prep", r"OP_FORPREP"],
    "OP_TFORLOOP": [r"tfor", r"generic\s*for"],
    "OP_SETLIST": [r"setlist", r"SETLIST"],
    "OP_CLOSURE": [
        r"closure",
        r"function\s*\(",
        r"makefunction",
        r"newclosure",
    ],
    "OP_VARARG": [r"\.\.\.", r"vararg", r"select\s*\("],
}

# Confidence scoring weights
WEIGHTS = {
    "exact_match": 1.0,
    "pattern_match": 0.7,
    "structural_match": 0.5,
    "heuristic_match": 0.3,
}


class OpcodeMapper:
    """Maps obfuscated VM opcodes to standard Lua opcodes using behavioral analysis."""

    def __init__(self):
        self.opcode_table: Dict[int, Optional[str]] = {}
        self.confidence_scores: Dict[int, float] = {}
        self._compiled_signatures = {}
        self._compile_signatures()

    def _compile_signatures(self):
        """Pre-compile regex patterns for performance."""
        for opcode, patterns in BEHAVIORAL_SIGNATURES.items():
            self._compiled_signatures[opcode] = [
                re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns
            ]

    def build_map(
        self, source: str, vm_info: Dict[str, Any]
    ) -> Dict[int, Optional[str]]:
        """
        Build a complete opcode mapping from the source and VM analysis.

        Args:
            source: The (partially decrypted) Lua source.
            vm_info: Output from VMAnalyzer containing handler info.

        Returns:
            Dict mapping obfuscated opcode IDs to standard Lua opcode names.
        """
        self.opcode_table = {}
        self.confidence_scores = {}

        handlers = vm_info.get("handlers", {})
        if not handlers:
            logger.warning("No VM handlers found - attempting brute-force extraction")
            handlers = self._extract_handlers_bruteforce(source)

        # Analyze each handler
        for opcode_id, handler_code in handlers.items():
            best_match = self._identify_handler(handler_code)
            if best_match:
                self.opcode_table[opcode_id] = best_match[0]
                self.confidence_scores[opcode_id] = best_match[1]
                logger.debug(
                    f"Opcode {opcode_id} -> {best_match[0]} (confidence: {best_match[1]:.2f})"
                )
            else:
                self.opcode_table[opcode_id] = None
                self.confidence_scores[opcode_id] = 0.0
                logger.debug(f"Opcode {opcode_id} -> UNKNOWN")

        # Apply cross-references to fill gaps
        self._cross_reference_filling(source)

        mapped = sum(1 for v in self.opcode_table.values() if v is not None)
        total = len(self.opcode_table)
        logger.info(f"Opcode mapping: {mapped}/{total} ({mapped/max(total,1)*100:.1f}%)")

        return self.opcode_table

    def _identify_handler(self, handler_code: str) -> Optional[tuple]:
        """
        Identify a VM handler by matching against behavioral signatures.

        Returns:
            Tuple of (opcode_name, confidence) or None.
        """
        scores: Dict[str, float] = {}

        for opcode, compiled_patterns in self._compiled_signatures.items():
            score = 0.0
            for pattern in compiled_patterns:
                if pattern.search(handler_code):
                    score += WEIGHTS["pattern_match"]
                # Also check for structural hints
                if self._check_structural_features(handler_code, opcode):
                    score += WEIGHTS["structural_match"]

            # Normalize by number of patterns
            if score > 0:
                max_possible = len(compiled_patterns) * WEIGHTS["pattern_match"]
                scores[opcode] = min(score / max(max_possible, 1), 1.0)

        if not scores:
            return None

        # Pick the best match
        best = max(scores, key=scores.get)
        if scores[best] >= 0.3:  # minimum confidence threshold
            return (best, scores[best])
        return None

    def _check_structural_features(self, code: str, opcode: str) -> bool:
        """Check for structural features that hint at a specific opcode."""
        code_lower = code.lower()

        structural_hints = {
            "OP_RETURN": lambda: "unpack" in code_lower or "return" in code_lower,
            "OP_CALL": lambda: "(" in code and ")" in code and "call" in code_lower,
            "OP_JMP": lambda: "pc" in code_lower or "ip" in code_lower,
            "OP_CLOSURE": lambda: "function" in code_lower or "closure" in code_lower,
            "OP_NEWTABLE": lambda: "{}" in code or "table" in code_lower,
            "OP_LOADK": lambda: "constant" in code_lower or "const" in code_lower,
            "OP_GETGLOBAL": lambda: "_g" in code_lower or "global" in code_lower or "env" in code_lower,
        }

        checker = structural_hints.get(opcode)
        if checker:
            return checker()
        return False

    def _extract_handlers_bruteforce(
        self, source: str
    ) -> Dict[int, str]:
        """
        Attempt to extract VM handlers when VMAnalyzer failed.
        Looks for numbered function tables or switch-case constructs.
        """
        handlers = {}

        # Pattern 1: Numbered table of functions
        # e.g., local opcodes = { [0] = function(...) ... end, [1] = ... }
        table_pattern = re.compile(
            r"

$$
(\d+)
$$

\s*=\s*function\s*\([^)]*$\s*(.*?)\s*end",
            re.DOTALL,
        )
        for match in table_pattern.finditer(source):
            idx = int(match.group(1))
            body = match.group(2)
            handlers[idx] = body

        if handlers:
            logger.info(f"Brute-force extracted {len(handlers)} handlers from table")
            return handlers

        # Pattern 2: Switch/if-elseif chain
        # e.g., if opcode == 0 then ... elseif opcode == 1 then ...
        switch_pattern = re.compile(
            r"(?:if|elseif)\s+opcode\s*==\s*(\d+)\s+then\s*(.*?)(?=elseif|else|end\b)",
            re.DOTALL,
        )
        for match in switch_pattern.finditer(source):
            idx = int(match.group(1))
            body = match.group(2).strip()
            handlers[idx] = body

        if handlers:
            logger.info(f"
