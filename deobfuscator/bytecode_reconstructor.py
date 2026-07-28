import struct
import logging
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class Instruction:
    """Represents a single reconstructed VM instruction."""
    def __init__(self, opcode: str, operands: List[Any] = None, offset: int = 0):
        self.opcode = opcode
        self.operands = operands or []
        self.offset = offset

    def __repr__(self):
        return f"Instruction({self.opcode}, {self.operands}, offset={self.offset})"

    def to_lua(self, indent: str = "    ") -> str:
        """Convert instruction back toward readable Lua-ish pseudocode."""
        op = self.opcode.upper()
        ops = self.operands

        if op == "MOVE":
            return f"{indent}R{ops[0]} = R{ops[1]}"
        elif op == "LOADK":
            return f"{indent}R{ops[0]} = K{ops[1]}"
        elif op == "LOADBOOL":
            return f"{indent}R{ops[0]} = {bool(ops[1])}"
        elif op == "LOADNIL":
            return f"{indent}R{ops[0]} = nil"
        elif op == "GETUPVAL":
            return f"{indent}R{ops[0]} = U{ops[1]}"
        elif op == "GETGLOBAL":
            return f"{indent}R{ops[0]} = _G[K{ops[1]}]"
        elif op == "GETTABLE":
            return f"{indent}R{ops[0]} = R{ops[1]}[{self._table_index(ops[2])}]"
        elif op == "SETGLOBAL":
            return f"{indent}_G[K{ops[1]}] = R{ops[0]}"
        elif op == "SETUPVAL":
            return f"{indent}U{ops[1]} = R{ops[0]}"
        elif op == "SETTABLE":
            return f"{indent}R{ops[1]}[{self._table_index(ops[0])}] = R{ops[2]}"
        elif op == "NEWTABLE":
            return f"{indent}R{ops[0]} = {{}}"
        elif op == "SELF":
            return f"{indent}R{ops[1]+1} = R{ops[1]}; R{ops[0]} = R{ops[1]}:method"
        elif op == "ADD" or op == "SUB" or op == "MUL" or op == "DIV" or op == "MOD" or op == "POW":
            return f"{indent}R{ops[0]} = {self._arith(op, ops[1], ops[2])}"
        elif op == "UNM":
            return f"{indent}R{ops[0]} = -R{ops[1]}"
        elif op == "NOT":
            return f"{indent}R{ops[0]} = not R{ops[1]}"
        elif op == "LEN":
            return f"{indent}R{ops[0]} = #R{ops[1]}"
        elif op == "CONCAT":
            return f"{indent}R{ops[0]} = R{ops[1]} .. R{ops[2]}"
        elif op == "JMP":
            return f"{indent}goto +{ops[0]}"
        elif op == "EQ" or op == "LT" or op == "LE":
            return f"{indent}if {self._compare(op, ops[1], ops[2])} then"
        elif op == "TEST":
            return f"{indent}if R{ops[0]} then goto +{ops[1]}"
        elif op == "CALL":
            nargs = ops[1]
            nrets = ops[2]
            ret_part = f"({', '.join(f'R{ops[0]+1+i}' for i in range(nrets)})" if nrets > 0 else ""
            return f"{indent}{ret_part} = R{ops[0]}({', '.join(f'R{ops[0]+1+i}' for i in range(nargs))})"
        elif op == "TAILCALL":
            return f"{indent}return R{ops[0]}({', '.join(f'R{ops[0]+1+i}' for i in range(ops[1]))})"
        elif op == "RETURN":
            rets = ", ".join(f"R{ops[0]+i}" for i in range(ops[1]))
            return f"{indent}return {rets}"
        elif op == "FORLOOP":
            return f"{indent}R{ops[0]} = R{ops[0]} + R{ops[0]+2]; if R{ops[0]} <= R{ops[0]+1} then goto +{ops[1]}"
        elif op == "FORPREP":
            return f"{indent}R{ops[0]} = R{ops[0]} - R{ops[0]+2]"
        elif op == "TFORLOOP":
            return f"{indent}R{ops[0]}, R{ops[0]+1}, R{ops[0]+2} = R{ops[0]+1}(R{ops[0]}, R{ops[0]+1]); if R{ops[0]} == nil then goto +{ops[1]}"
        elif op == "CLOSE":
            return f"{indent}-- close upvalues starting at R{ops[0]}"
        elif op == "CLOSURE":
            return f"{indent}R{ops[0]} = closure(proto[{ops[1]}])"
        else:
            return f"{indent}-- unknown op {op} {ops}"

    def _table_index(self, operand: Tuple) -> str:
        """Format a table index operand."""
        kind, value = operand if isinstance(operand, tuple) else ("RK", operand)
        if kind == "K":
            return f"K{value}"
        return f"R{value}"

    def _arith(self, op: str, a, b) -> str:
        symbols = {"ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%", "POW": "^"}
        sym = symbols.get(op, "?")
        left = self._rk_str(a)
        right = self._rk_str(b)
        return f"{left} {sym} {right}"

    def _compare(self, op: str, a, b) -> str:
        symbols = {"EQ": "==", "LT": "<", "LE": "<="}
        sym = symbols.get(op, "?")
        return f"{self._rk_str(a)} {sym} {self._rk_str(b)}"

    def _rk_str(self, operand) -> str:
        if isinstance(operand, tuple):
            kind, value = operand
            return f"K{value}" if kind == "K" else f"R{value}"
        return f"R{operand}"


class BytecodeReconstructor:
    """Reconstructs readable bytecode / pseudocode from deobfuscated VM state."""

    LURAPH_OPCODE_HINTS = {
        0x00: "MOVE",
        0x01: "LOADK",
        0x02: "LOADBOOL",
        0x03: "LOADNIL",
        0x04: "GETUPVAL",
        0x05: "GETGLOBAL",
        0x06: "GETTABLE",
        0x07: "SETGLOBAL",
        0x08: "SETUPVAL",
        0x09: "SETTABLE",
        0x0A: "NEWTABLE",
        0x0B: "SELF",
        0x0C: "ADD",
        0x0D: "SUB",
        0x0E: "MUL",
        0x0F: "DIV",
        0x10: "MOD",
        0x11: "POW",
        0x12: "UNM",
        0x13: "NOT",
        0x14: "LEN",
        0x15: "CONCAT",
        0x16: "JMP",
        0x17: "EQ",
        0x18: "LT",
        0x19: "LE",
        0x1A: "TEST",
        0x1B: "CALL",
        0x1C: "TAILCALL",
        0x1D: "RETURN",
        0x1E: "FORLOOP",
        0x1F: "FORPREP",
        0x20: "TFORLOOP",
        0x21: "CLOSE",
        0x22: "CLOSURE",
    }

    # Luraph sometimes remaps or virtualizes these, but the reconstructor
    # uses the opcode_mapper's output to pin down the true operation.

    def __init__(self):
        self.instructions: List[Instruction] = []
        self.constants: List[Any] = []
        self.upvalue_info: List[Dict] = []
        self.proto_info: Dict[str, Any] = {}
        self.line_mappings: Dict[int, int] = {}
        self.warnings: List[str] = []

    def reconstruct_from_vm_state(self, vm_state: Dict[str, Any], opcode_mapping: Dict[int, str]) -> List[Instruction]:
        """
        Reconstruct instructions from raw VM state extracted by the VM analyzer.

        Args:
            vm_state: Dict containing 'instructions', 'constants', 'protos', etc.
            opcode_mapping: Dict mapping obfuscated opcode IDs to standard names.

        Returns:
            List of reconstructed Instruction objects.
        """
        self.constants = vm_state.get("constants", [])
        self.upvalue_info = vm_state.get("upvalues", [])
        self.proto_info = vm_state.get("proto_info", {})
        self.line_mappings = vm_state.get("line_mappings", {})

        raw_instructions = vm_state.get("instructions", [])
        reconstructed = []

        for idx, raw in enumerate(raw_instructions):
            if isinstance(raw, dict):
                obf_opcode = raw.get("opcode", -1)
                operands = raw.get("operands", [])
            elif isinstance(raw, (list, tuple)):
                obf_opcode = raw[0] if raw else -1
                operands = list(raw[1:]) if len(raw) > 1 else []
            else:
                self.warnings.append(f"Instruction {idx}: unparseable raw format")
                continue

            # Map the obfuscated opcode to standard
            true_op = opcode_mapping.get(obf_opcode, self.LURAPH_OPCODE_HINTS.get(obf_opcode, f"OP_{obf_opcode:X}"))

            # Decode operands based on the opcode type
            decoded_operands = self._decode_operands(true_op, operands)

            instr = Instruction(
                opcode=true_op,
                operands=decoded_operands,
                offset=idx
            )
            reconstructed.append(instr)

        self.instructions = reconstructed
        logger.info(f"Reconstructed {len(reconstructed)} instructions from VM state")
        return reconstructed

    def _decode_operands(self, opcode: str, raw_operands: List[Any]) -> List[Any]:
        """Decode raw operand values based on the instruction format."""
        op = opcode.upper()
        decoded = []

        if op in ("MOVE", "LOADNIL", "GETUPVAL", "SETUPVAL", "UNM", "NOT", "LEN", "CLOSE"):
            # A, B format
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       self._reg(raw_operands[1]) if len(raw_operands) > 1 else 0]

        elif op in ("LOADK",):
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       self._const_index(raw_operands[1]) if len(raw_operands) > 1 else 0]

        elif op in ("LOADBOOL",):
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       raw_operands[1] if len(raw_operands) > 1 else 0,
                       raw_operands[2] if len(raw_operands) > 2 else 0]

        elif op in ("GETGLOBAL", "SETGLOBAL"):
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       self._const_index(raw_operands[1]) if len(raw_operands) > 1 else 0]

        elif op in ("GETTABLE", "SETTABLE"):
            decoded = [
                self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                self._reg(raw_operands[1]) if len(raw_operands) > 1 else 0,
                self._rk_decode(raw_operands[2]) if len(raw_operands) > 2 else (0, "R", 0),
            ]

        elif op == "NEWTABLE":
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       raw_operands[1] if len(raw_operands) > 1 else 0,
                       raw_operands[2] if len(raw_operands) > 2 else 0]

        elif op == "SELF":
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       self._reg(raw_operands[1]) if len(raw_operands) > 1 else 0,
                       self._rk_decode(raw_operands[2]) if len(raw_operands) > 2 else (0, "R", 0)]

        elif op in ("ADD", "SUB", "MUL", "DIV", "MOD", "POW"):
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       self._rk_decode(raw_operands[1]) if len(raw_operands) > 1 else ("R", 0),
                       self._rk_decode(raw_operands[2]) if len(raw_operands) > 2 else ("R", 0)]

        elif op in ("EQ", "LT", "LE"):
            decoded = [raw_operands[0] if len(raw_operands) > 0 else 0,
                       self._rk_decode(raw_operands[1]) if len(raw_operands) > 1 else ("R", 0),
                       self._rk_decode(raw_operands[2]) if len(raw_operands) > 2 else ("R", 0)]

        elif op in ("CONCAT",):
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       self._reg(raw_operands[1]) if len(raw_operands) > 1 else 0,
                       self._reg(raw_operands[2]) if len(raw_operands) > 2 else 0]

        elif op == "JMP":
            decoded = [raw_operands[0] if len(raw_operands) > 0 else 0]

        elif op == "TEST":
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       raw_operands[1] if len(raw_operands) > 1 else 0,
                       raw_operands[2] if len(raw_operands) > 2 else 0]

        elif op in ("CALL", "TAILCALL"):
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       raw_operands[1] if len(raw_operands) > 1 else 0,
                       raw_operands[2] if len(raw_operands) > 2 else 0]

        elif op == "RETURN":
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       raw_operands[1] if len(raw_operands) > 1 else 0]

        elif op in ("FORLOOP", "FORPREP"):
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       raw_operands[1] if len(raw_operands) > 1 else 0]

        elif op == "TFORLOOP":
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       raw_operands[1] if len(raw_operands) > 1 else 0]

        elif op == "CLOSURE":
            decoded = [self._reg(raw_operands[0]) if len(raw_operands) > 0 else 0,
                       self._proto_index(raw_operands[1]) if len(raw_operands) > 1 else 0]

        else:
            decoded = list(raw_operands)

        return decoded

    def _reg(self, value: Any) -> int:
        """Clamp/normalize a register index."""
        try:
            return int(value) & 0xFF
        except (ValueError, TypeError):
            return 0

    def _const_index(self, value: Any) -> int:
        """Normalize a constant table index."""
        try:
            idx = int(value)
            if idx < 0 or idx >= len(self.constants):
                self.warnings.append(f"Constant index {idx} out of range")
            return idx
        except (ValueError, TypeError):
            return 0

    def _proto_index(self, value: Any) -> int:
        try:
            return int(value) & 0xFF
        except (ValueError, TypeError):
            return 0

    def _rk_decode(self, value: Any) -> Tuple[str, int]:
        """
        Decode an RK operand (register or constant).
        In standard Lua bytecode, if the high bit is set, it's a constant.
        """
        if isinstance(value, tuple):
            return value

        try:
            raw = int(value)
        except (ValueError, TypeError):
            return ("R", 0)

        # Luraph typically uses bit 8 (0x100) as the constant flag
        is_const = (raw & 0x100) != 0
        index = raw & 0
