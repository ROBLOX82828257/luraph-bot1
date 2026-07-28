"""
Luraph VM Analyzer
Parses the custom virtual machine that Luraph injects to wrap the original bytecode.
Maps the VM's custom instruction set back to standard Lua 5.1 opcodes.
"""
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from collections import defaultdict


@dataclass
class VMInstruction:
    """A single decoded VM instruction."""
    raw_opcode: int
    mapped_opcode: Optional[str] = None
    operand_a: int = 0
    operand_b: int = 0
    operand_c: int = 0
    raw_args: list = field(default_factory=list)
    pc: int = 0  # program counter position
    size: int = 0  # instruction size in bytes


@dataclass
class VMDispatcher:
    """The VM's dispatch mechanism — maps opcodes to handlers."""
    dispatch_type: str = "if_chain"  # "if_chain", "table", "computed_goto"
    opcode_var: str = ""  # variable name holding the current opcode
    handlers: Dict[int, str] = field(default_factory=dict)  # opcode -> handler code
    handler_offsets: Dict[int, int] = field(default_factory=dict)  # opcode -> source offset


# Standard Lua 5.1 opcode names
LUA_51_OPCODES = {
    0: "OP_MOVE", 1: "OP_LOADK", 2: "OP_LOADBOOL", 3: "OP_LOADNIL",
    4: "OP_GETUPVAL", 5: "OP_GETGLOBAL", 6: "OP_GETTABLE", 7: "OP_SETGLOBAL",
    8: "OP_SETUPVAL", 9: "OP_SETTABLE", 10: "OP_NEWTABLE", 11: "OP_SELF",
    12: "OP_ADD", 13: "OP_SUB", 14: "OP_MUL", 15: "OP_DIV",
    16: "OP_MOD", 17: "OP_POW", 18: "OP_UNM", 19: "OP_NOT",
    20: "OP_LEN", 21: "OP_CONCAT", 22: "OP_JMP", 23:
