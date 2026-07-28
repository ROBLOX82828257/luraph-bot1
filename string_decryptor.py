"""
Luraph String Decryptor
Handles the various string protection schemes Luraph uses:
  - XOR (single-byte and multi-byte rotating)
  - Additive offset ciphers
  - string.char() reconstruction
  - Base64 + XOR layered encoding
"""
import re
import base64
from typing import Optional, Tuple, List


class EncryptedString:
    """Represents an encrypted string found in Luraph output."""
    def __init__(self, raw_bytes: bytes, cipher_type: str,
                 key: Optional[bytes] = None, offset: int = 0,
                 source_offset: int = 0):
        self.raw_bytes = raw_bytes
        self.cipher_type = cipher_type  # 'xor_single', 'xor_multi', 'add', 'char_table', 'b64_xor'
        self.key = key
        self.offset = offset
        self.source_offset = source_offset
        self.plaintext: Optional[str] = None

    def decrypt(self) -> str:
        if self.plaintext is not None:
            return self.plaintext

        if self.cipher_type == 'xor_single':
            key_byte = self.key[0] if self.key else 0
            dec = bytes(b ^ key_byte for b in self.raw_bytes)
            self.plaintext = dec.decode('utf-8', errors='replace')

        elif self.cipher_type == 'xor_multi':
            klen = len(self.key) if self.key else 1
            dec = bytearray(len(self.raw_bytes))
            for i, b in enumerate(self.raw_bytes):
                dec[i] = b ^ self.key[i % klen]
            self.plaintext = dec.decode('utf-8', errors='replace')

        elif self.cipher_type == 'add':
            dec = bytes((b - self.offset) & 0xFF for b in self.raw_bytes)
            self.plaintext = dec.decode('utf-8', errors='replace')

        elif self.cipher_type == 'char_table':
            # raw_bytes already IS the decoded byte sequence
            self.plaintext = self.raw_bytes.decode('utf-8', errors='replace')

        elif self.cipher_type == 'b64_xor':
            try:
                raw = base64.b64decode(self.raw_bytes)
                if self.key:
                    key_byte = self.key[0]
                    raw = bytes(b ^ key_byte for b in raw)
                self.plaintext = raw.decode('utf-8', errors='replace')
            except Exception:
                self.plaintext = self.raw_bytes.decode('utf-8', errors='replace')
        else:
            self.plaintext = self.raw_bytes.decode('utf-8', errors='replace')

        return self.plaintext

    def __repr__(self):
        return (f"EncryptedString(type={self.cipher_type}, "
                f"len={len(self.raw_bytes)}, offset={self.source_offset})")


class LuraphStringDecryptor:
    """Extracts and decrypts all protected strings from a Luraph script."""

    # string.char(n1, n2, n3, ...) — direct byte reconstruction
    RE_CHAR_TABLE = re.compile(
        rb'string\.char\(\s*([\d,\s]+)\s*$'
    )

    # bit32.bxor(val, key) — single-byte XOR pairs
    RE_BXOR = re.compile(
        rb'bit32\.bxor$\s*(\d+)\s*,\s*(\d+)\s*$'
    )

    # _lph_encode / _lph_decode("base64string")
    RE_LPH_ENCODED = re.compile(
        rb'_lph\w*$\s*["\']([A-Za-z0-9+/=]+)["\']\s*$'
    )

    # XOR with variable: (byte ~ key) or (byte ~ v1) chains
    RE_VAR_XOR = re.compile(
        rb'$\s*(\d+)\s*\~\s*(\w+)\s*$'
    )

    def extract_all(self, source: bytes) -> List[EncryptedString]:
        """Extract every encrypted string pattern from the source."""
        results = []

        # 1. string.char tables
        for match in self.RE_CHAR_TABLE.finditer(source):
            nums_str = match.group(1)
            nums = [int(x.strip()) for x in nums_str.split(b',') if x.strip()]
            if 2 <= len(nums) <= 4096:
                raw = bytes(n & 0xFF for n in nums)
                es = EncryptedString(
                    raw_bytes=raw,
                    cipher_type='char_table',
                    source_offset=match.start(),
                )
                es.decrypt()
                results.append(es)

        # 2. bxor pairs — collect consecutive pairs into strings
        bxor_pairs = []
        for match in self.RE_BXOR.finditer(source):
            val = int(match.group(1))
            key = int(match.group(2))
            bxor_pairs.append((val ^ key, match.start()))

        if bxor_pairs:
            # Group pairs that are close together (within 50 bytes) into single strings
            current_group = [bxor_pairs[0]]
            for i in range(1, len(bxor_pairs)):
                if bxor_pairs[i][1] - bxor_pairs[i-1][1] < 50:
                    current_group.append(bxor_pairs[i])
                else:
                    if len(current_group) >= 2:
                        raw = bytes(p[0] & 0xFF for p in current_group)
                        es = EncryptedString(
                            raw_bytes=raw,
                            cipher_type='xor_single',
                            key=bytes([0]),  # already XORed
                            source_offset=current_group[0][1],
                        )
                        es.decrypt()
                        results.append(es)
                    current_group = [bxor_pairs[i]]

            if len(current_group) >= 2:
                raw = bytes(p[0] & 0xFF for p in current_group)
                es = EncryptedString(
                    raw_bytes=raw,
                    cipher_type='xor_single',
                    key=bytes([0]),
                    source_offset=current_group[0][1],
                )
                es.decrypt()
                results.append(es)

        # 3. LPH encoded strings (base64 + possible XOR)
        for match in self.RE_LPH_ENCODED.finditer(source):
            encoded = match.group(1)
            es = EncryptedString(
                raw_bytes=encoded,
                cipher_type='b64_xor',
                source_offset=match.start(),
            )
            es.decrypt()
            results.append(es)

        return results

    def replace_in_source(self, source: bytes, strings: List[EncryptedString]) -> bytes:
        """Replace encrypted patterns with decrypted plaintext in source."""
        # Sort by offset descending so replacements don't shift earlier positions
        for s in sorted(strings, key=lambda x: x.source_offset, reverse=True):
            plaintext = s.plaintext or s.decrypt()
            # Find the original pattern extent
            # We replace from source_offset to the end of the matched pattern
            # Simple approach: replace the raw bytes around the offset
            # This is conservative — only replaces if we can find the pattern
            pass  # Actual replacement is handled in the reconstructor

        return source

    def build_string_table(self, strings: List[EncryptedString]) -> dict:
        """Build a lookup table of offset -> plaintext for the reconstructor."""
        return {
            s.source_offset: s.plaintext or s.decrypt()
            for s in strings
            if s.plaintext
        }
