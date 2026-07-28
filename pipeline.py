"""
Main deobfuscation pipeline - orchestrates the full deobfuscation process.
"""
import os
import time
import logging
from typing import Optional, Dict, Any
from .detector import LuraphDetector
from .string_decryptor import StringDecryptor
from .vm_analyzer import VMAnalyzer
from .opcode_mapper import OpcodeMapper
from .bytecode_reconstructor import BytecodeReconstructor

logger = logging.getLogger(__name__)


class DeobfuscationPipeline:
    """Full pipeline: detect -> decrypt strings -> analyze VM -> map opcodes -> reconstruct."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.detector = LuraphDetector()
        self.string_decryptor = StringDecryptor()
        self.vm_analyzer = VMAnalyzer()
        self.opcode_mapper = OpcodeMapper()
        self.bytecode_reconstructor = BytecodeReconstructor()

    def deobfuscate(self, input_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the full deobfuscation pipeline on a Lua file.

        Args:
            input_path: Path to obfuscated Lua file.
            output_path: Where to write cleaned file. Defaults to input_deobf.lua

        Returns:
            Dict with status, timing, and metadata about the process.
        """
        start_time = time.time()
        result = {
            "success": False,
            "input": input_path,
            "output": None,
            "stages": {},
            "errors": [],
            "elapsed": 0.0,
        }

        # --- Stage 0: Read file ---
        try:
            with open(input_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
            result["stages"]["read"] = {"size_bytes": len(source), "lines": source.count("\n") + 1}
            logger.info(f"Read {input_path} ({len(source)} bytes)")
        except Exception as e:
            result["errors"].append(f"Read failed: {e}")
            result["elapsed"] = time.time() - start_time
            return result

        # --- Stage 1: Detection ---
        try:
            detection = self.detector.detect(source)
            result["stages"]["detection"] = detection
            if not detection["is_luraph"]:
                logger.warning("File does not appear to be Luraph-obfuscated.")
                result["errors"].append("Not Luraph-obfuscated (or signature not recognized).")
                result["elapsed"] = time.time() - start_time
                return result
            logger.info(f"Detection: Luraph v{detection.get('version', 'unknown')}")
        except Exception as e:
            result["errors"].append(f"Detection failed: {e}")
            result["elapsed"] = time.time() - start_time
            return result

        # --- Stage 2: String Decryption ---
        try:
            t = time.time()
            decrypted_source, strings_decrypted = self.string_decryptor.decrypt_all(source)
            result["stages"]["string_decryption"] = {
                "count": strings_decrypted,
                "elapsed": time.time() - t,
            }
            logger.info(f"Decrypted {strings_decrypted} strings in {time.time()-t:.2f}s")
        except Exception as e:
            result["errors"].append(f"String decryption failed: {e}")
            strings_decrypted = 0
            decrypted_source = source

        # --- Stage 3: VM Analysis ---
        try:
            t = time.time()
            vm_info = self.vm_analyzer.analyze(decrypted_source)
            result["stages"]["vm_analysis"] = {
                **vm_info,
                "elapsed": time.time() - t,
            }
            logger.info(f"VM analysis complete: {vm_info.get('vm_count', 0)} VM handlers found")
        except Exception as e:
            result["errors"].append(f"VM analysis failed: {e}")
            vm_info = {}

        # --- Stage 4: Opcode Mapping ---
        try:
            t = time.time()
            opcode_table = self.opcode_mapper.build_map(decrypted_source, vm_info)
            mapped = sum(1 for v in opcode_table.values() if v is not None)
            result["stages"]["opcode_mapping"] = {
                "total_opcodes": len(opcode_table),
                "mapped": mapped,
                "elapsed": time.time() - t,
            }
            logger.info(f"Mapped {mapped}/{len(opcode_table)} opcodes")
        except Exception as e:
            result["errors"].append(f"Opcode mapping failed: {e}")
            opcode_table = {}

        # --- Stage 5: Bytecode Reconstruction ---
        try:
            t = time.time()
            reconstructed = self.bytecode_reconstructor.reconstruct(
                decrypted_source, opcode_table, vm_info
            )
            result["stages"]["reconstruction"] = {
                "elapsed": time.time() - t,
            }
            logger.info(f"Reconstruction complete in {time.time()-t:.2f}s")
        except Exception as e:
            result["errors"].append(f"Reconstruction failed: {e}")
            reconstructed = decrypted_source  # fallback to decrypted source

        # --- Write output ---
        if output_path is None:
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_deobf{ext or '.lua'}"

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(reconstructed)
            result["output"] = output_path
            result["success"] = True
            logger.info(f"Output written to {output_path}")
        except Exception as e:
            result["errors"].append(f"Write failed: {e}")

        result["elapsed"] = time.time() - start_time
        return result

    def deobfuscate_source(self, source: str) -> str:
        """Deobfuscate a source string directly without file I/O."""
        detection = self.detector.detect(source)
        if not detection["is_luraph"]:
            logger.warning("Source does not appear to be Luraph-obfuscated.")

        decrypted, _ = self.string_decryptor.decrypt_all(source)
        vm_info = self.vm_analyzer.analyze(decrypted)
        opcode_table = self.opcode_mapper.build_map(decrypted, vm_info)
        reconstructed = self.bytecode_reconstructor.reconstruct(
            decrypted, opcode_table, vm_info
        )
        return reconstructed
