#!/usr/bin/env python3
"""Focused unit tests for pure helper functions in Python research tools."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str):
    module_path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sweep = load_module("rth_sweep_sample_chunks", "tools/sweep_sample_chunks.py")
cli_runner = load_module("rth_run_sample_cli", "tools/run_sample_cli.py")


class ChunkPeriodTests(unittest.TestCase):
    def test_four_chunk_cycle(self) -> None:
        self.assertEqual(sweep.shortest_proper_period(["A", "B", "C", "D", "A", "B", "C", "D"]), 4)

    def test_two_chunk_cycle(self) -> None:
        self.assertEqual(sweep.shortest_proper_period(["A", "B", "A", "B", "A"]), 2)

    def test_constant_sequence_has_period_one(self) -> None:
        self.assertEqual(sweep.shortest_proper_period(["A", "A", "A"]), 1)

    def test_nonperiodic_sequence_reports_none(self) -> None:
        self.assertIsNone(sweep.shortest_proper_period(["A", "B", "C", "D"]))

    def test_one_chunk_is_not_a_repeat(self) -> None:
        self.assertIsNone(sweep.shortest_proper_period(["A"]))


class ArchivePathSafetyTests(unittest.TestCase):
    def test_accepts_normal_nested_member(self) -> None:
        self.assertEqual(sweep.parse_size("0x40000"), 0x40000)
        self.assertEqual(cli_runner.safe_relative_path("folder/asset.bin"), Path("folder/asset.bin"))

    def test_rejects_parent_traversal(self) -> None:
        with self.assertRaises(ValueError):
            cli_runner.safe_relative_path("../escape.bin")

    def test_rejects_windows_separator(self) -> None:
        with self.assertRaises(ValueError):
            cli_runner.safe_relative_path(r"..\escape.bin")

    def test_rejects_absolute_path(self) -> None:
        with self.assertRaises(ValueError):
            cli_runner.safe_relative_path("/tmp/escape.bin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
