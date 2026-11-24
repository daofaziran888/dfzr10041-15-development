#!/usr/bin/env python3
"""跑一遍“字段映射重算批次”的 A/B 完整剧本并打印/落盘回执。

用法（在 backend/ 目录下）：
    python3 run_recalc_scenario.py
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.mapping_recalc import run_standard_scenario  # noqa: E402


def main() -> int:
    report = run_standard_scenario(write_artifacts=True)
    print(json.dumps(report["checks"], ensure_ascii=False, indent=2))
    failed = [name for name, ok in report["checks"].items() if not ok]
    if failed:
        print("FAILED:", failed)
        return 1
    print("\n回执文件：")
    for p in report.get("artifact_paths", []):
        print(" -", p)
    print("\n全部核对通过：A 先 HIGH 出高警包；补齐 B 证据续跑后 B HIGH；并发只派一份。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
