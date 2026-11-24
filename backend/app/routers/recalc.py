"""字段映射重算批次的动作接口（可选的 HTTP 入口）。

核心逻辑全部在 app.core.mapping_recalc，路由只做分派与 JSON 序列化。
- 分阶段操作共享一个标准 A/B 场景单例，供“先查级别 → 首轮 → 补 B 证据 → 续跑”；
- /api/recalc/auto 在隔离批次里一次性跑完题目剧本并返回全部核对结果。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.mapping_recalc import (
    FieldMappingRecalcBatch,
    build_ab_scenario,
    run_standard_scenario,
)

router = APIRouter(prefix="/api/recalc", tags=["字段映射重算批次"])

_batch: FieldMappingRecalcBatch | None = None


def get_batch() -> FieldMappingRecalcBatch:
    global _batch
    if _batch is None:
        _batch = build_ab_scenario()
    return _batch


class EvidencePayload(BaseModel):
    source: str | None = None
    evidence_id: str | None = None
    key: str | None = None
    detail: str | None = None
    confirmed_by: str | None = None


class ClaimPayload(BaseModel):
    officer: str = "值班员"
    raw_line: str | None = None
    source: str | None = None
    package_id: str | None = None
    item_id: str | None = None


class ConfirmPayload(BaseModel):
    source: str


@router.post("/reset")
def reset() -> dict[str, Any]:
    global _batch
    _batch = build_ab_scenario()
    return {"ok": True, "batch_id": _batch.batch_id}


@router.get("/levels")
def levels() -> dict[str, Any]:
    batch = get_batch()
    return {"ok": True, "batch_id": batch.batch_id, "levels": batch.query_levels()}


@router.post("/run")
def run_batch(mode: str | None = None) -> dict[str, Any]:
    batch = get_batch()
    if mode in ("atomic", "per_source"):
        batch.release_mode = mode
    report = batch.run()
    return {"ok": True, **{k: v for k, v in report.items() if k not in ("sources", "receipts", "packages")},
            "receipts": [r.to_dict() for r in batch.receipts],
            "packages": [
                {"package_id": p.package_id, "source": p.source, "raw_lines": p.raw_lines}
                for p in batch.high_alert_packages
            ]}


@router.post("/evidence")
def complete_evidence(payload: EvidencePayload) -> dict[str, Any]:
    batch = get_batch()
    if payload.source and payload.key:
        ev = batch.confirm_key(
            payload.source, payload.key,
            detail=payload.detail or "",
            confirmed_by=payload.confirmed_by or "值班员")
    elif payload.evidence_id:
        ev = batch.confirm_key(
            payload.evidence_id,
            detail=payload.detail or "",
            confirmed_by=payload.confirmed_by or "值班员")
    else:
        return {"ok": False, "message": "需要 evidence_id 或 (source, key)"}
    return {"ok": True, "evidence": ev.to_dict()}


@router.post("/confirm")
def confirm_source(payload: ConfirmPayload) -> dict[str, Any]:
    receipt = get_batch().confirm_source(payload.source)
    return {"ok": True, "receipt": receipt.to_dict()}


@router.post("/retry")
def retry() -> dict[str, Any]:
    batch = get_batch()
    report = batch.retry()
    return {"ok": True, "continued_sources": report.get("continued_sources", []),
            "levels": batch.query_levels(),
            "receipts": [r.to_dict() for r in batch.receipts]}


@router.get("/receipts")
def receipts() -> dict[str, Any]:
    batch = get_batch()
    return {"ok": True, "receipts": [r.to_dict() for r in batch.receipts],
            "by_source": {s: batch.get_receipt(s).to_dict()
                          for s in batch._states if batch.get_receipt(s)}}


@router.get("/packages")
def packages() -> dict[str, Any]:
    batch = get_batch()
    return {"ok": True, "packages": [
        {"package_id": p.package_id, "source": p.source, "target": p.target,
         "count": p.count, "raw_lines": p.raw_lines, "items": p.payload()}
        for p in batch.high_alert_packages]}


@router.post("/claim")
def claim(payload: ClaimPayload) -> dict[str, Any]:
    ticket = get_batch().claim(
        officer=payload.officer, raw_line=payload.raw_line or "",
        source=payload.source or "", package_id=payload.package_id or "",
        item_id=payload.item_id or "")
    return {"ok": True, "ticket": ticket.to_dict()}


@router.get("/chain-evidence")
def chain_evidence(request_id: str = "REQ-CHAIN-001",
                   a_raw_line: str = "", b_raw_line: str = "") -> dict[str, Any]:
    ev = get_batch().build_chain_evidence(
        request_id=request_id,
        a_raw_line=a_raw_line or None, b_raw_line=b_raw_line or None)
    return {"ok": ev.ready, "evidence": ev.to_dict()}


@router.post("/auto")
def auto() -> dict[str, Any]:
    """一次性跑完题目完整剧本（在独立批次/独立探测上），返回全部核对项。"""
    report = run_standard_scenario(write_artifacts=False)
    return {"ok": all(report["checks"].values()), "report": report}
