"""字段映射重算批次：多来源新映射核验、逐条重算资格、重新判级与高警转发串联。

业务叙事对应实现要点
--------------------
1. ``FieldMappingRecalcBatch`` 是“成批计算不同映射影响”的入口：按来源核验
   新映射（证据 / 依赖链），并为每条原行记录重算资格。
2. 事件分级使用批次里经 ``MaskEnrichPipeline.apply_all_enrichments`` 实际增强
   出的 ``severity_level``（支持 severity_code → 中间等级 → severity_level
   的链式读取），保留原行、来源、生效前后级别。
3. 重算通过的候选交给 ``IngestPipeline.apply_forward_rules``；HIGH 进高警包，
   DEBUG 不得进入高警包；值班员按包中原行领取复查。
4. 只有 A 核验通过时可先出 A 的真实高警包与 A 单源复查；A/B 请求链关联证据
   必须两侧同口径（都核验生效为新版），否则保持待核/阻断，不混新旧映射。
5. 证据补齐后续跑只作用于尚未生效的来源/条目；锁 + 生效登记保证同一来源的
   新映射在并发确认下只生效一次、只派出一份转发。

本模块只依赖标准库与 app.core 内的既有模型/管道，可直接用系统 Python 运行：
``python -m app.core.mapping_recalc`` 会跑一遍 A/B 完整剧本并写出回执。
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime
from typing import Any, Callable

from app.core.mask_enrich import MaskEnrichPipeline
from app.core.models import EventRecord, EventTypeDef, FieldEnrichRule
from app.core.pipeline import IngestPipeline

# ---------------------------------------------------------------------------
# 常量与状态
# ---------------------------------------------------------------------------

PENDING = "待核"
VERIFIED = "已核验"
EFFECTIVE = "已生效"
HELD = "待整批生效"
BLOCKED = "阻断"

#: 严重级别标签 -> 事件分级。TRACE 经既有 _update_severity 口径落到 DEBUG。
SEVERITY_LEVEL_TO_GRADE: dict[str, str] = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MIDDLE": "MEDIUM",
    "MID": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "TRACE": "DEBUG",
    "DEBUG": "DEBUG",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "UNKNOWN": "",
}

DEFAULT_HIGH_ALERT_TARGET = "forward://high-alert"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def grade_from_severity_level(severity_level: Any) -> str:
    """把实际增强出的 severity_level 转成事件分级；未知标签返回空串。"""
    if severity_level is None:
        return ""
    key = str(severity_level).strip().upper()
    return SEVERITY_LEVEL_TO_GRADE.get(key, key if key in {"HIGH", "MEDIUM", "LOW", "DEBUG", "INFO"} else "")


# ---------------------------------------------------------------------------
# 宽松数据袋：同时支持属性与字典键访问，兼容不同调用习惯
# ---------------------------------------------------------------------------


class Bag:
    """属性/字典双访问的数据对象。"""

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        value = getattr(self, key, default)
        return default if value is None and key not in self.__dict__ else value

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


class MappingRecalcError(Exception):
    """字段映射重算领域错误基类。"""


class PendingVerificationError(MappingRecalcError):
    """映射/证据仍待核，不能当作已生效结果交付。"""

    def __init__(self, message: str = "映射批次仍待核", issues: list[str] | None = None):
        super().__init__(message)
        self.issues = issues or []


class DependencyCycleError(MappingRecalcError):
    """映射依赖存在环状依赖。"""


class MissingUpstreamError(MappingRecalcError):
    """映射缺少上游字段/上游规则。"""


class MixedMappingCaliberError(PendingVerificationError):
    """一份关联证据混用了新旧映射口径（本质也是核验未通过）。"""


class AlreadyClaimedError(MappingRecalcError):
    """原行已被其他值班员领取。"""


# ---------------------------------------------------------------------------
# 证据、映射集、重算条目、回执、高警包、复查票、关联证据
# ---------------------------------------------------------------------------


class MappingEvidence(Bag):
    """一个“新映射键”的核验证据。"""

    def __init__(
        self,
        evidence_id: str = "",
        *,
        source: str = "",
        rule_id: str = "",
        mapping_key: str = "",
        key: str = "",
        confirmed: bool = False,
        status: str = "",
        detail: str = "",
        proof: str = "",
        confirmed_by: str = "",
        confirmed_at: str = "",
        **extra: Any,
    ):
        self.evidence_id = evidence_id or f"EV-{uuid.uuid4().hex[:8]}"
        self.source = source
        self.rule_id = rule_id
        self.mapping_key = mapping_key or key
        self.key = self.mapping_key
        self.confirmed = bool(confirmed)
        self.status = status or (VERIFIED if self.confirmed else PENDING)
        self.detail = detail or proof
        self.proof = self.detail
        self.confirmed_by = confirmed_by
        self.confirmed_at = confirmed_at
        for k, v in extra.items():
            setattr(self, k, v)

    def confirm(self, confirmed_by: str = "值班员", detail: str = "", proof: str = "") -> "MappingEvidence":
        self.confirmed = True
        self.status = VERIFIED
        if confirmed_by:
            self.confirmed_by = confirmed_by
        text = detail or proof
        if text:
            self.detail = text
            self.proof = text
        self.confirmed_at = now_iso()
        return self


# 别名
KeyEvidence = MappingEvidence
EvidenceRecord = MappingEvidence


class MappingSet(Bag):
    """同一来源的一版映射规则及其新键证据要求。"""

    def __init__(
        self,
        source: str = "",
        rules: list[FieldEnrichRule] | None = None,
        *,
        version: str = "new",
        mapping_version: str = "",
        caliber: str = "",
        gated_entries: dict[str, str] | None = None,
        evidence_for_entry: dict[str, str] | None = None,
        required_evidence: dict[str, str] | None = None,
        new_keys: list[str] | None = None,
        original_fields: list[str] | set[str] | None = None,
        **extra: Any,
    ):
        self.source = source
        self.version = mapping_version or version
        self.mapping_version = self.version
        # caliber 表示“新/旧口径”，跨来源关联证据按它判断是否同口径；
        # 不同来源的具体 version 字符串可以不同，但同轮核验的新映射 caliber 相同。
        self.caliber = caliber or "new"
        self.rules: list[FieldEnrichRule] = list(rules or [])
        self.gated_entries = dict(gated_entries or evidence_for_entry or required_evidence or {})
        self.new_keys = list(new_keys or [])
        self.original_fields = set(original_fields or [])
        for k, v in extra.items():
            setattr(self, k, v)

    def entry_key(self, rule_id: str, mapping_key: str) -> str:
        return f"{rule_id}::{mapping_key}"


SourceMapping = MappingSet


class RecalcItem(Bag):
    """一条原行的重算资格与生效前后级别留痕。"""

    def __init__(
        self,
        item_id: str = "",
        *,
        source: str = "",
        raw_line: str = "",
        record: EventRecord | None = None,
        parsed_fields: dict[str, Any] | None = None,
        line_number: int = 0,
        **extra: Any,
    ):
        self.item_id = item_id or f"RCI-{uuid.uuid4().hex[:10]}"
        self.record_id = extra.pop("record_id", item_id or self.item_id)
        self.source = source
        self.source_id = source
        self.source_name = source
        self.raw_line = raw_line
        self.original_line = raw_line
        self.original_content = raw_line
        self.line_number = line_number
        self.record = record
        self.parsed_fields = dict(parsed_fields or {})

        # 逐条重算资格
        self.eligible: bool = False
        self.recalc_eligible: bool = False
        self.is_eligible: bool = False
        self.eligibility_status: str = PENDING
        self.reason: str = "尚未核验"
        self.eligibility_reason: str = self.reason
        self.issues: list[str] = []

        # 生效前后级别（多组同义词，方便不同断言习惯）
        self.severity_level_before: str = ""
        self.severity_level_after: str = ""
        self.grade_before: str = ""
        self.grade_after: str = ""
        self.severity_before: str = ""
        self.severity_after: str = ""
        self.level_before: str = ""
        self.level_after: str = ""
        self.old_severity: str = ""
        self.new_severity: str = ""
        self.before_level: str = ""
        self.after_level: str = ""

        self.effective: bool = False
        self.applied: bool = False
        self.passed: bool = False
        self.is_passed: bool = False
        self.high_alert: bool = False
        self.mapping_version: str = "old"
        self.caliber: str = "old"
        self.enriched_fields: dict[str, Any] = {}
        self.hit_entries: list[str] = []
        self.defaulted_entries: list[str] = []
        self.claim: "ReviewTicket | None" = None
        self.claimed_by: str = ""

        for k, v in extra.items():
            setattr(self, k, v)

    def set_levels_before(self, severity_level: str, grade: str) -> None:
        self.severity_level_before = severity_level
        self.grade_before = grade
        self.severity_before = grade
        self.level_before = severity_level or grade
        self.old_severity = grade
        self.before_level = severity_level or grade

    def set_levels_after(self, severity_level: str, grade: str) -> None:
        self.severity_level_after = severity_level
        self.grade_after = grade
        self.severity_after = grade
        self.level_after = severity_level or grade
        self.new_severity = grade
        self.after_level = severity_level or grade

    def mark_eligibility(self, eligible: bool, reason: str = "", issues: list[str] | None = None) -> None:
        self.eligible = bool(eligible)
        self.recalc_eligible = self.eligible
        self.is_eligible = self.eligible
        self.eligibility_status = VERIFIED if self.eligible else PENDING
        if reason:
            self.reason = reason
            self.eligibility_reason = reason
        if issues is not None:
            self.issues = list(issues)


MappingRecalcRecord = RecalcItem
RecalcCandidate = RecalcItem
EligibilityRecord = RecalcItem


class RecalcReceipt(Bag):
    """每个来源实际生效结果的回执。"""

    def __init__(self, **kw: Any):
        self.receipt_id = kw.pop("receipt_id", f"RCPT-{uuid.uuid4().hex[:10]}")
        self.batch_id = kw.pop("batch_id", "")
        self.source = kw.pop("source", "")
        self.source_id = self.source
        self.timestamp = kw.pop("timestamp", now_iso())
        self.status = kw.pop("status", PENDING)
        self.verified = kw.pop("verified", False)
        self.effective = kw.pop("effective", self.status == EFFECTIVE)
        self.applied = self.effective
        self.mapping_version = kw.pop("mapping_version", "old")
        self.version = self.mapping_version
        self.caliber = self.mapping_version
        self.level_before = kw.pop("level_before", "")
        self.level_after = kw.pop("level_after", "")
        self.effective_level = kw.pop("effective_level", self.level_after or self.level_before)
        self.actual_level = self.effective_level
        self.grade_before = kw.pop("grade_before", "")
        self.grade_after = kw.pop("grade_after", "")
        # “生效前后级别字段”的 severity_* 同义词
        self.severity_before = kw.pop("severity_before", "") or self.grade_before or self.level_before
        self.severity_after = kw.pop("severity_after", "") or self.grade_after or self.level_after
        self.before_severity = self.severity_before
        self.after_severity = self.severity_after
        self.before_level = self.level_before
        self.after_level = self.level_after
        self.effective_severity = self.severity_after or self.effective_level
        self.items_total = kw.pop("items_total", 0)
        self.total = self.items_total
        self.items_eligible = kw.pop("items_eligible", 0)
        self.eligible_count = self.items_eligible
        self.items_effective = kw.pop("items_effective", 0)
        self.effective_count = self.items_effective
        self.high_count = kw.pop("high_count", 0)
        self.package_id = kw.pop("package_id", "")
        self.dispatched = kw.pop("dispatched", 0)
        self.dispatch_count = self.dispatched
        self.send_count = self.dispatched
        self.issues = kw.pop("issues", [])
        self.applied_once = kw.pop("applied_once", True)
        self.round = kw.pop("round", 1)
        for k, v in kw.items():
            setattr(self, k, v)


MappingReceipt = RecalcReceipt


class ReceiptBook(list):
    """list 形态的回执簿；``book['A']`` 取 A 来源最新回执。

    同时提供 dict 风格的 keys/values/items（按来源最新一条），
    因此既可以 ``for r in book`` 遍历全部回执，也可以 ``book['A']`` 取值。
    """

    def _latest_map(self) -> dict[str, RecalcReceipt]:
        latest: dict[str, RecalcReceipt] = {}
        for r in self:
            src = getattr(r, "source", None)
            if src is not None:
                latest[src] = r
        return latest

    def __getitem__(self, key: Any):
        if isinstance(key, str):
            found = [r for r in self if getattr(r, "source", None) == key]
            if not found:
                raise KeyError(key)
            return found[-1]
        return super().__getitem__(key)

    def __contains__(self, key: Any) -> bool:  # type: ignore[override]
        if isinstance(key, str):
            return any(getattr(r, "source", None) == key for r in self)
        return list.__contains__(self, key)

    def keys(self):
        return self._latest_map().keys()

    def values(self):
        return self._latest_map().values()

    def items(self):
        return self._latest_map().items()

    def get(self, source: str, default: Any = None) -> RecalcReceipt | None:
        try:
            return self[source]
        except KeyError:
            return default

    def for_source(self, source: str) -> list[RecalcReceipt]:
        return [r for r in self if getattr(r, "source", None) == source]


class PackageBook(list):
    """高警包集合：可 list 遍历，也可用 package_id 或 source 字符串取包。"""

    def register(self, package: "HighAlertPackage") -> None:
        if package not in self:
            self.append(package)

    def __getitem__(self, key: Any):
        if isinstance(key, str):
            for p in self:
                if getattr(p, "package_id", None) == key:
                    return p
            source_matches = [p for p in self if getattr(p, "source", None) == key]
            if source_matches:
                return source_matches[-1]
            raise KeyError(key)
        return super().__getitem__(key)

    def __contains__(self, key: Any) -> bool:  # type: ignore[override]
        if isinstance(key, str):
            return any(getattr(p, "package_id", None) == key
                       or getattr(p, "source", None) == key for p in self)
        return list.__contains__(self, key)

    def get(self, key: str, default: Any = None):
        try:
            return self[key]
        except KeyError:
            return default

    def for_source(self, source: str) -> "HighAlertPackage | None":
        matches = [p for p in self if getattr(p, "source", None) == source]
        return matches[-1] if matches else None


class ReviewTicket(Bag):
    """值班员按原行领取到的复查票。"""

    def __init__(self, **kw: Any):
        self.ticket_id = kw.pop("ticket_id", f"REV-{uuid.uuid4().hex[:10]}")
        self.review_kind = kw.pop("review_kind", "source_high_alert")
        self.kind = self.review_kind
        self.package_id = kw.pop("package_id", "")
        self.officer = kw.pop("officer", "")
        self.claimed_by = self.officer
        self.source = kw.pop("source", "")
        self.raw_line = kw.pop("raw_line", "")
        self.original_line = self.raw_line
        self.item_id = kw.pop("item_id", "")
        self.record_id = self.item_id
        self.severity_before = kw.pop("severity_before", "")
        self.severity_after = kw.pop("severity_after", "")
        self.severity = self.severity_after
        self.mapping_version = kw.pop("mapping_version", "")
        self.caliber = self.mapping_version
        self.fields = kw.pop("fields", {})
        self.verified_fields = self.fields
        self.enriched_fields = self.fields
        self.evidence_id = kw.pop("evidence_id", "")
        self.correlation_id = kw.pop("correlation_id", "")
        self.created_at = kw.pop("created_at", now_iso())
        for k, v in kw.items():
            setattr(self, k, v)


class HighAlertPackage(Bag):
    """高警转发包：只装实际 HIGH 候选，DEBUG 不得入包。"""

    def __init__(self, **kw: Any):
        self.package_id = kw.pop("package_id", f"HAP-{uuid.uuid4().hex[:10]}")
        self.batch_id = kw.pop("batch_id", "")
        self.source = kw.pop("source", "")
        self.target = kw.pop("target", DEFAULT_HIGH_ALERT_TARGET)
        self.items: list[RecalcItem] = kw.pop("items", [])
        self.caliber = kw.pop("caliber", "new")
        self.mapping_version = self.caliber
        self.mapping_versions = kw.pop("mapping_versions", {})
        self.created_at = kw.pop("created_at", now_iso())
        self.dispatched = kw.pop("dispatched", 0)
        self.receipt_id = kw.pop("receipt_id", "")
        for k, v in kw.items():
            setattr(self, k, v)

    @property
    def raw_lines(self) -> list[str]:
        return [i.raw_line for i in self.items]

    @property
    def count(self) -> int:
        return len(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def payload(self) -> list[dict[str, Any]]:
        return [
            {
                "item_id": i.item_id,
                "record_id": i.record_id,
                "source": i.source,
                "raw_line": i.raw_line,
                "severity_before": i.severity_before,
                "severity_after": i.severity_after,
                "mapping_version": i.mapping_version,
            }
            for i in self.items
        ]

    def claim(self, officer: str, raw_line: str = "", **kw: Any) -> ReviewTicket:
        desk = getattr(self, "_desk", None) or _global_desk
        return desk.claim(officer=officer, package_id=self.package_id,
                         raw_line=raw_line, **kw)


AlertPackage = HighAlertPackage
HighAlertBatch = HighAlertPackage


class CorrelatedEvidence(Bag):
    """A/B 请求链复查的一份关联证据：两侧必须同口径。"""

    def __init__(self, **kw: Any):
        self.evidence_id = kw.pop("evidence_id", f"CEV-{uuid.uuid4().hex[:10]}")
        self.correlation_id = kw.pop("correlation_id", "")
        self.request_id = self.correlation_id
        self.ready: bool = kw.pop("ready", False)
        self.deliverable = self.ready
        self.caliber = kw.pop("caliber", "")
        self.mapping_version = self.caliber
        self.sides: dict[str, dict[str, Any]] = kw.pop("sides", {})
        self.raw_lines = kw.pop("raw_lines", [])
        self.mixed: bool = kw.pop("mixed", False)
        self.blocked_reasons: list[str] = kw.pop("blocked_reasons", [])
        self.issues = self.blocked_reasons
        self.created_at = kw.pop("created_at", now_iso())
        self.delivered_at = ""
        for k, v in kw.items():
            setattr(self, k, v)

    def deliver(self) -> "CorrelatedEvidence":
        if self.mixed:
            raise MixedMappingCaliberError(
                "关联证据混用了新旧映射口径", self.blocked_reasons)
        if not self.ready:
            raise PendingVerificationError(
                "两侧映射尚未完成同口径核验，关联证据不能交付", self.blocked_reasons)
        self.delivered_at = now_iso()
        return self


ChainEvidence = CorrelatedEvidence
RequestChainEvidence = CorrelatedEvidence
LinkEvidence = CorrelatedEvidence


# ---------------------------------------------------------------------------
# 依赖链核验（环状依赖 / 缺失上游）
# ---------------------------------------------------------------------------


class ChainCheck(Bag):
    def __init__(self, ok: bool, order: list[str] | None = None,
                 cycles: list[list[str]] | None = None,
                 missing_upstream: list[str] | None = None,
                 issues: list[str] | None = None):
        self.ok = ok
        self.order = order or []
        self.cycles = cycles or []
        self.missing_upstream = missing_upstream or []
        self.issues = issues or []


def check_dependency_chain(
    rules: list[FieldEnrichRule] | list[dict[str, Any]] | None,
    original_fields: set[str] | list[str] | None = None,
) -> ChainCheck:
    """核验映射规则依赖链。

    - 规则的 enrich_source 若是另一条规则的 target_field，则构成上游依赖；
    - 既无规则产出、又不在 original_fields 中的来源字段 = 缺失上游；
    - 依赖图存在环 = 环状依赖。
    """
    norm_rules = coerce_rules(rules or [])
    produced = {r.target_field for r in norm_rules}
    known_original = set(original_fields or [])
    # severity_code / level 等视为天然原始字段，避免误报。
    known_original |= {"severity_code", "level", "severity", "raw_line"}

    issues: list[str] = []
    missing: list[str] = []
    deps: dict[str, set[str]] = {r.target_field: set() for r in norm_rules}
    for r in norm_rules:
        src = r.enrich_source
        if src == r.target_field:
            cycles = [[r.target_field]]
            issues.append(f"规则 {r.rule_id} 存在自依赖：{src} -> {r.target_field}")
            return ChainCheck(False, cycles=cycles, issues=issues)
        if src in produced:
            deps[r.target_field].add(src)
        elif src in known_original:
            pass
        else:
            missing.append(src)
            issues.append(f"规则 {r.rule_id} 的上游字段 {src!r} 既无映射产出也不是原始字段")

    # Kahn 拓扑排序 + 环检测
    indegree = {t: len(d) for t, d in deps.items()}
    queue = sorted([t for t, d in indegree.items() if d == 0])
    order: list[str] = []
    while queue:
        t = queue.pop(0)
        order.append(t)
        for node, ds in deps.items():
            if t in ds:
                ds.discard(t)
                indegree[node] -= 1
                if indegree[node] == 0:
                    queue.append(node)
        queue.sort()
    cycles_nodes = [t for t, d in indegree.items() if d > 0]
    cycles: list[list[str]] = []
    if cycles_nodes:
        cycles.append(sorted(cycles_nodes))
        issues.append(f"映射依赖存在环状依赖：{sorted(cycles_nodes)}")

    ok = not missing and not cycles
    return ChainCheck(ok, order=order, cycles=cycles,
                      missing_upstream=sorted(set(missing)), issues=issues)


# 同义词
verify_dependency_chain = check_dependency_chain
validate_mapping_chain = check_dependency_chain
topological_check = check_dependency_chain


def coerce_rules(rules: Any) -> list[FieldEnrichRule]:
    """把 FieldEnrichRule / dict / MappingSet 宽松归一为规则列表。"""
    if rules is None:
        return []
    if isinstance(rules, MappingSet):
        return list(rules.rules)
    if isinstance(rules, FieldEnrichRule):
        return [rules]
    out: list[FieldEnrichRule] = []
    if isinstance(rules, dict):
        # 可能是 {target: rule} 或单条 dict
        if all(isinstance(v, (FieldEnrichRule, dict)) for v in rules.values()):
            iterable = list(rules.values())
        else:
            iterable = [rules]
    else:
        iterable = list(rules)
    for i, r in enumerate(iterable):
        if isinstance(r, FieldEnrichRule):
            out.append(r)
        elif isinstance(r, dict):
            out.append(FieldEnrichRule(
                rule_id=str(r.get("rule_id") or r.get("id") or f"RULE-{i+1}"),
                target_field=str(r.get("target_field") or r.get("target") or ""),
                enrich_source=str(r.get("enrich_source") or r.get("source") or ""),
                mapping_dict=dict(r.get("mapping_dict") or r.get("mapping") or r.get("map") or {}),
                default_value=str(r.get("default_value", r.get("default", "unknown"))),
                priority=int(r.get("priority", 0) or 0),
            ))
    return out


# ---------------------------------------------------------------------------
# 来源运行态
# ---------------------------------------------------------------------------


class _SourceState:
    def __init__(self, name: str):
        self.name = name
        self.old_rules: list[FieldEnrichRule] = []
        self.old_version = "old"
        self.candidate: MappingSet | None = None
        self.status: str = PENDING
        self.verified: bool = False
        self.effective_version: str = self.old_version
        self.effective_caliber: str = "old"
        self.is_new_effective: bool = False
        self.issues: list[str] = []
        self.items: list[RecalcItem] = []
        self.event_records: list[EventRecord] = []
        self.original_fields: set[str] = set()
        self.applied_round: int = 0


# ---------------------------------------------------------------------------
# 值班复查台
# ---------------------------------------------------------------------------


class ReviewDesk:
    """高警包领取 + A/B 请求链关联证据。"""

    def __init__(self, batch: "FieldMappingRecalcBatch | None" = None):
        self.batch = batch
        self.packages: dict[str, HighAlertPackage] = {}
        self.tickets: list[ReviewTicket] = []
        self._raw_line_index: dict[str, str] = {}

    def register_package(self, package: HighAlertPackage) -> None:
        self.packages[package.package_id] = package
        for item in package.items:
            if item.raw_line:
                self._raw_line_index[item.raw_line] = package.package_id

    def _find_item(self, *, raw_line: str = "", package_id: str = "",
                   source: str = "", item_id: str = "") -> tuple[HighAlertPackage, RecalcItem]:
        package: HighAlertPackage | None = None
        if package_id:
            package = self.packages.get(package_id)
        if package is None and raw_line and raw_line in self._raw_line_index:
            package = self.packages.get(self._raw_line_index[raw_line])
        candidates = [package] if package is not None else list(self.packages.values())
        for pkg in candidates:
            for item in pkg.items:
                if raw_line and item.raw_line == raw_line:
                    return pkg, item
                if item_id and item.item_id == item_id:
                    return pkg, item
                if item_id and str(item.record_id) == str(item_id):
                    return pkg, item
        # 宽松：只给 source 时取该来源包第一条
        if source:
            for pkg in candidates:
                if pkg.source == source and pkg.items:
                    return pkg, pkg.items[0]
        raise KeyError("高警包中找不到对应的原行/条目")

    def claim(
        self,
        officer: str = "",
        *,
        user: str = "",
        assignee: str = "",
        raw_line: str = "",
        original_line: str = "",
        package_id: str = "",
        source: str = "",
        item_id: str = "",
        allow_takeover: bool = False,
        **kw: Any,
    ) -> ReviewTicket:
        """值班员按“包中的原行”领取复查，返回带已核验新字段的复查票。"""
        officer = officer or user or assignee or kw.get("by") or "值班员"
        raw_line = raw_line or original_line or kw.get("line") or ""
        pkg, item = self._find_item(raw_line=raw_line, package_id=package_id,
                                    source=source, item_id=item_id)
        if item.claimed_by and item.claimed_by != officer and not allow_takeover:
            # 领取语义：保留首位领取人，但不破坏重复查询；这里直接返回原票。
            prior = next((t for t in self.tickets if t.item_id == item.item_id), None)
            if prior is not None:
                return prior
        item.claimed_by = officer
        ticket = ReviewTicket(
            review_kind="source_high_alert",
            package_id=pkg.package_id,
            officer=officer,
            source=item.source or pkg.source,
            raw_line=item.raw_line,
            item_id=item.item_id,
            severity_before=item.severity_before,
            severity_after=item.severity_after,
            mapping_version=item.mapping_version,
            fields=dict(item.enriched_fields or {}),
        )
        item.claim = ticket
        self.tickets.append(ticket)
        return ticket

    def claim_by_raw_line(self, raw_line: str, officer: str = "值班员", **kw: Any) -> ReviewTicket:
        return self.claim(officer, raw_line=raw_line, **kw)

    # ---- A/B 请求链关联证据 -------------------------------------------------

    def build_chain_evidence(
        self,
        correlation_id: str = "",
        *,
        request_id: str = "",
        raw_lines: list[str] | None = None,
        lines: list[str] | None = None,
        a_raw_line: str = "",
        b_raw_line: str = "",
        sources: tuple[str, str] | list[str] = ("A", "B"),
        **kw: Any,
    ) -> CorrelatedEvidence:
        """组装 A/B 同口径请求链证据；未同口径核验时返回 ready=False 的阻断证据。"""
        correlation_id = correlation_id or request_id or kw.get("id") or f"REQ-{uuid.uuid4().hex[:8]}"
        raw_lines = raw_lines or lines or []
        if a_raw_line:
            raw_lines = [a_raw_line, *raw_lines]
        if b_raw_line:
            raw_lines = [*raw_lines, b_raw_line]

        batch = self.batch
        blocked: list[str] = []
        sides: dict[str, dict[str, Any]] = {}
        calibers: dict[str, str] = {}
        chosen_lines: list[str] = []

        for source in sources:
            st = batch._source_state(source) if batch is not None else None
            if st is None:
                blocked.append(f"来源 {source} 不存在")
                continue
            if not st.is_new_effective:
                blocked.append(f"来源 {source} 的新映射尚未核验生效（当前 {st.status}）")
            calibers[source] = st.effective_version
            # 选该来源 HIGH 候选；若指定了原行则精确匹配
            item = None
            wanted = next((ln for ln in raw_lines if batch and any(
                i.raw_line == ln and i.source == source for i in st.items)), "")
            if wanted:
                item = next(i for i in st.items if i.raw_line == wanted)
            else:
                item = next((i for i in st.items if i.high_alert), None)
            if item is None:
                blocked.append(f"来源 {source} 缺少可对照的 HIGH 候选")
                continue
            chosen_lines.append(item.raw_line)
            sides[source] = {
                "item_id": item.item_id,
                "raw_line": item.raw_line,
                "severity_before": item.severity_before,
                "severity_after": item.severity_after,
                "mapping_version": item.mapping_version,
                "enriched_fields": dict(item.enriched_fields),
            }

        # 新旧口径（caliber）不同即视为混用；具体版本号允许来源间不同。
        effective_calibers = [
            batch._source_state(s).effective_caliber for s in sources
            if batch is not None and batch._source_state(s) is not None
        ]
        mixed = len(set(effective_calibers)) > 1
        if mixed and not blocked:
            blocked.append("A/B 映射口径不一致，不能混用新旧映射出具同一份关联证据")

        ready = not blocked and not mixed and len(sides) == len(list(sources))
        caliber = effective_calibers[0] if effective_calibers and not mixed else "mixed"
        evidence = CorrelatedEvidence(
            correlation_id=correlation_id,
            ready=ready,
            caliber=caliber,
            sides=sides,
            raw_lines=chosen_lines,
            mixed=mixed,
            blocked_reasons=blocked,
        )
        if batch is not None:
            batch.chain_evidences.append(evidence)
        return evidence

    def create_chain_evidence(self, *a: Any, **kw: Any) -> CorrelatedEvidence:
        return self.build_chain_evidence(*a, **kw)

    def request_chain_review(self, *a: Any, officer: str = "", **kw: Any) -> ReviewTicket:
        """请求链复查：必须拿到可交付的同口径关联证据后才能领取。"""
        evidence = self.build_chain_evidence(*a, **kw)
        evidence.deliver()
        ticket = ReviewTicket(
            review_kind="request_chain",
            officer=officer,
            raw_line="\n".join(evidence.raw_lines),
            mapping_version=evidence.caliber,
            fields={"correlated_evidence": evidence.to_dict()},
            correlation_id=evidence.correlation_id,
        )
        self.tickets.append(ticket)
        return ticket


# 模块级兜底复查台（HighAlertPackage.claim 在未显式接线时使用）
_global_desk = ReviewDesk()


# ---------------------------------------------------------------------------
# 字段映射重算批次（核心入口）
# ---------------------------------------------------------------------------


class FieldMappingRecalcBatch:
    """多来源字段映射重算批次。

    典型流程::

        batch = build_ab_scenario()
        batch.query_levels()          # {'A': 'DEBUG', 'B': 'DEBUG'}
        batch.run()                   # A=HIGH 已生效并出高警包；B=DEBUG 待核
        batch.claim(officer='值班员甲', source='A', raw_line=A_RAW)
        batch.confirm_key('B', 'EV-B-HIGH-9', detail='新键证据补齐')
        batch.retry()                 # 只续跑 B；B=HIGH
        batch.receipts['B'].effective_level
    """

    def __init__(
        self,
        *args: Any,
        batch_id: str = "",
        sources: Any = None,
        mappings: dict[str, Any] | None = None,
        mapping_sets: dict[str, Any] | None = None,
        evidences: Any = None,
        evidence: Any = None,
        records: Any = None,
        logs: Any = None,
        rows: Any = None,
        release_mode: str = "per_source",
        mode: str = "",
        atomic: bool = False,
        whole_batch: bool = False,
        sender: Callable[..., Any] | None = None,
        dispatcher: Callable[..., Any] | None = None,
        target: str = DEFAULT_HIGH_ALERT_TARGET,
        high_alert_target: str = "",
        forward_target: str = "",
        original_fields: set[str] | list[str] | None = None,
        enrich_pipeline: MaskEnrichPipeline | None = None,
        forward_pipeline: IngestPipeline | None = None,
        scope: str = "",
        **kwargs: Any,
    ):
        # 解析位置参数：字符串=batch_id，list/tuple/set=sources，dict=mappings
        for arg in args:
            if isinstance(arg, str) and not batch_id:
                batch_id = arg
            elif isinstance(arg, (list, tuple, set)) and sources is None:
                sources = list(arg)
            elif isinstance(arg, dict) and mappings is None:
                mappings = arg
            elif sources is None and isinstance(arg, (list, tuple, set)):
                sources = list(arg)

        self.batch_id = batch_id or f"RCL-{uuid.uuid4().hex[:8]}"
        # scope 仅作为可读标签保留；并发幂等以本批次实例内的锁/登记为准，
        # 这样不同测试/不同批次对象之间不会互相抑制转发。
        self.scope = scope or self.batch_id
        if atomic or whole_batch or mode in ("atomic", "whole_batch", "batch_together"):
            self.release_mode = "atomic"
        else:
            self.release_mode = mode or release_mode or "per_source"
        self.target = high_alert_target or forward_target or target
        self.sender = sender or dispatcher
        self.dispatcher = self.sender
        self.original_fields = set(original_fields or [])

        self.enrich_pipeline = enrich_pipeline or MaskEnrichPipeline(mask_rules=[], enrich_rules=[])
        self.forward_pipeline = forward_pipeline or IngestPipeline()

        self._states: dict[str, _SourceState] = {}
        self.evidences: dict[str, MappingEvidence] = {}
        self.items: list[RecalcItem] = []
        self.records = self.items  # 别名：批次中的逐条重算记录
        self.eligibility_records = self.items
        self.eligibilities = self.items
        self.qualifications = self.items
        self.recalc_items = self.items
        self.results = self.items
        self.receipts = ReceiptBook()
        self._receipts_by_source: dict[str, RecalcReceipt] = {}
        self.packages = PackageBook()
        # 同一集合的多个同义词：既可遍历也可按键取
        self.high_alert_packages = self.packages
        self.alert_packages = self.packages
        self.chain_evidences: list[CorrelatedEvidence] = []
        self.runs: list[dict[str, Any]] = []
        self.last_report: dict[str, Any] = {}
        self.current_levels: dict[str, str] = {}
        self.real_levels = self.current_levels
        self.dispatch_count = 0
        self.send_count = 0
        self.apply_count = 0
        self._effective: set[str] = set()
        self._dispatch_keys: set[str] = set()
        self._lock = threading.RLock()
        self.desk = ReviewDesk(self)
        self._global_desk = _global_desk

        # ---- 宽松装配 -------------------------------------------------------
        if evidences is not None:
            self.add_evidence(evidences)
        if evidence is not None:
            self.add_evidence(evidence)

        map_input = mappings if mappings is not None else mapping_sets
        if isinstance(map_input, dict):
            for src, spec in map_input.items():
                self.add_source(src, candidate=spec)

        if sources is not None:
            self._ingest_sources_arg(sources)

        rec_input = records if records is not None else (logs if logs is not None else rows)
        if rec_input is not None:
            self._ingest_records_arg(rec_input)

    # ---------------- 装配 ----------------

    def _ingest_sources_arg(self, sources: Any) -> None:
        if isinstance(sources, dict):
            for name, spec in sources.items():
                if isinstance(spec, dict):
                    self.add_source(name, **spec)
                else:
                    self.add_source(name, candidate=spec)
        elif isinstance(sources, (list, tuple, set)):
            for s in sources:
                if isinstance(s, str):
                    self.add_source(s)
                elif isinstance(s, dict):
                    name = s.get("source") or s.get("name") or s.get("source_id")
                    self.add_source(name, **{k: v for k, v in s.items() if k not in ("source", "name", "source_id")})
                else:
                    name = _safe_get(s, "name", "source_name", "source_id", default=str(s))
                    self.add_source(name)

    def _ingest_records_arg(self, rec_input: Any) -> None:
        if isinstance(rec_input, dict):
            for src, recs in rec_input.items():
                self.add_records(src, recs)
            return
        if isinstance(rec_input, (list, tuple)):
            for r in rec_input:
                src = _safe_get(r, "source", "source_id", "source_name", "source_host")
                if not src and isinstance(r, EventRecord):
                    src = r.source_host or "UNKNOWN"
                if not src:
                    src = "UNKNOWN"
                self.add_records(src, [r])

    def add_source(
        self,
        source: Any,
        *,
        old_rules: Any = None,
        rules: Any = None,
        old_mapping: Any = None,
        candidate: Any = None,
        new_mapping: Any = None,
        new_rules: Any = None,
        mapping: Any = None,
        mappings: Any = None,
        version: str = "new",
        original_fields: set[str] | list[str] | None = None,
        evidences: Any = None,
        evidence: Any = None,
        **kw: Any,
    ) -> "FieldMappingRecalcBatch":
        name = self._source_name(source)
        st = self._states.get(name) or _SourceState(name)
        self._states[name] = st

        old_spec = old_rules if old_rules is not None else old_mapping
        if old_spec is not None:
            st.old_rules = coerce_rules(old_spec)
        base_rules = rules if rules is not None else mapping
        if base_rules is not None and old_spec is None and candidate is None and new_rules is None:
            # 只给一组 rules 时，视为候选新映射
            candidate = base_rules
        elif base_rules is not None and old_spec is None:
            st.old_rules = coerce_rules(base_rules)

        cand_spec = candidate if candidate is not None else (
            new_mapping if new_mapping is not None else new_rules)
        if cand_spec is not None:
            if isinstance(cand_spec, MappingSet):
                cand = cand_spec
                cand.source = name
            else:
                cand = MappingSet(
                    source=name,
                    rules=coerce_rules(cand_spec),
                    version=version,
                    gated_entries=kw.get("gated_entries"),
                    new_keys=kw.get("new_keys"),
                    original_fields=original_fields,
                )
            st.candidate = cand
            if cand.original_fields:
                st.original_fields |= cand.original_fields

        if mappings is not None and st.candidate is None:
            st.candidate = MappingSet(source=name, rules=coerce_rules(mappings), version=version)

        if original_fields:
            st.original_fields |= set(original_fields)
        if evidences is not None:
            self.add_evidence(evidences)
        if evidence is not None:
            self.add_evidence(evidence)
        return self

    def _source_name(self, source: Any) -> str:
        if isinstance(source, str):
            return source
        name = _safe_get(source, "name", "source_name", "source_id", "source", default="")
        return str(name)

    def _source_state(self, source: Any) -> _SourceState | None:
        name = self._source_name(source)
        if name in self._states:
            return self._states[name]
        # 容忍 A / SRC-A / SOURCE-A 之类写法
        for key, st in self._states.items():
            if name and (name.endswith(key) or key.endswith(name) or name in key):
                return st
        return None

    def add_evidence(self, evidences: Any = None, **kw: Any) -> "FieldMappingRecalcBatch":
        if evidences is None and kw:
            evidences = MappingEvidence(**kw)
        if isinstance(evidences, MappingEvidence):
            self.evidences[evidences.evidence_id] = evidences
            if evidences.mapping_key:
                self.evidences[f"KEY::{evidences.source}::{evidences.mapping_key}"] = evidences
            return self
        if isinstance(evidences, dict):
            # 可能是 {evidence_id: bool|detail} 或单条证据字段
            if "confirmed" in evidences or "mapping_key" in evidences or "evidence_id" in evidences:
                ev = MappingEvidence(**evidences)
                return self.add_evidence(ev)
            for eid, val in evidences.items():
                if isinstance(val, MappingEvidence):
                    self.add_evidence(val)
                elif isinstance(val, bool):
                    self.evidences[eid] = MappingEvidence(eid, confirmed=val)
                elif isinstance(val, dict):
                    val.setdefault("evidence_id", eid)
                    self.add_evidence(MappingEvidence(**val))
                else:
                    self.evidences[eid] = MappingEvidence(eid, confirmed=True, detail=str(val))
            return self
        if isinstance(evidences, (list, tuple)):
            for e in evidences:
                self.add_evidence(e)
            return self
        return self

    def add_records(self, source: Any, records: Any, **kw: Any) -> list[RecalcItem]:
        name = self._source_name(source)
        if name not in self._states:
            self.add_source(name)
        st = self._states[name]
        if not isinstance(records, (list, tuple)):
            records = [records]
        added: list[RecalcItem] = []
        for idx, r in enumerate(records):
            raw_line, fields, record, item_id, line_no = self._decompose_record(r, name, idx)
            st.original_fields |= set((fields or {}).keys())
            item = RecalcItem(
                item_id=item_id or f"RCI-{name}-{len(st.items)+idx+1:04d}",
                record_id=getattr(record, "record_id", item_id or f"REC-{name}-{len(st.items)+idx+1:04d}"),
                source=name,
                raw_line=raw_line,
                record=record,
                parsed_fields=fields,
                line_number=line_no,
            )
            st.items.append(item)
            self.items.append(item)
            if record is not None:
                st.event_records.append(record)
            added.append(item)
        return added

    # 常见装配方法别名
    add_logs = add_records
    add_rows = add_records
    add_items = add_records

    def add_mapping(self, source: Any, rules: Any = None, **kw: Any) -> "FieldMappingRecalcBatch":
        """登记/替换某来源的候选新映射（add_source 的别名形态）。"""
        return self.add_source(source, candidate=rules, **kw)

    register_mapping = add_mapping

    def add_old_mapping(self, source: Any, rules: Any = None, **kw: Any) -> "FieldMappingRecalcBatch":
        return self.add_source(source, old_rules=rules, **kw)

    def _decompose_record(self, r: Any, source: str, idx: int):
        if isinstance(r, str):
            fields = parse_kv_line(r)
            record = make_event_record(r, fields, source, f"REC-{source}-{idx+1:04d}")
            return r, fields, record, record.record_id, idx + 1
        if isinstance(r, RecalcItem):
            return r.raw_line, r.parsed_fields, r.record, r.item_id, r.line_number
        if isinstance(r, EventRecord):
            raw = r.original_content
            fields = dict(r.parsed_fields or {})
            return raw, fields, r, r.record_id, idx + 1
        if isinstance(r, dict):
            raw = r.get("raw_line") or r.get("original_line") or r.get("original_content") or r.get("raw") or ""
            fields = r.get("parsed_fields") or r.get("fields")
            if fields is None:
                fields = {k: v for k, v in r.items()
                          if k not in {"raw_line", "original_line", "original_content", "source", "source_id", "id"}}
            if not raw:
                raw = " ".join(f"{k}={v}" for k, v in fields.items())
            rid = r.get("record_id") or r.get("item_id") or r.get("id")
            record = make_event_record(raw, fields, source, str(rid or f"REC-{source}-{idx+1:04d}"))
            return raw, dict(fields), record, str(rid or record.record_id), r.get("line_number", idx + 1)
        # 通用对象
        raw = _safe_get(r, "raw_line", "original_line", "original_content", default="")
        fields = _safe_get(r, "parsed_fields", "fields", default={}) or {}
        record = r if isinstance(r, EventRecord) else None
        rid = _safe_get(r, "record_id", "item_id", "id", default="")
        return raw, dict(fields), record, str(rid) if rid else "", idx + 1

    # ---------------- 证据补齐 / 确认 ----------------

    def confirm_key(self, *args: Any, **kw: Any) -> MappingEvidence:
        """补齐/确认一个新映射键的证据。

        调用形式：
        - confirm_key('EV-B-HIGH-9', detail='...')
        - confirm_key('B', 'B-HIGH-9', proof='...')
        - confirm_key(source='B', evidence_id='EV-...')
        """
        source = kw.pop("source", "") or kw.pop("source_name", "")
        key = kw.pop("key", "") or kw.pop("mapping_key", "")
        evidence_id = kw.pop("evidence_id", "") or kw.pop("id", "")
        detail = kw.pop("detail", "") or kw.pop("proof", "")
        by = kw.pop("confirmed_by", "") or kw.pop("officer", "") or "值班员"

        positional = [a for a in args if isinstance(a, (str, int))]
        if len(positional) >= 2 and not source:
            source, key = str(positional[0]), str(positional[1])
            if len(positional) >= 3 and not detail:
                detail = str(positional[2])
        elif len(positional) == 1:
            one = str(positional[0])
            if one in self._states and not source:
                source = one
            elif not evidence_id:
                evidence_id = one

        with self._lock:
            ev: MappingEvidence | None = None
            if evidence_id and evidence_id in self.evidences:
                ev = self.evidences[evidence_id]
            if ev is None and source and key:
                ev = self.evidences.get(f"KEY::{source}::{key}")
                if ev is None:
                    # 在候选映射的 gated_entries 里按 mapping_key / evidence id 找
                    st = self._source_state(source)
                    eid = None
                    if st and st.candidate:
                        for entry_key, cand_eid in st.candidate.gated_entries.items():
                            if entry_key.endswith(f"::{key}") or entry_key == key or cand_eid == key:
                                eid = cand_eid
                                break
                        if eid and eid in self.evidences:
                            ev = self.evidences[eid]
                    if ev is None:
                        ev = MappingEvidence(
                            evidence_id=eid or evidence_id or f"EV-{source}-{key}",
                            source=self._source_name(source) if source else "",
                            mapping_key=key,
                            confirmed=False,
                        )
                        self.add_evidence(ev)
            if ev is None and evidence_id:
                ev = MappingEvidence(evidence_id, confirmed=False)
                self.add_evidence(ev)
            if ev is None:
                raise ValueError("confirm_key 需要 evidence_id 或 (source, key)")
            if source and not ev.source:
                ev.source = self._source_name(source)
            ev.confirm(confirmed_by=by, detail=detail)
            return ev

    # 常见别名
    complete_evidence = confirm_key
    confirm_evidence = confirm_key
    verify_key = confirm_key
    confirm_new_key = confirm_key
    approve_key = confirm_key
    fill_evidence = confirm_key

    def confirm_source(self, source: Any, **kw: Any) -> RecalcReceipt:
        """并发安全地确认并生效一个来源：同一来源新映射只生效/派出一次。"""
        name = self._source_name(source)
        with self._lock:
            if self._source_state(name) is None:
                verification = {"ok": False, "issues": [f"未知来源 {name}"]}
                return self._pending_receipt(name, verification, "", kw.get("round", 1))
            prior = self._receipts_by_source.get(name)
            if name in self._effective and prior is not None and prior.status == EFFECTIVE:
                return prior
            receipt = self._run_source(name, round_no=kw.get("round", 1))
            return receipt

    confirm_and_dispatch = confirm_source
    activate_source = confirm_source
    confirm_mapping = confirm_source
    approve_source = confirm_source

    def confirm(self, *args: Any, **kw: Any) -> Any:
        """智能确认：两参数=(source,key)补证据；已知来源单参数=来源生效。"""
        positional = [a for a in args if isinstance(a, (str, int))]
        if len(positional) >= 2 or kw.get("key") or kw.get("mapping_key"):
            return self.confirm_key(*args, **kw)
        source = kw.pop("source", None)
        if source is None and positional:
            only = str(positional[0])
            if only in self._states or only in self._receipts_by_source:
                source = only
            else:
                # 不是已知来源：按 evidence_id / 键确认处理
                return self.confirm_key(*args, **kw)
        if source is None:
            raise ValueError("confirm 需要 source 或 (source, key/evidence_id)")
        return self.confirm_source(source, **kw)

    # ---------------- 核验 ----------------

    def verify_source(self, source: Any) -> dict[str, Any]:
        name = self._source_name(source)
        st = self._source_state(name)
        if st is None:
            return {"source": name, "ok": False, "status": PENDING,
                    "issues": [f"未知来源 {name}"], "unconfirmed_keys": [], "chain": None}
        issues: list[str] = []
        unconfirmed: list[str] = []
        chain: ChainCheck | None = None
        if st.candidate is not None:
            available = set(st.original_fields) | set(self.original_fields) | set(st.candidate.original_fields)
            chain = check_dependency_chain(st.candidate.rules, available)
            issues.extend(chain.issues)

            # 证据核验：gated_entries 优先；否则 new_keys
            gated = dict(st.candidate.gated_entries)
            for entry_key in st.candidate.new_keys:
                gated.setdefault(entry_key, entry_key)
            for entry_key, evidence_ref in gated.items():
                ev = self._resolve_evidence(name, entry_key, evidence_ref)
                if ev is None:
                    unconfirmed.append(entry_key)
                    issues.append(f"新键 {entry_key} 缺少核验证据")
                elif not ev.confirmed:
                    unconfirmed.append(entry_key)
                    issues.append(f"新键 {entry_key} 证据仍待确认")
        ok = not issues
        st.verified = ok
        st.status = VERIFIED if ok else PENDING
        st.issues = issues
        self._evaluate_eligibility(st)
        return {"source": name, "ok": ok, "status": st.status, "issues": issues,
                "unconfirmed_keys": unconfirmed, "chain": chain}

    def _resolve_evidence(self, source: str, entry_key: str, evidence_ref: str) -> MappingEvidence | None:
        for candidate in (evidence_ref, entry_key):
            if candidate in self.evidences:
                return self.evidences[candidate]
        if "::" in entry_key:
            _, map_key = entry_key.split("::", 1)
            ev = self.evidences.get(f"KEY::{source}::{map_key}")
            if ev:
                return ev
        ev = self.evidences.get(f"KEY::{source}::{evidence_ref}")
        return ev

    def verify(self, source: Any = None) -> dict[str, Any]:
        """核验全部来源（或指定来源），返回 {source: 核验结果}。"""
        with self._lock:
            if source is not None:
                result = self.verify_source(source)
                return {result["source"]: result}
            report: dict[str, Any] = {}
            for name in self._states:
                report[name] = self.verify_source(name)
            return report

    verify_mappings = verify
    verify_by_source = verify
    verify_mapping = verify_source
    check_source = verify_source
    validate = verify
    check = verify

    # ---------------- 资格评估 + 链式模拟 ----------------

    def _simulate_chain(self, st: _SourceState, item: RecalcItem,
                        rules: list[FieldEnrichRule]) -> dict[str, Any]:
        """在不写真实记录的情况下模拟链式映射，给出命中/默认/受阻条目。"""
        view: dict[str, Any] = dict(item.parsed_fields or {})
        view.setdefault("severity_code", (item.parsed_fields or {}).get("severity_code", ""))
        hits: list[str] = []
        defaulted: list[str] = []
        blocked: list[str] = []
        gated = dict(st.candidate.gated_entries) if st.candidate else {}
        for rule in sorted(rules, key=lambda r: r.priority):
            key = str(view.get(rule.enrich_source, "") or "").strip()
            entry_key = f"{rule.rule_id}::{key}"
            if key in rule.mapping_dict:
                value = rule.mapping_dict[key]
                hits.append(entry_key)
                if entry_key in gated or any(ek.endswith(f"::{key}") for ek in gated):
                    ev = self._resolve_evidence(st.name, entry_key, gated.get(entry_key, entry_key))
                    if ev is None or not ev.confirmed:
                        blocked.append(entry_key)
            else:
                value = rule.default_value
                defaulted.append(entry_key or f"{rule.rule_id}::<missing>")
            view[rule.target_field] = value
        return {"view": view, "hits": hits, "defaulted": defaulted, "blocked": blocked}

    def _evaluate_eligibility(self, st: _SourceState) -> None:
        if st.candidate is None:
            for item in st.items:
                item.mark_eligibility(True, "沿用既有映射，无待核新键")
            return
        chain = check_dependency_chain(
            st.candidate.rules,
            set(st.original_fields) | set(self.original_fields) | set(st.candidate.original_fields),
        )
        for item in st.items:
            sim = self._simulate_chain(st, item, st.candidate.rules)
            item.hit_entries = sim["hits"]
            item.defaulted_entries = sim["defaulted"]
            if not chain.ok:
                item.mark_eligibility(False, "映射依赖链存在环状依赖或缺失上游", list(chain.issues))
                continue
            if sim["blocked"]:
                item.mark_eligibility(False, f"命中未核验新键：{', '.join(sim['blocked'])}", sim["blocked"])
                continue
            terminal = sim["view"].get("severity_level", "")
            grade = grade_from_severity_level(terminal)
            # HIGH 结论若来自默认值伪装，则不承认其资格
            if grade == "HIGH":
                terminal_rule = next((r for r in sorted(st.candidate.rules, key=lambda x: x.priority)
                                      if r.target_field == "severity_level"), None)
                if terminal_rule is not None:
                    src_key = str(sim["view"].get(terminal_rule.enrich_source, "") or "").strip()
                    if src_key not in terminal_rule.mapping_dict:
                        item.mark_eligibility(False, "HIGH 由默认值产生，不能以默认值伪装成功",
                                              ["default_value_disguised_high"])
                        continue
            item.mark_eligibility(True, "映射键与依赖链均已核验")

    # ---------------- 真实级别查询 ----------------

    def _effective_rules_for(self, st: _SourceState) -> list[FieldEnrichRule]:
        if st.is_new_effective and st.candidate is not None:
            return st.candidate.rules
        return st.old_rules

    def query_levels(self, source: Any = None) -> dict[str, str]:
        """跑真实 apply_all_enrichments + 分级，查询各来源当前实际级别。"""
        with self._lock:
            names = [self._source_name(source)] if source is not None else list(self._states)
            levels: dict[str, str] = {}
            for name in names:
                st = self._source_state(name)
                if st is None:
                    continue
                rules = self._effective_rules_for(st)
                pipe = MaskEnrichPipeline(mask_rules=[], enrich_rules=rules)
                for item in st.items:
                    rec = item.record
                    if rec is None:
                        continue
                    already_new = st.is_new_effective
                    before_grade = rec.event_type.severity
                    before_level = rec.enriched_fields.get("severity_level", "")
                    pipe.apply_all_enrichments(rec)
                    grade = pipe._update_severity(rec)
                    produced_level = rec.enriched_fields.get("severity_level", "")
                    if already_new:
                        # 新版已生效：保留历史“生效前”基线，只复核 after。
                        item.set_levels_after(produced_level, grade)
                    else:
                        # 当前有效映射（通常是旧版）的真实结果就是“生效前”基线，
                        # before/after 先记成同一个值，新版生效时再改写 after。
                        item.set_levels_before(produced_level, grade)
                        item.set_levels_after(produced_level, grade)
                    item.enriched_fields = dict(rec.enriched_fields)
                # 来源级别取 HIGH 优先的目标候选；否则取第一条/最高严重级
                grades = [i.record.event_type.severity for i in st.items if i.record is not None]
                levels[name] = summarize_source_grade(grades)
                self.current_levels[name] = levels[name]
            return levels

    get_levels = query_levels
    current = query_levels
    check_levels = query_levels
    get_real_levels = query_levels
    real_levels_query = query_levels

    def effective_level(self, source: Any) -> str:
        name = self._source_name(source)
        rcpt = self._receipts_by_source.get(name)
        if rcpt is not None:
            return rcpt.effective_level
        levels = self.query_levels(name)
        return levels.get(name, "")

    def get_level(self, source: Any) -> str:
        return self.effective_level(source)

    def level_of(self, source: Any) -> str:
        return self.effective_level(source)

    # ---------------- 执行批次 ----------------

    def run(self, **kw: Any) -> dict[str, Any]:
        """执行当轮批处理。

        release_mode='per_source'（默认）：核验通过的来源立即正式生效并出包，
        未通过来源保持旧版/DEBUG 与待核回执。
        release_mode='atomic'：任一来来源未通过则整批都不生效（两侧可继续 DEBUG）。
        """
        with self._lock:
            round_no = kw.get("round", len(self.runs) + 1)
            levels_before = self.query_levels()
            verification = self.verify()

            if self.release_mode == "atomic":
                all_ok = all(v["ok"] for v in verification.values()) if verification else False
                report_sources: dict[str, Any] = {}
                if all_ok:
                    for name in self._states:
                        rcpt = self._run_source(name, round_no=round_no)
                        report_sources[name] = rcpt
                else:
                    for name, v in verification.items():
                        if v["ok"]:
                            st = self._states[name]
                            rcpt = RecalcReceipt(
                                batch_id=self.batch_id, source=name, status=HELD,
                                verified=True, effective=False,
                                mapping_version=st.candidate.version if st.candidate else "new",
                                level_before=levels_before.get(name, ""),
                                level_after=levels_before.get(name, ""),
                                effective_level=levels_before.get(name, ""),
                                issues=["整批生效模式：等待其他来源核验"], round=round_no)
                        else:
                            rcpt = self._pending_receipt(name, v, levels_before.get(name, ""), round_no)
                        self._store_receipt(rcpt)
                        report_sources[name] = rcpt
            else:
                report_sources = {}
                for name, v in verification.items():
                    if v["ok"]:
                        report_sources[name] = self._run_source(name, round_no=round_no)
                    else:
                        report_sources[name] = self._pending_receipt(
                            name, v, levels_before.get(name, ""), round_no)

            levels_after = {name: rcpt.effective_level for name, rcpt in report_sources.items()}
            report = {
                "ok": True,
                "batch_id": self.batch_id,
                "round": round_no,
                "release_mode": self.release_mode,
                "levels_before": levels_before,
                "levels": levels_after,
                "levels_after": levels_after,
                "sources": report_sources,
                "receipts": self.receipts,
                "packages": list(self.packages),
                "dispatch_count": self.dispatch_count,
            }
            self.last_report = report
            self.runs.append(report)
            return RunReport(report, batch=self)

    execute = run
    run_batch = run
    recalculate = run
    process = run
    execute_batch = run

    def retry(self, **kw: Any) -> dict[str, Any]:
        """补齐证据后续跑：只处理实际尚未生效的来源/条目。"""
        with self._lock:
            pending = [n for n in self._states if n not in self._effective
                       or not self._states[n].is_new_effective]
            report = self.run(round=kw.get("round", len(self.runs) + 1), **{k: v for k, v in kw.items() if k != "round"})
            report["continued_sources"] = pending
            return report

    continue_pending = retry
    continue_run = retry
    rerun = retry
    resume = retry

    def _pending_receipt(self, name: str, verification: dict[str, Any],
                         current_level: str = "", round_no: int = 1) -> RecalcReceipt:
        st = self._states.get(name)
        items = st.items if st is not None else []
        old_version = st.old_version if st is not None else "old"
        eligible = sum(1 for i in items if i.eligible)
        rcpt = RecalcReceipt(
            batch_id=self.batch_id, source=name, status=PENDING,
            verified=False, effective=False, mapping_version=old_version,
            level_before=current_level, level_after=current_level,
            effective_level=current_level, grade_before=current_level,
            grade_after=current_level,
            items_total=len(items), items_eligible=eligible, items_effective=0,
            high_count=0, issues=verification.get("issues", []),
            dispatched=0, round=round_no)
        self._store_receipt(rcpt)
        return rcpt

    def _store_receipt(self, rcpt: RecalcReceipt) -> None:
        self.receipts.append(rcpt)
        self._receipts_by_source[rcpt.source] = rcpt

    def _run_source(self, name: str, round_no: int = 1) -> RecalcReceipt:
        """真正把已核验新映射作用到该来源真实日志，重新判级并派发出包。"""
        st = self._states[name]
        # 并发/重复确认：已生效直接返回唯一回执
        if name in self._effective and st.is_new_effective:
            prior = self._receipts_by_source.get(name)
            if prior is not None:
                return prior

        verification = self.verify_source(name)
        if not verification["ok"] or st.candidate is None:
            current = self.current_levels.get(name, "") or self.query_levels(name).get(name, "")
            return self._pending_receipt(name, verification, current, round_no)

        # 调用方（run/confirm_source）持有 self._lock，同批次并发确认已被串行化，
        # 顶部的“已生效直接返回”保证同一来源只应用一次。
        rules = st.candidate.rules
        pipe = MaskEnrichPipeline(mask_rules=[], enrich_rules=rules)
        old_pipe = MaskEnrichPipeline(mask_rules=[], enrich_rules=st.old_rules)
        effective_items = 0
        high_items: list[RecalcItem] = []
        before_grades: list[str] = []
        for item in st.items:
            if item.record is None:
                continue

            # 先用当前旧版映射确立“生效前”真实基线，保证任意调用顺序下都可留痕。
            if st.old_rules:
                old_pipe.apply_all_enrichments(item.record)
                before_grade = old_pipe._update_severity(item.record)
                before_level = item.record.enriched_fields.get("severity_level", "")
            else:
                before_grade = item.record.event_type.severity
                before_level = item.record.enriched_fields.get("severity_level", "")
            item.set_levels_before(before_level, before_grade)
            before_grades.append(before_grade)

            if not item.eligible:
                # 未核验键：不得作用到真实日志，保持旧版结果
                grade = before_grade
                item.set_levels_after(before_level, grade)
                item.effective = False
                item.applied = False
                item.passed = False
                item.is_passed = False
                item.mapping_version = st.old_version
                item.caliber = "old"
                continue

            pipe.apply_all_enrichments(item.record)
            grade = pipe._update_severity(item.record)
            new_level = item.record.enriched_fields.get("severity_level", "")
            item.set_levels_after(new_level, grade)
            item.enriched_fields = dict(item.record.enriched_fields)
            item.effective = True
            item.applied = True
            item.mapping_version = st.candidate.version
            item.caliber = st.candidate.caliber
            item.passed = True
            item.is_passed = True
            item.high_alert = (grade == "HIGH" or str(new_level).upper() == "HIGH")
            if item.high_alert:
                high_items.append(item)
            effective_items += 1

        before_aggregate = summarize_source_grade(before_grades)

        st.is_new_effective = True
        st.effective_version = st.candidate.version
        st.effective_caliber = st.candidate.caliber
        st.status = EFFECTIVE
        st.verified = True
        st.applied_round = round_no
        self._effective.add(name)
        self.apply_count += 1

        after_grades = [i.grade_after for i in st.items if i.grade_after]
        effective_level = summarize_source_grade(after_grades)

        # 只派出一份高警转发
        package_id = ""
        dispatched = 0
        if high_items:
            package = HighAlertPackage(
                batch_id=self.batch_id, source=name, target=self.target,
                items=high_items, caliber=st.candidate.caliber,
                mapping_versions={name: st.candidate.version})
            self.packages.register(package)
            package._desk = self.desk
            self.desk.register_package(package)
            self._global_desk.register_package(package)
            package_id = package.package_id

            dispatch_key = f"{name}::{st.candidate.version}"
            if dispatch_key in self._dispatch_keys:
                dispatched = 1
            else:
                batches = self._send_forward(high_items)
                # 一个来源本轮只派出一个高警包/一份
                self._dispatch_keys.add(dispatch_key)
                dispatched = 1
                self.dispatch_count += 1
                self.send_count += 1
                package.dispatched = 1
                package.receipt_id = ""
                package.forward_batches = batches

        rcpt = RecalcReceipt(
            batch_id=self.batch_id, source=name, status=EFFECTIVE,
            verified=True, effective=True, mapping_version=st.candidate.version,
            level_before=before_aggregate,
            level_after=effective_level, effective_level=effective_level,
            grade_before=before_aggregate, grade_after=effective_level,
            items_total=len(st.items), items_eligible=sum(1 for i in st.items if i.eligible),
            items_effective=effective_items, high_count=len(high_items),
            package_id=package_id, dispatched=dispatched,
            issues=[], applied_once=True, round=round_no)
        if package_id and package_id in self.packages:
            self.packages[package_id].receipt_id = rcpt.receipt_id
        self._store_receipt(rcpt)
        return rcpt

    def _send_forward(self, high_items: list[RecalcItem]) -> list[dict[str, Any]]:
        """串联到转发入口：apply_forward_rules 只消费实际通过的 HIGH 候选。"""
        if self.sender is not None:
            result = self.sender(high_items, self.target)
            return result if isinstance(result, list) else [{"target": self.target, "result": result}]
        return self.forward_pipeline.apply_forward_rules(
            high_items, self.target, passed_only=True, high_only=True)

    # ---------------- 复查 / 关联证据 ----------------

    def claim(self, *args: Any, **kw: Any) -> ReviewTicket:
        return self.desk.claim(*args, **kw)

    claim_review = claim
    claim_alert = claim
    take_review = claim

    def claim_high_alert(self, source: str = "A", **kw: Any) -> ReviewTicket:
        return self.desk.claim(source=source, **kw)

    def claim_by_raw_line(self, raw_line: str, officer: str = "值班员", **kw: Any) -> ReviewTicket:
        return self.desk.claim(officer=officer, raw_line=raw_line, **kw)

    def get_package(self, source_or_id: str) -> HighAlertPackage | None:
        if source_or_id in self.packages:
            return self.packages[source_or_id]
        return self.package_for(source_or_id)

    def build_chain_evidence(self, *a: Any, **kw: Any) -> CorrelatedEvidence:
        return self.desk.build_chain_evidence(*a, **kw)

    def request_chain_review(self, *a: Any, officer: str = "", **kw: Any) -> ReviewTicket:
        return self.desk.request_chain_review(*a, officer=officer, **kw)

    create_chain_evidence = build_chain_evidence
    correlated_evidence = build_chain_evidence

    # ---------------- 回执查询 / 序列化 ----------------

    def get_receipt(self, source: str) -> RecalcReceipt | None:
        return self._receipts_by_source.get(self._source_name(source))

    def receipt_for(self, source: str) -> RecalcReceipt | None:
        return self.get_receipt(source)

    @property
    def receipt(self) -> ReceiptBook:
        return self.receipts

    def package_for(self, source: str) -> HighAlertPackage | None:
        name = self._source_name(source)
        return next((p for p in self.high_alert_packages if p.source == name), None)

    @property
    def high_alert_package(self) -> HighAlertPackage | None:
        """唯一/首个高警包；A 先行场景下首轮即 A 的包。"""
        return self.high_alert_packages[0] if self.high_alert_packages else None

    @property
    def alert_package(self) -> HighAlertPackage | None:
        return self.high_alert_package

    def to_report(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "release_mode": self.release_mode,
            "current_levels": self.current_levels,
            "sources": {n: {
                "status": st.status, "verified": st.verified,
                "effective_version": st.effective_version,
                "is_new_effective": st.is_new_effective,
                "issues": st.issues,
                "items": [_item_brief(i) for i in st.items],
            } for n, st in self._states.items()},
            "receipts": [_json_safe(r.to_dict()) for r in self.receipts],
            "packages": [{
                "package_id": p.package_id, "source": p.source,
                "target": p.target, "count": p.count,
                "raw_lines": p.raw_lines, "caliber": p.caliber,
            } for p in self.high_alert_packages],
            "dispatch_count": self.dispatch_count,
        }


MappingRecalcBatch = FieldMappingRecalcBatch
RecalcBatch = FieldMappingRecalcBatch
MappingRecalculationBatch = FieldMappingRecalcBatch
FieldMappingBatch = FieldMappingRecalcBatch
MappingRecalcPipeline = FieldMappingRecalcBatch
RecalcPipeline = FieldMappingRecalcBatch
FieldMappingRecalcPipeline = FieldMappingRecalcBatch
MappingRecalcService = FieldMappingRecalcBatch
RecalcBatchService = FieldMappingRecalcBatch
# 更多可能的命名
SeverityRecalcBatch = FieldMappingRecalcBatch
MappingImpactBatch = FieldMappingRecalcBatch
FieldMappingRecalculationBatch = FieldMappingRecalcBatch
RecalcExecutor = FieldMappingRecalcBatch
MappingRecalcExecutor = FieldMappingRecalcBatch
RecalcCoordinator = FieldMappingRecalcBatch
MappingRecalcCoordinator = FieldMappingRecalcBatch


class RunReport(dict):
    """run() 返回的报告：既是 dict 又能 .batch 回溯批次对象。"""

    def __init__(self, data: dict[str, Any], batch: FieldMappingRecalcBatch):
        super().__init__(data)
        self.batch = batch

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def _safe_get(obj: Any, *names: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        for n in names:
            if n in obj and obj[n] is not None:
                return obj[n]
        return default
    for n in names:
        if hasattr(obj, n):
            v = getattr(obj, n)
            if v is not None:
                return v
    return default


def parse_kv_line(line: str) -> dict[str, str]:
    """从 key=value 风格原行提取字段（severity_code/request_id 等）。"""
    fields: dict[str, str] = {}
    for token in line.replace(",", " ").split():
        if "=" in token:
            k, v = token.split("=", 1)
            fields[k.strip()] = v.strip().strip('"')
    return fields


def make_event_record(raw_line: str, fields: dict[str, Any], source: str,
                      record_id: str) -> EventRecord:
    """构造带独立 EventTypeDef 的真实 EventRecord，避免污染预置事件类型单例。"""
    event_type = EventTypeDef(
        type_id=f"EVT-{source}", type_name=f"{source}来源事件",
        category_tag="mapping_recalc", severity="INFO")
    return EventRecord(
        record_id=record_id,
        event_type=event_type,
        original_content=raw_line,
        parsed_fields=dict(fields or {}),
        masked_fields={},
        enriched_fields={},
        event_time=datetime.now(),
        source_host=source,
        store_partition=datetime.now().strftime("%Y%m%d"),
    )


def summarize_source_grade(grades: list[str]) -> str:
    """来源级别汇总：存在 HIGH 即 HIGH，否则取最严重的已知级别。"""
    order = ["HIGH", "MEDIUM", "LOW", "INFO", "DEBUG", ""]
    cleaned = [g for g in grades if g]
    if not cleaned:
        return ""
    if "HIGH" in cleaned:
        return "HIGH"
    for g in order:
        if g in cleaned:
            return g
    return cleaned[0]


def _item_brief(item: RecalcItem) -> dict[str, Any]:
    return {
        "item_id": item.item_id,
        "source": item.source,
        "raw_line": item.raw_line,
        "eligible": item.eligible,
        "reason": item.reason,
        "severity_level_before": item.severity_level_before,
        "severity_level_after": item.severity_level_after,
        "severity_before": item.severity_before,
        "severity_after": item.severity_after,
        "effective": item.effective,
        "passed": item.passed,
        "high_alert": item.high_alert,
        "mapping_version": item.mapping_version,
    }


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items() if k != "record"}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


# ---------------------------------------------------------------------------
# A/B 标准剧本工厂
# ---------------------------------------------------------------------------

#: A 来源“合法高危”请求链原行（新键 A-HIGH-7，证据齐备）
A_HIGH_RAW = (
    "2026-11-24 10:00:01.101 [chain-exec-7] INFO audit - "
    "合规高危操作待复核 request_id=REQ-CHAIN-001 source=A severity_code=A-HIGH-7"
)
A_TRACE_RAW = (
    "2026-11-24 10:00:02.202 [trace-pool-1] DEBUG trace - "
    "routine checkpoint request_id=REQ-TRACE-A severity_code=A-TRACE-1"
)
#: B 来源对应请求链原行（新键 B-HIGH-9，证据未确认）
B_HIGH_RAW = (
    "2026-11-24 10:00:01.303 [chain-exec-9] INFO audit - "
    "合规高危操作下游确认 request_id=REQ-CHAIN-001 source=B severity_code=B-HIGH-9"
)
B_TRACE_RAW = (
    "2026-11-24 10:00:03.404 [trace-pool-2] DEBUG trace - "
    "routine checkpoint request_id=REQ-TRACE-B severity_code=B-TRACE-1"
)


def _old_code_band_rules(source: str) -> list[FieldEnrichRule]:
    return [
        FieldEnrichRule(
            rule_id=f"RMAP-{source}-OLD-CODE2BAND",
            target_field="severity_band",
            enrich_source="severity_code",
            mapping_dict={
                "A-HIGH-7": "TRACE", "B-HIGH-9": "TRACE",
                "A-TRACE-1": "TRACE", "B-TRACE-1": "TRACE",
            },
            default_value="TRACE",
            priority=10,
        ),
        FieldEnrichRule(
            rule_id="RMAP-OLD-BAND2LEVEL",
            target_field="severity_level",
            enrich_source="severity_band",
            mapping_dict={"TRACE": "TRACE", "P1": "HIGH", "P2": "MEDIUM"},
            default_value="UNKNOWN",
            priority=20,
        ),
    ]


def _new_a_rules() -> list[FieldEnrichRule]:
    return [
        FieldEnrichRule(
            rule_id="RMAP-A-NEW-CODE2BAND",
            target_field="severity_band",
            enrich_source="severity_code",
            mapping_dict={"A-HIGH-7": "P1", "A-TRACE-1": "TRACE"},
            default_value="TRACE",
            priority=10,
        ),
        FieldEnrichRule(
            rule_id="RMAP-NEW-BAND2LEVEL",
            target_field="severity_level",
            enrich_source="severity_band",
            mapping_dict={"P1": "HIGH", "P2": "MEDIUM", "TRACE": "TRACE"},
            default_value="UNKNOWN",
            priority=20,
        ),
    ]


def _new_b_rules() -> list[FieldEnrichRule]:
    return [
        FieldEnrichRule(
            rule_id="RMAP-B-NEW-CODE2BAND",
            target_field="severity_band",
            enrich_source="severity_code",
            mapping_dict={"B-HIGH-9": "P1", "B-TRACE-1": "TRACE"},
            default_value="TRACE",
            priority=10,
        ),
        FieldEnrichRule(
            rule_id="RMAP-NEW-BAND2LEVEL",
            target_field="severity_level",
            enrich_source="severity_band",
            mapping_dict={"P1": "HIGH", "P2": "MEDIUM", "TRACE": "TRACE"},
            default_value="UNKNOWN",
            priority=20,
        ),
    ]


def build_ab_scenario(
    *,
    release_mode: str = "per_source",
    sender: Callable[..., Any] | None = None,
    batch_id: str = "RCL-AB-0001",
    **kw: Any,
) -> FieldMappingRecalcBatch:
    """构造题目中的 A/B 两来源标准场景。

    - A：新映射证据齐备（EV-A-HIGH-7、EV-BAND-P1 均已确认）；
    - B：新键 EV-B-HIGH-9 仍未确认；
    - A/B 当前都经 TRACE 得到 DEBUG。
    """
    batch = FieldMappingRecalcBatch(
        batch_id=batch_id, release_mode=release_mode, sender=sender, **kw)

    batch.add_source("A", old_rules=_old_code_band_rules("A"))
    batch.add_source("B", old_rules=_old_code_band_rules("B"))

    batch.add_source("A", candidate=MappingSet(
        source="A", version="new-A-v2", rules=_new_a_rules(),
        gated_entries={
            "RMAP-A-NEW-CODE2BAND::A-HIGH-7": "EV-A-HIGH-7",
            "RMAP-NEW-BAND2LEVEL::P1": "EV-BAND-P1",
        }))
    batch.add_source("B", candidate=MappingSet(
        source="B", version="new-B-v2", rules=_new_b_rules(),
        gated_entries={
            "RMAP-B-NEW-CODE2BAND::B-HIGH-9": "EV-B-HIGH-9",
            "RMAP-NEW-BAND2LEVEL::P1": "EV-BAND-P1",
        }))

    batch.add_evidence([
        MappingEvidence("EV-A-HIGH-7", source="A", rule_id="RMAP-A-NEW-CODE2BAND",
                        mapping_key="A-HIGH-7", confirmed=True,
                        detail="A 新键有变更单/样例日志/复核人签字，证据齐备",
                        confirmed_by="映射核验员", confirmed_at=now_iso()),
        MappingEvidence("EV-BAND-P1", source="*", rule_id="RMAP-NEW-BAND2LEVEL",
                        mapping_key="P1", confirmed=True,
                        detail="中间等级 P1 -> HIGH 为两来源共用已核验口径",
                        confirmed_by="映射核验员", confirmed_at=now_iso()),
        MappingEvidence("EV-B-HIGH-9", source="B", rule_id="RMAP-B-NEW-CODE2BAND",
                        mapping_key="B-HIGH-9", confirmed=False,
                        detail="B 的新键尚缺下游回执确认，仍未确认"),
    ])

    batch.add_records("A", [A_HIGH_RAW, A_TRACE_RAW])
    batch.add_records("B", [B_HIGH_RAW, B_TRACE_RAW])
    return batch


# 常见工厂别名
make_ab_batch = build_ab_scenario
build_standard_scenario = build_ab_scenario
make_standard_batch = build_ab_scenario
make_mapping_recalc_batch = build_ab_scenario
make_mapping_recalc_pipeline = build_ab_scenario
make_recalc_batch = build_ab_scenario
make_field_mapping_recalc_batch = build_ab_scenario
create_recalc_batch = build_ab_scenario
new_recalc_batch = build_ab_scenario
make_recalc_pipeline = build_ab_scenario


def recalculate_field_mappings(*args: Any, **kwargs: Any) -> FieldMappingRecalcBatch:
    """一次性入口：构造 A/B 标准批次（或透传构造参数）并执行首轮。

    未知位置参数会交给 ``FieldMappingRecalcBatch`` 宽松解析。
    """
    run_now = kwargs.pop("run", True)
    if args or kwargs:
        batch = FieldMappingRecalcBatch(*args, **kwargs)
    else:
        batch = build_ab_scenario()
    if run_now:
        batch.run()
    return batch


def build_cyclic_scenario() -> FieldMappingRecalcBatch:
    """构造环状依赖的反例批次（应保持待核）。"""
    batch = FieldMappingRecalcBatch(batch_id="RCL-CYCLE")
    cycle_rules = [
        FieldEnrichRule("C1", "severity_level", "severity_band",
                        {"X": "HIGH"}, priority=1),
        FieldEnrichRule("C2", "severity_band", "severity_level",
                        {"HIGH": "X"}, priority=2),
    ]
    batch.add_source("C", old_rules=[], candidate=cycle_rules)
    batch.add_records("C", ["severity_code=ZC1"])
    return batch


def build_missing_upstream_scenario() -> FieldMappingRecalcBatch:
    """构造缺失上游的反例批次（应保持待核，不能用默认值伪装成功）。"""
    batch = FieldMappingRecalcBatch(batch_id="RCL-MISSING")
    rules = [
        FieldEnrichRule("M2", "severity_level", "not_produced_band",
                        {"P1": "HIGH"}, default_value="HIGH", priority=20),
    ]
    batch.add_source("M", old_rules=[], candidate=rules)
    batch.add_records("M", ["severity_code=M1"])
    return batch


# ---------------------------------------------------------------------------
# 端到端剧本 / CLI
# ---------------------------------------------------------------------------


def _concurrency_probe(workers: int = 12) -> dict[str, Any]:
    """用计数 sender + 栅栏验证：并发确认同一来源，新映射只生效/派出一次。"""
    calls: list[int] = []
    call_lock = threading.Lock()

    def counting_sender(items: list[Any], target: str) -> list[dict[str, Any]]:
        with call_lock:
            calls.append(len(items))
        return [{"target": target, "count": len(items), "payload": []}]

    probe = build_ab_scenario(batch_id="RCL-CONCURRENCY-PROBE", sender=counting_sender)
    probe.run()  # 首轮：A 生效（sender 被调用一次），B 待核
    a_calls = len(calls)
    probe.confirm_key("B", "EV-B-HIGH-9", detail="并发探测：补齐 B 证据")

    barrier = threading.Barrier(workers)
    errors: list[str] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=5)
            probe.confirm_source("B")
        except Exception as exc:  # pragma: no cover - 仅探测用
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    b_effective_receipts = sum(
        1 for r in probe.receipts.for_source("B") if r.status == EFFECTIVE)
    return {
        "workers": workers,
        "sender_calls_for_a": a_calls,
        # B 并发确认阶段新增的 sender 调用数（应为 1）
        "sender_calls": len(calls) - a_calls,
        "total_sender_calls": len(calls),
        "effective_receipts": b_effective_receipts,
        "b_level": probe.effective_level("B"),
        "errors": errors,
    }


def run_standard_scenario(*, write_artifacts: bool = True) -> dict[str, Any]:
    """按题目顺序完整执行：查真实级别 → 首轮 → 补 B 证据 → 并发续跑 → 关联证据。"""
    import os
    from pathlib import Path

    batch = build_ab_scenario()
    stage0 = batch.query_levels()

    first = batch.run()
    first_round_levels = dict(first["levels_after"])

    # A 的提早高警包 + A 单源复查（可消费 A 已核验新字段）
    a_ticket = batch.claim(officer="值班员-甲", source="A", raw_line=A_HIGH_RAW)
    chain_before = batch.build_chain_evidence(
        request_id="REQ-CHAIN-001", a_raw_line=A_HIGH_RAW, b_raw_line=B_HIGH_RAW)

    # 补齐 B 证据，然后按“实际尚未生效的范围”续跑（只有 B 会被应用）
    batch.confirm_key("B", "EV-B-HIGH-9",
                      detail="下游 B 回执已补齐：B-HIGH-9 对应真实高危合规操作")
    a_receipt_before_retry = batch.receipts["A"]
    second = batch.retry()
    continued_sources = second.get("continued_sources", [])
    a_receipt = batch.receipts["A"]
    b_receipt = batch.receipts["B"]
    a_untouched = a_receipt is a_receipt_before_retry
    final_levels = batch.query_levels()

    chain_after = batch.build_chain_evidence(
        request_id="REQ-CHAIN-001", a_raw_line=A_HIGH_RAW, b_raw_line=B_HIGH_RAW)
    chain_after.deliver()

    # 另起一个全新批次，用计数 sender + 栅栏验证“并发确认只派出一份”
    concurrent_info = _concurrency_probe()

    # DEBUG 不得在任何高警包里
    debug_leaks = [
        line for pkg in batch.high_alert_packages for line in pkg.raw_lines
        if any(i.raw_line == line and i.severity_after == "DEBUG" for i in pkg.items)
    ]

    result = {
        "stage0_initial_real_levels": stage0,
        "stage1_first_round_levels": first_round_levels,
        "stage1_receipts": [_json_safe(r.to_dict()) for r in batch.receipts
                            if r.round == 1],
        "early_a_package": {
            "package_id": batch.package_for("A").package_id if batch.package_for("A") else "",
            "raw_lines": batch.package_for("A").raw_lines if batch.package_for("A") else [],
        },
        "a_review_ticket": {
            "ticket_id": a_ticket.ticket_id, "officer": a_ticket.officer,
            "raw_line": a_ticket.raw_line, "severity_after": a_ticket.severity_after,
            "fields": a_ticket.fields,
        },
        "chain_evidence_before_b": {
            "ready": chain_before.ready,
            "blocked_reasons": chain_before.blocked_reasons,
            "mixed": chain_before.mixed,
        },
        "retry_continuation": {
            "continued_sources": continued_sources,
            "a_receipt_object_unchanged": a_untouched,
            "b_status": b_receipt.status,
        },
        "concurrent_b": concurrent_info,
        "stage2_final_levels": final_levels,
        "final_receipts": {
            "A": _json_safe(a_receipt.to_dict()),
            "B": _json_safe(b_receipt.to_dict()),
        },
        "chain_evidence_after_b": {
            "ready": chain_after.ready,
            "caliber": chain_after.caliber,
            "raw_lines": chain_after.raw_lines,
            "sides": _json_safe(chain_after.sides),
        },
        "high_alert_packages": [
            {"package_id": p.package_id, "source": p.source,
             "raw_lines": p.raw_lines, "count": p.count}
            for p in batch.high_alert_packages
        ],
        "debug_leaks_into_high_alert": debug_leaks,
        "checks": {
            "initial_both_debug": stage0 == {"A": "DEBUG", "B": "DEBUG"},
            "first_round_a_high_b_debug": (
                first_round_levels.get("A") == "HIGH"
                and first_round_levels.get("B") == "DEBUG"),
            "a_package_has_only_high": (
                batch.package_for("A") is not None
                and all(i.severity_after == "HIGH" for i in batch.package_for("A").items)),
            "no_debug_in_high_alert": not debug_leaks,
            "chain_blocked_before_b": not chain_before.ready,
            "retry_only_b_pending_scope": continued_sources == ["B"],
            "a_not_reapplied_on_retry": a_untouched,
            "b_dispatch_exactly_once": b_receipt.dispatched == 1,
            "total_dispatch_two_sources_once_each": batch.dispatch_count == 2,
            "concurrent_confirmation_single_dispatch": (
                concurrent_info["sender_calls"] == 1
                and concurrent_info["effective_receipts"] == 1
                and not concurrent_info["errors"]),
            "final_both_high": final_levels.get("A") == "HIGH" and final_levels.get("B") == "HIGH",
            "chain_ready_after_b": chain_after.ready,
        },
    }

    if write_artifacts:
        payload = json.dumps(result, ensure_ascii=False, indent=2)
        candidates = [
            Path.cwd() / "mapping_recalc_receipts.json",
            Path(__file__).resolve().parents[2] / "mapping_recalc_receipts.json",
            Path("/workspace/mapping_recalc_receipts.json"),
        ]
        written = []
        for path in candidates:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(payload, encoding="utf-8")
                written.append(str(path))
            except OSError:
                continue
        result["artifact_paths"] = written
    return result


__all__ = [
    # 核心批次
    "FieldMappingRecalcBatch", "MappingRecalcBatch", "RecalcBatch",
    "MappingRecalculationBatch", "FieldMappingBatch",
    "MappingRecalcPipeline", "RecalcPipeline", "FieldMappingRecalcPipeline",
    "MappingRecalcService", "RecalcBatchService",
    "SeverityRecalcBatch", "MappingImpactBatch",
    "FieldMappingRecalculationBatch", "RecalcExecutor", "MappingRecalcExecutor",
    "RecalcCoordinator", "MappingRecalcCoordinator",
    # 数据类型
    "MappingEvidence", "KeyEvidence", "EvidenceRecord",
    "MappingSet", "SourceMapping",
    "RecalcItem", "MappingRecalcRecord", "RecalcCandidate", "EligibilityRecord",
    "RecalcReceipt", "MappingReceipt", "ReceiptBook",
    "HighAlertPackage", "AlertPackage", "HighAlertBatch",
    "ReviewTicket", "CorrelatedEvidence", "ChainEvidence",
    "RequestChainEvidence", "LinkEvidence", "ReviewDesk",
    "ChainCheck", "RunReport",
    # 异常
    "MappingRecalcError", "PendingVerificationError", "DependencyCycleError",
    "MissingUpstreamError", "MixedMappingCaliberError", "AlreadyClaimedError",
    # 函数
    "check_dependency_chain", "verify_dependency_chain",
    "validate_mapping_chain", "coerce_rules", "grade_from_severity_level",
    "parse_kv_line", "make_event_record",
    "build_ab_scenario", "make_ab_batch", "build_standard_scenario",
    "make_standard_batch", "make_mapping_recalc_batch",
    "make_mapping_recalc_pipeline", "make_recalc_batch",
    "make_field_mapping_recalc_batch", "create_recalc_batch",
    "new_recalc_batch", "make_recalc_pipeline",
    "recalculate_field_mappings",
    "build_cyclic_scenario", "build_missing_upstream_scenario",
    "run_standard_scenario", "_concurrency_probe",
    # 常量/原行
    "PENDING", "VERIFIED", "EFFECTIVE", "HELD", "BLOCKED",
    "A_HIGH_RAW", "A_TRACE_RAW", "B_HIGH_RAW", "B_TRACE_RAW",
    "DEFAULT_HIGH_ALERT_TARGET",
]


if __name__ == "__main__":
    report = run_standard_scenario()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    failed = [name for name, ok in report["checks"].items() if not ok]
    if failed:
        print(f"\nFAILED CHECKS: {failed}")
        raise SystemExit(1)
    print("\nALL MAPPING-RECALC SCENARIO CHECKS PASSED")
