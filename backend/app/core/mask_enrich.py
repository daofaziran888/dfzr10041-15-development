"""拾音工坊脱敏与字段增强管道：event_store→mask_rule→field_enrich→event_type。

数据流：已存储的 EventRecord → 脱敏变换 (mask_rule) → 字段增强 (field_enrich) → 更新事件分类标记
涉及模块：event_store, mask_rule, field_enrich, event_type
"""
from __future__ import annotations

from typing import Any

from app.core.models import (
    EventRecord, FieldEnrichRule, MaskMethod, MaskResult, MaskRule,
)

# ---------- 预置脱敏规则 ----------

PRESET_MASK_RULES: list[MaskRule] = [
    MaskRule(
        rule_id="MASK-0001",
        target_field="client_ip",
        mask_method=MaskMethod.IP,
        mask_pattern="",
        rule_state="生效中",
    ),
    MaskRule(
        rule_id="MASK-0002",
        target_field="user_agent",
        mask_method=MaskMethod.CUSTOM_REGEX,
        mask_pattern=r'[A-Za-z0-9+/]{40,}=*',
        rule_state="生效中",
    ),
    MaskRule(
        rule_id="MASK-0003",
        target_field="message",
        mask_method=MaskMethod.PHONE,
        mask_pattern="",
        rule_state="生效中",
    ),
]

# ---------- 预置字段增强规则 ----------

PRESET_ENRICH_RULES: list[FieldEnrichRule] = [
    FieldEnrichRule(
        rule_id="FIEL-0001",
        target_field="app_name",
        enrich_source="logger",
        mapping_dict={
            "com.example.IngestController": "ingest-service",
            "com.example.ParserEngine": "parser-engine",
            "com.example.CheckpointStore": "checkpoint-store",
            "com.example.MaskService": "mask-service",
        },
        default_value="unknown-service",
        priority=10,
    ),
    FieldEnrichRule(
        rule_id="FIEL-0002",
        target_field="severity_level",
        enrich_source="level",
        mapping_dict={
            "INFO": "LOW",
            "WARN": "MEDIUM",
            "ERROR": "HIGH",
            "DEBUG": "TRACE",
        },
        default_value="UNKNOWN",
        priority=10,
    ),
    FieldEnrichRule(
        rule_id="FIEL-0003",
        target_field="status_category",
        enrich_source="status",
        mapping_dict={
            "200": "SUCCESS",
            "201": "SUCCESS",
            "301": "REDIRECT",
            "302": "REDIRECT",
            "400": "CLIENT_ERROR",
            "401": "AUTH_ERROR",
            "403": "AUTH_ERROR",
            "404": "CLIENT_ERROR",
            "500": "SERVER_ERROR",
            "502": "SERVER_ERROR",
            "503": "SERVER_ERROR",
        },
        default_value="OTHER",
        priority=5,
    ),
]


class MaskEnrichPipeline:
    """脱敏与字段增强处理管道。

    接收 EventRecord 集合 → 依次应用 mask_rule → field_enrich → 更新 event_type 标记
    """

    def __init__(self, mask_rules: list[MaskRule] | None = None,
                 enrich_rules: list[FieldEnrichRule] | None = None):
        if mask_rules is None:
            mask_rules = PRESET_MASK_RULES
        if enrich_rules is None:
            enrich_rules = PRESET_ENRICH_RULES
        self.mask_rules = mask_rules
        self.enrich_rules = enrich_rules
        self._mask_results: list[MaskResult] = []

    # ---------- 数据流 3: event_store → mask_rule → field_enrich → event_type ----------

    def apply_all_masks(self, record: EventRecord) -> MaskResult:
        """对一条事件记录的所有敏感字段执行脱敏变换。

        每条脱敏规则按目标字段匹配 record.parsed_fields，
        执行对应脱敏方式（phone/id_card/email/ip/custom_regex）。
        脱敏后的值写入 record.masked_fields。
        """
        last_result: MaskResult | None = None
        for rule in self.mask_rules:
            target = rule.target_field
            value = record.parsed_fields.get(target, "")
            if not value:
                continue
            masked_value = rule.apply(value)
            record.masked_fields[target] = masked_value
            result = MaskResult(
                rule_id=rule.rule_id,
                field_name=target,
                original=value,
                masked=masked_value,
                method=rule.mask_method,
                is_masked=masked_value != value,
            )
            self._mask_results.append(result)
            last_result = result
        return last_result if last_result else MaskResult(
            rule_id="", field_name="", original="", masked="",
            method=MaskMethod.CUSTOM_REGEX, is_masked=False,
        )

    def apply_all_enrichments(self, record: EventRecord) -> dict[str, str]:
        """对一条事件记录执行所有字段增强。

        每条增强规则按 enrich_source 作为查询键查找 mapping_dict，
        将映射值写入 record.enriched_fields 的 target_field 下。
        未命中映射时使用 default_value。

        依赖链支持：后执行的规则可以读取同一记录上一条增强刚产生的字段
        （例如先由原始 severity_code 得到中间等级 severity_band，再由
        severity_band 得到 severity_level）。查询视图由 原始字段 → 脱敏字段
        （仅补缺）→ 已产生的增强字段 逐层叠加，而不是只向原字段查询。
        """
        enriched: dict[str, str] = {}
        view: dict[str, Any] = dict(record.parsed_fields or {})
        for key, value in (record.masked_fields or {}).items():
            view.setdefault(key, value)
        for rule in sorted(self.enrich_rules, key=lambda r: r.priority):
            # 显式解析一次来源值，保证链式上游产物可见。
            source_value = (
                view.get(rule.enrich_source)
                or (record.parsed_fields or {}).get(rule.enrich_source)
                or (record.masked_fields or {}).get(rule.enrich_source)
                or ""
            )
            lookup = dict(view)
            lookup[rule.enrich_source] = source_value
            mapped = rule.enrich(lookup)
            record.enriched_fields[rule.target_field] = mapped
            enriched[rule.target_field] = mapped
            # 让本条增强的产物立刻成为后续规则可查询的上游字段。
            view[rule.target_field] = mapped
        return enriched

    def process_records(self, records: list[EventRecord]) -> list[EventRecord]:
        """批量处理事件记录：依次执行脱敏和字段增强。

        这是 event_store → mask_rule → field_enrich → event_type 的完整实现。
        """
        for record in records:
            # 1. mask_rule: 脱敏变换
            self.apply_all_masks(record)
            # 2. field_enrich: 字段增强
            self.apply_all_enrichments(record)
            # 3. event_type: 增强后重新评估严重级别
            self._update_severity(record)
        return records

    def verify_mask_completeness(self, records: list[EventRecord]) -> dict[str, Any]:
        """验证脱敏完整性：检查是否有敏感值泄露（遗漏告警）。

        逐个检查 mask_results，确认掩码值不包含原始敏感数据核心部分。
        返回遗漏清单和覆盖率。
        """
        leaks: list[dict[str, str]] = []
        for record in records:
            for rule in self.mask_rules:
                target = rule.target_field
                original = record.parsed_fields.get(target, "")
                masked = record.masked_fields.get(target, original)
                if not original:
                    continue
                if len(original) > 3 and original[2:-2] in masked:
                    leaks.append({
                        "record_id": record.record_id,
                        "field": target,
                        "original_snippet": original[:50],
                        "masked_snippet": masked[:50],
                        "rule_id": rule.rule_id,
                    })
        total_fields = len(self.mask_rules)
        covered = total_fields - len(leaks)
        return {
            "total_rules": total_fields,
            "leaks_found": len(leaks),
            "leaks_detail": leaks,
            "coverage_rate": round(covered / total_fields, 4) if total_fields else 1.0,
        }

    def verify_enrich_mapping(self, expected_enrich_count: int) -> dict[str, Any]:
        """验证字段增强：检查是否有映射缺失。

        统计 enrichment 实际生效的规则数量和映射质量。
        """
        return {
            "expected_rules": expected_enrich_count,
            "actual_rules": len(self.enrich_rules),
            "rules_active": [r.rule_id for r in self.enrich_rules],
            "mapping_missing": any(
                r.default_value != "unknown" for r in self.enrich_rules
            ),
        }

    def get_mask_results(self) -> list[MaskResult]:
        return list(self._mask_results)

    def _update_severity(self, record: EventRecord) -> str:
        """根据增强后的字段更新事件记录的严重级别，并返回生效级别。

        事件分级必须使用 apply_all_enrichments 实际写入的
        enriched_fields["severity_level"]，不能回查未增强的原字段。
        """
        enhanced_severity = record.enriched_fields.get("severity_level", "")
        if enhanced_severity == "HIGH":
            record.event_type.severity = "HIGH"
        elif enhanced_severity == "MEDIUM":
            record.event_type.severity = "MEDIUM"
        elif enhanced_severity in ("TRACE", "DEBUG"):
            # TRACE 是映射产生的中间/低层标签，事件分级落到 DEBUG。
            record.event_type.severity = "DEBUG"
        return record.event_type.severity


def make_mask_enrich_pipeline() -> MaskEnrichPipeline:
    """工厂函数：创建预配置的脱敏/增强管道实例。"""
    return MaskEnrichPipeline()