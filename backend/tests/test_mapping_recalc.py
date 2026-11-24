"""测试：字段映射重算批次（多来源核验 / 链式依赖 / 重新判级 / 高警转发 / 关联复查）。

覆盖题目要求：
- 按来源核验新映射、逐条重算资格与生效前后级别留痕；
- severity_code -> 中间等级 -> severity_level 链式增强；
- 环/缺失上游保持待核，默认值不得伪装 HIGH 成功；
- A 先 HIGH 出高警包，B 待核仍 DEBUG；补证据续跑后 B HIGH；
- DEBUG 不进高警包，值班员按原行领取 A 复查；
- A/B 请求链证据必须同口径，未核验前不可交付；
- 并发确认同一来源只生效/派出一次。

既可直接 ``python tests/test_mapping_recalc.py``，也可被 pytest 收集。
"""
from __future__ import annotations

import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.models import EventRecord, EventTypeDef, FieldEnrichRule
from app.core.mask_enrich import MaskEnrichPipeline
from app.core.pipeline import IngestPipeline
from app.core.mapping_recalc import (
    A_HIGH_RAW, B_HIGH_RAW,
    FieldMappingRecalcBatch, MappingRecalcBatch,
    build_ab_scenario, check_dependency_chain,
)


def _record(severity_code: str, rid: str = "T-1") -> EventRecord:
    return EventRecord(
        record_id=rid,
        event_type=EventTypeDef(type_id="EVT-T", type_name="t", category_tag="t"),
        original_content=f"severity_code={severity_code}",
        parsed_fields={"severity_code": severity_code},
        masked_fields={}, enriched_fields={},
        event_time=__import__("datetime").datetime.now(),
        source_host="T",
    )


class TestChainedEnrichment:
    """apply_all_enrichments 必须能读到上一条增强产生的字段。"""

    def test_severity_code_chain_to_level(self):
        rules = [
            FieldEnrichRule("R1", "severity_band", "severity_code",
                            {"C-HIGH": "P1"}, priority=10),
            FieldEnrichRule("R2", "severity_level", "severity_band",
                            {"P1": "HIGH"}, priority=20),
        ]
        pipe = MaskEnrichPipeline(mask_rules=[], enrich_rules=rules)
        rec = _record("C-HIGH")
        enriched = pipe.apply_all_enrichments(rec)
        # 关键：第二跳不能仍只向 parsed_fields 原字段查询
        assert enriched["severity_band"] == "P1"
        assert enriched["severity_level"] == "HIGH"
        assert rec.enriched_fields["severity_level"] == "HIGH"
        assert pipe._update_severity(rec) == "HIGH"

    def test_old_trace_chain_gives_debug(self):
        rules = [
            FieldEnrichRule("R1", "severity_band", "severity_code",
                            {"C-TRACE": "TRACE"}, default_value="TRACE", priority=10),
            FieldEnrichRule("R2", "severity_level", "severity_band",
                            {"TRACE": "TRACE"}, default_value="UNKNOWN", priority=20),
        ]
        pipe = MaskEnrichPipeline(mask_rules=[], enrich_rules=rules)
        rec = _record("C-TRACE")
        pipe.apply_all_enrichments(rec)
        assert pipe._update_severity(rec) == "DEBUG"


class TestDependencyVerification:
    def test_cycle_detected(self):
        rules = [
            FieldEnrichRule("C1", "severity_level", "severity_band", {"X": "HIGH"}),
            FieldEnrichRule("C2", "severity_band", "severity_level", {"HIGH": "X"}),
        ]
        result = check_dependency_chain(rules, original_fields={"severity_code"})
        assert result.ok is False
        assert result.cycles

    def test_missing_upstream_detected(self):
        rules = [
            FieldEnrichRule("M2", "severity_level", "no_such_band",
                            {"P1": "HIGH"}, default_value="HIGH"),
        ]
        result = check_dependency_chain(rules, original_fields={"severity_code"})
        assert result.ok is False
        assert result.missing_upstream == ["no_such_band"]

    def test_valid_chain_passes(self):
        rules = [
            FieldEnrichRule("R1", "severity_band", "severity_code", {"A": "P1"}),
            FieldEnrichRule("R2", "severity_level", "severity_band", {"P1": "HIGH"}),
        ]
        result = check_dependency_chain(rules)
        assert result.ok is True
        assert result.order.index("severity_band") < result.order.index("severity_level")

    def test_cyclic_batch_stays_pending(self):
        from app.core.mapping_recalc import build_cyclic_scenario
        batch = build_cyclic_scenario()
        report = batch.run()
        assert report["levels_after"]["C"] != "HIGH"
        receipt = batch.receipts["C"]
        assert receipt.status == "待核"

    def test_missing_upstream_batch_stays_pending_not_default_high(self):
        from app.core.mapping_recalc import build_missing_upstream_scenario
        batch = build_missing_upstream_scenario()
        batch.run()
        receipt = batch.receipts["M"]
        assert receipt.status == "待核"
        target = batch.items[0]
        assert target.severity_after != "HIGH" or not target.effective


class TestABScenario:
    def test_initial_real_levels_are_debug(self):
        batch = build_ab_scenario()
        levels = batch.query_levels()
        assert levels == {"A": "DEBUG", "B": "DEBUG"}

    def test_first_round_a_high_b_pending_debug(self):
        batch = build_ab_scenario()
        batch.query_levels()
        report = batch.run()
        assert report["levels_after"]["A"] == "HIGH"
        assert report["levels_after"]["B"] == "DEBUG"
        assert batch.receipts["A"].status == "已生效"
        assert batch.receipts["B"].status == "待核"
        # 逐条资格：B 的高危原行命中未确认新键 -> 无资格
        b_high = next(i for i in batch.items if i.source == "B" and "B-HIGH-9" in i.raw_line)
        assert b_high.eligible is False
        assert b_high.effective is False
        # A 高危行资格齐备且生效为 HIGH
        a_high = next(i for i in batch.items if i.source == "A" and "A-HIGH-7" in i.raw_line)
        assert a_high.eligible is True
        assert a_high.effective is True
        assert a_high.severity_before == "DEBUG"
        assert a_high.severity_after == "HIGH"
        assert a_high.raw_line == A_HIGH_RAW

    def test_high_alert_package_excludes_debug(self):
        batch = build_ab_scenario()
        batch.run()
        pkg_a = batch.package_for("A")
        assert pkg_a is not None
        assert len(pkg_a) == 1
        assert pkg_a.raw_lines == [A_HIGH_RAW]
        assert all(i.severity_after == "HIGH" for i in pkg_a.items)
        # B 待核，不应有高警包
        assert batch.package_for("B") is None
        for pkg in batch.high_alert_packages:
            assert all(i.severity_after != "DEBUG" for i in pkg.items)

    def test_claim_review_by_raw_line_consumes_new_fields(self):
        batch = build_ab_scenario()
        batch.run()
        ticket = batch.claim(officer="值班员甲", raw_line=A_HIGH_RAW)
        assert ticket.raw_line == A_HIGH_RAW
        assert ticket.officer == "值班员甲"
        assert ticket.severity_after == "HIGH"
        assert ticket.fields.get("severity_level") == "HIGH"
        assert ticket.fields.get("severity_band") == "P1"

    def test_forward_rules_consumes_passed_candidates_only(self):
        batch = build_ab_scenario()
        batch.run()
        pipeline = IngestPipeline()
        # 不带 high_only：只消费 passed=True 的候选（A 的两条都 passed，因为新映射生效）
        all_passed = [i for i in batch.items if i.passed]
        batches = pipeline.apply_forward_rules(batch.items, "fw://x")
        # 默认候选感知会剔除 passed=False（B 的条目），剩下 A 的 2 条
        assert sum(b["count"] for b in batches) == len(all_passed) == 2
        # 高警：只给 HIGH
        high_batches = pipeline.apply_forward_rules(
            batch.items, "fw://high", passed_only=True, high_only=True)
        assert sum(b["count"] for b in high_batches) == 1
        payload_line = high_batches[0]["payload"][0]["raw_line"]
        assert payload_line == A_HIGH_RAW

    def test_plain_eventrecord_forward_backward_compatible(self):
        # 既有行为：EventRecord 列表不带过滤参数时全部转发
        from app.core.pipeline import make_pipeline, PRESET_LOG_SOURCES, PRESET_PARSE_RULES
        p = make_pipeline()
        entries = p.parse_raw_lines(PRESET_LOG_SOURCES["access-web"], [
            '192.168.1.10 - - [15/Nov/2026:14:30:05 +0800] "GET /x HTTP/1.1" 200 1 "-" "curl"'])
        parsed = p.apply_parse_rules(entries, PRESET_PARSE_RULES[0])
        records = p.classify_events(parsed)
        out = p.apply_forward_rules(records, "webhook://t")
        assert len(out) == 1 and out[0]["count"] == 1

    def test_chain_evidence_blocked_until_both_verified(self):
        batch = build_ab_scenario()
        batch.run()
        ev = batch.build_chain_evidence(a_raw_line=A_HIGH_RAW, b_raw_line=B_HIGH_RAW)
        assert ev.ready is False
        # 不依赖 pytest：deliver 必须抛出待核错误
        from app.core.mapping_recalc import PendingVerificationError
        try:
            ev.deliver()
            raise AssertionError("应当阻断")
        except PendingVerificationError:
            pass

    def test_complete_b_evidence_retry_makes_b_high_and_chain_ready(self):
        batch = build_ab_scenario()
        batch.run()
        batch.confirm_key("B", "EV-B-HIGH-9", detail="证据补齐")
        report = batch.retry()
        assert report["continued_sources"] == ["B"]
        assert batch.effective_level("B") == "HIGH"
        assert batch.effective_level("A") == "HIGH"
        rb = batch.receipts["B"]
        assert rb.status == "已生效" and rb.dispatched == 1
        assert rb.severity_before in ("DEBUG", "")
        assert rb.level_after == "HIGH"
        ev = batch.build_chain_evidence(a_raw_line=A_HIGH_RAW, b_raw_line=B_HIGH_RAW)
        assert ev.ready is True
        assert set(ev.sides) == {"A", "B"}
        assert ev.caliber == "new"

    def test_mixed_caliber_evidence_rejected(self):
        # A 新、B 旧：直接构造一个口径不一致的证据并尝试交付
        batch = build_ab_scenario()
        batch.run()
        ev = batch.build_chain_evidence()
        assert ev.mixed is True and ev.ready is False
        from app.core.mapping_recalc import MixedMappingCaliberError
        try:
            ev.deliver()
            raise AssertionError("混用口径必须拒绝")
        except MixedMappingCaliberError:
            pass

    def test_atomic_mode_keeps_both_debug_when_b_pending(self):
        batch = build_ab_scenario(release_mode="atomic")
        report = batch.run()
        assert report["levels_after"]["A"] == "DEBUG"
        assert report["levels_after"]["B"] == "DEBUG"
        assert batch.receipts["A"].status == "待整批生效"


class TestConcurrency:
    def test_concurrent_confirm_dispatches_once(self):
        calls = []
        lock = threading.Lock()

        def sender(items, target):
            with lock:
                calls.append(len(items))
            return []

        batch = build_ab_scenario(batch_id="RCL-CONC-TEST", sender=sender)
        batch.run()  # A -> 1 call
        assert len(calls) == 1
        batch.confirm_key("B", "EV-B-HIGH-9", detail="ok")

        barrier = threading.Barrier(10)
        errs = []

        def worker():
            try:
                barrier.wait(timeout=5)
                batch.confirm_source("B")
            except Exception as e:  # pragma: no cover
                errs.append(e)

        ts = [threading.Thread(target=worker) for _ in range(10)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert not errs
        b_effective = [r for r in batch.receipts.for_source("B") if r.status == "已生效"]
        assert len(b_effective) == 1
        # A 一次 + B 恰好一次
        assert len(calls) == 2
        assert batch.dispatch_count == 2

    def test_alias_class_identity(self):
        assert MappingRecalcBatch is FieldMappingRecalcBatch


# ---------- 独立运行入口（与既有 tests 风格一致） ----------

if __name__ == "__main__":
    import traceback

    test_cases = []
    for cls in (TestChainedEnrichment, TestDependencyVerification,
                TestABScenario, TestConcurrency):
        obj = cls()
        for name in dir(obj):
            if name.startswith("test_"):
                test_cases.append((f"{cls.__name__}.{name}", getattr(obj, name)))

    passed = failed = 0
    for name, fn in test_cases:
        try:
            fn()
            passed += 1
            print(f"  PASS  test_mapping_recalc: {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  test_mapping_recalc: {name}")
            traceback.print_exc()

    print(f"\ntest_mapping_recalc: {passed} passed, {failed} failed, {len(test_cases)} total")
    sys.exit(1 if failed else 0)
