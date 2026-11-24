"""兼容入口：字段映射重算（规范实现见 app.core.mapping_recalc）。"""
from __future__ import annotations

from app.core.mapping_recalc import *  # noqa: F401,F403
from app.core import mapping_recalc as _canonical

FieldMappingRecalcBatch = _canonical.FieldMappingRecalcBatch
MappingRecalcBatch = _canonical.MappingRecalcBatch
RecalcBatch = _canonical.RecalcBatch
build_ab_scenario = _canonical.build_ab_scenario
run_standard_scenario = _canonical.run_standard_scenario
check_dependency_chain = _canonical.check_dependency_chain
