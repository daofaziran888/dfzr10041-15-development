"""兼容入口：mapping_recalculation（规范实现见 app.core.mapping_recalc）。"""
from __future__ import annotations

from app.core.mapping_recalc import *  # noqa: F401,F403
from app.core import mapping_recalc as _c

FieldMappingRecalcBatch = _c.FieldMappingRecalcBatch
MappingRecalculationBatch = _c.FieldMappingRecalcBatch
MappingRecalcBatch = _c.MappingRecalcBatch
RecalcBatch = _c.RecalcBatch
build_ab_scenario = _c.build_ab_scenario
run_standard_scenario = _c.run_standard_scenario
check_dependency_chain = _c.check_dependency_chain
