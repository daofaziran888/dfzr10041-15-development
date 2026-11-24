"""拾音工坊核心业务层：真实跨模块数据流与数据处理管道。"""

# 先导入既有管道，再导入重算批次（重算批次依赖它们）。
from app.core import dedup_sample, mask_enrich, models, pipeline  # noqa: F401
from app.core import mapping_recalc  # noqa: F401
from app.core.mapping_recalc import *  # noqa: F401,F403

# 让习惯从既有管道模块寻找新入口的调用方也能取到同一组类/函数。
for _mod in (mask_enrich, pipeline):
    for _name in getattr(mapping_recalc, "__all__", []):
        if not hasattr(_mod, _name):
            setattr(_mod, _name, getattr(mapping_recalc, _name))
