"""业务路由汇总：recalc 等专用路由先注册，通用资源路由后注册，避免路径参数抢占。"""
from __future__ import annotations

from app.routers import recalc, resource

ROUTERS = [recalc, resource]
