"""go-ah 统一登录平台 · 扫码登录的 Python 客户端。

模块划分即职责划分：

    api.py       一台设备如何与认证中心说话（含"设备 = 独立 Cookie 容器"这条铁律）
    render.py    把二维码画到终端上（ANSI 与 ASCII 两条路）
    roles.py     PC / 手机两条流程各自的编排
    security.py  负向检查：攻击必须失败
    cli.py       命令行装配

用 `python -m goah_qr` 或 `goah-qr` 启动，不要直接 import 这里的内部函数写脚本 ——
子命令已经覆盖了常见组合，绕过 CLI 会丢掉退出码与日志分流的约定。
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
