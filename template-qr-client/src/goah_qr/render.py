"""终端里把二维码画出来。

只借 segno 做 QR 编码（那才是难的部分：掩码、纠错、Reed-Solomon），
**渲染自己画**。原因是 segno 1.6.6 的 writer 覆盖不到这个用例：

    save(kind='terminal')  → 依赖 ANSI 背景色，NO_COLOR 的终端、纯文本日志里全废
    save(kind='ans')       → 每个模块一格空格 + 反显转义，宽到溢出终端
    save(kind='txt')       → 打的是 0/1 矩阵，人不可读、机器不可扫
    print_ascii()          → 这个版本压根没有这个方法

而自己画只有十几行，且换来两样要紧的东西：
不依赖颜色的渲染路径、以及"同一张码在两种字符集下形状一致"的确定性。

两种模式：
    blocks  半块字符（▀▄█），一行画两行模块，**不需要任何颜色支持**。
            默认走这条：它是唯一既紧凑又对终端无要求的组合。
    ascii   '##' 与 '  '，纯 7-bit ASCII，给 UTF-8 有问题的老终端兜底。

无论哪条，四周都留 2 模块静区 —— 没有静区时扫码器无法把码从终端背景里分离，
这是"扫不出来"的头号原因，不是美观问题。
"""

from __future__ import annotations

import io
import os
import sys

try:
    import segno
except ImportError:  # pragma: no cover
    segno = None  # type: ignore[assignment]

#: 静区宽度（模块数）。QR 规范要求至少 4 个模块，终端里 2 个已经让图明显变大，
#: 再宽就没有一半屏幕放不下了；实测手机在 2 模块静区下识别正常。
QUIET_ZONE = 2

BLOCK_TOP = "\u2580"     # ▀ 上半黑
BLOCK_BOTTOM = "\u2584"  # ▄ 下半黑
BLOCK_FULL = "\u2588"    # █ 全黑


class QrRenderError(RuntimeError):
    """画不出来。消息里必须包含"那该怎么办"。"""


def _require_segno() -> None:
    if segno is None:
        raise QrRenderError(
            "缺少 segno 依赖。先 `uv sync` 安装依赖，"
            "或临时用 `uv run --with segno goah-qr ...`。"
        )


def _matrix(data: str) -> list[tuple[int, ...]]:
    """把字符串编码成 QR 模块矩阵。

    error='M'（约 15% 容错）是屏幕扫码的经验平衡点：'L' 省不下多少尺寸，
    而屏幕反光、投影仪摩尔纹就足以让它扫不出来；'Q'/'H' 则让终端里的图明显过大。
    """
    _require_segno()
    qr = segno.make(data, error="M", micro=False)
    return [tuple(int(v) for v in row) for row in qr.matrix]


def _prefer_blocks() -> bool:
    """默认能否使用半块字符（即终端是不是 UTF-8）。

    判据是编码而不是"是不是 tty"：半块字符只是三个 Unicode 码点，
    不需要颜色、不需要 ANSI 转义支持，唯一前提是终端按 UTF-8 解码字节。
    所以这里只看编码 —— Windows 的 cmd 默认 cp936，那才是会画成乱码的场景。
    """
    enc = (getattr(sys.stdout, "encoding", None) or "").lower()
    if os.environ.get("GOAH_QR_ASCII"):
        return False
    return any(t in enc for t in ("utf", "unicode"))


def _draw_blocks(m: list[tuple[int, ...]]) -> str:
    """半块渲染：一行字符承载两行模块。

    奇数高度的 QR（版本 1 是 21×21，都是奇数）最后一行没有配对行，
    用"上半黑"补一行空白 —— 等价于在末尾垫一行空格再配对，
    单独处理掉比"整张图多加一圈"省两行。
    """
    rows = list(m)
    if len(rows) % 2:
        rows.append(tuple(0 for _ in range(len(rows[0]))))

    out: list[str] = []
    w = len(rows[0])
    pad = " " * QUIET_ZONE
    for i in range(0, len(rows), 2):
        top, bot = rows[i], rows[i + 1]
        line = []
        for x in range(w):
            t, b = bool(top[x]), bool(bot[x])
            line.append(BLOCK_FULL if (t and b) else BLOCK_TOP if t else BLOCK_BOTTOM if b else " ")
        out.append(pad + "".join(line) + pad)
    # 上下各垫两行空白当静区的纵向部分
    blank = " " * (w + 2 * QUIET_ZONE)
    return "\n".join([blank] * QUIET_ZONE + out + [blank] * QUIET_ZONE)


def _draw_ascii(m: list[tuple[int, ...]]) -> str:
    """纯 ASCII 渲染：一个模块两个字符宽（'##' 接近正方形字符比例）。"""
    out: list[str] = []
    w = len(m[0])
    pad = "  " * QUIET_ZONE
    for row in m:
        cells = "".join("##" if v else "  " for v in row)
        out.append(pad + cells + pad)
    blank = " " * (2 * w + 2 * len(pad))
    return "\n".join([blank] * QUIET_ZONE + out + [blank] * QUIET_ZONE)


def render(data: str, *, mode: str | None = None) -> tuple[str, str]:
    """画二维码，返回 (画面文本, 实际使用的方式)。

    把"用了哪种方式"作为返回值而不是内部变量：降级必须让用户看见。
    他在窄终端里对着一个自己不知道被降级过的码举着手机，
    只会得出"这功能扫不上"的错误结论。
    """
    if not data:
        raise QrRenderError("二维码内容为空，无从绘制")

    if mode in (None, "auto"):
        mode = "blocks" if _prefer_blocks() else "ascii"
    if mode not in ("blocks", "ascii"):
        raise QrRenderError(f"未知渲染方式 {mode!r}，只支持 blocks / ascii")

    m = _matrix(data)
    pic = _draw_blocks(m) if mode == "blocks" else _draw_ascii(m)
    if not pic.strip():
        raise QrRenderError("绘制结果为空，请改用 --ascii 重试")
    return pic, mode


def dump_terminal(data: str) -> str:
    """segno 自带的 ANSI 终端输出，留作对照与排障用（--dump-terminal）。

    不作为默认路径：它依赖背景色，而本项目其余所有输出都刻意不依赖颜色
    （见 idp-web/app.css 的"只用灰阶"规则）。
    """
    _require_segno()
    buf = io.StringIO()
    segno.make(data, error="M").terminal(out=buf, compact=True)
    return buf.getvalue()


def width_of(pic: str) -> int:
    """画面宽度（字符数），用于居中与"要不要缩小"的判断。"""
    return max((len(ln) for ln in pic.splitlines()), default=0)


__all__ = ["render", "dump_terminal", "width_of", "QrRenderError"]
