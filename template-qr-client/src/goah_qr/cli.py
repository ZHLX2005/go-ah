"""命令行入口。

子命令按**设备**划分，而不是按步骤划分：

    demo      一个进程里同时扮演 PC 与手机（两台设备、两份 Cookie 容器）
    pc        只扮演 PC：建票 → 终端画二维码 → 轮询 → 领取
    phone     只扮演手机：解析扫到的 URL → 登录 → 预览 → 批准/拒绝
    security  跑负向检查（攻击必须失败）

之所以要把 pc / phone 拆开：真实场景里它们是两台物理设备，
`demo` 虽然能验证协议正确性，但它没法还原"手机用浏览器打开那个 URL"这件事。
用 `pc` 打印二维码 + 真手机扫码（或第二台机器跑 `phone`）才是端到端的全貌。

issuer 的默认值是 http://127.0.0.1:8080（auth-hub 直接跑起来的地址）。
注意二维码里的地址来自**服务端下发的 qr_content**，而不是这里的 --issuer：
后者只决定 CLI 把请求发到哪。两者不一致时（比如 CLI 走内网、
二维码要公网可扫），CLI 照常工作，但手机打不开码 —— 这是部署配置问题，
不是客户端问题，所以这里不试图替用户纠正它，只在 banner 里把两个地址都印出来。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import __version__
from .api import ApiError, Device, SEED_PASSWORD, SEED_USERNAME, TransportError
from .render import QrRenderError
from .roles import pc_create_ticket, pc_wait_and_claim, phone_act, run_two_devices, say
from .security import run_security_suite

DEFAULT_ISSUER = os.environ.get("GOAH_ISSUER", "http://127.0.0.1:8080")


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--issuer", default=DEFAULT_ISSUER, help="认证中心地址（默认 %(default)s，可用环境变量 GOAH_ISSUER 覆盖）")
    p.add_argument("--username", default=os.environ.get("GOAH_USERNAME", SEED_USERNAME), help="手机端登录用的账号")
    p.add_argument("--password", default=os.environ.get("GOAH_PASSWORD", SEED_PASSWORD), help="手机端登录用的口令")
    p.add_argument("--timeout", type=float, default=10.0, help="单次 HTTP 请求超时秒数")
    p.add_argument("--quiet", "-q", action="store_true", help="只打印结论，不打印过程")


def _add_render(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--ascii", dest="render_mode", action="store_const", const="ascii",
                   help="强制纯 ASCII 画二维码（'##'，给 UTF-8 有问题的老 cmd 兜底）")
    g.add_argument("--blocks", dest="render_mode", action="store_const", const="blocks",
                   help="强制半块字符画二维码（▀▄█，紧凑但需终端按 UTF-8 解码）")
    p.add_argument("--no-qr", dest="show_qr", action="store_false", help="不画二维码，只打印扫码 URL")
    p.set_defaults(render_mode=None, show_qr=True)


def _device(args: argparse.Namespace, name: str, ua: str) -> Device:
    return Device(issuer=args.issuer, name=name, user_agent=ua, timeout=args.timeout)


def _banner(args: argparse.Namespace) -> None:
    if args.quiet:
        return
    say(f"go-ah 扫码登录客户端 v{__version__} · issuer={args.issuer}")


# ── 子命令 ───────────────────────────────────────────────────────────────────


def cmd_pc(args: argparse.Namespace) -> int:
    """只扮演 PC：建票、画码、等确认、领取。"""
    _banner(args)
    pc = _device(args, "pc", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0 goah-qr-client")
    try:
        sess = pc_create_ticket(pc, show_qr=args.show_qr, render_mode=args.render_mode)
    except (ApiError, TransportError) as e:
        say(f"[pc] 建票失败：{e}")
        say("     先确认认证中心在跑：cd auth-hub && go run . （或看 README §3 一键启动）")
        return 2
    except QrRenderError as e:
        say(f"[pc] 二维码绘制失败：{e}")
        return 2

    res = pc_wait_and_claim(pc, sess, overall_timeout=args.overall_timeout, quiet=args.quiet)
    return _report_pc(res, as_json=getattr(args, "json", False), extra={"qr_content": sess.qr_content})


def cmd_phone(args: argparse.Namespace) -> int:
    """只扮演手机：把扫到的 URL 走一遍批准流程。"""
    _banner(args)
    if not args.url and not args.ticket:
        say("[phone] 需要 --url（扫码得到的完整链接）或 --ticket（只给 ticket 值）")
        return 2
    scan_url = args.url or f"{args.issuer.rstrip('/')}/scan?t={args.ticket}"

    phone = _device(args, "phone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148 goah-qr-client")
    res = phone_act(
        phone,
        scan_url,
        username=args.username,
        password=args.password,
        action="refuse" if args.refuse else "confirm",
        interactive=args.interactive,
        quiet=args.quiet,
    )
    if res.status == "confirmed":
        say("[phone] 已批准。请回到电脑那头看它领取会话。")
        return 0
    if res.status == "refused":
        say("[phone] 已拒绝这次登录请求。")
        return 0
    say(f"[phone] 未完成：{res.detail or res.status}")
    return 1


def cmd_demo(args: argparse.Namespace) -> int:
    """一个进程演完两端（两台设备、两份独立 Cookie 容器）。"""
    _banner(args)
    if not args.quiet:
        say("        PC 与手机是两个独立设备实例；若共用 Cookie 容器，")
        say("        本演示将失去验证意义（详见 src/goah_qr/api.py 模块注释）")
        say()

    pc = _device(args, "pc", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0 goah-qr-client")
    phone = _device(args, "phone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148 goah-qr-client")

    # 建票只在 run_two_devices 里做一次。之前这里先建一张、里面又建一张，
    # 结果**屏幕上那张二维码属于票据 A，而手机拿到的内容是票据 B** ——
    # 演示看起来"跑了"，实际上没有任何人扫过屏幕上那张码，
    # 而用真手机去扫它会得到"二维码无效"。这类"两条路径各自成功、
    # 但指向不同对象"的错误，只有在真扫码时才暴露，所以更要在这里掐死。
    try:
        # 真并发：手机在后台线程上"过一秒才掏出来扫"，PC 同时在轮询。
        # 顺序执行会把状态机跑成直线，看不到"轮询途中票据被改"的交叠。
        _sess, pc_res, phone_res = run_two_devices(
            pc,
            phone,
            show_qr=args.show_qr,
            render_mode=args.render_mode,
            phone_delay=args.phone_delay,
            username=args.username,
            password=args.password,
            action="refuse" if args.refuse else "confirm",
            overall_timeout=args.overall_timeout,
        )
    except (ApiError, TransportError) as e:
        say(f"[demo] 流程中断：{e}")
        return 2
    except QrRenderError as e:
        say(f"[demo] 二维码绘制失败：{e}")
        return 2

    if args.refuse:
        say(f"[demo] 手机端结果：{phone_res.status} · {phone_res.detail or '已拒绝'}")
        ok = phone_res.status == "refused"
        if ok:
            say("[demo] 预期：PC 侧应当领不到会话")
            say(f"[demo] PC 侧实际：{pc_res.status} {pc_res.detail}")
            return 0 if pc_res.status != "claimed" else 1
        return 1

    if args.with_security:
        say()
        _, bad = run_security_suite(args.issuer, args.username, args.password)
        if bad:
            say("[demo] 负向检查有失败项，先别管 happy path 了")
            return 1

    say(f"[demo] 手机端结果：{phone_res.status} {phone_res.detail}")
    return _report_pc(pc_res, as_json=args.json)


def _report_pc(res: Any, *, as_json: bool = False, extra: dict[str, Any] | None = None) -> int:
    """把 PC 侧结论打出来并给出退出码。

    判定成功的标准不是"后端说 claimed"，而是**用这个会话真的能取到身份**：
    领取响应写得再漂亮，如果 /api/me 认不出这个 Cookie，
    那扫码登录对下游依然是一场空 —— 会话必须自己证明自己。
    """
    payload: dict[str, Any] = {"status": res.status, "username": res.username, "detail": res.detail, "me": res.me}
    if extra:
        payload.update(extra)

    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        if res.status == "claimed":
            say(f"[pc] 登录成功：{res.username}")
            if res.me:
                say(f"[pc] 会话自检 GET /api/me → id={res.me.get('id')} username={res.me.get('username')} nickname={res.me.get('nickname')}")
            else:
                say("[pc] 领取返回成功，但 /api/me 认不出这个会话 —— 会话实际无效")
                return 1
        else:
            say(f"[pc] 未完成：{res.status} {res.detail}")

    return 0 if res.status == "claimed" else 1


def cmd_security(args: argparse.Namespace) -> int:
    """只跑负向检查。"""
    _banner(args)
    _, bad = run_security_suite(args.issuer, args.username, args.password)
    return 1 if bad else 0


# ── 装配 ─────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="goah-qr",
        description="go-ah 统一登录平台 · 扫码登录客户端（终端出二维码 + 模拟手机端）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例
  goah-qr demo                      # 一个进程演完：画码 → 手机扫 → 批准 → PC 领取
  goah-qr demo --with-security      # 顺手把负向检查也跑了
  goah-qr pc                        # 终端一：只当 PC，画码等人扫
  goah-qr phone --url "<扫到的URL>"  # 终端二：只当手机，走批准流程
  goah-qr phone --ticket qrt_xxx --refuse
  goah-qr security                  # 只跑攻击必须失败的检查
""",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("pc", help="只扮演 PC：建票、画二维码、轮询、领取")
    _add_common(p)
    _add_render(p)
    p.add_argument("--overall-timeout", type=float, default=150.0, help="等待手机端批准的最长秒数")
    p.add_argument("--json", action="store_true", help="结论以 JSON 输出到 stdout（过程日志走 stderr）")
    p.set_defaults(func=cmd_pc)

    p = sub.add_parser("phone", help="只扮演手机：解析二维码、登录、预览、批准或拒绝")
    _add_common(p)
    p.add_argument("--url", help="扫码得到的完整链接（形如 http://issuer/scan?t=…）")
    p.add_argument("--ticket", help="直接给 ticket 值（与 --url 二选一）")
    p.add_argument("--refuse", action="store_true", help="点「不是我操作」而不是确认")
    p.add_argument("--interactive", action="store_true", help="打印设备画像后询问 y/n")
    p.set_defaults(func=cmd_phone)

    p = sub.add_parser("demo", help="一个进程演完两端（默认子命令）")
    _add_common(p)
    _add_render(p)
    p.add_argument("--overall-timeout", type=float, default=150.0)
    p.add_argument("--phone-delay", type=float, default=1.2, help="模拟「掏手机」的延迟秒数")
    p.add_argument("--refuse", action="store_true", help="让手机端拒绝，验证 PC 领不到")
    p.add_argument("--with-security", action="store_true", help="附上负向检查")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("security", help="只跑负向安全检查")
    _add_common(p)
    p.set_defaults(func=cmd_security)

    return ap


def _force_utf8_stdio() -> None:
    """把 stdout/stderr 切成 UTF-8。

    本工具的输出几乎全是中文，还包含 ▀▄█ 这类二维码字符。Windows 控制台
    默认跟随系统 ANSI 代码页（中文环境是 cp936），Python 据此选择 sys.stdout
    的编码 —— 结果是 `--help` 与所有日志打成乱码，而二维码会直接画不出来
    （cp936 里没有 U+2580）。这不是显示瑕疵，是功能故障。

    errors 用 'replace' 而不是 'strict'：真要碰上不支持 UTF-8 的怪终端，
    宁可个别字符变成 '?' 也不要整个命令在打印中途抛 UnicodeEncodeError。
    重配置失败也不该终止程序（例如 stdout 被换成了不接受该参数的对象），
    所以整段包在 try 里静默降级。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdio()
    ap = build_parser()
    args = ap.parse_args(argv)
    if getattr(args, "cmd", None) is None:
        # 不带子命令 = demo。这是个演示型工具，最短路径必须最短。
        args = ap.parse_args(["demo", *(argv or [])])
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        say("\n[中断] 已退出")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
