"""把扫码登录的两端各编排成一条可复用的流程。

设计约定：**每个角色函数只碰自己那台设备的 Device**。
角色之间唯一的通信是二维码里那个 URL —— 这在演示里看起来"绕"，
但它是这个功能真实形态的忠实还原：手机端与 PC 端之间没有任何直连通道，
它们各自只与认证中心说话。一旦图省事让 phone_role 直接收 ticket 对象、
或者让两个角色共用一个 Device，演示就会失去验证能力（见 api.py 模块注释）。
"""

from __future__ import annotations

import sys
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass

from .api import ApiError, Device, QRSession, SEED_PASSWORD, SEED_USERNAME, TransportError, sleep, ticket_of
from .render import render


def say(msg: str = "") -> None:
    """统一出口：写 stderr 而不是 stdout。

    为什么：`goah-qr pc --json` 之类要把结果管道给别的程序，
    过程日志混进 stdout 会直接毁掉输出。日志走 stderr 是这类工具的基本礼貌。
    """
    print(msg, file=sys.stderr, flush=True)


def _fmt_when(raw: object) -> str:
    """把后端下发的 RFC3339 时刻渲染成"刚刚 / N 秒前 / 绝对时间"。

    为什么不直接印原始串：用户在手机上要判断的是"这是不是我刚才干的"，
    相对时间比 `2026-10-10T15:55:13Z` 好读得多 —— 而且那个 Z 会让人误以为
    自己八点零五分就发了请求。绝对时间仍留在括号里，
    因为真要排查时需要的恰好是那个精确值。
    """
    s = str(raw or "").strip()
    if not s:
        return "?"
    try:
        when = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return s
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    delta = (datetime.now(timezone.utc) - when).total_seconds()
    abs_part = when.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    if 0 <= delta < 60:
        return f"{int(delta)} 秒前（{abs_part}）"
    if delta < 0:
        return f"超前 {-delta:.0f}s（{abs_part}）"
    return abs_part


# ── PC 侧 ────────────────────────────────────────────────────────────────────


@dataclass
class PcOutcome:
    status: str  # claimed / expired / refused / cancelled / error / timeout
    username: str = ""
    detail: str = ""
    me: dict | None = None


def pc_create_ticket(
    pc: Device, *, show_qr: bool = True, render_mode: str | None = None
) -> QRSession:
    """建票并在终端画出二维码。"""
    s = pc.qr_create()
    say(f"[pc:{pc.name}] 已创建票据 {s.ticket[:16]}…（{s.expires_in}s 内有效，轮询间隔 {s.interval_ms}ms）")
    if show_qr:
        pic, mode = render(s.qr_content, mode=render_mode)
        say(f"[pc:{pc.name}] 二维码（渲染方式 {mode}）：")
        say()
        for line in pic.splitlines():
            say("    " + line)
        say()
        say(f"[pc:{pc.name}] 内容是 {s.qr_content}")
        say(f"[pc:{pc.name}] ↑ 手机扫它；没手机就把这个 URL 交给 phone 子命令")
    return s


def pc_wait_and_claim(
    pc: Device,
    sess: QRSession,
    *,
    overall_timeout: float = 150.0,
    quiet: bool = False,
) -> PcOutcome:
    """轮询直到手机端批准，然后领取会话。

    串行 await 而不并发轮询：与前端 QrPanel 同一个理由 —— 并发轮询的响应
    到达顺序不等于发出顺序，会让状态"从 confirmed 倒回 pending"。
    这里还多一层：自检脚本要判定成败，一个乱序的状态序列会把结论直接判错。
    """
    deadline = time.monotonic() + overall_timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            status = pc.qr_poll(sess.ticket)
        except (ApiError, TransportError) as e:
            return PcOutcome("error", detail=f"轮询失败：{e}")

        if status != last:
            if not quiet:
                say(f"[pc:{pc.name}] 状态 → {status}")
            last = status

        if status == "confirmed":
            break
        if status in ("expired", "cancelled", "consumed"):
            return PcOutcome(status, detail="手机端未在本次有效期内完成批准")
        sleep(sess.interval_ms)
    else:
        return PcOutcome("timeout", detail=f"{overall_timeout:.0f}s 内没有等到确认")

    # 领取。注意这一步的失败**不重试**：confirmed → consumed 是一次性的，
    # 重试只会拿到 409，而那张票据其实已经被这次调用消费掉了 ——
    # 重试会把一个"已经成功"的结果读成失败。
    try:
        data = pc.qr_claim(sess.ticket)
    except ApiError as e:
        return PcOutcome("error", detail=f"领取失败：{e}（reason={e.reason}）")

    username = str(data.get("username") or "")
    me = pc.me()
    if not quiet:
        say(f"[pc:{pc.name}] 已领取登录态，账号 = {username}")
    return PcOutcome("claimed", username=username, me=me)


# ── 手机侧 ───────────────────────────────────────────────────────────────────


@dataclass
class PhoneOutcome:
    status: str  # confirmed / refused / unauthenticated / error / rejected
    detail: str = ""
    pc_info: dict | None = None


def phone_act(
    phone: Device,
    scan_url: str,
    *,
    username: str = SEED_USERNAME,
    password: str = SEED_PASSWORD,
    action: str = "confirm",
    auto_login: bool = True,
    interactive: bool = False,
    delay: float = 0.0,
    quiet: bool = False,
) -> PhoneOutcome:
    """扮演手机端：解析二维码 → 确保已登录 → 预览 → 扫码 → 确认/拒绝。

    delay 用于把"用户掏手机"这点真实延迟演出来：PC 那边才有机会观察到
    pending → scanned → confirmed 的完整序列，而不是一上来就直接 confirmed。
    """
    if delay > 0:
        sleep(delay * 1000)

    try:
        ticket = ticket_of(scan_url)
    except ValueError as e:
        return PhoneOutcome("error", detail=str(e))

    if not quiet:
        say(f"[phone:{phone.name}] 从二维码解析出 ticket={ticket[:16]}…")

    # 登录：只在确实没有会话时才做
    try:
        who = phone.me()
    except (ApiError, TransportError) as e:
        return PhoneOutcome("error", detail=f"探测登录态失败：{e}")

    if who is None:
        if not auto_login:
            return PhoneOutcome("unauthenticated", detail="手机端未登录，且未允许自动登录")
        try:
            phone.login(username, password)
            who = phone.me()
            if not quiet:
                say(f"[phone:{phone.name}] 已登录为 {username}")
        except ApiError as e:
            return PhoneOutcome("error", detail=f"手机端登录失败：{e}（reason={e.reason}）")
        except TransportError as e:
            return PhoneOutcome("error", detail=f"手机端登录传输失败：{e}")

    # 预览：这一页的"设备画像"就是真用户点确认前看到的全部内容，
    # 所以必须打印出来 —— 演示的价值有一半在这里。
    try:
        pv = phone.qr_preview(ticket)
    except ApiError as e:
        return PhoneOutcome("error", detail=f"预览失败：{e}（reason={e.reason}）")
    except TransportError as e:
        return PhoneOutcome("error", detail=f"预览传输失败：{e}")

    pc_info = pv.get("pc") or {}
    if not quiet:
        say(f"[phone:{phone.name}] 有人请求登录，目标设备：")
        say(f"    设备    : {pc_info.get('ua') or '未知设备'}")
        say(f"    来源    : {pc_info.get('geo') or '未知'} / {pc_info.get('ip') or '未知 IP'}")
        say(f"    发起时间: {_fmt_when(pc_info.get('created_at'))}")
        say(f"    当前状态: {pv.get('status')}")

    if interactive:
        answer = input(f"[phone:{phone.name}] 确认在这台机器上登录？(y/n) ").strip().lower()
        action = "confirm" if answer == "y" else "refuse"

    # scan：让 PC 进入"已扫码"中间态。失败不致命 —— pending|scanned → confirmed
    # 两条路后端都认（见 logic/qr.Confirm 的说明），而"这台设备确实扫到了"
    # 已经由上面的 preview 成立。
    try:
        if pv.get("status") == "pending":
            phone.qr_scan(ticket)
            if not quiet:
                say(f"[phone:{phone.name}] 已上报扫码")
    except (ApiError, TransportError) as e:
        if not quiet:
            say(f"[phone:{phone.name}] 上报扫码失败（不影响确认）：{e}")

    try:
        if action == "refuse":
            phone.qr_refuse(ticket)
            if not quiet:
                say(f"[phone:{phone.name}] 已拒绝这次登录请求")
            return PhoneOutcome("refused", pc_info=pc_info)
        phone.qr_confirm(ticket)
        if not quiet:
            say(f"[phone:{phone.name}] 已批准登录")
        return PhoneOutcome("confirmed", pc_info=pc_info)
    except ApiError as e:
        return PhoneOutcome("error", detail=f"{action} 失败：{e}（reason={e.reason}）", pc_info=pc_info)
    except TransportError as e:
        return PhoneOutcome("error", detail=f"{action} 传输失败：{e}", pc_info=pc_info)


# ── 把两端跑在一起 ───────────────────────────────────────────────────────────


def run_two_devices(
    pc: Device,
    phone: Device,
    *,
    show_qr: bool = True,
    render_mode: str | None = None,
    phone_delay: float = 1.2,
    username: str = SEED_USERNAME,
    password: str = SEED_PASSWORD,
    action: str = "confirm",
    overall_timeout: float = 150.0,
) -> tuple[QRSession, PcOutcome, PhoneOutcome]:
    """PC 主线程轮询、手机后台线程批准 —— 两者真正并发，不是顺序脚本。

    用线程而不是"先跑 PC 再跑手机"：后者的时序会把状态机跑成一条直线，
    永远观察不到"PC 正在轮询时票据被改"这个真实交叠，
    而那正是条件 UPDATE 排他性唯一会被检验到的时刻。
    """
    sess = pc_create_ticket(pc, show_qr=show_qr, render_mode=render_mode)

    box: dict[str, PhoneOutcome] = {}

    def phone_thread() -> None:
        try:
            box["r"] = phone_act(
                phone,
                sess.qr_content,
                username=username,
                password=password,
                action=action,
                delay=phone_delay,
            )
        except Exception as e:  # pragma: no cover - 线程里的意外必须被收口，否则静默消失
            box["r"] = PhoneOutcome("error", detail=f"手机线程异常：{e!r}")

    # daemon=False：手机那半边的结果要能打印出来。设成 daemon 会在主线程
    # 先退出时把批准动作整个吞掉，表现为"PC 超时了"，而原因在另一个线程里。
    t = threading.Thread(target=phone_thread, name=f"phone-{phone.name}", daemon=False)
    t.start()

    pc_res = pc_wait_and_claim(pc, sess, overall_timeout=overall_timeout)
    t.join(timeout=20)
    phone_res = box.get("r") or PhoneOutcome("error", detail="手机线程没有产出结果")
    return sess, pc_res, phone_res
