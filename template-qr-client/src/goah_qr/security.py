"""扫码登录的负向自检：验证"攻击走不通"，而不只是"正常流程走得通"。

为什么要专门有这一份：扫码登录的全部风险都在**转发**上 —— 二维码天生就是
给人拍照、截图、发微信的东西。正常流程跑通只证明了功能可用，
一条都证明不了安全性。而"qr_ctx 绑定"这条防线如果被删掉，
happy path 依然 100% 通过：因为只有攻击者才会碰到那个分支。

所以这里的每一条检查都是"**先制造一次攻击，再断言它失败**"。
一条检查如果永远不可能失败，它就不该写在这里。

每台设备都是独立 Device（独立 Cookie 容器）。这一点在本模块里不是风格问题：
攻击者与受害者如果共用容器，攻击会因为"顺到了对方的 qr_ctx"而成功，
自检就会红得莫名其妙 —— 而最坏的情况是它恰好绿了，让人误以为测过了。
"""

from __future__ import annotations

from dataclasses import dataclass

from .api import ApiError, Device, TransportError
from .roles import say


@dataclass
class Check:
    name: str
    desc: str
    passed: bool
    detail: str


def _fail(name: str, desc: str, detail: str) -> Check:
    return Check(name, desc, False, detail)


def _ok(name: str, desc: str, detail: str) -> Check:
    return Check(name, desc, True, detail)


def _mk(issuer: str, name: str, ua: str) -> Device:
    return Device(issuer=issuer, name=name, user_agent=ua)


# ── 1. 二维码转发攻击 ───────────────────────────────────────────────────────


def check_forward_attack(issuer: str, username: str, password: str) -> Check:
    """攻击者拿到二维码内容（含 ticket），但浏览器里没有受害者的 qr_ctx。

    这是扫码登录最现实、也最容易被忽视的攻击：骗子在群里发一张"领奖二维码"，
    受害者手机一扫并批准，而那张码其实来自攻击者自己的登录页 ——
    结果攻击者的浏览器登录进了受害者的账号。
    防住它的唯一机制就是领取必须由**创建票据的那台浏览器**发起。
    """
    name, desc = "forward_attack", "攻击者持有 ticket 但无 qr_ctx，不能领走会话"
    victim = _mk(issuer, "victim-pc", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0")
    phone = _mk(issuer, "owner-phone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile")
    attacker = _mk(issuer, "attacker-pc", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/141.0")

    try:
        sess = victim.qr_create()
        phone.login(username, password)
        phone.qr_confirm(sess.ticket)

        # 攻击者：知道完整 ticket（二维码就在图片里），但没有受害者的 qr_ctx
        try:
            attacker.qr_claim(sess.ticket)
            return _fail(name, desc, "攻击者在没有 qr_ctx 的情况下领取成功 —— 防转发机制失效")
        except ApiError as e:
            if e.reason != "qr_not_ready":
                say(f"    （攻击者被拒，但 reason={e.reason} 与期望 qr_not_ready 不同）")
        except TransportError as e:
            return _fail(name, desc, f"攻击者领取时传输异常，无法判定：{e}")

        # 关键的后半段：攻击失败不能把票据弄坏，真受害者仍须能登录
        data = victim.qr_claim(sess.ticket)
        if str(data.get("username") or "") != username:
            return _fail(name, desc, f"受害者领取到的账号是 {data.get('username')!r}，期望 {username!r}")
        return _ok(name, desc, "攻击者被拒，且票据未被消耗、受害者照常登录")
    except (ApiError, TransportError) as e:
        return _fail(name, desc, f"链路异常：{e}")


# ── 2. 用自己的 qr_ctx 领别人的票 ───────────────────────────────────────────


def check_ctx_not_interchangeable(issuer: str, username: str, password: str) -> Check:
    """攻击者**有**自己的 qr_ctx（他创建过自己的票据），拿去领受害者的票。

    它补的是第 1 条的盲区：如果后端只检查"请求带了 qr_ctx"而不比对
    "是不是这张票当初那一个"，那么攻击者带着自己的 ctx 就能领走别人的会话。
    两个检查合起来才等于"绑定"。
    """
    name, desc = "ctx_not_interchangeable", "攻击者带着自己的 qr_ctx 不能领走别人的票据"
    victim = _mk(issuer, "victim-pc", "goah-qr-client/1.0 victim")
    phone = _mk(issuer, "owner-phone", "goah-qr-client/1.0 phone")
    attacker = _mk(issuer, "attacker-pc", "goah-qr-client/1.0 attacker")

    try:
        victim_sess = victim.qr_create()
        # 攻击者先建自己的票，从而**合法地**获得一个属于他的 qr_ctx Cookie
        attacker.qr_create()
        phone.login(username, password)
        phone.qr_confirm(victim_sess.ticket)

        try:
            attacker.qr_claim(victim_sess.ticket)
            return _fail(name, desc, "攻击者用自己的 qr_ctx 领走了受害者的会话 —— 绑定只查了存在性")
        except ApiError:
            pass

        data = victim.qr_claim(victim_sess.ticket)
        if str(data.get("username") or "") != username:
            return _fail(name, desc, f"受害者领取结果异常：{data}")
        return _ok(name, desc, "跨票据复用 qr_ctx 被拒，受害者照常登录")
    except (ApiError, TransportError) as e:
        return _fail(name, desc, f"链路异常：{e}")


# ── 3. 状态探测 ─────────────────────────────────────────────────────────────


def check_status_probe(issuer: str, username: str, password: str) -> Check:
    """旁观者拿着 ticket 轮询，不该看到真实进度。

    二维码会被拍照投屏，图片里就有 URL。如果任何人 GET 一次就能知道
    "已经有手机扫过了/批准了"，那是一个真实的信息泄露面
    （攻击者据此挑"已经批准但还没领取"的那张票去抢）。
    """
    name, desc = "status_probe", "无 qr_ctx 者轮询已批准的票据，只能看到 pending"
    victim = _mk(issuer, "victim-pc", "goah-qr-client/1.0 victim")
    phone = _mk(issuer, "owner-phone", "goah-qr-client/1.0 phone")
    bystander = _mk(issuer, "bystander", "goah-qr-client/1.0 bystander")

    try:
        sess = victim.qr_create()
        if bystander.qr_poll(sess.ticket) != "pending":
            return _fail(name, desc, "刚创建的票据就泄漏了非 pending 状态")
        phone.login(username, password)
        phone.qr_confirm(sess.ticket)

        seen = bystander.qr_poll(sess.ticket)
        if seen != "pending":
            return _fail(name, desc, f"旁观者看到真实状态 {seen!r}，应当一律是 pending")

        mine = victim.qr_poll(sess.ticket)
        if mine != "confirmed":
            return _fail(name, desc, f"持有正确 qr_ctx 的受害者反而看到 {mine!r}，期望 confirmed")
        return _ok(name, desc, "旁观者只见 pending，创建者可见 confirmed")
    except (ApiError, TransportError) as e:
        return _fail(name, desc, f"链路异常：{e}")


# ── 4. 匿名批准 ─────────────────────────────────────────────────────────────


def check_anonymous_confirm(issuer: str) -> Check:
    """未登录的设备不能批准任何扫码。

    这条如果失守，任何人只要拍到一张二维码就能替别人"确认"，
    整套模型立刻归零 —— 所以它是这里优先级最高的一条。
    """
    name, desc = "anonymous_confirm", "未登录的手机侧调用被挡在 401"
    victim = _mk(issuer, "victim-pc", "goah-qr-client/1.0 victim")
    anon = _mk(issuer, "anonymous-phone", "goah-qr-client/1.0 anon")

    try:
        sess = victim.qr_create()
        for op in (anon.qr_preview, anon.qr_scan, anon.qr_confirm, anon.qr_refuse):
            try:
                op(sess.ticket)
                return _fail(name, desc, f"{op.__name__} 竟然对匿名调用成功了")
            except ApiError as e:
                if e.status != 401 or e.reason != "unauthenticated":
                    return _fail(name, desc, f"{op.__name__} 返回 {e.status}/{e.reason}，期望 401/unauthenticated")
            except TransportError as e:
                return _fail(name, desc, f"{op.__name__} 传输异常：{e}")
        return _ok(name, desc, "preview/scan/confirm/refuse 四条全部要求身份")
    except (ApiError, TransportError) as e:
        return _fail(name, desc, f"链路异常：{e}")


# ── 5. 跳过批准直接领取 ─────────────────────────────────────────────────────


def check_claim_without_confirm(issuer: str) -> Check:
    """票据刚创建（pending）时，创建者自己也领不动 —— 必须有人在手机上批准。

    防的是"把 qr_ctx 当成唯一凭据"的实现退化：一旦 claim 只校验 ctx，
    攻击者自己建票自己领，就能凭空造出任意账号的登录态吗？
    不会，但**会**造出他自己的匿名会话；真正的问题是这让"批准"这一步形同虚设。
    """
    name, desc = "claim_without_confirm", "未经手机批准时，连创建者自己也领不到会话"
    pc = _mk(issuer, "pc", "goah-qr-client/1.0 pc")
    try:
        sess = pc.qr_create()
        try:
            pc.qr_claim(sess.ticket)
            return _fail(name, desc, "pending 状态下直接领取成功 —— 手机批准这一步被绕过了")
        except ApiError:
            pass
        except TransportError as e:
            return _fail(name, desc, f"传输异常：{e}")
        if pc.me() is not None:
            return _fail(name, desc, "领取失败但设备已持有会话 —— 副作用泄漏")
        return _ok(name, desc, "被拒，且没有意外建立会话")
    except (ApiError, TransportError) as e:
        return _fail(name, desc, f"链路异常：{e}")


# ── 6. 票据只能用一次 ───────────────────────────────────────────────────────


def check_single_use(issuer: str, username: str, password: str) -> Check:
    """confirmed → consumed 是一次性的：重复领取必须失败。

    不失败的话，一张被截图外流的二维码会在整个保留期内
    成为一个"可重复登录"的入口。
    """
    name, desc = "single_use", "会话领取一次即失效，重复领取被拒"
    pc = _mk(issuer, "pc", "goah-qr-client/1.0 pc")
    phone = _mk(issuer, "phone", "goah-qr-client/1.0 phone")
    try:
        sess = pc.qr_create()
        phone.login(username, password)
        phone.qr_confirm(sess.ticket)
        pc.qr_claim(sess.ticket)
        try:
            pc.qr_claim(sess.ticket)
            return _fail(name, desc, "同一张票据被领取了两次")
        except ApiError:
            pass
        except TransportError as e:
            return _fail(name, desc, f"传输异常：{e}")
        return _ok(name, desc, "第二次领取被拒")
    except (ApiError, TransportError) as e:
        return _fail(name, desc, f"链路异常：{e}")


# ── 7. 手机拒绝后不可领取 ───────────────────────────────────────────────────


def check_refuse_blocks_claim(issuer: str, username: str, password: str) -> Check:
    """用户点"不是我操作"之后，那张码必须彻底作废。"""
    name, desc = "refuse_blocks_claim", "手机端拒绝后，PC 再也领不到会话"
    pc = _mk(issuer, "pc", "goah-qr-client/1.0 pc")
    phone = _mk(issuer, "phone", "goah-qr-client/1.0 phone")
    try:
        sess = pc.qr_create()
        phone.login(username, password)
        phone.qr_refuse(sess.ticket)
        try:
            pc.qr_claim(sess.ticket)
            return _fail(name, desc, "被拒绝的票据仍然可以领取")
        except ApiError:
            pass
        except TransportError as e:
            return _fail(name, desc, f"传输异常：{e}")
        if pc.me() is not None:
            return _fail(name, desc, "拒绝之后 PC 侧却拿到了会话")
        return _ok(name, desc, "拒绝生效")
    except (ApiError, TransportError) as e:
        return _fail(name, desc, f"链路异常：{e}")


# ── 汇总 ────────────────────────────────────────────────────────────────────


def all_checks(issuer: str, username: str, password: str) -> list[Check]:
    """按"失守后果严重程度"排序，而不是按实现顺序。

    排第一的应该是"匿名也能批准" —— 它一旦破了，其余检查全都没有意义。
    读输出的人只看前几行，顺序就是注意力分配。
    """
    return [
        check_anonymous_confirm(issuer),
        check_forward_attack(issuer, username, password),
        check_ctx_not_interchangeable(issuer, username, password),
        check_claim_without_confirm(issuer),
        check_single_use(issuer, username, password),
        check_refuse_blocks_claim(issuer, username, password),
        check_status_probe(issuer, username, password),
    ]


def run_security_suite(issuer: str, username: str, password: str) -> tuple[list[Check], int]:
    """跑完所有检查并打印结论，返回 (结果列表, 失败数)。"""
    say(f"[security] 在 {issuer} 上执行 {7} 项负向检查")
    checks = all_checks(issuer, username, password)
    bad = 0
    for c in checks:
        mark = "PASS" if c.passed else "FAIL"
        if not c.passed:
            bad += 1
        say(f"  [{mark}] {c.name}: {c.desc}")
        say(f"         {c.detail}")
    say(f"[security] {len(checks) - bad}/{len(checks)} 通过")
    return checks, bad
