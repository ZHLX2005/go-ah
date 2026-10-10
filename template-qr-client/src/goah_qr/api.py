"""扫码登录服务端的 HTTP 客户端。

一个 `Device` = 一台独立的设备。这个等式是整个模块的核心，理由是扫码登录的
安全模型**完全建立在设备隔离上**：

    PC  持有 qr_ctx Cookie  ——「这张二维码是我发起的」
    手机 持有 idp_session   ——「我有权批准用这个账号登录」

两者若共用一个 Cookie 容器，演示与自检都会失去意义：领取凭据与批准身份
落在同一个 jar 里，那么"qr_ctx 绑定"这条防线即使被删掉，测试照样全绿 ——
这是最糟糕的一类测试，它通过的方式恰恰是掩盖 bug。

所以这里没有任何"默认 client"、没有模块级 Session、没有全局共享。
每一个角色都必须显式 `Device(...)`，`demo` 里三台设备三个实例，一眼可见。

后端契约见 auth-hub/api/qr/v1/qr.go；改字段名要两头一起改。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs

import requests

#: 演示账号（auth-hub 首次启动写入的种子账号，见 consts.SeedUsername）
SEED_USERNAME = "test"
SEED_PASSWORD = "test123456"


class ApiError(Exception):
    """后端返回了失败信封 {code:1, error, message}。

    `reason` 是机器可读的 error 字段（qr_not_found / qr_expired / unauthenticated …）。
    调用方按 reason 分支，不要匹配 message 文本 —— 文案是给看的，会改。
    """

    def __init__(self, message: str, reason: str = "", status: int = 0) -> None:
        super().__init__(message)
        self.reason = reason
        self.status = status


class TransportError(Exception):
    """连不上、超时、返回不是 JSON。

    与 ApiError 分开是必要的：前者说明"服务端明确拒绝了我"，
    后者说明"我根本不知道服务端怎么想"。把两者混成一个，
    自检脚本就会把"服务没起来"误报成"安全校验失败"，那是最误导人的报错。
    """


@dataclass
class QRSession:
    """POST /api/qr/sessions 的结果。"""

    ticket: str
    qr_content: str
    expires_in: int
    interval_ms: int

    @property
    def ticket_from_url(self) -> str:
        """从二维码内容里把 ticket 解出来。

        为什么需要这个方法而不是直接用手里的 ticket：**真实手机端拿不到
        ticket 字段，它只有相机扫出来的一串 URL**。自检脚本要走同一条路，
        就必须从 URL 反解 —— 否则 we'd 悄悄绕过"二维码内容是不是可用"这一步，
        而那正是 Universal Link / H5 兜底能不能工作的前提。
        """
        return ticket_of(self.qr_content)


@dataclass
class Device:
    """一台独立设备：自己的 Cookie 容器 + 自己的 User-Agent。

    UA 不是装饰。后端会把"要被登录的那台机器"的 UA 摘要显示到手机上，
    所以给出一个可辨认的 UA 是这套演示能自证清楚的前提（见 utility/useragent.go）。
    """

    issuer: str
    name: str = "device"
    user_agent: str = "goah-qr-client/1.0"
    timeout: float = 10.0
    _http: requests.Session = field(default_factory=requests.Session, repr=False)

    def __post_init__(self) -> None:
        self.issuer = self.issuer.rstrip("/")
        self._http.headers.update({"User-Agent": self.user_agent, "Accept": "application/json"})

    # ── 底层 ────────────────────────────────────────────────────────────

    def _call(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """发一次请求并按统一信封拆包。

        POST 一律带 `{}` 而不是 None：后端的 claim/confirm/cancel 是**无请求体**
        的端点，用 requests 的 json=None 会连 Content-Type 都不发，
        某些网关会把它判成畸形请求。空对象在后端等价于"字段全为空串"，
        而这些端点根本不读 body，所以两者行为一致。
        """
        url = f"{self.issuer}{path}"
        try:
            resp = self._http.request(
                method, url, json=json_body if json_body is not None else {}, timeout=self.timeout
            )
        except requests.RequestException as e:  # 连接失败、超时、DNS
            raise TransportError(f"{method} {path} 请求失败：{e}") from e

        # 先试着解析响应体，再决定按哪种失败处理 —— 这个顺序很重要。
        #
        # 后端对 401/409/410 返回的是**业务失败信封**（{code:1,error,message}），
        # 它们是安全自检要读的东西：例如"攻击者无 qr_ctx 领取被拒"的判定
        # 依据就是 reason == 'qr_not_ready'。若按 HTTP 状态先判失败，
        # 这些拒绝会被归成 TransportError，reason 丢失，
        # 于是"服务端正确拒绝了攻击"和"服务压根没应答"看起来一模一样 ——
        # 那等于把这套检查最要紧的结论给抹平了。
        body: Any = None
        if resp.text:
            try:
                body = resp.json()
            except ValueError:
                body = None

        if not resp.ok:
            if isinstance(body, dict) and ("code" in body or "error" in body):
                reason = str(body.get("error") or "")
                msg = str(body.get("message") or body.get("error_description") or reason or "请求失败")
                raise ApiError(f"{method} {path} → HTTP {resp.status_code}: {msg}", reason=reason, status=resp.status_code)
            # 没有可解析的失败信封（网关 HTML 错误页等）：确实无从判断后端意图
            raise TransportError(f"{method} {path} → HTTP {resp.status_code}: {resp.text[:200]}")

        if body is None:
            raise TransportError(f"{method} {path} 响应不是 JSON：{resp.text[:200]}")
        if not isinstance(body, dict):
            raise TransportError(f"{method} {path} 响应不是对象：{body!r}")

        if "code" in body and body["code"] != 0:
            raise ApiError(
                str(body.get("message") or body.get("error") or "请求失败"),
                reason=str(body.get("error") or ""),
                status=resp.status_code,
            )
        if "error" in body and body["error"]:
            # 少数端点（userinfo/consent）返回裸协议错，没有 code 字段
            raise ApiError(
                str(body.get("error_description") or body["error"]),
                reason=str(body["error"]),
                status=resp.status_code,
            )
        return body

    def _data(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        body = self._call(method, path, **kw)
        data = body.get("data")
        return data if isinstance(data, dict) else body

    # ── 扫码端点：PC 侧 ──────────────────────────────────────────────────

    def qr_create(self) -> QRSession:
        d = self._data("POST", "/api/qr/sessions")
        return QRSession(
            ticket=str(d["ticket"]),
            qr_content=str(d["qr_content"]),
            expires_in=int(d.get("expires_in", 120)),
            interval_ms=int(d.get("interval_ms", 1500)),
        )

    def qr_poll(self, ticket: str) -> str:
        """查状态。返回 status 字符串。"""
        d = self._data("GET", f"/api/qr/sessions/{quote(ticket)}")
        return str(d["status"])

    def qr_claim(self, ticket: str) -> dict[str, Any]:
        return self._data("POST", f"/api/qr/sessions/{quote(ticket)}/claim")

    def qr_cancel(self, ticket: str) -> None:
        self._data("POST", f"/api/qr/sessions/{quote(ticket)}/cancel")

    # ── 扫码端点：手机侧（需身份）────────────────────────────────────────

    def qr_preview(self, ticket: str) -> dict[str, Any]:
        return self._data("GET", f"/api/qr/sessions/{quote(ticket)}/preview")

    def qr_scan(self, ticket: str) -> None:
        self._data("POST", f"/api/qr/sessions/{quote(ticket)}/scan")

    def qr_confirm(self, ticket: str) -> None:
        self._data("POST", f"/api/qr/sessions/{quote(ticket)}/confirm")

    def qr_refuse(self, ticket: str) -> None:
        self._data("POST", f"/api/qr/sessions/{quote(ticket)}/refuse")

    # ── 身份 ────────────────────────────────────────────────────────────

    def login(self, username: str = SEED_USERNAME, password: str = SEED_PASSWORD) -> dict[str, Any]:
        """口令登录，拿到 idp_session。手机端在批准扫码之前必须先有这一步。"""
        return self._data("POST", "/api/login", json_body={"username": username, "password": password, "return_to": ""})

    def me(self) -> dict[str, Any] | None:
        """当前会话对应的用户；未登录时后端返回 data=null（不是错误）。

        这里**不能**走 _data()：那条路径在 data 缺失或为 null 时会回吐整个信封
        （为了兼容 /api/consent 那类裸对象响应）。对 me() 而言那正是致命的 ——
        {code:0, data:null} 会被当成"有登录态"，于是"还没登录"被读成"已经登录"，
        后续所有依赖这个判断的流程（手机端要不要先登录）全部走偏，
        而且报错会出现在离根因很远的位置（preview 401）。
        """
        body = self._call("GET", "/api/me")
        data = body.get("data")
        return data if isinstance(data, dict) and data else None

    def logout(self) -> None:
        self._data("POST", "/api/logout", json_body={"post_logout_redirect_uri": "", "state": ""})

    # ── 探测辅助（自检用）────────────────────────────────────────────────

    def poll_status_raw(self, ticket: str) -> str:
        """与 qr_poll 相同，但把传输失败也归一成一个状态串。

        自检里"拿不到状态"和"状态是 expired"要同等对待：都意味着这张票不能再用了。
        """
        try:
            return self.qr_poll(ticket)
        except (ApiError, TransportError):
            return "unknown"


# ── 工具 ────────────────────────────────────────────────────────────────────


def quote(s: str) -> str:
    """路径段转义。ticket 是 base64url，本身安全，但拼接一律走转义：
    今天安全不代表改了生成规则之后还安全。"""
    from urllib.parse import quote as _q

    return _q(s, safe="")


def ticket_of(scan_url: str) -> str:
    """从二维码内容（形如 {issuer}/scan?t=qrt_xxx）里取出 ticket。

    解析失败抛异常而不是返回空串：二维码内容是这个功能的**跨界契约**，
    它一旦不合约定，手机端根本无从工作，这里静默返回空串只会让后面的
    失败变得无法解释。
    """
    q = parse_qs(urlparse(scan_url).query)
    vals = q.get("t") or []
    if not vals:
        raise ValueError(f"二维码内容里没有 t 参数，无法解析出 ticket：{scan_url!r}")
    return vals[0]


def sleep(ms: float) -> None:
    time.sleep(ms / 1000.0)


__all__ = ["Device", "QRSession", "ApiError", "TransportError", "ticket_of", "SEED_USERNAME", "SEED_PASSWORD"]
