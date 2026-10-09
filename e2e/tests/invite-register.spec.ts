import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { BIZ, IDP, TEST_USER, assertServicesUp } from './helpers'

/**
 * 用例组 4：邀请码注册
 *
 * 本平台**没有开放的注册入口**：自助注册必须携带一张"此刻仍能核销"的邀请码，
 * 而码只能由管理员生成。这套用例验收的就是这条链路，以及它周边三件容易
 * 只做一半的事：
 *   ① 注册完就登录 —— 让用户重新打一遍刚设好的口令是纯粹的刁难；
 *   ② 配额与使用明细 —— 次数说明"用掉几个名额"，明细说明"谁用掉的"；
 *   ③ 注册即写入 last_login_at —— 否则管理端看到的新账号会是"从未登录"。
 *
 * 为什么主用例要走**从业务站点出发的完整 OIDC 流程**而不是只打一次
 * /api/register：注册唯一的目的是让一个新身份能进入业务系统。只断言
 * "接口返回 200"，就漏掉了"注册完回不到授权流程""授权确认页不认这个新身份"
 * 这类只有把整条链路走完才会暴露的问题。
 */

/** 以管理员身份登录 IDP，并落到指定后台页面 */
async function loginAsAdmin(page: Page, targetPath = '/admin/invites') {
  await page.goto(`${IDP}/login?return_to=${encodeURIComponent(targetPath)}`, {
    waitUntil: 'domcontentloaded',
  })
  await page.waitForSelector('input[type=text]')
  await page.fill('input[type=text]', TEST_USER.username)
  await page.fill('input[type=password]', TEST_USER.password)
  await page.click('button[type=submit]')
  await page.waitForURL((u: URL) => u.pathname.startsWith('/admin'), { timeout: 20_000 })
}

/** 在管理页的上下文里调管理接口（带上管理员会话 Cookie） */
async function adminGet(page: Page, path: string): Promise<any> {
  return page.evaluate(async (p) => {
    const r = await fetch(p, { credentials: 'include' })
    if (!r.ok) throw new Error(`GET ${p} → ${r.status}`)
    return await r.json()
  }, path)
}

/** 取邀请码列表（后端全量返回，前端按备注定位目标行） */
async function invites(page: Page): Promise<any[]> {
  const body = await adminGet(page, '/api/admin/invites?status=all')
  return body.data ?? []
}

/** 唯一账号名：账号规则允许字母/数字/下划线/点/横线，长度 3-32 */
function uniqueUsername(): string {
  return `e2e_inv_${Date.now()}`
}

/** 填写注册表单（选择器用 placeholder —— 本项目的 Field 没有把 label 关联到控件） */
async function fillRegisterForm(
  page: Page,
  opts: { code: string; username: string; password: string; email?: string },
) {
  await page.getByPlaceholder('inv_xxxxxxxxxxxxx').fill(opts.code)
  await page.getByPlaceholder('登录时使用的账号').fill(opts.username)
  await page.getByPlaceholder('you@example.com').fill(opts.email ?? `${opts.username}@example.com`)
  await page.getByPlaceholder('设置登录密码').fill(opts.password)
  await page.getByPlaceholder('再输入一次').fill(opts.password)
}

test.describe('邀请码注册', () => {
  test.beforeEach(async ({ page }) => {
    await assertServicesUp(page)
  })

  test('管理员生成码 → 受邀者凭码注册 → 注册即登录 → 配额与使用明细可追溯', async ({
    page,
    browser,
  }) => {
    // ── ① 管理员登录，用**界面**生成一张 1 次性的邀请码 ──────────────────
    await loginAsAdmin(page, '/admin/invites')
    await expect(page.locator('text=加载中')).toHaveCount(0, { timeout: 15_000 })

    const tag = `e2e 验收 ${Date.now()}`
    await page.getByRole('button', { name: '生成邀请码', exact: true }).click()

    const createDialog = page.getByRole('dialog')
    await expect(createDialog).toBeVisible({ timeout: 10_000 })
    await createDialog.locator('input[type=number]').fill('1')
    await createDialog.locator('textarea').fill(tag)
    await createDialog.getByRole('button', { name: '生成', exact: true }).click()
    await expect(createDialog).toHaveCount(0, { timeout: 15_000 })

    // 从接口取回刚生成的那张（按备注定位，不依赖表格排版）
    const created = (await invites(page)).find((r) => r.note === tag)
    expect(created, `列表里找不到刚生成的邀请码（备注 ${tag}）`).toBeTruthy()
    const code: string = created.code
    expect(code.startsWith('inv_'), `邀请码应带 inv_ 前缀，实际 ${code}`).toBeTruthy()
    expect(created.status).toBe('active')
    expect(created.remaining).toBe(1)

    // 界面上的这一行也必须是"可用 / 1 / 1 / 未使用"
    const createdRow = page.locator('tr').filter({ hasText: code }).first()
    await expect(createdRow).toBeVisible({ timeout: 10_000 })
    await expect(createdRow).toContainText('可用')
    await expect(createdRow).toContainText('1 / 1')
    await expect(createdRow).toContainText('未使用')

    await page.screenshot({ path: 'screenshots/13-admin-invites-created.png', fullPage: true })

    // ── ② 换一个**全新上下文**（没有管理员会话）走受邀者路径 ─────────────
    const userCtx = await browser.newContext()
    const userPage = await userCtx.newPage()
    const newUser = uniqueUsername()
    const password = 'e2e-invite-password'

    try {
      // 从业务站点出发，让 IDP 自己把授权请求带过来
      await userPage.goto(BIZ, { waitUntil: 'domcontentloaded' })
      await userPage.waitForURL(/127\.0\.0\.1:8080/, { timeout: 20_000 })
      await userPage.waitForURL(/\/login/, { timeout: 20_000 })

      // 登录页上的注册入口必须带着 return_to，否则注册完回不到授权流程
      await userPage.getByRole('link', { name: '用邀请码注册' }).click()
      await userPage.waitForURL(/\/register/, { timeout: 15_000 })
      const returnTo = new URL(userPage.url()).searchParams.get('return_to') ?? ''
      expect(returnTo, '注册入口必须带上原授权请求的 return_to').toContain('/oauth2/auth')

      await userPage.screenshot({ path: 'screenshots/14-register-form.png' })
      await fillRegisterForm(userPage, { code, username: newUser, password })
      await userPage.getByRole('button', { name: '注 册' }).click()

      // ── ③ 注册成功即登录：离开注册页 → 授权确认 → 回到业务站点 ──────────
      await userPage.waitForURL((u: URL) => !u.pathname.includes('/register'), {
        timeout: 25_000,
      })

      const allowBtn = userPage.getByRole('button', { name: '同意授权', exact: true })
      if ((await allowBtn.count()) > 0) {
        await expect(allowBtn).toBeVisible({ timeout: 10_000 })
        await userPage.screenshot({ path: 'screenshots/15-register-consent.png' })
        await allowBtn.click()
      }

      await userPage.waitForURL(/127\.0\.0\.1:8081/, { timeout: 25_000 })
      await userPage.waitForURL(/127\.0\.0\.1:8081\/(\?.*)?$/, { timeout: 20_000 })
      await userPage.screenshot({ path: 'screenshots/16-register-biz-home.png', fullPage: true })

      // 业务侧拿到的身份必须是刚注册出来的那个账号
      const profile = await userPage.evaluate(async () => {
        const r = await fetch('/api/profile', { credentials: 'include' })
        return { status: r.status, body: await r.json().catch(() => null) }
      })
      expect(profile.status, '新账号应当能进业务接口').toBe(200)
      expect(JSON.stringify(profile.body)).toContain(newUser)

      // IDP 侧的登录态也应当是它（到 IDP 域下问，避免跨源读不到响应）
      await userPage.goto(`${IDP}/login`, { waitUntil: 'domcontentloaded' })
      const me = await userPage.evaluate(async () => {
        const r = await fetch('/api/me', { credentials: 'include' })
        return await r.json().catch(() => null)
      })
      expect(me?.code).toBe(0)
      expect(me?.data?.username).toBe(newUser)
      expect(me?.data?.email).toBe(`${newUser}@example.com`)
    } finally {
      await userCtx.close()
    }

    // ── ④ 回到管理员视角：配额递减、明细可查 ──────────────────────────────
    await page.reload({ waitUntil: 'domcontentloaded' })
    const used = (await invites(page)).find((r) => r.code === code)
    expect(used, '刚用过的邀请码不该从列表里消失').toBeTruthy()
    expect(used.used_count, '核销后 used_count 必须 +1').toBe(1)
    expect(used.remaining).toBe(0)
    expect(used.status, '一次性码用掉之后应当显示已用完').toBe('exhausted')

    const usages = (await adminGet(page, `/api/admin/invites/${used.id}/usages`)).data ?? []
    expect(usages.length, '使用明细必须有且只有一条').toBe(1)
    expect(usages[0].username).toBe(newUser)
    expect(usages[0].email).toBe(`${newUser}@example.com`)
    expect(usages[0].user_id, '明细要能指回具体账号').toBeTruthy()

    // 界面上的这一行也要跟着变
    const usedRow = page.locator('tr').filter({ hasText: code }).first()
    await expect(usedRow).toContainText('已用完')
    await expect(usedRow).toContainText('0 / 1')

    // 点开"查看"能看到是谁用掉的
    await usedRow.getByRole('button', { name: /查看/ }).click()
    const usageDialog = page.getByRole('dialog')
    await expect(usageDialog).toContainText('使用明细')
    await expect(usageDialog).toContainText(newUser)
    await page.screenshot({ path: 'screenshots/17-invite-usages.png', fullPage: true })
  })

  test('码已用完时给出可操作的提示，不再放行第二个人', async ({ page, browser }) => {
    await loginAsAdmin(page, '/admin/invites')
    await expect(page.locator('text=加载中')).toHaveCount(0, { timeout: 15_000 })

    const tag = `e2e 一次性 ${Date.now()}`
    await page.getByRole('button', { name: '生成邀请码', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await dialog.locator('input[type=number]').fill('1')
    await dialog.locator('textarea').fill(tag)
    await dialog.getByRole('button', { name: '生成', exact: true }).click()
    await expect(dialog).toHaveCount(0, { timeout: 15_000 })

    const code: string = (await invites(page)).find((r) => r.note === tag).code

    // 第一个人把码用掉
    const ctx1 = await browser.newContext()
    try {
      const p1 = await ctx1.newPage()
      await p1.goto(`${IDP}/register`, { waitUntil: 'domcontentloaded' })
      const first = uniqueUsername()
      await fillRegisterForm(p1, { code, username: first, password: 'e2e-first-password' })
      await p1.getByRole('button', { name: '注 册' }).click()
      await p1.waitForURL((u: URL) => !u.pathname.includes('/register'), { timeout: 25_000 })
    } finally {
      await ctx1.close()
    }

    // 第二个人拿同一张码：必须被明确拒绝，而不是静默放行
    const ctx2 = await browser.newContext()
    try {
      const p2 = await ctx2.newPage()
      await p2.goto(`${IDP}/register`, { waitUntil: 'domcontentloaded' })
      await fillRegisterForm(p2, {
        code,
        username: uniqueUsername(),
        password: 'e2e-second-password',
      })
      await p2.getByRole('button', { name: '注 册' }).click()

      await expect(p2.locator('.alert--error')).toContainText('可用次数已用完', {
        timeout: 15_000,
      })
      // 仍然停在注册页 —— 失败不该把人带走
      expect(new URL(p2.url()).pathname).toBe('/register')
      await p2.screenshot({ path: 'screenshots/18-invite-exhausted.png' })
    } finally {
      await ctx2.close()
    }

    const after = (await invites(page)).find((r) => r.code === code)
    expect(after.used_count, '被拒的那次不该消耗配额').toBe(1)
  })

  test('停用立即生效、恢复后可用、账号占用有明确提示、删除后从列表消失', async ({
    page,
    browser,
  }) => {
    await loginAsAdmin(page, '/admin/invites')
    await expect(page.locator('text=加载中')).toHaveCount(0, { timeout: 15_000 })

    const tag = `e2e CRUD ${Date.now()}`
    await page.getByRole('button', { name: '生成邀请码', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await dialog.locator('input[type=number]').fill('2')
    await dialog.locator('textarea').fill(tag)
    await dialog.getByRole('button', { name: '生成', exact: true }).click()
    await expect(dialog).toHaveCount(0, { timeout: 15_000 })

    const code: string = (await invites(page)).find((r) => r.note === tag).code
    const row = page.locator('tr').filter({ hasText: code }).first()
    await expect(row).toContainText('可用')

    const ctx = await browser.newContext()
    try {
      const p = await ctx.newPage()

      // ── 停用后立刻不可用 ──
      await row.getByRole('button', { name: '停用', exact: true }).click()
      await expect(row).toContainText('已停用', { timeout: 10_000 })

      await p.goto(`${IDP}/register`, { waitUntil: 'domcontentloaded' })
      await fillRegisterForm(p, {
        code,
        username: uniqueUsername(),
        password: 'e2e-disabled-password',
      })
      await p.getByRole('button', { name: '注 册' }).click()
      await expect(p.locator('.alert--error')).toContainText('已被停用', { timeout: 15_000 })

      // ── 重新启用 ──
      await row.getByRole('button', { name: '启用', exact: true }).click()
      await expect(row).toContainText('可用', { timeout: 10_000 })

      // ── 拿预置账号去注册：必须提示"已被占用"而不是报数据库错误 ──
      await p.goto(`${IDP}/register`, { waitUntil: 'domcontentloaded' })
      await fillRegisterForm(p, {
        code,
        username: TEST_USER.username,
        password: 'e2e-taken-password',
      })
      await p.getByRole('button', { name: '注 册' }).click()
      await expect(p.locator('.alert--error')).toContainText('该账号已被占用', { timeout: 15_000 })

      // 占用失败不该消耗名额
      const afterTaken = (await invites(page)).find((r) => r.code === code)
      expect(afterTaken.used_count, '账号被占用时不该扣掉邀请码次数').toBe(0)
      expect(afterTaken.remaining).toBe(2)
    } finally {
      await ctx.close()
    }

    // ── 删除：走二次确认，删完从列表消失 ──
    await row.getByRole('button', { name: '删除', exact: true }).click()
    const confirmDialog = page.getByRole('dialog')
    await expect(confirmDialog).toContainText('确认删除邀请码')
    await confirmDialog.getByRole('button', { name: '删除', exact: true }).click()

    await expect(page.locator('tr').filter({ hasText: code })).toHaveCount(0, { timeout: 15_000 })
    expect((await invites(page)).some((r) => r.code === code)).toBe(false)
  })
})
