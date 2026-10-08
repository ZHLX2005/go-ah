import { defineConfig, devices } from '@playwright/test'
import { existsSync } from 'node:fs'

/**
 * Playwright 配置
 *
 * 前置条件：IDP(127.0.0.1:8080) 与业务平台(127.0.0.1:8081) 已启动。
 * 若未启动，请先执行 README 中的「一键启动」。
 *
 * 浏览器：默认使用 Playwright 自带下载的 Chromium。
 * 若环境已缓存其它版本的 Chromium（离线/内网场景），
 * 可通过 CHROMIUM_PATH 环境变量显式指定可执行文件：
 *   CHROMIUM_PATH=/path/to/chrome npx playwright test
 */

// 允许通过环境变量复用已缓存的 Chromium，避免重复下载
const executablePath = process.env.CHROMIUM_PATH || undefined

// 若指定路径不存在则忽略，回落到 Playwright 默认解析逻辑
const resolvedExecutablePath =
  executablePath && existsSync(executablePath) ? executablePath : undefined

export default defineConfig({
  testDir: './tests',
  // 端到端流程涉及多次跳转，给足超时
  timeout: 60_000,
  expect: { timeout: 10_000 },
  // 流程有状态（会话/cookie/令牌），串行执行避免互相干扰
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],
  use: {
    baseURL: 'http://127.0.0.1:8081',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    // 忽略本地自签/HTTP 限制
    ignoreHTTPSErrors: true,
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: resolvedExecutablePath
          ? { executablePath: resolvedExecutablePath }
          : {},
      },
    },
  ],
  outputDir: 'test-results',
})

