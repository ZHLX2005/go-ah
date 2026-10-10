import { StrictMode, Suspense, lazy } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { ToastProvider, Loading } from '@/ui'
import AdminLayout from '@/layout/AdminLayout'
import LoginPage from '@/pages/Login'
import RegisterPage from '@/pages/Register'
import ConsentPage from '@/pages/Consent'
import LogoutPage from '@/pages/Logout'
import ScanPage from '@/pages/Scan'
import './app.css'

// 管理台面板按需加载：认证页（登录/注册/授权/登出）是终端用户唯一会碰到的
// 界面，首屏必须快；管理台只有管理员进，没必要拖累前者。
const AdminUsers = lazy(() => import('@/pages/admin/Users'))
const AdminInvites = lazy(() => import('@/pages/admin/Invites'))
const AdminClients = lazy(() => import('@/pages/admin/Clients'))
const AdminTokens = lazy(() => import('@/pages/admin/Tokens'))

const host = document.getElementById('root')
if (host == null) throw new Error('缺少 #root 挂载点')

createRoot(host).render(
  <StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <Routes>
          {/* ── IDP 认证页面（终端用户会看到的几个）── */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/consent" element={<ConsentPage />} />
          <Route path="/logout" element={<LogoutPage />} />
          {/*
            手机扫码确认页。这条路由的名字被后端写死在二维码内容里
            （auth-hub/internal/controller/qr 的 scanPagePath），
            两边必须一致 —— 改这里要同时改那边，否则扫出来是 404。

            它也必须留在 SPA 路由里而不是"由 App 独占"：Universal Link 命中时
            系统直接唤起 App，压根不会请求到这个 URL；只有没装 App 或深链失败，
            浏览器才会来取这里 —— 这正是它存在的目的。
          */}
          <Route path="/scan" element={<ScanPage />} />

          {/* ── 管理后台：需全局会话 + users.is_admin，门控在 AdminLayout 里 ── */}
          <Route path="/admin" element={<AdminLayout />}>
            <Route index element={<Navigate to="/admin/users" replace />} />
            <Route
              path="users"
              element={
                <Suspense fallback={<Loading />}>
                  <AdminUsers />
                </Suspense>
              }
            />
            <Route
              path="invites"
              element={
                <Suspense fallback={<Loading />}>
                  <AdminInvites />
                </Suspense>
              }
            />
            <Route
              path="clients"
              element={
                <Suspense fallback={<Loading />}>
                  <AdminClients />
                </Suspense>
              }
            />
            <Route
              path="tokens"
              element={
                <Suspense fallback={<Loading />}>
                  <AdminTokens />
                </Suspense>
              }
            />
          </Route>

          {/* 根路径进管理台；其余未知路径回登录页 ——
              本平台不是内容站点，用户走错路时最可能的意图就是「我要登录」 */}
          <Route path="/" element={<Navigate to="/admin" replace />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>,
)
