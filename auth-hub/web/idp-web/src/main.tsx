import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import LoginPage from './pages/LoginPage'
import ConsentPage from './pages/ConsentPage'
import LogoutPage from './pages/LogoutPage'
import AdminLayout from './pages/AdminLayout'
import AdminUsers from './pages/AdminUsers'
import AdminClients from './pages/AdminClients'
import AdminTokens from './pages/AdminTokens'
import './index.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        {/* IDP 认证页面 */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/consent" element={<ConsentPage />} />
        <Route path="/logout" element={<LogoutPage />} />

        {/* 管理后台（需全局会话 + is_admin） */}
        <Route path="/admin" element={<AdminLayout />}>
          <Route index element={<Navigate to="/admin/users" replace />} />
          <Route path="users" element={<AdminUsers />} />
          <Route path="clients" element={<AdminClients />} />
          <Route path="tokens" element={<AdminTokens />} />
        </Route>

        {/* 根路径兜底 */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
