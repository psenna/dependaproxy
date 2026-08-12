import { Route, Routes } from 'react-router-dom'
import ProtectedRoute from './components/ProtectedRoute'
import DashboardPage from './pages/DashboardPage'
import LoginPage from './pages/LoginPage'
import NotFoundPage from './pages/NotFoundPage'
import PlaceholderPage from './pages/PlaceholderPage'

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/projects" element={<PlaceholderPage title="Projects" />} />
        <Route path="/projects/new" element={<PlaceholderPage title="New project" />} />
        <Route path="/projects/:key" element={<PlaceholderPage title="Project detail" />} />
        <Route path="/projects/:key/edit" element={<PlaceholderPage title="Edit project" />} />
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}
