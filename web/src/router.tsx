import { Route, Routes } from 'react-router-dom'
import ProtectedRoute from './components/ProtectedRoute'
import DashboardPage from './pages/DashboardPage'
import LoginPage from './pages/LoginPage'
import NotFoundPage from './pages/NotFoundPage'
import ProjectCreatePage from './pages/ProjectCreatePage'
import ProjectDetailPage from './pages/ProjectDetailPage'
import ProjectEditPage from './pages/ProjectEditPage'
import ProjectsListPage from './pages/ProjectsListPage'

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/projects" element={<ProjectsListPage />} />
        <Route path="/projects/new" element={<ProjectCreatePage />} />
        <Route path="/projects/:key" element={<ProjectDetailPage />} />
        <Route path="/projects/:key/edit" element={<ProjectEditPage />} />
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}
