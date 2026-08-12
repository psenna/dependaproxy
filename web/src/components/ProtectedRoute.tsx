import { Navigate, useLocation } from 'react-router-dom'
import { getToken } from '../lib/storage'
import Layout from './Layout'

export default function ProtectedRoute() {
  const location = useLocation()
  if (!getToken()) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }
  return <Layout />
}
