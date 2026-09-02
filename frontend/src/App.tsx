import { Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { ProtectedRoute } from './components/ProtectedRoute'
import { AlertQueue } from './pages/AlertQueue'
import { AssetManagement } from './pages/AssetManagement'
import { Login } from './pages/Login'
import { ResponseLog } from './pages/ResponseLog'

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <Layout>
              <Routes>
                <Route path="/" element={<Navigate to="/alerts" replace />} />
                <Route path="/alerts" element={<AlertQueue />} />
                <Route path="/response-actions" element={<ResponseLog />} />
                <Route path="/assets" element={<AssetManagement />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}

export default App
