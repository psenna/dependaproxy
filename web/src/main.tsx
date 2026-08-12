import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import ErrorBoundary from './components/ErrorBoundary'
import { queryClient } from './lib/queryClient'
import './index.css'

async function enableMocks() {
  if (import.meta.env.MODE !== 'e2e') return
  const { worker, setHealth, invalidateHealth } = await import('./mocks/browser')
  await worker.start({ onUnhandledRequest: 'bypass' })
  window.__mswStarted = true
  window.__mswSetHealth = setHealth
  window.__refetchHealth = invalidateHealth
}

enableMocks().finally(() => {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ErrorBoundary>
          <App />
        </ErrorBoundary>
      </QueryClientProvider>
    </StrictMode>,
  )
})
