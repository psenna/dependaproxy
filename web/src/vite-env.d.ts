/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string
}

interface Window {
  __mswStarted?: boolean
  __mswSetHealth?: (status: number, body: string) => Promise<void>
  __refetchHealth?: () => Promise<void>
}
