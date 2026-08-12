interface Window {
  __mswStarted?: boolean
  __mswSetHealth?: (status: number, body: string) => Promise<void>
  __refetchHealth?: () => Promise<void>
}
