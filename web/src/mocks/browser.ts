import { setupWorker } from 'msw/browser'
import { http, HttpResponse } from 'msw'
import { handlers } from './handlers'

export const worker = setupWorker(...handlers)

export async function setHealth(status: number, body: string): Promise<void> {
  worker.use(http.get('*/healthz', () => new HttpResponse(body, { status })))
}

export function invalidateHealth(): Promise<void> {
  return import('../lib/queryClient').then(({ queryClient }) =>
    queryClient.invalidateQueries({ queryKey: ['health'] }),
  )
}
