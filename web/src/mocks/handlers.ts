import { http, HttpResponse } from 'msw'

export const handlers = [
  http.get('*/healthz', () => HttpResponse.text('ok', { status: 200 })),
]
