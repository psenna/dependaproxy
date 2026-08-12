import { useQuery } from '@tanstack/react-query'
import { getHealth } from '../../lib/api'

export const HEALTH_QUERY_KEY = ['health'] as const
export const HEALTH_POLL_MS = 10_000

export function useHealth() {
  return useQuery({
    queryKey: HEALTH_QUERY_KEY,
    queryFn: () => getHealth(),
    refetchInterval: HEALTH_POLL_MS,
    refetchIntervalInBackground: false,
    retry: 1,
    staleTime: 0,
  })
}
