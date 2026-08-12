import { useQuery } from '@tanstack/react-query'
import { listProjects } from '../../lib/api'

export const PROJECTS_QUERY_KEY = ['projects'] as const

export function useProjects() {
  return useQuery({
    queryKey: PROJECTS_QUERY_KEY,
    queryFn: () => listProjects(),
    retry: 1,
    staleTime: 30_000,
  })
}
