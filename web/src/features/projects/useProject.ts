import { useQuery } from '@tanstack/react-query'
import { getProject } from '../../lib/api'
import { PROJECTS_QUERY_KEY } from './useProjects'

export function useProject(key: string) {
  return useQuery({
    queryKey: [...PROJECTS_QUERY_KEY, 'detail', key],
    queryFn: () => getProject(key),
    enabled: key !== '',
    retry: 1,
    staleTime: 30_000,
  })
}
