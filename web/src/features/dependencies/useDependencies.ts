import { useQuery } from '@tanstack/react-query'
import { getDependencies } from '../../lib/api'
import { ApiError } from '../../lib/types'

export const DEPENDENCIES_QUERY_KEY = (key: string, registry: string, pkg: string) =>
  ['projects', 'detail', key, 'dependencies', { registry, pkg }] as const

export interface DependenciesFilters {
  registry?: string
  pkg?: string
}

export function useDependencies(key: string, filters: DependenciesFilters = {}) {
  const registry = filters.registry?.trim() ?? ''
  const pkg = filters.pkg?.trim() ?? ''
  return useQuery({
    queryKey: DEPENDENCIES_QUERY_KEY(key, registry, pkg),
    queryFn: async () => {
      try {
        return await getDependencies(key, { registry: registry || undefined, pkg: pkg || undefined })
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) return { dependencies: [] } // empty, not error
        throw err
      }
    },
    enabled: key !== '',
    retry: 1,
    staleTime: 30_000,
  })
}
