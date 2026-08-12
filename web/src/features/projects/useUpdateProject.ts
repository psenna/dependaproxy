import { useMutation, useQueryClient } from '@tanstack/react-query'
import { updateProject } from '../../lib/api'
import type { RegistryConfig } from '../../lib/types'
import { PROJECTS_QUERY_KEY } from './useProjects'

export function useUpdateProject(key: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (registries: Record<string, RegistryConfig>) => updateProject(key, { registries }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: PROJECTS_QUERY_KEY })
    },
  })
}
