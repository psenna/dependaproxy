import { useMutation, useQueryClient } from '@tanstack/react-query'
import { deleteProject } from '../../lib/api'
import { PROJECTS_QUERY_KEY } from './useProjects'

export function useDeleteProject() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (key: string) => deleteProject(key),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: PROJECTS_QUERY_KEY })
    },
  })
}
