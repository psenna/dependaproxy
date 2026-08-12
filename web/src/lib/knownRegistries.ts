export const DEFAULT_KNOWN_REGISTRIES = 'npm,pypi,maven,goproxy'

function parse(raw: string | undefined): string[] {
  const source = raw ?? DEFAULT_KNOWN_REGISTRIES
  return source
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '')
}

export const KNOWN_REGISTRIES: string[] = parse(import.meta.env.VITE_KNOWN_REGISTRIES)
