import { createAdminHandlers, healthzHandler } from '../test/handlers'

export const handlers = [healthzHandler, ...createAdminHandlers()]
