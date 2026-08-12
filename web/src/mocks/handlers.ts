import { createAdminHandlers, defaultFixtures, healthzHandler, type Fixtures } from '../test/handlers'

// The e2e worker starts with a fresh fixture on every page load. my-app is
// deliberately configured with only a validation chain so the edit flow can
// exercise toggling an override on (retrieval starts unchecked).
const e2eFixtures: Fixtures = {
  ...defaultFixtures,
  projects: [
    {
      key: 'my-app',
      registries: {
        npm: {
          validation: [{ type: 'allowlist', params: { packages: ['react'] } }],
        },
      },
    },
    {
      key: 'empty-app',
      registries: {
        npm: {
          validation: [],
        },
      },
    },
  ],
}

export const handlers = [healthzHandler, ...createAdminHandlers(e2eFixtures)]
