export const IN_DEVELOPMENT_EVENT = 'fvra:in-development'

export function showInDevelopment() {
  window.dispatchEvent(new CustomEvent(IN_DEVELOPMENT_EVENT, { detail: 'In development' }))
}
