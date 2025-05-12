import { baseUrl } from '@/composables/useAuth'

export const authService = {
    async login(payload, params) {
        const url = params
            ? `${baseUrl}/auth/login?${new URLSearchParams(params)}`
            : `${baseUrl}/auth/login`

        return fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
    },

    async register(payload) {
        return fetch(`${baseUrl}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
    }
}