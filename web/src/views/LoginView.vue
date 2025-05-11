<script setup>
import {ref} from 'vue'
import {useRoute, useRouter} from 'vue-router'

const router = useRouter()
const route = useRoute()

const baseUrl = 'https://api.smarthome.hipahopa.ru'

const queryParams = route.query
const decodedParams = {
  state: decodeURIComponent(queryParams.state || ''),
  scope: decodeURIComponent(queryParams.scope || ''),
  redirect_uri: decodeURIComponent(queryParams.redirect_uri || ''),
  response_type: queryParams.response_type || '',
  client_id: queryParams.client_id || ''
}

const form = ref({
  email: '',
  password: ''
})

const handleLogin = async () => {
  let apiUrl = `${baseUrl}/auth/login`

  if (
      decodedParams['state'] &&
      decodedParams['redirect_uri'] &&
      decodedParams['response_type'] &&
      decodedParams['client_id']
  ) {
    const params = new URLSearchParams({
      'smart-home': 'true',
      state: decodedParams['state'],
      scope: decodedParams['scope'],
      client_id: decodedParams['client_id']
    }).toString()

    apiUrl = `${baseUrl}/auth/login?${params}`
  }

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: form.value.email,
        password: form.value.password
      })
    })

    if (!response.ok) {
      throw new Error('Login failed')
    }

    const data = await response.json()

    const redirect_url = data['redirect_url']
    if (redirect_url) {
      window.location.href = redirect_url
    } else {
      router.push('/')
    }
  } catch (error) {
    console.error('Error:', error)
    alert('Login failed. Please check your credentials.')
  }
}
</script>

<template>
  <h2>Login</h2>
  <form @submit.prevent="handleLogin">
    <label for="email">Email: </label>
    <input v-model="form.email" type="text" id="email" name="email" required/><br/><br/>

    <label for="password">Password: </label>
    <input v-model="form.password" type="password" id="password" name="password" required/><br/><br/>

    <button type="submit">Sign In</button>
  </form>
</template>

<style scoped>

</style>