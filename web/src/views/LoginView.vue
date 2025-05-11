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
  <div class="login-container">
    <h2>Авторизация</h2>
    <div class="form-container">

    </div>
    <form @submit.prevent="handleLogin" class="login-form">

      <input v-model="form.email" type="text" id="email" name="email" placeholder="mail@mail.ru" required/>

      <input v-model="form.password" type="password" id="password" name="password" placeholder="your-password" required/>

      <router-link to="/reset-password" class="forgot-link">Forgot password?</router-link>
      <p class="register-link">Not a Member? <router-link to="/register" class="forgot-link">Create an account</router-link></p>

      <button type="submit" class>Sign In</button>
    </form>
  </div>
</template>

<style scoped>
* {
  color: white;
}

.login-container {
  display: flex;
  flex-direction: column;
  background: linear-gradient(135deg, #1f1f1f, #3a3a3a);
  width: 100%;
  height: 100vh;
  padding-top: 230px;
  margin: auto 0;
}

.form-container {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}

.login-form {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  width: 100%;
}

.login-form input {
  margin: 5px auto;
  padding: 14px;
  background-color: #1e1e1e;
  border: 1px solid #2c2c2c;
  border-radius: 10px;
  color: #fff;
  font-size: 14px;
  outline: none;
  transition: border 0.2s;
  width: 100%;
  max-width: 300px;
}

.login-form button {
  margin-top: 10px;
  padding: 14px;
  background: linear-gradient(90deg, #5f9df7, #3a74d9);
  border: none;
  border-radius: 10px;
  color: white;
  font-weight: bold;
  font-size: 16px;
  cursor: pointer;
  transition: opacity 0.2s;
  width: 100%;
  max-width: 300px;
}

.login-form button:hover {
  opacity: 0.9;
}

.forgot-link,
.register-link {
  font-size: 13px;
  color: #b0b0b0;
  margin-top: 10px;
  text-align: center;
}

.register-link a,
.forgot-link {
  color: #a0c4ff;
  text-decoration: none;
}

.register-link a:hover,
.forgot-link:hover {
  text-decoration: underline;
}
</style>