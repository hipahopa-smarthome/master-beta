<script setup>
import {ref, watch} from 'vue'
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

const errors = ref({
  email: '',
  password: '',
  form: ''
})

const handleLogin = async () => {
  errors.value = {
    email: '',
    password: '',
    form: ''
  }

  if (!form.value.email) {
    errors.value.email = 'Введите email'
  }
  if (!form.value.password) {
    errors.value.password = 'Введите пароль'
  }
  if (errors.value.email || errors.value.password) {
    return
  }

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
      if (response.status === 401) {
        errors.value.form = 'Неверная почта или пароль'
      } else {
        errors.value.form = 'Неизвестная ошибка'
        console.error(response)
      }
      return
    }

    const data = await response.json()

    const redirect_url = data['redirect_url']
    if (redirect_url) {
      window.location.href = redirect_url
    } else {
      await router.push('/')
    }
  } catch (error) {
    console.error('Error:', error)
    errors.value.form = 'Ошибка соединения с сервером'
  }
}

watch(() => form.value.email, (newVal) => {
  if (!newVal) {
    errors.value.email = 'Введите email'
  } else if (!/^\S+@\S+\.\S+$/.test(newVal)) {
    errors.value.email = 'Некорректный email'
  } else {
    errors.value.email = ''
  }
})

watch(() => form.value.password, (newVal) => {
  if (!newVal) {
    errors.value.password = 'Введите пароль'
  } else if (newVal.length < 8) {
    errors.value.password = 'Минимум 8 символов'
  } else {
    errors.value.password = ''
  }
})
</script>

<template>
  <div class="login-container">
    <h2>Авторизация</h2>
    <div class="form-container">

    </div>
    <form @submit.prevent="handleLogin" class="login-form">

      <input v-model="form.email"
             :class="{'input-error': errors.email || errors.form}"
             type="text"
             id="email"
             name="email"
             placeholder="mail@mail.ru"
             required/>
      <span v-if="errors.email" class="error-text">{{ errors.email }}</span>


      <input v-model="form.password"
             :class="{'input-error': errors.password || errors.form}"
             type="password"
             id="password"
             name="password"
             placeholder="password"
             required/>
      <span v-if="errors.password" class="error-text">{{ errors.password }}</span>

      <router-link to="/reset-password" class="forgot-link">Забыли пароль?</router-link>
      <p class="register-link">Нет аккаунта?
        <router-link to="/register" class="forgot-link">Зарегистрироваться</router-link>
      </p>

      <button type="submit" class>Войти</button>

      <span v-if="errors.form" class="error-text">{{ errors.form }}</span>
    </form>
  </div>
</template>

<style scoped>
* {
  color: white;
}

.input-error {
  border: 1px solid #ff4d4f !important;
}

.error-text {
  color: #ff4d4f;
  font-size: 12px;
  max-width: 300px;
  margin-top: 4px;
  width: 100%;
  text-align: center;
}

.login-container {
  display: flex;
  flex-direction: column;
  width: 100%;
  height: calc(100vh - 230px);
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