<script setup>
// defineProps({
//   type: {
//     type: String,
//     default: 'text',
//     validator: value => ['text', 'password', 'email'].includes(value)
//   },
//   placeholder: {
//     type: String,
//     default: ''
//   },
//   modelValue: {
//     type: String,
//     default: ''
//   }
// })
</script>

<template>
  <input v-model="form.password"
         :type="type"
         :placeholder="placeholder"
         :value="modelValue"
         @input="$emit('update:modelValue', $event.target.value)"
         required
  />
</template>

<style scoped>

</style>