<script>
</script>

<template>
  <div id="app">
    <!-- This is where Vue Router injects the current page component -->
    <router-view/>
  </div>
</template>


<style>
#app {
  display: flex;
  flex-direction: column;
  margin: 0;
  padding: 0;

  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
}

body {
  margin: 0;
}
</style>
