<template>
  <!-- The mount target in index.html already carries id="app"; repeating it
       here produced two elements with the same id, which is invalid. -->
  <div class="min-h-screen flex flex-col">
    <nav class="navbar bg-neutral shadow-lg">
      <div class="navbar-start">
        <ul class="menu menu-horizontal px-1">
          <li>
            <router-link to="/" class="text-neutral-content hover:text-white" :class="{ 'bg-secondary text-white': $route.path === '/' }">Home</router-link>
          </li>
          <li>
            <router-link to="/docs" class="text-neutral-content hover:text-white" :class="{ 'bg-secondary text-white': $route.path === '/docs' }">Docs</router-link>
          </li>
          <li>
            <router-link to="/about" class="text-neutral-content hover:text-white" :class="{ 'bg-secondary text-white': $route.path === '/about' }">About</router-link>
          </li>
        </ul>
      </div>
      <div class="navbar-end pr-4">
        <span class="text-xs text-neutral-content/60">{{ buildId }}</span>
      </div>
    </nav>

    <main class="flex-grow">
      <router-view />
    </main>

    <div class="h-20 bg-base-300"></div>

    <footer class="footer footer-center p-4 bg-neutral text-neutral-content border-t border-black/40 shadow-[0_-5px_5px_-5px_rgba(0,0,0,0.22)]">
      <div class="flex flex-wrap items-center justify-center gap-4">
        <img class="h-14" :src="logoSvg" alt="QRL Logo">
        <div v-if="qrllibLoaded" class="text-left">
          <p class="text-sm text-neutral-content/80"><font-awesome-icon icon="check" class="text-success mr-1" />QRL Library loaded</p>
          <p class="text-xs text-neutral-content/60">qrllib v{{ qrllibVersion }}</p>
        </div>
        <div v-else-if="qrllibLoadFailed" class="text-left">
          <p class="text-sm text-error"><font-awesome-icon icon="triangle-exclamation" class="mr-1" />Failed to load QRL Library</p>
          <p class="text-xs text-neutral-content/60">Do not generate a wallet. Re-download and verify the file.</p>
        </div>
        <a v-if="!isOfflineBuild" class="link link-hover text-sm" href="https://offline-wallet-generator.theqrl.org" rel="noopener">Open deployed wallet</a>
        <a class="link link-hover text-sm" href="https://github.com/theQRL/offline-wallet-generator/releases/latest" rel="noopener">Download offline release</a>
      </div>
    </footer>
  </div>
</template>

<script>
import logoSvgRaw from '/logo.svg?raw';

export default {
  name: 'App',
  data() {
    return {
      qrllibLoaded: false,
      qrllibLoadFailed: false,
      logoSvg: `data:image/svg+xml;base64,${btoa(logoSvgRaw)}`,
      buildId: __APP_BUILD_ID__,
      qrllibVersion: __QRLLIB_VERSION__,
      isOfflineBuild: __OFFLINE_BUILD__,
    };
  },
  mounted() {
    // Exercise a known entry point rather than asserting success because the
    // component mounted. An indicator that cannot display a negative result
    // is not an indicator, and the docs tell users to rely on this one.
    try {
      const probe = QRLLIB.str2bin('qrl');
      this.qrllibLoaded = typeof probe?.size === 'function' && probe.size() === 3;
    } catch {
      this.qrllibLoaded = false;
    }
    this.qrllibLoadFailed = !this.qrllibLoaded;
  }
};
</script>

<style>
html {
  position: relative;
  min-height: 100%;
}
</style>
