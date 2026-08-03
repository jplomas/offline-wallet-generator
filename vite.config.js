import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { viteSingleFile } from 'vite-plugin-singlefile'

const pkg = JSON.parse(readFileSync(resolve('package.json'), 'utf8'))

function resolveCommit() {
  if (process.env.COMMIT_REF) return process.env.COMMIT_REF.slice(0, 12)
  try {
    return execSync('git rev-parse --short=12 HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim()
  } catch {
    return 'unknown'
  }
}

const buildId = `${pkg.version}+${resolveCommit()}`

function inlinePublicAssets() {
  return {
    name: 'inline-public-assets',
    enforce: 'post',
    transformIndexHtml(html) {
      const qrllib = readFileSync(resolve('public/qrllib.js'), 'utf8')
      const favicon = readFileSync(resolve('public/favicon.ico')).toString('base64')
      return html
        .replace(/<script src="\.\/qrllib\.js"><\/script>/, () => `<script>${qrllib}</script>`)
        .replace(/href="\.\/favicon\.ico"/, `href="data:image/x-icon;base64,${favicon}"`)
    },
  }
}

function inlinePublicImports() {
  const id = '\0offline-logo-svg'
  return {
    name: 'inline-public-imports',
    resolveId(source) {
      if (source === '/logo.svg?raw') return id
    },
    load(source) {
      if (source === id) return `export default ${JSON.stringify(readFileSync(resolve('public/logo.svg'), 'utf8'))}`
    },
  }
}

export default defineConfig(({ mode }) => {
  const offline = mode === 'offline'
  return {
    base: './',
    publicDir: offline ? false : 'public',
    plugins: [...(offline ? [inlinePublicImports()] : []), vue(), ...(offline ? [viteSingleFile(), inlinePublicAssets()] : [])],
    resolve: { alias: { '@': resolve('src'), buffer: 'buffer' } },
    define: {
      global: 'globalThis',
      __APP_VERSION__: JSON.stringify(pkg.version),
      __APP_BUILD_ID__: JSON.stringify(buildId),
      __OFFLINE_BUILD__: JSON.stringify(offline),
    },
    optimizeDeps: { include: ['buffer'] },
    build: {
      outDir: offline ? 'dist-offline' : 'dist',
      assetsInlineLimit: offline ? Number.MAX_SAFE_INTEGER : 4096,
      cssCodeSplit: !offline,
      rollupOptions: offline ? { output: { inlineDynamicImports: true } } : {},
    },
  }
})
