import './app.css';
import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import store from './store';
import { library } from '@fortawesome/fontawesome-svg-core';
import { faCheck, faTriangleExclamation } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome';
import { Buffer } from "buffer";

window.Buffer = Buffer;

library.add(faCheck, faTriangleExclamation);

const app = createApp(App)
  .use(router)
  .use(store)
  .component("font-awesome-icon", FontAwesomeIcon);

// Last-resort visible failure. If the app never mounts, nothing else in the
// bundle is in a position to tell the user why.
function renderStartupFailure(error) {
  const root = document.getElementById('app');
  if (!root) return;
  const heading = document.createElement('h1');
  heading.textContent = 'The wallet generator could not start';
  const detail = document.createElement('p');
  detail.textContent = error && error.message ? error.message : String(error);
  const advice = document.createElement('p');
  advice.textContent = 'Re-download the file and verify its checksum, and check that '
    + 'your browser supports WebAssembly. Do not generate a wallet with a copy that '
    + 'fails to load.';
  root.replaceChildren(heading, detail, advice);
  root.setAttribute('style', 'max-width:40rem;margin:4rem auto;padding:0 1rem;font-family:system-ui,sans-serif');
}

async function startup() {
  try {
    await window.qrllibReady;
    await router.isReady();
  } catch (error) {
    renderStartupFailure(error);
    return;
  }
  app.mount('#app');
}

// Nothing in the export path may fail invisibly.
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled rejection:', event.reason);
});

startup();
