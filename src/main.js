import './app.css';
import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import store from './store';
import { library } from '@fortawesome/fontawesome-svg-core';
import { faCheck } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome';
import { Buffer } from "buffer";

window.Buffer = Buffer;

library.add(faCheck);

const app = createApp(App)
  .use(router)
  .use(store)
  .component("font-awesome-icon", FontAwesomeIcon);

async function startup() {
  await window.qrllibReady;
  await router.isReady();
  app.mount('#app');
}

startup();
