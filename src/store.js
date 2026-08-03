import { reactive } from 'vue';

const state = reactive({
  // SHAKE_256 by default. All three functions QRL supports produce 32-byte
  // digests, so collision resistance is 128 bits either way, but SHAKE_256's
  // larger capacity gives 256-bit preimage resistance against SHAKE_128's 128.
  // Measured at tree height 10 it costs nothing (1353 ms vs 1374 ms), while
  // SHA2_256 — same preimage margin — takes 2866 ms.
  // Note this differs from the QRL web wallet, which defaults to SHAKE_128.
  // The choice is encoded in the address descriptor, so wallets remain valid
  // and importable either way.
  hash: 'SHAKE_256',
  height: 10,
});

export default {
  state,
  install(app) {
    app.config.globalProperties.$store = this;
  },
};
