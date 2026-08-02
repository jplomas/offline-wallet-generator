import assert from 'node:assert/strict';
import test from 'node:test';
import { getSecureRandomSeed, SECURE_RANDOM_ERROR } from '../src/secure-random.js';
import { generateWalletData } from '../src/wallet-generation.js';

test('requests 48 CSPRNG bytes and passes them unchanged to fromParameters', async () => {
  const entropy = Uint8Array.from({ length: 48 }, (_, index) => index + 1);
  let requestedLength;
  const seed = getSecureRandomSeed({
    getRandomValues(target) {
      requestedLength = target.length;
      target.set(entropy);
      return target;
    },
  });

  let received;
  function Uint8Vector() { this.values = []; }
  Uint8Vector.prototype.push_back = function pushBack(value) { this.values.push(value); };
  function FromParameters(vector) {
    received = vector.values;
    return {
      getAddress: () => 'address', getPK: () => 'pk',
      getHexSeed: () => 'hexseed', getMnemonic: () => 'mnemonic',
    };
  }
  const qrllib = {
    Uint8Vector,
    eHashFunction: { SHAKE_128: 0 },
    Xmss: { fromParameters: FromParameters },
  };

  await generateWalletData(qrllib, {
    randomSeed: Array.from(seed), xmssHeight: 10, hashFunction: 'SHAKE_128', regen: false,
  });

  assert.equal(requestedLength, 48);
  assert.deepEqual(received, Array.from(entropy));
});

test('fails closed immediately when secure randomness is unavailable', () => {
  assert.throws(() => getSecureRandomSeed(undefined), { message: SECURE_RANDOM_ERROR });
  assert.throws(() => getSecureRandomSeed({}), { message: SECURE_RANDOM_ERROR });
  assert.throws(() => getSecureRandomSeed({ getRandomValues() { throw new Error('platform failure'); } }), {
    message: SECURE_RANDOM_ERROR,
  });
});
