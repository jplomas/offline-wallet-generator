export const SECURE_RANDOM_ERROR =
  'This browser has no secure random number generator. Wallet generation cannot continue safely.';

export function getSecureRandomSeed(cryptoObject) {
  const cryptoSource = arguments.length === 0 ? globalThis.crypto : cryptoObject;

  if (!cryptoSource || typeof cryptoSource.getRandomValues !== 'function') {
    throw new Error(SECURE_RANDOM_ERROR);
  }

  let seed;
  try {
    seed = cryptoSource.getRandomValues(new Uint8Array(48));
  } catch {
    throw new Error(SECURE_RANDOM_ERROR);
  }
  if (!(seed instanceof Uint8Array) || seed.length !== 48) {
    throw new Error(SECURE_RANDOM_ERROR);
  }

  if (seed.every((byte) => byte === 0)) {
    throw new Error('The secure random number generator returned all zeroes. Wallet generation stopped.');
  }

  return seed;
}
