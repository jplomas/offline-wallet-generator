export function toUint8Vector(qrllib, bytes) {
  const vector = new qrllib.Uint8Vector();
  for (const byte of bytes) vector.push_back(byte);
  return vector;
}

function getHashFunction(qrllib, name) {
  return qrllib.eHashFunction[name] || qrllib.eHashFunction.SHAKE_128;
}

export async function generateWalletData(qrllib, options) {
  const { randomSeed, xmssHeight, hashFunction, regen, hexseedMnemonic } = options;
  let xmss;

  if (!regen) {
    if (!Array.isArray(randomSeed) || randomSeed.length !== 48) {
      throw new Error('Wallet generation requires exactly 48 bytes of secure entropy');
    }
    const seedVector = toUint8Vector(qrllib, randomSeed);
    xmss = await new qrllib.Xmss.fromParameters(
      seedVector,
      xmssHeight,
      getHashFunction(qrllib, hashFunction),
    );
  } else if (hexseedMnemonic.trim().length === 102) {
    xmss = qrllib.Xmss.fromHexSeed(hexseedMnemonic.trim());
  } else if (hexseedMnemonic.trim().split(/\s+/).length === 34) {
    xmss = qrllib.Xmss.fromMnemonic(hexseedMnemonic.trim());
  } else {
    throw new Error('Invalid hexseed/mnemonic');
  }

  return {
    address: xmss.getAddress(),
    pk: xmss.getPK(),
    hexseed: xmss.getHexSeed(),
    mnemonic: xmss.getMnemonic(),
  };
}
