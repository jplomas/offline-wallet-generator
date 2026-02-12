<template>
  <div>
    <div class="card bg-base-200 shadow-lg mx-auto my-8 max-w-4xl">
      <div class="card-body">
        <h1 class="card-title text-3xl justify-center mb-4">QRL Offline Wallet Generator</h1>

        <!-- Loading State -->
        <div id="loading" v-show="!qrllibLoaded">
          <div class="flex flex-col items-center gap-2">
            <p class="text-primary">Loading QRL Library...</p>
            <p class="text-base-content/60 text-sm">qrllib v1.2.4</p>
            <span class="loading loading-spinner loading-lg text-primary"></span>
          </div>
        </div>

        <!-- Loaded State -->
        <div id="loaded" v-show="qrllibLoaded">
          <!-- Generate Options -->
          <div id="generateButton" v-show="showGenerateButton">
            <div class="flex flex-col sm:flex-row justify-center items-center gap-6 mt-4">
              <!-- Hash Function Select -->
              <div class="flex flex-col items-center gap-1">
                <span class="text-sm font-medium">Hash function</span>
                <select class="select select-bordered select-secondary w-48" v-model="selectedHash" @change="thisHash(selectedHash)">
                  <option value="SHAKE_128">SHAKE_128</option>
                  <option value="SHAKE_256">SHAKE_256</option>
                  <option value="SHA2_256">SHA2_256</option>
                </select>
              </div>

              <!-- Tree Height Select -->
              <div class="flex flex-col items-center gap-1">
                <span class="text-sm font-medium">Tree height</span>
                <select class="select select-bordered select-secondary w-64" v-model="selectedHeight" @change="thisHeight(selectedHeight)">
                  <option :value="8">Height: 8, Signatures: 256</option>
                  <option :value="10">Height: 10, Signatures: 1,024</option>
                  <option :value="12">Height: 12, Signatures: 4,096</option>
                  <option :value="14">Height: 14, Signatures: 16,384</option>
                  <option :value="16">Height: 16, Signatures: 65,536</option>
                  <option :value="18">Height: 18, Signatures: 262,144</option>
                </select>
              </div>
            </div>

            <div class="flex justify-center mt-4">
              <button class="btn btn-primary" @click="generateWallet(false)">Generate</button>
            </div>
          </div>

          <!-- Generating Spinner -->
          <div id="generatingSpinner" v-show="showGeneratingSpinner" class="mt-8">
            <div class="flex flex-col items-center gap-4">
              <p>Generating new address...</p>
              <span class="loading loading-spinner loading-lg"></span>
              <p class="text-sm text-base-content/70">{{ estimatedTimeMessage }}</p>
              <p class="text-sm font-mono">Elapsed: {{ formattedElapsedTime }}</p>
            </div>
          </div>

          <!-- Generated Wallet -->
          <div id="generated" v-show="showGenerated" class="mt-8 space-y-4">
            <div class="flex justify-center">
              <img id="wasm" :src="logoSvg" class="h-16" alt="QRL Logo">
            </div>

            <!-- Address -->
            <div class="bg-base-300 p-4 rounded-lg">
              <p class="font-bold text-sm mb-1">Address</p>
              <p id="address" class="font-mono text-xs break-all"></p>
            </div>
            <div class="alert alert-info">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" class="stroke-current shrink-0 w-6 h-6"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
              <span>It's okay to share your address with others.</span>
            </div>

            <!-- Mnemonic -->
            <div class="bg-base-300 p-4 rounded-lg">
              <p class="font-bold text-sm mb-1">Mnemonic</p>
              <p id="mnemonic" class="font-mono text-xs break-words"></p>
            </div>
            <div class="alert alert-error">
              <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              <span>Do not share your mnemonic phrase with anyone!</span>
            </div>

            <!-- Hexseed -->
            <div class="bg-base-300 p-4 rounded-lg">
              <p class="font-bold text-sm mb-1">Hexseed</p>
              <p id="hexseed" class="font-mono text-xs break-all"></p>
            </div>
            <div class="alert alert-error">
              <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              <span>Do not share your hexseed with anyone!</span>
            </div>

            <!-- Public Key (hidden) -->
            <p id="pk" class="hidden"></p>

            <!-- Action Buttons -->
            <div class="flex flex-wrap justify-center gap-2 mt-6">
              <button class="btn btn-primary btn-sm" @click="printWallet">Print</button>
              <button id="pdfSave" class="btn btn-primary btn-sm" @click="pdfSave">Save PDF</button>
            </div>

            <!-- Save Options -->
            <div class="divider">Save Wallet</div>

            <div class="alert alert-warning">
              <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
              <span>Remember to move saved files to a secure location.</span>
            </div>

            <div class="flex justify-center">
              <label class="label cursor-pointer gap-2">
                <span class="label-text">Use encrypted format</span>
                <input type="checkbox" class="toggle toggle-primary" v-model="isSecure" />
              </label>
            </div>

            <!-- Encrypted Save -->
            <div v-if="isSecure" class="space-y-4">
              <div class="form-control w-full max-w-md mx-auto">
                <label class="label">
                  <span class="label-text">Password (min 8 characters)</span>
                </label>
                <input
                  type="password"
                  v-model="password"
                  v-on:input="check"
                  class="input input-bordered w-full focus:input-secondary focus:border-secondary"
                  placeholder="Enter password"
                />
                <!-- Password strength indicator -->
                <div v-if="password.length > 0" class="mt-2">
                  <div class="flex gap-1">
                    <div class="h-1 flex-1 rounded" :class="strengthBarClass(1)"></div>
                    <div class="h-1 flex-1 rounded" :class="strengthBarClass(2)"></div>
                    <div class="h-1 flex-1 rounded" :class="strengthBarClass(3)"></div>
                  </div>
                  <p class="text-xs mt-1 font-medium" :class="strengthTextClass">
                    {{ passwordStrength.feedback }}
                  </p>
                </div>
              </div>
              <div class="form-control w-full max-w-md mx-auto">
                <label class="label">
                  <span class="label-text">Confirm Password</span>
                </label>
                <input
                  type="password"
                  v-model="passwordConfirm"
                  v-on:input="check"
                  class="input input-bordered w-full focus:input-secondary focus:border-secondary"
                  placeholder="Confirm password"
                />
              </div>
              <p v-if="error" class="text-error text-center text-sm">{{ error }}</p>
              <!-- Encryption progress -->
              <div v-if="isEncrypting" class="w-full max-w-md mx-auto">
                <p class="text-sm text-center mb-2">Encrypting wallet (this may take a moment)...</p>
                <progress class="progress progress-primary w-full" :value="encryptionProgress" max="100"></progress>
                <p class="text-xs text-center mt-1">{{ encryptionProgress }}%</p>
              </div>
              <div v-else class="flex justify-center">
                <button
                  class="btn btn-primary"
                  :class="{ 'btn-disabled': !validated }"
                  :disabled="!validated"
                  v-on:click="saveJSON"
                >
                  Save encrypted (v3 format)
                </button>
              </div>
              <p class="text-xs text-center text-base-content/60">
                Uses scrypt key derivation + AES-256-GCM authenticated encryption
              </p>
            </div>

            <!-- Unencrypted Save -->
            <div v-else class="space-y-4">
              <div class="alert alert-warning">
                <span>Warning: Saving without encryption is not recommended for production use.</span>
              </div>
              <div class="flex justify-center">
                <button class="btn btn-warning" v-on:click="saveJSON">Save unencrypted (v3 format)</button>
              </div>
            </div>
          </div>

          <!-- Regenerate Section -->
          <div id="regenArea" v-show="showRegenArea" class="mt-8">
            <div class="divider">Or Regenerate from Existing</div>
            <div class="flex flex-col items-center gap-1 max-w-lg mx-auto">
              <span class="text-sm font-medium">Enter hexseed or mnemonic</span>
              <textarea
                v-model="hexseedMnemonic"
                class="textarea textarea-bordered w-full h-24 focus:textarea-secondary focus:border-secondary"
                placeholder="Enter your hexseed or mnemonic phrase..."
              ></textarea>
            </div>
            <div class="flex justify-center mt-4">
              <button class="btn btn-primary" @click="generateWallet(true)">Regenerate</button>
            </div>
            <p v-if="errorM" class="text-error text-center mt-2">{{ errorM }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
/* eslint new-cap:0, import/order:0 */
/* global QRLLIB */
import { jsPDF } from 'jspdf';
import print from 'print-js';
import { scrypt } from 'scrypt-js';
import logoSvgRaw from '/logo.svg?raw';

// V3 Wallet Format - Strong KDF with authenticated encryption
// Uses scrypt (N=2^17, r=8, p=1) + AES-256-GCM
// Addresses V-01 (Weak KDF) and V-02 (No AEAD) from security audit

const DEFAULT_SCRYPT_PARAMS = {
  N: 1 << 17, // 131072 - strong work factor
  r: 8,
  p: 1,
  dkLen: 32,
  saltLen: 32,
};

const DEFAULT_IV_LEN = 12;
const TAG_LEN = 16;

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    const value = bytes[i].toString(16);
    hex += value.length === 1 ? `0${value}` : value;
  }
  return hex;
}

function encodeUtf8(text) {
  return new TextEncoder().encode(text);
}

function buildAad(meta) {
  return encodeUtf8(JSON.stringify({
    version: meta.version,
    kdf: meta.kdf,
    cipher: {
      name: meta.cipher.name,
      iv: meta.cipher.iv,
    },
  }));
}

async function deriveKeyScrypt(password, salt, params, progressCallback) {
  const passwordBytes = typeof password === 'string' ? encodeUtf8(password) : new Uint8Array(password);
  return scrypt(passwordBytes, salt, params.N, params.r, params.p, params.dkLen, progressCallback);
}

async function encryptAead(plainBytes, keyBytes, iv, aad) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const algorithm = {
    name: 'AES-GCM',
    iv,
    tagLength: TAG_LEN * 8,
  };
  if (aad) {
    algorithm.additionalData = aad;
  }
  const cipherBuffer = await crypto.subtle.encrypt(algorithm, key, plainBytes);
  const cipherBytes = new Uint8Array(cipherBuffer);
  const authTag = cipherBytes.slice(cipherBytes.length - TAG_LEN);
  const encrypted = cipherBytes.slice(0, cipherBytes.length - TAG_LEN);
  return { encrypted, authTag };
}

// Build V3 encrypted wallet envelope
async function buildEncryptedEnvelope(walletData, password, progressCallback) {
  const params = { ...DEFAULT_SCRYPT_PARAMS };
  const salt = randomBytes(params.saltLen);
  const iv = randomBytes(DEFAULT_IV_LEN);

  const key = await deriveKeyScrypt(password, salt, params, progressCallback);

  const meta = {
    version: 3,
    kdf: {
      name: 'scrypt',
      params: {
        N: params.N,
        r: params.r,
        p: params.p,
        dkLen: params.dkLen,
        salt: bytesToHex(salt),
      },
    },
    cipher: {
      name: 'aes-256-gcm',
      iv: bytesToHex(iv),
    },
  };

  const plainJson = JSON.stringify(walletData);
  const aad = buildAad(meta);
  const { encrypted, authTag } = await encryptAead(encodeUtf8(plainJson), key, iv, aad);

  meta.cipher.authTag = bytesToHex(authTag);

  return {
    version: 3,
    encrypted: true,
    kdf: meta.kdf,
    cipher: meta.cipher,
    data: bytesToHex(encrypted),
  };
}

// Build V3 unencrypted wallet envelope
function buildUnencryptedEnvelope(walletData) {
  return {
    version: 3,
    encrypted: false,
    data: walletData,
  };
}

// Common passwords and patterns to reject (lowercase for comparison)
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', 'password1234',
  'qwerty', 'qwerty123', 'qwertyuiop', 'qwerty1234',
  'letmein', 'welcome', 'welcome1', 'welcome123',
  'admin', 'admin123', 'administrator', 'login',
  'master', 'master123', 'root', 'toor',
  'dragon', 'monkey', 'shadow', 'sunshine', 'princess',
  'football', 'baseball', 'soccer', 'hockey',
  'superman', 'batman', 'trustno1', 'passw0rd',
  'iloveyou', 'letmein', 'access', 'mustang',
  'michael', 'jennifer', 'thomas', 'charlie', 'andrew',
  'abcdef', 'abcdefg', 'abcdefgh', 'abcd1234',
  'abc123', 'a]bc1234', '1234abcd', 'pass1234',
  '12345678', '123456789', '1234567890', '87654321',
  '11111111', '00000000', '12341234', '11223344',
  'internet', 'computer', 'whatever', 'changeme',
]);

// Keyboard patterns to detect
const KEYBOARD_PATTERNS = [
  'qwerty', 'qwertz', 'azerty', 'asdfgh', 'zxcvbn',
  'qazwsx', '1qaz2wsx', 'qaswed', 'ytrewq', 'rewq',
  '123456', '654321', '987654', '456789', '567890',
];

function hasKeyboardPattern(pwd) {
  const lower = pwd.toLowerCase();
  return KEYBOARD_PATTERNS.some((pattern) => lower.includes(pattern));
}

function hasRepeatingPattern(pwd) {
  // Check for repeating sequences like "abcabc" or "123123"
  const len = pwd.length;
  for (let patternLen = 2; patternLen <= len / 2; patternLen += 1) {
    const pattern = pwd.slice(0, patternLen);
    const repeated = pattern.repeat(Math.ceil(len / patternLen)).slice(0, len);
    if (repeated === pwd) return true;
  }
  // Check for character repetition like "aaaaaaaa"
  if (/^(.)\1+$/.test(pwd)) return true;
  return false;
}

// Password strength estimation using check-password-strength + common password check
function estimatePasswordStrength(password) {
  if (!password) return { score: 0, feedback: 'Password is required' };

  // Minimum 8 characters required
  if (password.length < 8) {
    return { score: 0, feedback: 'Password must be at least 8 characters' };
  }

  // Check for common passwords (case-insensitive, ignoring trailing numbers/symbols)
  const lowerPwd = password.toLowerCase();
  const baseWord = lowerPwd.replace(/[0-9!@#$%^&*()]+$/g, '');
  if (COMMON_PASSWORDS.has(lowerPwd) || COMMON_PASSWORDS.has(baseWord)) {
    return { score: 1, feedback: 'This is a commonly used password' };
  }

  // Check for keyboard patterns
  if (hasKeyboardPattern(password)) {
    return { score: 1, feedback: 'Avoid keyboard patterns' };
  }

  // Check for repeating patterns
  if (hasRepeatingPattern(password)) {
    return { score: 1, feedback: 'Avoid repeating patterns' };
  }

  // Check what character types are present using simple regex
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  const hasNumberOrSymbol = hasNumber || hasSymbol;

  // Build list of missing character types (numbers/symbols are either/or)
  const missing = [];
  if (!hasLower) missing.push('lowercase');
  if (!hasUpper) missing.push('uppercase');
  if (!hasNumberOrSymbol) missing.push('numbers or symbols');

  // Determine score and feedback
  let score;
  let feedback;

  if (missing.length >= 2) {
    // Missing 2+ categories - weak
    score = 1;
    feedback = `Add ${missing.join(', ')}`;
  } else if (missing.length === 1) {
    // Missing 1 category - medium
    score = 2;
    feedback = `Add ${missing.join(', ')}`;
  } else if (password.length < 12) {
    // All categories but short
    score = 2;
    feedback = 'Consider a longer password';
  } else {
    // All categories and good length
    score = 3;
    feedback = 'Strong password';
  }

  return { score, feedback };
}

export default {
  name: 'LoadQRLLIB',
  data() {
    return {
      password: '',
      passwordConfirm: '',
      error: 'A password is required',
      validated: false,
      isSecure: true,
      hexseedMnemonic: '',
      errorM: '',
      qrllibLoaded: false,
      showGenerateButton: true,
      showGeneratingSpinner: false,
      showGenerated: false,
      showRegenArea: true,
      selectedHash: 'SHAKE_128',
      selectedHeight: 10,
      elapsedSeconds: 0,
      elapsedTimer: null,
      logoSvg: `data:image/svg+xml;base64,${btoa(logoSvgRaw)}`,
      // V-03: Password strength tracking
      passwordStrength: { score: 0, feedback: 'Password is required' },
      // Encryption progress tracking
      encryptionProgress: 0,
      isEncrypting: false,
    };
  },
  mounted() {
    if (typeof QRLLIB !== 'undefined' && typeof QRLLIB.str2bin === 'function') {
      this.qrllibLoaded = true;
    }
  },
  computed: {
    estimatedTimeMessage() {
      const height = this.$store.state.height;
      const estimates = {
        8: 'Estimated time: ~1 second',
        10: 'Estimated time: ~2-3 seconds',
        12: 'Estimated time: ~10-15 seconds',
        14: 'Estimated time: ~1-2 minutes',
        16: 'Estimated time: ~5-10 minutes',
        18: 'Estimated time: ~20-30 minutes',
      };
      return estimates[height] || 'Estimated time: calculating...';
    },
    formattedElapsedTime() {
      const mins = Math.floor(this.elapsedSeconds / 60);
      const secs = this.elapsedSeconds % 60;
      if (mins > 0) {
        return `${mins}m ${secs.toString().padStart(2, '0')}s`;
      }
      return `${secs}s`;
    },
    // Password strength text color - darker for readability
    strengthTextClass() {
      const { score } = this.passwordStrength;
      if (score === 0) return 'text-base-content/70';
      if (score === 1) return 'text-error';
      if (score === 2) return 'text-amber-600';
      return 'text-green-600';
    },
  },
  methods: {
    // Password strength bar color based on position and score
    // Score 0: all grey, Score 1: red (1/3), Score 2: amber (2/3), Score 3: green (3/3)
    strengthBarClass(position) {
      const { score } = this.passwordStrength;
      if (score === 0) return 'bg-base-300';
      if (score === 1) {
        return position <= 1 ? 'bg-error' : 'bg-base-300';
      }
      if (score === 2) {
        return position <= 2 ? 'bg-amber-500' : 'bg-base-300';
      }
      // score === 3
      return 'bg-success';
    },

    async saveJSON() {
      const thisAddress = document.getElementById('address').textContent;
      const thisPk = document.getElementById('pk').textContent;
      const thisHashFunction = QRLLIB.getHashFunction(thisAddress).value;
      const thisSignatureType = QRLLIB.getSignatureType(thisAddress).value;
      const thisHeight = this.$store.state.height;
      const thisHexSeed = document.getElementById('hexseed').textContent;
      const thisMnemonic = document.getElementById('mnemonic').textContent;

      // V3 wallet data structure
      const walletData = {
        address: thisAddress,
        pk: thisPk,
        hexseed: thisHexSeed,
        mnemonic: thisMnemonic,
        height: thisHeight,
        hashFunction: thisHashFunction,
        signatureType: thisSignatureType,
        index: 0,
      };

      let walletEnvelope;
      if (this.isSecure) {
        // V3 encrypted format with scrypt + AES-256-GCM
        this.isEncrypting = true;
        this.encryptionProgress = 0;
        try {
          walletEnvelope = await buildEncryptedEnvelope(
            walletData,
            this.password,
            (progress) => { this.encryptionProgress = Math.round(progress * 100); },
          );
        } finally {
          this.isEncrypting = false;
          this.encryptionProgress = 0;
          // V-04: Clear password from memory after use
          this.password = '';
          this.passwordConfirm = '';
          this.validated = false;
          this.error = 'A password is required';
          this.passwordStrength = { score: 0, feedback: 'Password is required' };
        }
      } else {
        // V3 unencrypted format
        walletEnvelope = buildUnencryptedEnvelope(walletData);
      }

      const walletJson = JSON.stringify(walletEnvelope, null, 2);
      const binBlob = new Blob([walletJson], { type: 'application/json' });
      const a = window.document.createElement('a');
      const blobUrl = window.URL.createObjectURL(binBlob);
      a.href = blobUrl;
      a.download = 'wallet.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      // V-07: Fix Blob URL memory leak
      window.URL.revokeObjectURL(blobUrl);
    },

    check() {
      // V-03: Enhanced password validation with strength check
      this.passwordStrength = estimatePasswordStrength(this.password);

      if (!this.password.length) {
        this.error = 'A password is required';
        this.validated = false;
        return;
      }

      if (this.password.length < 8) {
        this.error = 'Password must be at least 8 characters';
        this.validated = false;
        return;
      }

      if (this.passwordStrength.score < 1) {
        this.error = this.passwordStrength.feedback;
        this.validated = false;
        return;
      }

      if (this.password !== this.passwordConfirm) {
        this.error = 'Passwords must match';
        this.validated = false;
        return;
      }

      this.error = '';
      this.validated = true;
    },

    height() {
      return this.$store.state.height;
    },

    hash() {
      return this.$store.state.hash;
    },

    thisHeight(height) {
      this.$store.state.height = height;
    },

    thisHash(hash) {
      this.$store.state.hash = hash;
    },

    printWallet() {
      // Get wallet data
      const address = document.getElementById('address').textContent;
      const mnemonic = document.getElementById('mnemonic').textContent;
      const hexseed = document.getElementById('hexseed').textContent;

      // Create print-friendly HTML
      const printContent = `
        <div style="font-family: Arial, sans-serif; max-width: 700px; margin: 0 auto;">
          <div style="background: #f0f0f0; padding: 15px; margin-bottom: 10px; border-radius: 8px; border: 1px solid #ddd;">
            <p style="font-weight: bold; margin: 0 0 8px 0; font-size: 14px;">Address</p>
            <p style="font-family: monospace; font-size: 10px; word-break: break-all; margin: 0; line-height: 1.4;">${address}</p>
          </div>
          <div style="background: #e8f5e9; border: 1px solid #4caf50; padding: 10px; margin-bottom: 15px; border-radius: 6px;">
            <p style="margin: 0; color: #2e7d32; font-size: 12px;">It's okay to share your address with others.</p>
          </div>

          <div style="background: #f0f0f0; padding: 15px; margin-bottom: 10px; border-radius: 8px; border: 1px solid #ddd;">
            <p style="font-weight: bold; margin: 0 0 8px 0; font-size: 14px;">Mnemonic</p>
            <p style="font-family: monospace; font-size: 10px; word-break: break-word; margin: 0; line-height: 1.4;">${mnemonic}</p>
          </div>
          <div style="background: #ffebee; border: 1px solid #f44336; padding: 10px; margin-bottom: 15px; border-radius: 6px;">
            <p style="margin: 0; color: #c62828; font-size: 12px;">Do not share your mnemonic phrase with anyone!</p>
          </div>

          <div style="background: #f0f0f0; padding: 15px; margin-bottom: 10px; border-radius: 8px; border: 1px solid #ddd;">
            <p style="font-weight: bold; margin: 0 0 8px 0; font-size: 14px;">Hexseed</p>
            <p style="font-family: monospace; font-size: 10px; word-break: break-all; margin: 0; line-height: 1.4;">${hexseed}</p>
          </div>
          <div style="background: #ffebee; border: 1px solid #f44336; padding: 10px; margin-bottom: 15px; border-radius: 6px;">
            <p style="margin: 0; color: #c62828; font-size: 12px;">Do not share your hexseed with anyone!</p>
          </div>

          <div style="background: #fff8e1; border: 1px solid #ff9800; padding: 10px; border-radius: 6px;">
            <p style="margin: 0; color: #e65100; font-size: 12px;">Remember to move saved files to a secure location.</p>
          </div>
        </div>
      `;

      print({
        printable: printContent,
        type: 'raw-html',
        header: 'The Quantum Resistant Ledger',
        headerStyle: 'font-weight: 500; font-size: 24px; text-align: center; margin-bottom: 20px;',
      });
    },

    pdfSave() {
      // Get wallet data
      const address = document.getElementById('address').textContent;
      const mnemonic = document.getElementById('mnemonic').textContent;
      const hexseed = document.getElementById('hexseed').textContent;

      // Create PDF using jsPDF directly
      const doc = new jsPDF();
      const pageWidth = doc.internal.pageSize.getWidth();
      const margin = 15;
      const contentWidth = pageWidth - 2 * margin;
      let y = 25;

      // Title
      doc.setFontSize(24);
      doc.setTextColor(11, 24, 30);
      doc.text('QRL Wallet', pageWidth / 2, y, { align: 'center' });
      y += 20;

      // Helper function to add a section
      const addSection = (label, content, warning, isShareable) => {
        const fontSize = 11;
        doc.setFontSize(fontSize);
        doc.setFont('courier', 'normal');
        const textLines = doc.splitTextToSize(content, contentWidth - 14);
        const lineHeight = 5;
        const boxHeight = 18 + textLines.length * lineHeight;

        // Section background
        doc.setFillColor(245, 245, 245);
        doc.setDrawColor(180, 180, 180);
        doc.roundedRect(margin, y, contentWidth, boxHeight, 3, 3, 'FD');

        // Label
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(0, 0, 0);
        doc.text(label, margin + 7, y + 10);

        // Content
        doc.setFontSize(fontSize);
        doc.setFont('courier', 'normal');
        doc.setTextColor(30, 30, 30);
        doc.text(textLines, margin + 7, y + 18);
        y += boxHeight + 4;

        // Warning box
        if (isShareable) {
          doc.setFillColor(220, 252, 231);
          doc.setDrawColor(22, 163, 74);
        } else {
          doc.setFillColor(254, 226, 226);
          doc.setDrawColor(220, 38, 38);
        }
        doc.roundedRect(margin, y, contentWidth, 10, 3, 3, 'FD');
        doc.setFontSize(11);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(isShareable ? 22 : 153, isShareable ? 101 : 27, isShareable ? 52 : 27);
        doc.text(warning, margin + 7, y + 7);
        y += 18;
      };

      // Add sections
      addSection('Address', address, "It's okay to share your address with others.", true);
      addSection('Mnemonic', mnemonic, 'Do not share your mnemonic phrase with anyone!', false);
      addSection('Hexseed', hexseed, 'Do not share your hexseed with anyone!', false);

      // Final warning
      doc.setFillColor(254, 243, 199);
      doc.setDrawColor(217, 119, 6);
      doc.roundedRect(margin, y, contentWidth, 10, 3, 3, 'FD');
      doc.setFontSize(11);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(146, 64, 14);
      doc.text('Remember to move saved files to a secure location.', margin + 7, y + 7);

      // Save
      doc.save('qrl-wallet.pdf');
    },

    async generateWallet(regen) {
      this.showGenerateButton = false;
      this.showGeneratingSpinner = true;
      this.showRegenArea = false;
      this.errorM = '';

      // Start elapsed time counter
      this.elapsedSeconds = 0;
      this.elapsedTimer = setInterval(() => {
        this.elapsedSeconds += 1;
      }, 1000);

      const { hexseedMnemonic } = this;
      const hashFunction = this.$store.state.hash;
      const xmssHeight = this.$store.state.height;

      // V-06: Improved QRLLIB detection with explicit marker
      // Find QRLLIB code from scripts - prioritize by detection confidence
      let qrllibCode = '';

      // Method 1: Look for script with QRLLIB global variable definition
      const scripts = Array.from(document.getElementsByTagName('script'));
      for (const script of scripts) {
        if (script.src && script.src.includes('qrllib')) {
          // External script - fetch it
          try {
            const response = await fetch(script.src);
            qrllibCode = await response.text();
            break;
          } catch (e) {
            // Continue to next method
          }
        }
      }

      // Method 2: Find inline script containing QRLLIB module marker
      if (!qrllibCode) {
        const inlineScript = scripts.find((s) => s.textContent
          && (s.textContent.includes('QRLLIB')
            || s.textContent.includes('eHashFunction')
            || s.textContent.includes('Uint8Vector')));
        if (inlineScript) {
          qrllibCode = inlineScript.textContent;
        }
      }

      // Method 3: Fallback - find largest inline script (QRLLIB is ~2MB)
      if (!qrllibCode) {
        const largeScript = scripts
          .filter((s) => s.textContent && s.textContent.length > 100000)
          .sort((a, b) => b.textContent.length - a.textContent.length)[0];
        if (largeScript) {
          qrllibCode = largeScript.textContent;
        }
      }

      if (!qrllibCode) {
        this.errorM = 'Failed to locate QRLLIB code. Please refresh the page.';
        this.showGeneratingSpinner = false;
        this.showGenerateButton = true;
        clearInterval(this.elapsedTimer);
        return;
      }

      // V-05: Worker code with timeout on QRLLIB polling
      const QRLLIB_TIMEOUT_MS = 30000; // 30 second timeout
      const workerCode = `
        ${qrllibCode}

        self.window = self;
        self.document = { createElement: () => ({}) };

        self.onmessage = async function(e) {
          const { randomSeed, xmssHeight, hashFunction, regen, hexseedMnemonic, timeoutMs } = e.data;

          // V-05: waitForQRLLIB with timeout
          const waitForQRLLIB = (maxWaitMs) => {
            return new Promise((resolve, reject) => {
              const startTime = Date.now();
              const check = () => {
                if (typeof QRLLIB !== 'undefined' && typeof QRLLIB.Xmss !== 'undefined') {
                  resolve();
                } else if (Date.now() - startTime > maxWaitMs) {
                  reject(new Error('QRLLIB failed to initialize within ' + (maxWaitMs / 1000) + ' seconds'));
                } else {
                  setTimeout(check, 100);
                }
              };
              check();
            });
          };

          try {
            await waitForQRLLIB(timeoutMs);
          } catch (err) {
            self.postMessage({ error: err.message });
            return;
          }

          const toUint8Vector = arr => {
            const vec = new QRLLIB.Uint8Vector();
            for (let i = 0; i < arr.length; i += 1) {
              vec.push_back(arr[i]);
            }
            return vec;
          };

          let hashFn = QRLLIB.eHashFunction.SHAKE_128;
          switch (hashFunction) {
            case 'SHAKE_128':
              hashFn = QRLLIB.eHashFunction.SHAKE_128;
              break;
            case 'SHAKE_256':
              hashFn = QRLLIB.eHashFunction.SHAKE_256;
              break;
            case 'SHA2_256':
              hashFn = QRLLIB.eHashFunction.SHA2_256;
              break;
          }

          try {
            let XMSS_OBJECT = null;

            if (!regen) {
              const seedVector = toUint8Vector(new Uint8Array(randomSeed));
              XMSS_OBJECT = await new QRLLIB.Xmss.fromParameters(seedVector, xmssHeight, hashFn);
            } else {
              if (hexseedMnemonic.trim().length === 102) {
                XMSS_OBJECT = QRLLIB.Xmss.fromHexSeed(hexseedMnemonic);
              } else if (hexseedMnemonic.trim().split(' ').length === 34) {
                XMSS_OBJECT = QRLLIB.Xmss.fromMnemonic(hexseedMnemonic.trim());
              } else {
                self.postMessage({ error: 'Invalid hexseed/mnemonic' });
                return;
              }
            }

            self.postMessage({
              address: XMSS_OBJECT.getAddress(),
              pk: XMSS_OBJECT.getPK(),
              hexseed: XMSS_OBJECT.getHexSeed(),
              mnemonic: XMSS_OBJECT.getMnemonic(),
            });
          } catch (err) {
            self.postMessage({ error: err.message || 'Wallet generation failed' });
          }
        };
      `;

      const blob = new Blob([workerCode], { type: 'application/javascript' });
      const workerUrl = URL.createObjectURL(blob);
      const worker = new Worker(workerUrl);

      worker.onmessage = (e) => {
        worker.terminate();
        URL.revokeObjectURL(workerUrl);
        clearInterval(this.elapsedTimer);
        this.showGeneratingSpinner = false;

        if (e.data.error) {
          this.errorM = e.data.error;
          this.showGenerateButton = true;
          this.showRegenArea = true;
          return;
        }

        document.getElementById('address').textContent = e.data.address;
        document.getElementById('pk').textContent = e.data.pk;
        document.getElementById('hexseed').textContent = e.data.hexseed;
        document.getElementById('mnemonic').textContent = e.data.mnemonic;

        this.showGenerated = true;
        this.showRegenArea = false;
      };

      worker.onerror = (err) => {
        worker.terminate();
        URL.revokeObjectURL(workerUrl);
        clearInterval(this.elapsedTimer);
        this.showGeneratingSpinner = false;
        this.showGenerateButton = true;
        this.showRegenArea = true;
        this.errorM = `Wallet generation failed: ${err.message}`;
      };

      // Generate random seed and send to worker
      const randomSeed = Array.from(crypto.getRandomValues(new Uint8Array(48)));

      worker.postMessage({
        randomSeed,
        xmssHeight,
        hashFunction,
        regen,
        hexseedMnemonic,
        timeoutMs: QRLLIB_TIMEOUT_MS,
      });
    },
  },
};
</script>

<style scoped>
#address,
#mnemonic,
#pk,
#hexseed {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
</style>
