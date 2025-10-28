'use client';

import './globals.css';
import { useState, useEffect } from 'react';

// Utility functions for BigInt operations
function gcd(a, b) {
  while (b !== 0n) {
    [a, b] = [b, a % b];
  }
  return a;
}

function modInverse(a, m) {
  // Extended Euclidean Algorithm to find modular inverse
  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];
  let [oldT, t] = [0n, 1n];

  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
    [oldT, t] = [t, oldT - quotient * t];
  }

  if (oldR > 1n) return null; // No inverse
  if (oldS < 0n) oldS += m;

  return oldS;
}

function modPow(base, exponent, modulus) {
  // Fast modular exponentiation
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent >> 1n;
    base = (base * base) % modulus;
  }
  return result;
}

// Primality testing using Miller-Rabin
function isPrime(n, k = 5) {
  // Handle small cases
  if (n <= 1n) return false;
  if (n <= 3n) return true;
  if (n % 2n === 0n || n % 3n === 0n) return false;

  // Check for divisibility by small primes
  const smallPrimes = [5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n];
  for (const prime of smallPrimes) {
    if (n === prime) return true;
    if (n % prime === 0n) return false;
  }

  // Write n-1 as d * 2^r
  let r = 0n;
  let d = n - 1n;
  while (d % 2n === 0n) {
    d /= 2n;
    r++;
  }

  // Perform k rounds of Miller-Rabin test
  for (let i = 0; i < k; i++) {
    // Generate a random number between 2 and n-2
    const limit = n - 2n;
    const randomNum = 2n + BigInt(Math.floor(Math.random() * Number(limit)));
    let x = modPow(randomNum, d, n);
    
    if (x === 1n || x === n - 1n) continue;
    
    let composite = true;
    for (let j = 0n; j < r - 1n; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    
    if (composite) return false;
  }
  
  return true;
}

function generatePrime(bits) {
  // Generate a random prime with specified bit length
  const min = 1n << BigInt(bits - 1); // 2^(bits-1)
  const max = (1n << BigInt(bits)) - 1n; // 2^bits - 1
  
  while (true) {
    // Generate random number in range
    const range = max - min + 1n;
    const randomNum = BigInt(Math.floor(Math.random() * Number(range)));
    let candidate = randomNum + min;
    
    // Make sure it's odd (except for 2, but we're dealing with larger numbers)
    if (candidate % 2n === 0n) candidate++;
    
    if (isPrime(candidate)) {
      return candidate;
    }
  }
}

// RSA Implementation
function generateRSA(bits) {
  // Generate two distinct primes
  let p, q;
  do {
    p = generatePrime(bits);
    q = generatePrime(bits);
  } while (p === q);
  
  // Calculate n and phi
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  
  // Choose public exponent e (commonly 65537)
  const e = 65537n;
  
  // Calculate private exponent d
  const d = modInverse(e, phi);
  
  return {
    p, q, n, phi, e, d,
    publicKey: { n, e },
    privateKey: { n, d }
  };
}

function encryptRSA(message, publicKey) {
  // Convert message to BigInt
  const messageBytes = new TextEncoder().encode(message);
  let messageInt = 0n;
  for (let i = 0; i < messageBytes.length; i++) {
    messageInt = (messageInt << 8n) + BigInt(messageBytes[i]);
  }
  
  // Encrypt using RSA formula: c = m^e mod n
  return modPow(messageInt, publicKey.e, publicKey.n);
}

function decryptRSA(ciphertext, privateKey) {
  // Decrypt using RSA formula: m = c^d mod n
  const decryptedInt = modPow(ciphertext, privateKey.d, privateKey.n);
  
  // Convert BigInt back to string
  let bytes = [];
  let temp = decryptedInt;
  while (temp > 0n) {
    bytes.push(Number(temp & 0xFFn));
    temp = temp >> 8n;
  }
  
  // Reverse bytes since we built them backwards
  bytes.reverse();
  
  // Convert bytes to string
  return new TextDecoder().decode(new Uint8Array(bytes));
}

// Diffie-Hellman Implementation
function generateDHKeys(p, g) {
  // Generate private key (in practice, this should be much larger)
  const privateKey = BigInt(Math.floor(Math.random() * 1000)) + 1n;
  
  // Calculate public key: A = g^a mod p
  const publicKey = modPow(g, privateKey, p);
  
  return { privateKey, publicKey };
}

function computeSharedSecret(theirPublicKey, myPrivateKey, p) {
  // Compute shared secret: s = B^a mod p
  return modPow(theirPublicKey, myPrivateKey, p);
}

export default function Home() {
  // RSA State
  const [rsaBits, setRsaBits] = useState(16);
  const [manualP, setManualP] = useState('');
  const [manualQ, setManualQ] = useState('');
  const [rsaKeys, setRsaKeys] = useState(null);
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [message, setMessage] = useState('Hello, World!');
  const [ciphertext, setCiphertext] = useState(null);
  const [plaintext, setPlaintext] = useState('');
  
  // Diffie-Hellman State
  const [dhP, setDhP] = useState(23n);
  const [dhG, setDhG] = useState(5n);
  const [aliceKeys, setAliceKeys] = useState(null);
  const [bobKeys, setBobKeys] = useState(null);
  const [sharedSecret, setSharedSecret] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  
  // Sample primes for Diffie-Hellman
  const samplePrimes = [
    { value: 23n, label: '23 (small demo)' },
    { value: 97n, label: '97' },
    { value: 199n, label: '199' },
    { value: 541n, label: '541' }
  ];
  
  const sampleGenerators = [
    { value: 5n, label: '5' },
    { value: 2n, label: '2' },
    { value: 3n, label: '3' }
  ];

  // RSA Functions
  const handleGenerateRSA = () => {
    let p, q;
    
    if (manualP && manualQ) {
      p = BigInt(manualP);
      q = BigInt(manualQ);
      
      if (!isPrime(p) || !isPrime(q)) {
        alert('Provided numbers must be prime');
        return;
      }
    }
    
    const keys = generateRSA(rsaBits);
    setRsaKeys(keys);
    setCiphertext(null);
    setPlaintext('');
  };

  const handleEncrypt = () => {
    if (!rsaKeys || !message) return;
    
    try {
      const encrypted = encryptRSA(message, rsaKeys.publicKey);
      setCiphertext(encrypted);
    } catch (error) {
      console.error('Encryption error:', error);
      alert('Encryption failed');
    }
  };

  const handleDecrypt = () => {
    if (!rsaKeys || !ciphertext) return;
    
    try {
      const decrypted = decryptRSA(ciphertext, rsaKeys.privateKey);
      setPlaintext(decrypted);
    } catch (error) {
      console.error('Decryption error:', error);
      alert('Decryption failed');
    }
  };

  // Diffie-Hellman Functions
  const handleGenerateDH = () => {
    const alice = generateDHKeys(dhP, dhG);
    const bob = generateDHKeys(dhP, dhG);
    
    setAliceKeys(alice);
    setBobKeys(bob);
    setSharedSecret(null);
    setVerificationResult(null);
  };

  const handleComputeSharedSecret = () => {
    if (!aliceKeys || !bobKeys) return;
    
    const aliceShared = computeSharedSecret(bobKeys.publicKey, aliceKeys.privateKey, dhP);
    const bobShared = computeSharedSecret(aliceKeys.publicKey, bobKeys.privateKey, dhP);
    
    setSharedSecret({ alice: aliceShared, bob: bobShared });
    
    // Verify they're equal
    const isEqual = aliceShared === bobShared;
    setVerificationResult(isEqual);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text.toString());
  };

  return (
    <div className="min-h-screen bg-gray-100 py-8 px-4">
      <div className="max-w-6xl mx-auto">
        <header className="text-center mb-12">
          <h1 className="text-3xl font-bold text-gray-800">Cryptography Demo</h1>
          <p className="text-gray-600 mt-2">
            Interactive demonstration of RSA and Diffie-Hellman key exchange
          </p>
          <div className="bg-yellow-100 border-l-4 border-yellow-500 text-yellow-700 p-4 mt-4 rounded">
            <p className="font-bold">Security Disclaimer</p>
            <p>
              This demo is for educational purposes only. It uses small primes for clarity and is not secure for production use.
              Real-world cryptography requires much larger keys and additional security measures.
            </p>
          </div>
        </header>

        {/* Theory Section */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <h2 className="text-2xl font-bold text-gray-800 mb-4">Cryptographic Theory</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* RSA Theory */}
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-xl font-semibold text-gray-700 mb-3">RSA Encryption</h3>
              <div className="space-y-3 text-gray-600">
                <p>
                  <strong>Concept:</strong> RSA is an asymmetric encryption algorithm that uses a pair of keys - a public key for encryption and a private key for decryption.
                </p>
                <p>
                  <strong>How it works:</strong>
                </p>
                <ol className="list-decimal list-inside space-y-2 ml-4">
                  <li>Choose two large prime numbers (p and q)</li>
                  <li>Compute n = p × q (this is the modulus)</li>
                  <li>Compute φ(n) = (p-1) × (q-1) (Euler's totient function)</li>
                  <li>Choose an integer e such that 1 &lt; e &lt; φ(n) and gcd(e, φ(n)) = 1</li>
                  <li>Compute d such that (d × e) mod φ(n) = 1 (modular inverse)</li>
                  <li>Public key is (n, e), Private key is (n, d)</li>
                  <li>To encrypt: c = m<sup>e</sup> mod n</li>
                  <li>To decrypt: m = c<sup>d</sup> mod n</li>
                </ol>
                <p>
                  <strong>Why it's secure:</strong> It's computationally difficult to factor large numbers, making it hard to derive the private key from the public key.
                </p>
              </div>
            </div>
            
            {/* Diffie-Hellman Theory */}
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-xl font-semibold text-gray-700 mb-3">Diffie-Hellman Key Exchange</h3>
              <div className="space-y-3 text-gray-600">
                <p>
                  <strong>Concept:</strong> Diffie-Hellman allows two parties to establish a shared secret over an insecure channel without ever transmitting the secret itself.
                </p>
                <p>
                  <strong>How it works:</strong>
                </p>
                <ol className="list-decimal list-inside space-y-2 ml-4">
                  <li>Agree on public numbers: prime p and base g</li>
                  <li>Alice chooses private key a and computes public key A = g<sup>a</sup> mod p</li>
                  <li>Bob chooses private key b and computes public key B = g<sup>b</sup> mod p</li>
                  <li>Alice and Bob exchange public keys</li>
                  <li>Alice computes shared secret s = B<sup>a</sup> mod p</li>
                  <li>Bob computes shared secret s = A<sup>b</sup> mod p</li>
                  <li>Both arrive at the same shared secret: g<sup>ab</sup> mod p</li>
                </ol>
                <p>
                  <strong>Why it's secure:</strong> The discrete logarithm problem makes it computationally infeasible to determine the private keys from the public information.
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* RSA Section */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-2xl font-bold text-gray-800 mb-4">RSA Encryption</h2>
            
            {/* Theory Explanation */}
            <div className="mb-6 p-4 bg-blue-50 rounded-lg">
              <h3 className="text-lg font-semibold text-gray-700 mb-2">How RSA Works</h3>
              <p className="text-gray-600 text-sm">
                RSA encryption uses the mathematical property that multiplying two large prime numbers is easy, 
                but factoring the result back into primes is extremely difficult. This one-way function forms 
                the basis of RSA's security.
              </p>
            </div>
            
            {/* Step 1: Key Generation */}
            <div className="mb-8">
              <h3 className="text-xl font-semibold text-gray-700 mb-3">Step 1: Generate Keys</h3>
              <p className="text-gray-600 mb-3 text-sm">
                In RSA, we first generate a key pair consisting of a public key (used for encryption) and a 
                private key (used for decryption). This involves selecting two prime numbers and computing 
                several mathematical values.
              </p>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Prime Size (bits)
                  </label>
                  <select
                    value={rsaBits}
                    onChange={(e) => setRsaBits(Number(e.target.value))}
                    className="w-full p-2 border border-gray-300 rounded-md"
                  >
                    <option value={16}>16 bits (demo)</option>
                    <option value={32}>32 bits</option>
                    <option value={64}>64 bits</option>
                  </select>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Manual Prime p (optional)
                    </label>
                    <input
                      type="text"
                      value={manualP}
                      onChange={(e) => setManualP(e.target.value)}
                      placeholder="Enter prime number"
                      className="w-full p-2 border border-gray-300 rounded-md"
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Manual Prime q (optional)
                    </label>
                    <input
                      type="text"
                      value={manualQ}
                      onChange={(e) => setManualQ(e.target.value)}
                      placeholder="Enter prime number"
                      className="w-full p-2 border border-gray-300 rounded-md"
                    />
                  </div>
                </div>
                
                <button
                  onClick={handleGenerateRSA}
                  className="w-full bg-blue-500 hover:bg-blue-600 text-white font-medium py-2 px-4 rounded-md transition duration-300"
                >
                  Generate RSA Keys
                </button>
              </div>
              
              {rsaKeys && (
                <div className="mt-4 p-4 bg-gray-50 rounded-md">
                  <h4 className="font-medium text-gray-700 mb-2">Generated Keys:</h4>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div>p = {rsaKeys.p.toString()}</div>
                    <div>q = {rsaKeys.q.toString()}</div>
                    <div>n = {rsaKeys.n.toString()}</div>
                    <div>φ(n) = {rsaKeys.phi.toString()}</div>
                    <div>e = {rsaKeys.e.toString()}</div>
                    <div>
                      d = {showPrivateKey ? rsaKeys.d.toString() : '••••••••'}
                      <button
                        onClick={() => setShowPrivateKey(!showPrivateKey)}
                        className="ml-2 text-xs bg-gray-200 hover:bg-gray-300 px-2 py-1 rounded"
                      >
                        {showPrivateKey ? 'Hide' : 'Show'}
                      </button>
                      <button
                        onClick={() => copyToClipboard(rsaKeys.d)}
                        className="ml-2 text-xs bg-gray-200 hover:bg-gray-300 px-2 py-1 rounded"
                      >
                        Copy
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
            
            {/* Step 2: Encryption */}
            <div className="mb-8">
              <h3 className="text-xl font-semibold text-gray-700 mb-3">Step 2: Encrypt Message</h3>
              <p className="text-gray-600 mb-3 text-sm">
                To encrypt a message, we convert it to a number and raise it to the power of the public exponent, 
                then take the modulus with respect to n. This process is easy to compute but difficult to reverse 
                without knowing the private key.
              </p>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Message to Encrypt
                  </label>
                  <input
                    type="text"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    className="w-full p-2 border border-gray-300 rounded-md"
                  />
                </div>
                
                <button
                  onClick={handleEncrypt}
                  disabled={!rsaKeys}
                  className={`w-full font-medium py-2 px-4 rounded-md transition duration-300 ${
                    rsaKeys 
                      ? 'bg-green-500 hover:bg-green-600 text-white' 
                      : 'bg-gray-300 text-gray-500 cursor-not-allowed'
                  }`}
                >
                  Encrypt Message
                </button>
                
                {ciphertext !== null && (
                  <div className="p-4 bg-green-50 rounded-md">
                    <h4 className="font-medium text-gray-700 mb-2">Ciphertext:</h4>
                    <div className="flex items-center">
                      <code className="flex-grow bg-white p-2 rounded border">
                        {ciphertext.toString()}
                      </code>
                      <button
                        onClick={() => copyToClipboard(ciphertext)}
                        className="ml-2 bg-gray-200 hover:bg-gray-300 px-3 py-2 rounded"
                      >
                        Copy
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
            
            {/* Step 3: Decryption */}
            <div>
              <h3 className="text-xl font-semibold text-gray-700 mb-3">Step 3: Decrypt Message</h3>
              <p className="text-gray-600 mb-3 text-sm">
                Decryption uses the private key to reverse the encryption process. We raise the ciphertext to 
                the power of the private exponent and take the modulus with respect to n, recovering the 
                original message.
              </p>
              
              <button
                onClick={handleDecrypt}
                disabled={ciphertext === null}
                className={`w-full font-medium py-2 px-4 rounded-md transition duration-300 ${
                  ciphertext !== null
                    ? 'bg-purple-500 hover:bg-purple-600 text-white'
                    : 'bg-gray-300 text-gray-500 cursor-not-allowed'
                }`}
              >
                Decrypt Ciphertext
              </button>
              
              {plaintext && (
                <div className="mt-4 p-4 bg-purple-50 rounded-md">
                  <h4 className="font-medium text-gray-700 mb-2">Decrypted Plaintext:</h4>
                  <div className="bg-white p-2 rounded border">
                    {plaintext}
                  </div>
                </div>
              )}
            </div>
          </div>
          
          {/* Diffie-Hellman Section */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-2xl font-bold text-gray-800 mb-4">Diffie-Hellman Key Exchange</h2>
            
            {/* Theory Explanation */}
            <div className="mb-6 p-4 bg-green-50 rounded-lg">
              <h3 className="text-lg font-semibold text-gray-700 mb-2">How Diffie-Hellman Works</h3>
              <p className="text-gray-600 text-sm">
                Diffie-Hellman allows two parties to create a shared secret key over an insecure channel. 
                It uses the property that (g<sup>a</sup>)<sup>b</sup> = (g<sup>b</sup>)<sup>a</sup> = g<sup>ab</sup>, 
                so both parties can compute the same value without ever transmitting their private values.
              </p>
            </div>
            
            {/* Step 1: Setup */}
            <div className="mb-8">
              <h3 className="text-xl font-semibold text-gray-700 mb-3">Step 1: Choose Parameters</h3>
              <p className="text-gray-600 mb-3 text-sm">
                Both parties agree on public parameters: a large prime number p and a base g (generator). 
                These values can be shared openly as they are not secret.
              </p>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Prime (p)
                  </label>
                  <select
                    value={dhP.toString()}
                    onChange={(e) => setDhP(BigInt(e.target.value))}
                    className="w-full p-2 border border-gray-300 rounded-md"
                  >
                    {samplePrimes.map((prime) => (
                      <option key={prime.value} value={prime.value.toString()}>
                        {prime.label}
                      </option>
                    ))}
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Generator (g)
                  </label>
                  <select
                    value={dhG.toString()}
                    onChange={(e) => setDhG(BigInt(e.target.value))}
                    className="w-full p-2 border border-gray-300 rounded-md"
                  >
                    {sampleGenerators.map((gen) => (
                      <option key={gen.value} value={gen.value.toString()}>
                        {gen.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
            
            {/* Step 2: Key Generation */}
            <div className="mb-8">
              <h3 className="text-xl font-semibold text-gray-700 mb-3">Step 2: Generate Keys</h3>
              <p className="text-gray-600 mb-3 text-sm">
                Each party generates their own private key (a secret number) and computes a public key by 
                raising the base g to the power of their private key, modulo p. The public keys are then 
                exchanged between the parties.
              </p>
              
              <button
                onClick={handleGenerateDH}
                className="w-full bg-blue-500 hover:bg-blue-600 text-white font-medium py-2 px-4 rounded-md transition duration-300"
              >
                Generate DH Keys
              </button>
              
              {aliceKeys && bobKeys && (
                <div className="mt-4 space-y-4">
                  <div className="p-4 bg-blue-50 rounded-md">
                    <h4 className="font-medium text-gray-700 mb-2">Alice's Keys:</h4>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div>
                        Private (a) = {aliceKeys.privateKey.toString()}
                        <button
                          onClick={() => copyToClipboard(aliceKeys.privateKey)}
                          className="ml-2 text-xs bg-gray-200 hover:bg-gray-300 px-2 py-1 rounded"
                        >
                          Copy
                        </button>
                      </div>
                      <div>
                        Public (A) = {aliceKeys.publicKey.toString()}
                        <button
                          onClick={() => copyToClipboard(aliceKeys.publicKey)}
                          className="ml-2 text-xs bg-gray-200 hover:bg-gray-300 px-2 py-1 rounded"
                        >
                          Copy
                        </button>
                      </div>
                    </div>
                  </div>
                  
                  <div className="p-4 bg-green-50 rounded-md">
                    <h4 className="font-medium text-gray-700 mb-2">Bob's Keys:</h4>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div>
                        Private (b) = {bobKeys.privateKey.toString()}
                        <button
                          onClick={() => copyToClipboard(bobKeys.privateKey)}
                          className="ml-2 text-xs bg-gray-200 hover:bg-gray-300 px-2 py-1 rounded"
                        >
                          Copy
                        </button>
                      </div>
                      <div>
                        Public (B) = {bobKeys.publicKey.toString()}
                        <button
                          onClick={() => copyToClipboard(bobKeys.publicKey)}
                          className="ml-2 text-xs bg-gray-200 hover:bg-gray-300 px-2 py-1 rounded"
                        >
                          Copy
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
            
            {/* Step 3: Compute Shared Secret */}
            <div>
              <h3 className="text-xl font-semibold text-gray-700 mb-3">Step 3: Compute Shared Secret</h3>
              <p className="text-gray-600 mb-3 text-sm">
                Each party uses the other's public key and their own private key to compute the shared secret. 
                Due to the mathematical property mentioned above, both parties arrive at the same value, 
                which can be used as a symmetric encryption key.
              </p>
              
              <button
                onClick={handleComputeSharedSecret}
                disabled={!aliceKeys || !bobKeys}
                className={`w-full font-medium py-2 px-4 rounded-md transition duration-300 mb-4 ${
                  aliceKeys && bobKeys
                    ? 'bg-purple-500 hover:bg-purple-600 text-white'
                    : 'bg-gray-300 text-gray-500 cursor-not-allowed'
                }`}
              >
                Compute Shared Secrets
              </button>
              
              {sharedSecret && (
                <div className="space-y-4">
                  <div className="p-4 bg-purple-50 rounded-md">
                    <h4 className="font-medium text-gray-700 mb-2">Computed Shared Secrets:</h4>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div>Alice computes: B<sup>a</sup> mod p = {sharedSecret.alice.toString()}</div>
                      <div>Bob computes: A<sup>b</sup> mod p = {sharedSecret.bob.toString()}</div>
                    </div>
                  </div>
                  
                  <div className="p-4 rounded-md text-center">
                    <h4 className="font-medium text-gray-700 mb-2">Verification:</h4>
                    {verificationResult ? (
                      <div className="text-green-600 font-bold">
                        ✓ Success! Both parties have the same shared secret.
                      </div>
                    ) : (
                      <div className="text-red-600 font-bold">
                        ✗ Failed! Shared secrets do not match.
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
        
        <footer className="mt-12 text-center text-gray-600 text-sm">
          <p>
            This educational demo shows the mathematical foundations of RSA encryption and Diffie-Hellman key exchange.
            For production use, always use well-tested cryptographic libraries.
          </p>
          <p className="mt-2">
            Created by the team: Goodwell Sreejith S, Vasudha, Nikhil
          </p>
        </footer>
      </div>
    </div>
  );
}