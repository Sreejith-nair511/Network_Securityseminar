# Cryptography Demo

This is a Next.js application that demonstrates RSA encryption and Diffie-Hellman key exchange using pure JavaScript BigInt operations. The implementation is for educational purposes only and uses small primes for clarity.

## Team

This project was created by:
- Goodwell Sreejith S
- Vasudha
- Nikhil

## Features

- **RSA Encryption Demo**:
  - Generates RSA key pairs with configurable prime sizes (16, 32, or 64 bits)
  - Shows all intermediate values (p, q, n, φ(n), e, d)
  - Encrypts and decrypts text messages
  - Step-by-step visualization of the process
  - Clear theoretical explanations of how RSA works

- **Diffie-Hellman Key Exchange Demo**:
  - Allows selection of prime and generator values
  - Generates private/public key pairs for Alice and Bob
  - Computes shared secrets on both sides
  - Verifies that both parties arrive at the same shared secret
  - Detailed explanation of the Diffie-Hellman protocol

## How It Works

### RSA Encryption

RSA is an asymmetric encryption algorithm that uses a pair of keys - a public key for encryption and a private key for decryption.

**Mathematical Foundation:**
1. Choose two large prime numbers (p and q)
2. Compute n = p × q (this is the modulus)
3. Compute φ(n) = (p-1) × (q-1) (Euler's totient function)
4. Choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
5. Compute d such that (d × e) mod φ(n) = 1 (modular inverse)
6. Public key is (n, e), Private key is (n, d)
7. To encrypt: c = m^e mod n
8. To decrypt: m = c^d mod n

**Why it's secure:** It's computationally difficult to factor large numbers, making it hard to derive the private key from the public key.

### Diffie-Hellman Key Exchange

Diffie-Hellman allows two parties to establish a shared secret over an insecure channel without ever transmitting the secret itself.

**Mathematical Foundation:**
1. Agree on public numbers: prime p and base g
2. Alice chooses private key a and computes public key A = g^a mod p
3. Bob chooses private key b and computes public key B = g^b mod p
4. Alice and Bob exchange public keys
5. Alice computes shared secret s = B^a mod p
6. Bob computes shared secret s = A^b mod p
7. Both arrive at the same shared secret: g^(ab) mod p

**Why it's secure:** The discrete logarithm problem makes it computationally infeasible to determine the private keys from the public information.

## Getting Started

### Prerequisites

- Node.js (version 16 or higher)

### Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Run the development server:
   ```bash
   npm run dev
   ```

3. Open [http://localhost:3000](http://localhost:3000) in your browser to see the demo.

### Available Scripts

- `npm run dev` - Runs the app in development mode
- `npm run build` - Builds the app for production
- `npm run start` - Runs the built app in production mode

## How to Use

### RSA Demo

1. Select a prime size (16 bits recommended for speed)
2. Optionally enter manual prime numbers (must be prime)
3. Click "Generate RSA Keys" to create a key pair
4. Enter a message to encrypt
5. Click "Encrypt Message" to see the ciphertext
6. Click "Decrypt Ciphertext" to recover the original message

### Diffie-Hellman Demo

1. Select a prime and generator from the dropdowns (defaults are fine for demo)
2. Click "Generate DH Keys" to create key pairs for Alice and Bob
3. Click "Compute Shared Secrets" to calculate the shared secret on both sides
4. The verification will show whether both parties arrived at the same secret

## Implementation Details

All cryptographic operations are implemented using JavaScript's native BigInt type:

- **Miller-Rabin primality testing** with 5 rounds for prime generation
- **Modular exponentiation** for efficient computation
- **Extended Euclidean algorithm** for finding modular inverses
- **UTF-8 encoding/decoding** for message conversion

## Security Notice

⚠️ **This demo is for educational purposes only!**

- Uses small primes for demonstration clarity (real RSA uses 2048+ bit primes)
- Not suitable for production cryptographic applications
- Does not include important security features like padding schemes
- Random number generation is not cryptographically secure

For production applications, always use well-tested cryptographic libraries like OpenSSL, WebCrypto API, or sodium.js.

## Files

- [`src/app/page.js`](src/app/page.js) - Contains all UI and cryptographic implementation