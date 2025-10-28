# Cryptography Demo - Summary

This project demonstrates two fundamental cryptographic algorithms:

1. **RSA Encryption** - An asymmetric encryption algorithm
2. **Diffie-Hellman Key Exchange** - A method for securely exchanging cryptographic keys

## Implementation Details

### RSA Encryption

The RSA implementation includes:

- Prime number generation using Miller-Rabin primality testing
- Key generation with configurable bit sizes (16, 32, 64 bits)
- Modular exponentiation for encryption/decryption
- UTF-8 encoding/decoding for message handling
- Display of all intermediate values (p, q, n, φ(n), e, d)

### Diffie-Hellman Key Exchange

The Diffie-Hellman implementation includes:

- Configurable prime (p) and generator (g) parameters
- Private key generation
- Public key calculation (A = g^a mod p, B = g^b mod p)
- Shared secret computation (s = B^a mod p = A^b mod p)
- Verification that both parties arrive at the same shared secret

## Educational Enhancements

### Theoretical Explanations
We've added comprehensive theoretical explanations to make the cryptographic concepts easy to understand:

1. **RSA Theory Section**:
   - Clear explanation of the mathematical foundation
   - Step-by-step breakdown of how RSA works
   - Explanation of why RSA is secure

2. **Diffie-Hellman Theory Section**:
   - Clear explanation of the key exchange protocol
   - Step-by-step breakdown of how Diffie-Hellman works
   - Explanation of why Diffie-Hellman is secure

### Team Attribution
The application now clearly displays the team members who created this project:
- Goodwell Sreejith S
- Vasudha
- Nikhil

### Technical Stack

- **Next.js 14** - React framework for building the web application
- **React** - UI library for building interactive components
- **Tailwind CSS** - Utility-first CSS framework for styling
- **JavaScript BigInt** - Native big integer support for cryptographic calculations

## Educational Features

- Step-by-step visualization of cryptographic processes
- Interactive controls for parameter adjustment
- Clear display of intermediate values
- Copy-to-clipboard functionality for keys and values
- Security disclaimers about production usage
- Detailed theoretical explanations of both algorithms

## Security Notes

This implementation is for educational purposes only:

- Uses small primes for demonstration clarity
- Does not include padding schemes required for secure RSA
- Uses Math.random() which is not cryptographically secure
- Lacks many security features required for production use

For production applications, always use well-tested cryptographic libraries.