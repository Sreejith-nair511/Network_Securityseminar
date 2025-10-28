import './globals.css';
 
export const metadata = {
  title: 'Cryptography Demo',
  description: 'Interactive demonstration of RSA and Diffie-Hellman key exchange',
};
 
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}