import type { ReactNode } from 'react';

export const metadata = { title: 'Демо auth-v3' };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="ru">
      <body style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 640, margin: '40px auto', padding: '0 16px' }}>
        {children}
      </body>
    </html>
  );
}
