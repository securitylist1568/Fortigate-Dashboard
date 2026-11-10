import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: '資安防護清單與威脅情資自動化更新系統',
  description:
    'Cyber Threat Intelligence & Automated Blocklist Management System (AES-256-GCM Security Vault)',
  robots: {
    index: false,
    follow: false,
    nocache: true,
    googleBot: {
      index: false,
      follow: false,
      noimageindex: true,
    },
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-TW">
      <body className="antialiased selection:bg-sky-500 selection:text-white">
        {children}
      </body>
    </html>
  );
}
