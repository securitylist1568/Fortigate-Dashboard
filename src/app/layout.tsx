import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: '國立臺灣師範大學 — 資訊安全情資協防暨自動化縱深防禦體系高階主管摘要報告',
  description:
    'NTNU Fortigate-3001F Threat Intelligence Collaborative Defense Executive Dashboard (AES-256-GCM Security Vault)',
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
