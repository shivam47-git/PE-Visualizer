import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'PE Visualizer — Static Analysis',
  description: 'Comprehensive PE32/PE64 static analysis: disassembly, YARA, entropy, imports, exports, resources, anomaly detection',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-200 antialiased overflow-hidden">{children}</body>
    </html>
  );
}
