import "./globals.css";
import type { Metadata } from "next";
import Nav from "@/components/Nav";
import ApprovalDock from "@/components/ApprovalDock";
import ThemeProvider from "@/components/ThemeProvider";

export const metadata: Metadata = {
  title: "VAPT-AI | Tamkeen Technologies",
  description: "Authorized security-assessment platform — Tamkeen Technologies",
  icons: { icon: "/tamkeen-favicon.svg" },
};

const themeScript = `(function(){try{var t=localStorage.getItem('vapt-theme');if(t==='dark')document.documentElement.setAttribute('data-theme','dark')}catch(e){}})()`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <ThemeProvider>
          <div className="min-h-screen flex flex-col md:flex-row">
            <Nav />
            <main className="flex-1 min-w-0 p-4 md:p-8">{children}</main>
          </div>
          <ApprovalDock />
        </ThemeProvider>
      </body>
    </html>
  );
}
