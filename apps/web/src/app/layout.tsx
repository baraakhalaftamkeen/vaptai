import "./globals.css";
import type { Metadata } from "next";
import Nav from "@/components/Nav";
import ApprovalDock from "@/components/ApprovalDock";

export const metadata: Metadata = {
  title: "VAPT-AI V2",
  description: "Authorized security-assessment platform — internal beta",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="min-h-screen flex flex-col md:flex-row">
          <Nav />
          <main className="flex-1 min-w-0 p-4 md:p-8">{children}</main>
        </div>
        <ApprovalDock />
      </body>
    </html>
  );
}
