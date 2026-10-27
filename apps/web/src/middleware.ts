import { NextRequest, NextResponse } from "next/server";

// Server-side gate: no session cookie -> redirect to /login before any protected
// page renders. The cookie is HttpOnly, so middleware (not the browser JS) checks it.
// Cookie presence is a cheap gate; the API still authorizes every request, and the
// client redirects to /login on a 401 from a stale cookie.
const PUBLIC_PATHS = ["/login"];
const COOKIE = "vapt_session";

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const hasSession = req.cookies.has(COOKIE);
  const isPublic = PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"));

  if (!hasSession && !isPublic) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }
  if (hasSession && pathname === "/login") {
    const url = req.nextUrl.clone();
    url.pathname = "/dashboard";
    url.search = "";
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  // Run on pages only. Exclude /api/* (the backend enforces its own auth; gating
  // these here would block the login request itself) and Next internals/assets.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
