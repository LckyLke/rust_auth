import { NextResponse } from 'next/server';
import { jwtVerify } from 'jose';

const ADMIN_PATHS = ['/admin'];
const USER_PATHS = ['/user'];
const PUBLIC_PATHS = ['/', '/login', '/signup'];

export async function middleware(req) {
  const { pathname } = req.nextUrl;
  const token = req.cookies.get('token')?.value;
  const refreshToken = req.cookies.get('refresh_token')?.value;

  // 1) If on a public route, no token required:
  if (PUBLIC_PATHS.includes(pathname)) {
    // If the user DOES have an access token, optionally redirect them
    if (token) {
      try {
        const { payload } = await jwtVerify(token, getSecretKey());
        // If valid token, redirect based on role:
        if (payload.role === 'Admin') {
          return NextResponse.redirect(new URL('/admin', req.url));
        } else {
          return NextResponse.redirect(new URL('/user', req.url));
        }
      } catch (e) {
        // If token invalid, continue to the public route
      }
    }
    return NextResponse.next();
  }

  // 2) For protected routes (ADMIN or USER):
  if (ADMIN_PATHS.includes(pathname) || USER_PATHS.includes(pathname)) {
    // If we do NOT have an access token...
    if (!token) {
      // ...then see if we can refresh using the refresh token.
      if (!refreshToken) {
        // No refresh token either → must log in
        return NextResponse.redirect(new URL('/login', req.url));
      } else {
        // Attempt to refresh
        const refreshSucceeded = await attemptRefresh(req);
        if (!refreshSucceeded) {
          return NextResponse.redirect(new URL('/login', req.url));
        }
        // If refresh succeeded, proceed
        return NextResponse.next();
      }
    }

    // If we do have a token, verify it:
    try {
      const { payload } = await jwtVerify(token, getSecretKey());
      // If ADMIN path, ensure the user is actually Admin:
      if (ADMIN_PATHS.includes(pathname) && payload.role !== 'Admin') {
        return NextResponse.redirect(new URL('/user', req.url));
      }
      // If verified, let them through
      return NextResponse.next();
    } catch (e) {
      // If token verification fails, try refresh
      console.error('Token invalid/expired, attempting refresh:', e);

      if (!refreshToken) {
        return NextResponse.redirect(new URL('/login', req.url));
      }
      const refreshSucceeded = await attemptRefresh(req);
      if (!refreshSucceeded) {
        return NextResponse.redirect(new URL('/login', req.url));
      }
      return NextResponse.next();
    }
  }

  // For routes not matched, do nothing special
  return NextResponse.next();
}

/**
 * Attempt to call our Next.js /api/refresh route,
 * forwarding cookies. Returns true if successful.
 */
async function attemptRefresh(req) {
  try {
    const refreshUrl = new URL('/api/refresh', req.url);
    const refreshResponse = await fetch(refreshUrl, {
      method: 'POST',
      // forward cookies so /api/refresh can read them
      headers: { cookie: req.headers.get('cookie') || '' },
    });

    if (!refreshResponse.ok) {
      return false;
    }

    // If refresh was successful, we get new cookies back in set-cookie header
    const setCookie = refreshResponse.headers.get('set-cookie');
    if (setCookie) {
      const newResponse = NextResponse.next();
      newResponse.headers.set('set-cookie', setCookie);
      // Commit the new response to the environment
      return newResponse;
    }
    return true;
  } catch (err) {
    console.error('Refresh error in middleware:', err);
    return false;
  }
}

function getSecretKey() {
  const secretKey = process.env.SECRET_KEY;
  if (!secretKey) {
    throw new Error('SECRET_KEY is not defined in environment variables');
  }
  return new TextEncoder().encode(secretKey.trim());
}

export const config = {
  matcher: ['/:path*'],
};
