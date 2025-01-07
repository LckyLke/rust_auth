import { NextResponse } from 'next/server';
import { jwtVerify } from 'jose';

const ADMIN_PATHS = ['/admin'];
const USER_PATHS = ['/user'];
// For convenience, define your public routes:
const PUBLIC_PATHS = ['/', '/login'];

export async function middleware(req) {
  const { pathname } = req.nextUrl;

  // Load secret key from environment variables
  const secretKey = process.env.SECRET_KEY;
  if (!secretKey) {
    throw new Error('SECRET_KEY is not defined in environment variables');
  }
  const secretBuffer = new TextEncoder().encode(secretKey.trim());

  // user is on public routes, check if already logged in
  if (PUBLIC_PATHS.includes(pathname)) {
    const token = req.cookies.get('token')?.value;
    if (token) {
      try {
        const { payload } = await jwtVerify(token, secretBuffer);
        const role = payload.role;
        console.log(payload);
        // If valid token, redirect based on role:
        if (role === 'Admin') {
          return NextResponse.redirect(new URL('/admin', req.url));
        } else {
          // If user, or any other recognized role, redirect accordingly:
          return NextResponse.redirect(new URL('/user', req.url));
        }
      } catch (error) {
        // Token verification failed -> ignore and let user continue to public route
        console.error('JWT verification failed on public route:', error);
      }
    }
    return NextResponse.next();
  }

  // If user is trying to access protected routes:
  if (ADMIN_PATHS.includes(pathname) || USER_PATHS.includes(pathname)) {
    // Extract token:
    const token = req.cookies.get('token')?.value;
    if (!token) {
      // No token -> must log in
      return NextResponse.redirect(new URL('/login', req.url));
    }

    // Verify token:
    try {
      const { payload } = await jwtVerify(token, secretBuffer);
      const userRole = payload.role;

      // If ADMIN path but user is not Admin, redirect to /user:
      if (ADMIN_PATHS.includes(pathname) && userRole !== 'Admin') {
        return NextResponse.redirect(new URL('/user', req.url));
      }

      // If everything passes, allow:
      return NextResponse.next();
    } catch (error) {
      // If token is invalid or expired -> must log in again
      console.error('JWT verification failed on protected route:', error);
      return NextResponse.redirect(new URL('/login', req.url));
    }
  }

  // For anything else not matched above, just continue:
  return NextResponse.next();
}

export const config = {
  matcher: ['/:path*'],
};
