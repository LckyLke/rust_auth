import { NextResponse } from 'next/server';

export async function POST(request) {
  try {
    const { email, password } = await request.json();
    // 1. Send credentials to your Rust server
    const response = await fetch('http://localhost:8000/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    // 2. If invalid credentials or server error
    if (!response.ok) {
      // e.g. 404 => user not found, 401 => wrong credentials, etc.
      const errorData = await response.json().catch(() => ({}));
      return NextResponse.json(errorData, { status: response.status });
    }

    // 3. Extract tokens from Rust server’s response
    const { token, refresh_token } = await response.json();

    // 4. Create a NextResponse, store both tokens as HTTP-only cookies
    const nextResponse = NextResponse.json({ message: 'Login successful' });
    nextResponse.cookies.set('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60, // 1 hour
      sameSite: 'strict',
      path: '/',
    });

    nextResponse.cookies.set('refresh_token', refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 24 * 14, // e.g. 14 days
      sameSite: 'strict',
      path: '/',
    });

    return nextResponse;
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json({ message: 'Internal server error' }, { status: 500 });
  }
}
