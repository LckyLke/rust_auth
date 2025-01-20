import { NextResponse } from 'next/server';

export async function POST(request) {
  try {
    const refreshToken = request.cookies.get('refresh_token')?.value;

    //1) If no refresh token in cookies, then user must re-login
    if (!refreshToken) {
      return NextResponse.json({ error: 'No refresh token found' }, { status: 401 });
    }

    // 2) Call the Rust server’s /refresh
    const rustResponse = await fetch('http://localhost:8000/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    // If Rust server says invalid or expired
    if (!rustResponse.ok) {
      const errorData = await rustResponse.json().catch(() => ({}));
      return NextResponse.json(errorData, { status: rustResponse.status });
    }

    // 3) Extract new tokens
    const data = await rustResponse.json();
    const { access_token, refresh_token } = data;

    // 4) Set the new cookies
    const res = NextResponse.json({ message: 'Tokens refreshed' });

    // Overwrite the old short-living token
    res.cookies.set('token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60, // 1 hour
      sameSite: 'strict',
      path: '/',
    });

    // Overwrite the old refresh token, if any
    if (refresh_token) {
      res.cookies.set('refresh_token', refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 60 * 60 * 24 * 14, // 14 days
        sameSite: 'strict',
        path: '/',
      });
    }

    return res;
  } catch (err) {
    console.error('Refresh error:', err);
    return NextResponse.json({ error: 'Failed to refresh token' }, { status: 500 });
  }
}
