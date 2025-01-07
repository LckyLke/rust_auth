import { NextResponse } from 'next/server';

export async function POST(request) {
  try {
    // 1. Parse JSON body from the request
    const { email, password } = await request.json();

    // 2. Send credentials to Rust server
    const response = await fetch('http://localhost:8000/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    // 3. If invalid credentials or server error
    if (!response.ok) {
      if (response.status === 404) {
        return NextResponse.json({ message: 'User not found' }, { status: response.status });
      }
      return NextResponse.json({ message: 'Invalid credentials' }, { status: response.status });
    }

    // 4. Extract token from Rust server’s response
    const data = await response.json();
    console.log(data);
    const { token } = data;

    // 5. Create a NextResponse and set the HTTP-only cookie
    const nextResponse = NextResponse.json({ message: 'Login successful' });
    nextResponse.cookies.set('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
      maxAge: 60 * 60, // 1 hour
      sameSite: 'strict',
      path: '/',
    });

    return nextResponse;
  } catch (error) {
    console.error(error);
    return NextResponse.json({ message: 'Internal server error' }, { status: 500 });
  }
}
