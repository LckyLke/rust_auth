import { NextResponse } from 'next/server';

export async function POST(request) {
  try {
    const { email, password } = await request.json();
    const rustRes = await fetch('http://localhost:8000/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!rustRes.ok) {
      const errorData = await rustRes.json().catch(() => ({}));
      return NextResponse.json(errorData, { status: rustRes.status });
    }

    const data = await rustRes.json();
    return NextResponse.json(data, { status: 200 });
  } catch (error) {
    console.error('Signup error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
