import { NextResponse } from 'next/server';

export async function POST(request) {
  try {
    // 1) Parse JSON body from the incoming request
    const { email, password } = await request.json();

    // 2) Forward to rust server
    const rustRes = await fetch('http://localhost:8000/signup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    // 3) If Rust returns an error, pass it along
    if (!rustRes.ok) {
      const errorData = await rustRes.json().catch(() => ({}));
	  if (rustRes.status === 400) {
		return NextResponse.json({ error: 'Invalid email or password' }, { status: 400 });
	  }
      return NextResponse.json(errorData, { status: rustRes.status });
    }

    // 4) On success, pass along the response
    const data = await rustRes.json();
    return NextResponse.json(data, { status: 200 });
  } catch (error) {
    console.error('Signup error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
