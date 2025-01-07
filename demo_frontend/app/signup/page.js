"use client";
import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function Signup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const router = useRouter();

  const handleSignup = async (e) => {
    e.preventDefault();

    try {
      const res = await fetch('/api/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (res.ok) {
        alert('Signup successful!');
        setEmail('');
        setPassword('');
        router.push('/user');
      } else {
        const data = await res.json();
        alert(`Signup failed: ${data.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error(error);
      alert('Something went wrong during signup.');
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form 
        className="bg-white p-6 rounded shadow-md w-full max-w-sm"
        onSubmit={handleSignup}
      >
        <h2 className="text-2xl mb-6">Sign Up</h2>
        <div className="mb-4">
          <label className="block mb-2">Email</label>
          <input
            type="email"
            className="border p-2 w-full"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div className="mb-4">
          <label className="block mb-2">Password</label>
          <input
            type="password"
            className="border p-2 w-full"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button
          type="submit"
          className="bg-green-600 text-white py-2 px-4 rounded hover:bg-green-700"
        >
          Sign Up
        </button>
      </form>
    </div>
  );
}
