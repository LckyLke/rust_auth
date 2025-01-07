import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center">
      <h1 className="text-2xl font-bold mb-4">Welcome to the App</h1>
      <Link href="/login" className="text-blue-500">Login</Link>
    </div>
  );
}