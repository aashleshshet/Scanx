import { ClerkProvider } from '@clerk/nextjs';
import './style.css';
export const dynamic = 'force-dynamic';
export const metadata = { title: 'Scanx · API security workspace', description: 'Evidence-led API security, with verified email access.' };
export default function Layout({ children }) {
  return <html lang="en"><body><ClerkProvider signInUrl="/sign-in" signUpUrl="/sign-up" signInForceRedirectUrl="/workspace/index.html" signUpForceRedirectUrl="/workspace/index.html">{children}</ClerkProvider></body></html>;
}
