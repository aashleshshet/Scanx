export default {
  outputFileTracingIncludes: { '/workspace/[[...path]]': ['./src/api_sentry/web/static/**/*'] },
  async headers() { return [{ source: '/:path*', headers: [
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'X-Frame-Options', value: 'DENY' },
    { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }
  ] }]; }
};
