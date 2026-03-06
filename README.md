# jwtdecode

Paste any JWT token — get a decoded, annotated breakdown.

![jwtdecode screenshot](screenshot.png)

## What it does

- Colorized token visualizer (header · payload · signature)
- Decoded header with algorithm and key ID explained
- Decoded payload with all claims annotated (iss, sub, exp, iat, and more)
- Expiry status — expired, valid, or no expiration
- Timestamps shown as human-readable dates with relative time
- Signature presence noted (verification requires the secret key)

## Stack

- **Runtime** — [Bun](https://bun.sh)
- **Framework** — [Hono](https://hono.dev) with JSX SSR
- **Styling** — Tailwind CSS (CDN)

## Run locally

```bash
bun install
bun run dev
```

Open [http://localhost:3000](http://localhost:3000).

## License

MIT
