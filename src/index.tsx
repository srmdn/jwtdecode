import { Hono } from "hono";
import { decodeJWT, type ClaimInfo, type DecodedJWT } from "./decode";

const app = new Hono();

const EXAMPLE_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMzQ1IiwibmFtZSI6IkphbmUgRG9lIiwiZW1haWwiOiJqYW5lQGV4YW1wbGUuY29tIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTl9.placeholder";

function Layout({ children, title }: { children: any; title?: string }) {
  return (
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>{title ? `${title} — jwtdecode` : "jwtdecode"}</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-white text-slate-900 min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}

function TokenVisualizer({ raw }: { raw: DecodedJWT["raw"] }) {
  return (
    <div class="rounded-lg bg-slate-900 px-4 py-3 font-mono text-xs break-all leading-loose">
      <span class="text-rose-400">{raw.header}</span>
      <span class="text-slate-600">.</span>
      <span class="text-violet-400">{raw.payload}</span>
      <span class="text-slate-600">.</span>
      {raw.signature ? (
        <span class="text-emerald-400">{raw.signature}</span>
      ) : (
        <span class="text-slate-600">{"<no signature>"}</span>
      )}
    </div>
  );
}

function ExpiryBanner({ state, message }: { state: string; message: string }) {
  if (state === "none") return null;
  const cls =
    state === "expired"
      ? "bg-red-50 border border-red-200 text-red-700"
      : "bg-green-50 border border-green-200 text-green-700";
  const icon = state === "expired" ? "✕" : "✓";
  return (
    <div class={`rounded-lg px-4 py-3 text-sm flex items-center gap-2 ${cls}`}>
      <span class="font-semibold">{icon}</span>
      <span>{message}</span>
    </div>
  );
}

function ClaimsTable({ claims }: { claims: ClaimInfo[] }) {
  if (claims.length === 0) return <p class="text-sm text-slate-400">No claims.</p>;
  return (
    <div class="divide-y divide-slate-100">
      {claims.map((c) => (
        <div class="py-3 grid grid-cols-[6rem_1fr] gap-x-4 gap-y-0.5">
          <div>
            <span class="font-mono text-xs text-slate-400">{c.key}</span>
          </div>
          <div>
            <div class="flex items-baseline gap-2 flex-wrap">
              {c.label !== c.key && (
                <span class="text-xs font-semibold text-slate-500">{c.label}</span>
              )}
              <span class={`font-mono text-xs ${c.isTimestamp ? "text-slate-700" : "text-slate-900"}`}>
                {c.formatted}
              </span>
            </div>
            {c.description && (
              <p class="text-xs text-slate-400 mt-0.5">{c.description}</p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function Section({ title, color, children }: { title: string; color: string; children: any }) {
  return (
    <div class="rounded-lg border border-slate-200 overflow-hidden">
      <div class={`px-4 py-2.5 border-b border-slate-200 ${color}`}>
        <span class="text-xs font-semibold uppercase tracking-widest text-slate-500">{title}</span>
      </div>
      <div class="px-4 py-1">{children}</div>
    </div>
  );
}

function Result({ jwt }: { jwt: DecodedJWT }) {
  return (
    <div class="space-y-4">
      <TokenVisualizer raw={jwt.raw} />
      <ExpiryBanner state={jwt.expiry.state} message={jwt.expiry.message} />

      <Section title="Header" color="bg-rose-50">
        <ClaimsTable claims={jwt.headerClaims} />
      </Section>

      <Section title="Payload" color="bg-violet-50">
        <ClaimsTable claims={jwt.payloadClaims} />
      </Section>

      <Section title="Signature" color="bg-emerald-50">
        <div class="py-3 text-sm text-slate-600">
          {jwt.hasSignature ? (
            <span>
              <span class="text-emerald-600 font-semibold">Signature present.</span>{" "}
              This tool only decodes — it cannot verify the signature without the secret key.
            </span>
          ) : (
            <span class="text-slate-400">No signature — this token is unsigned (algorithm: none).</span>
          )}
        </div>
      </Section>
    </div>
  );
}

app.get("/", (c) => {
  const token = c.req.query("token") ?? "";
  const result = token ? decodeJWT(token) : null;

  return c.html(
    <Layout title={token ? "Decoded" : undefined}>
      <div class="max-w-2xl mx-auto px-4 py-12">
        <div class="mb-8">
          <h1 class="text-2xl font-bold tracking-tight">jwtdecode</h1>
          <p class="text-slate-500 mt-1 text-sm">Inspect any JWT token — header, payload, expiry.</p>
        </div>

        <form method="GET" action="/" class="mb-6 space-y-3">
          <textarea
            name="token"
            rows={4}
            placeholder="Paste a JWT token here..."
            spellcheck="false"
            class="w-full font-mono bg-slate-50 border border-slate-200 rounded-lg px-4 py-3 text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent placeholder:text-slate-400 resize-none"
          >
            {token}
          </textarea>
          <div class="flex items-center gap-3">
            <button
              type="submit"
              class="px-5 py-2.5 bg-indigo-600 text-white rounded-lg text-sm font-semibold hover:bg-indigo-700 transition-colors"
            >
              Decode
            </button>
            {!token && (
              <a
                href={`/?token=${encodeURIComponent(EXAMPLE_TOKEN)}`}
                class="text-sm text-slate-500 hover:text-slate-700 underline"
              >
                Try an example
              </a>
            )}
          </div>
        </form>

        {result && !result.valid && (
          <div class="rounded-lg border border-red-200 bg-red-50 px-4 py-3">
            <p class="text-sm text-red-700">
              <span class="font-semibold">Invalid token:</span> {result.error}
            </p>
          </div>
        )}

        {result && result.valid && <Result jwt={result} />}

        <footer class="mt-16 pt-6 border-t border-slate-100">
          <p class="text-xs text-slate-400">
            Decodes only — tokens never leave your browser.{" "}
            Made by{" "}
            <a href="https://github.com/srmdn" class="underline hover:text-slate-600">
              srmdn
            </a>
            .
          </p>
        </footer>
      </div>
    </Layout>
  );
});

export default {
  port: 3000,
  fetch: app.fetch,
};
