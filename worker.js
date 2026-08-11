// Verifies Stripe webhook events server-side and is the ONLY thing
// permitted to mark a purchase as paid. The client must never be trusted
// to self-report payment status — see index.html PaymentScreen/App for
// the corresponding client-side changes.
//
// Required secrets (set with `wrangler secret put <NAME>`):
//   STRIPE_WEBHOOK_SECRET      — from the Stripe Dashboard webhook config
//   SUPABASE_SERVICE_ROLE_KEY  — from Supabase Project Settings → API
//     (service_role key, NOT the anon key — this bypasses RLS so it must
//     stay a server-side secret and never be exposed to the client)

const SUPA_URL = "https://nrtovlmelrwvezwhkdoh.supabase.co";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/stripe-webhook" && request.method === "POST") {
      return handleStripeWebhook(request, env);
    }

    // Everything else is the static app/PWA files.
    const response = await env.ASSETS.fetch(request);
    return withSecurityHeaders(response);
  },
};

// No CSP here on purpose: this app runs Babel standalone in the browser to
// transpile JSX at runtime, which requires 'unsafe-eval' to do anything —
// a CSP without that would break the app, and one with it provides little
// real XSS protection anyway. These headers are all safe, no-tradeoff wins.
function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("X-Frame-Options", "DENY"); // clickjacking protection
  headers.set("X-Content-Type-Options", "nosniff"); // stop MIME-sniffing
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function handleStripeWebhook(request, env) {
  const signatureHeader = request.headers.get("Stripe-Signature");
  const rawBody = await request.text();

  if (!signatureHeader || !env.STRIPE_WEBHOOK_SECRET) {
    return new Response("Missing signature or webhook secret", { status: 400 });
  }

  const verified = await verifyStripeSignature(rawBody, signatureHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!verified) {
    return new Response("Invalid signature", { status: 400 });
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const userId = session.client_reference_id;

    if (!userId) {
      // Nothing we can tie this payment to — log and acknowledge so Stripe
      // doesn't retry, but this should not happen if the client always
      // includes client_reference_id when redirecting to Stripe.
      console.log("checkout.session.completed with no client_reference_id", session.id);
      return new Response("ok", { status: 200 });
    }

    try {
      await recordPurchase(userId, env);
    } catch (err) {
      console.log("Failed to record purchase for", userId, String(err));
      // Return 500 so Stripe retries the webhook — we want it to keep
      // trying until it succeeds rather than silently losing the payment.
      return new Response("Failed to record purchase", { status: 500 });
    }
  }

  return new Response("ok", { status: 200 });
}

async function recordPurchase(userId, env) {
  // Stripe explicitly documents that the same webhook event can be
  // delivered more than once (retries, at-least-once delivery), and the
  // access check elsewhere in this app only cares whether ANY purchase
  // row exists for a user — so skip the insert if one is already there,
  // rather than accumulating duplicate rows on every retry.
  const existing = await fetch(
    `${SUPA_URL}/rest/v1/purchases?user_id=eq.${encodeURIComponent(userId)}&select=id&limit=1`,
    {
      headers: {
        "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
    }
  );
  if (!existing.ok) {
    throw new Error(`Supabase lookup failed: ${existing.status} ${await existing.text()}`);
  }
  const rows = await existing.json();
  if (Array.isArray(rows) && rows.length > 0) {
    return; // already recorded, nothing to do
  }

  const res = await fetch(`${SUPA_URL}/rest/v1/purchases`, {
    method: "POST",
    headers: {
      "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
      "Authorization": `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      "Prefer": "return=minimal",
    },
    body: JSON.stringify({
      user_id: userId,
      product: "12_week_plan",
      purchased_at: new Date().toISOString(),
    }),
  });
  if (!res.ok) {
    throw new Error(`Supabase insert failed: ${res.status} ${await res.text()}`);
  }
}

// Implements Stripe's documented webhook signature scheme:
// https://stripe.com/docs/webhooks/signatures
async function verifyStripeSignature(rawBody, signatureHeader, secret) {
  // During Stripe secret rotation the header can contain more than one
  // v1=<sig> pair (signed with both the old and new secret) — collect all
  // of them and accept if any one matches, rather than only the last.
  let timestamp = null;
  const providedSignatures = [];
  for (const pair of signatureHeader.split(",")) {
    const [k, v] = pair.split("=");
    if (k === "t") timestamp = v;
    else if (k === "v1" && v) providedSignatures.push(v);
  }
  if (!timestamp || providedSignatures.length === 0) return false;

  // Reject payloads older than 5 minutes to mitigate replay of a captured request.
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(age) || age > 300) return false;

  const signedPayload = `${timestamp}.${rawBody}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signatureBytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPayload));
  const expectedSignature = [...new Uint8Array(signatureBytes)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return providedSignatures.some((sig) => timingSafeEqual(expectedSignature, sig));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
