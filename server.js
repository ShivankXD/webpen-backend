/**
 * WebPen Premium — Express Backend
 * ─────────────────────────────────────────────────────────────────
 *  Routes:
 *    POST /webhook/paypal          — receives PayPal lifecycle events
 *    POST /paypal/verify-subscription — called by popup after approval
 *    GET  /health                  — uptime check for Render
 *
 *  Stack: Node 18+ · Express · Supabase JS v2 · axios · dotenv
 * ─────────────────────────────────────────────────────────────────
 */

"use strict";

require("dotenv").config();
const express              = require("express");
const axios                = require("axios");
const { createClient }     = require("@supabase/supabase-js");

// ── Validate required env vars at startup ──────────────────────────
const REQUIRED_ENV = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_KEY",
  "PAYPAL_CLIENT_ID",
  "PAYPAL_CLIENT_SECRET",
  "PAYPAL_WEBHOOK_ID",
];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[WebPen] FATAL: Missing env var "${key}". Check your .env file.`);
    process.exit(1);
  }
}

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Supabase client (service-role key — server-side only) ──────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY   // bypasses Row Level Security
);

// ── PayPal base URL ────────────────────────────────────────────────
const PAYPAL_BASE =
  process.env.PAYPAL_MODE === "live"
    ? "https://api-m.paypal.com"
    : "https://api-m.sandbox.paypal.com";

// ─────────────────────────────────────────────────────────────────
//  IMPORTANT: /webhook/paypal MUST receive the raw body buffer so
//  PayPal's HMAC signature verification works correctly.
//  We mount express.raw() ONLY on that route before express.json().
// ─────────────────────────────────────────────────────────────────
app.use(
  "/webhook/paypal",
  express.raw({ type: "application/json" })  // raw Buffer, not parsed JSON
);
app.use(express.json());                      // JSON parser for all other routes

// ══════════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════════

/** Fetch a short-lived PayPal OAuth access token. */
async function getPayPalToken() {
  const { data } = await axios.post(
    `${PAYPAL_BASE}/v1/oauth2/token`,
    "grant_type=client_credentials",
    {
      auth: {
        username: process.env.PAYPAL_CLIENT_ID,
        password: process.env.PAYPAL_CLIENT_SECRET,
      },
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    }
  );
  return data.access_token;
}

/**
 * Verify a PayPal webhook signature via PayPal's own API.
 * Never skip — without this, any attacker can spoof payment events.
 *
 * @param {import('express').Request} req  — must have raw Buffer body
 * @returns {Promise<boolean>}
 */
async function verifyPayPalWebhook(req) {
  const token = await getPayPalToken();

  const payload = {
    auth_algo:         req.headers["paypal-auth-algo"],
    cert_url:          req.headers["paypal-cert-url"],
    transmission_id:   req.headers["paypal-transmission-id"],
    transmission_sig:  req.headers["paypal-transmission-sig"],
    transmission_time: req.headers["paypal-transmission-time"],
    webhook_id:        process.env.PAYPAL_WEBHOOK_ID,
    webhook_event:     JSON.parse(req.body.toString()),  // Buffer → object
  };

  const { data } = await axios.post(
    `${PAYPAL_BASE}/v1/notifications/verify-webhook-signature`,
    payload,
    {
      headers: {
        Authorization:  `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    }
  );

  return data.verification_status === "SUCCESS";
}

// ── Supabase: grant Premium ────────────────────────────────────────
/**
 * Upsert a user row and mark is_premium = true.
 *
 * @param {string}      userId        — the user's `id` (text PK in Supabase)
 * @param {string}      subscriptionId — PayPal subscription ID
 * @param {string|null} email
 */
async function setUserPremium(userId, subscriptionId, email = null) {
  const record = {
    id:               userId,
    is_premium:       true,
    paypal_sub_id:    subscriptionId,
    premium_since:    new Date().toISOString(),
    ...(email ? { email } : {}),
  };

  const { error } = await supabase
    .from("users")
    .upsert(record, { onConflict: "id" });

  if (error) throw new Error(`Supabase upsert failed: ${error.message}`);
}

// ── Supabase: revoke Premium ───────────────────────────────────────
/**
 * Mark is_premium = false when a subscription is cancelled / expired.
 *
 * @param {string} subscriptionId — PayPal subscription ID
 */
async function revokeUserPremium(subscriptionId) {
  const { error } = await supabase
    .from("users")
    .update({ is_premium: false, premium_revoked_at: new Date().toISOString() })
    .eq("paypal_sub_id", subscriptionId);

  if (error) throw new Error(`Supabase revoke failed: ${error.message}`);
}

// ══════════════════════════════════════════════════════════════════
//  ROUTE 1 — POST /webhook/paypal
//
//  Register this URL in PayPal Developer Dashboard → Webhooks.
//  Recommended event subscriptions:
//    • BILLING.SUBSCRIPTION.ACTIVATED
//    • BILLING.SUBSCRIPTION.CANCELLED
//    • BILLING.SUBSCRIPTION.SUSPENDED
//    • BILLING.SUBSCRIPTION.EXPIRED
//    • PAYMENT.SALE.COMPLETED
// ══════════════════════════════════════════════════════════════════
app.post("/webhook/paypal", async (req, res) => {
  // Always respond 200 immediately — PayPal retries on anything else.
  res.sendStatus(200);

  try {
    // ── Step 1: Verify the request is genuinely from PayPal ────────
    const isValid = await verifyPayPalWebhook(req);
    if (!isValid) {
      console.warn("[WebPen Webhook] ⚠ Signature verification FAILED — ignoring event");
      return;
    }

    const event     = JSON.parse(req.body.toString());
    const eventType = event.event_type;
    const resource  = event.resource;

    console.log(`[WebPen Webhook] ✉ Received: ${eventType}`);

    // ── Step 2: Handle each event type ────────────────────────────
    switch (eventType) {

      // Subscription activated (first successful payment)
      case "BILLING.SUBSCRIPTION.ACTIVATED": {
        const subId  = resource.id;
        const email  = resource.subscriber?.email_address ?? null;
        // custom_id should hold your internal user ID; set it when
        // creating the subscription server-side via PayPal's API.
        const userId = resource.custom_id ?? null;

        if (!userId) {
          console.warn("[WebPen Webhook] ⚠ ACTIVATED event missing custom_id — cannot link user");
          break;
        }

        await setUserPremium(userId, subId, email);
        console.log(`[WebPen Webhook] ✓ Activated premium — user=${userId} sub=${subId}`);
        break;
      }

      // Subscription ended (cancelled, expired, or payment failure)
      case "BILLING.SUBSCRIPTION.CANCELLED":
      case "BILLING.SUBSCRIPTION.EXPIRED":
      case "BILLING.SUBSCRIPTION.SUSPENDED": {
        const subId = resource.id;
        await revokeUserPremium(subId);
        console.log(`[WebPen Webhook] ✗ Revoked premium — sub=${subId} reason=${eventType}`);
        break;
      }

      // Successful renewal charge — log for analytics, no DB change needed
      case "PAYMENT.SALE.COMPLETED": {
        const amount   = resource.amount?.total;
        const currency = resource.amount?.currency;
        console.log(`[WebPen Webhook] 💳 Renewal payment: ${currency} ${amount}`);
        break;
      }

      default:
        console.log(`[WebPen Webhook] Unhandled event type: ${eventType}`);
    }

  } catch (err) {
    // Log internally; do NOT send an error response — 200 already sent.
    console.error("[WebPen Webhook] Processing error:", err.message);
  }
});

// ══════════════════════════════════════════════════════════════════
//  ROUTE 2 — POST /paypal/verify-subscription
//
//  Called by popup.js immediately after the user approves in the
//  PayPal window. We re-verify with PayPal before trusting the ID.
//
//  Body: { subscriptionId: string, userId: string }
// ══════════════════════════════════════════════════════════════════
app.post("/paypal/verify-subscription", async (req, res) => {
  const { subscriptionId, userId } = req.body;

  if (!subscriptionId || !userId) {
    return res.status(400).json({ error: "Missing subscriptionId or userId" });
  }

  try {
    // Fetch subscription from PayPal to confirm it is genuinely ACTIVE
    const token = await getPayPalToken();
    const { data: subscription } = await axios.get(
      `${PAYPAL_BASE}/v1/billing/subscriptions/${subscriptionId}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    if (subscription.status !== "ACTIVE") {
      return res.status(402).json({
        isPremium: false,
        error: `Subscription status is "${subscription.status}", not ACTIVE`,
      });
    }

    const email = subscription.subscriber?.email_address ?? null;

    // Write to Supabase
    await setUserPremium(userId, subscriptionId, email);
    console.log(`[WebPen] ✓ Verified & activated premium — user=${userId}`);

    return res.json({ isPremium: true, email });

  } catch (err) {
    console.error("[WebPen] verify-subscription error:", err.message);
    return res.status(500).json({ isPremium: false, error: "Internal server error" });
  }
});

// ── Serve static files from public directory ───────────────────────
const path = require("path");
app.use(express.static(path.join(__dirname, "public")));

// ══════════════════════════════════════════════════════════════════
//  ROUTE 3 — GET /api/user-status
//  Checks the database to verify if a user has premium enabled.
// ══════════════════════════════════════════════════════════════════
app.get("/api/user-status", async (req, res) => {
  const { userId } = req.query;
  if (!userId) {
    return res.status(400).json({ error: "Missing userId" });
  }
  try {
    const { data, error } = await supabase
      .from("users")
      .select("is_premium, email")
      .eq("id", userId)
      .maybeSingle();

    if (error) throw error;

    return res.json({
      isPremium: data ? !!data.is_premium : false,
      email: data ? data.email : null,
    });
  } catch (err) {
    console.error("[WebPen] /api/user-status error:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ══════════════════════════════════════════════════════════════════
//  HEALTH CHECK — GET /health
//  Render uses this to confirm the service is alive.
// ══════════════════════════════════════════════════════════════════
app.get("/health", (_req, res) =>
  res.json({
    status:  "ok",
    service: "webpen-backend",
    ts:      new Date().toISOString(),
  })
);

// ── Start ──────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(
    `[WebPen Backend] 🚀 Running on port ${PORT} | PayPal mode: ${process.env.PAYPAL_MODE ?? "sandbox"}`
  );
});

module.exports = app; // exported for testing
