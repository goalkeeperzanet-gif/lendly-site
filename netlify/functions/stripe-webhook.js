// Netlify Function — receives Stripe's webhook directly, no Supabase
// gateway involved at all. Verifies Stripe's signature using Node's
// built-in crypto (no external packages needed), then records the
// paid email straight into Supabase using the service role key.

const crypto = require("crypto");

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

function verifyStripeSignature(payload, sigHeader, secret) {
  if (!sigHeader) return false;
  const parts = sigHeader.split(",").reduce((acc, part) => {
    const [k, v] = part.split("=");
    acc[k] = v;
    return acc;
  }, {});
  const timestamp = parts["t"];
  const signature = parts["v1"];
  if (!timestamp || !signature) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const expected = crypto.createHmac("sha256", secret).update(signedPayload, "utf8").digest("hex");

  try {
    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(signature, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (e) {
    return false;
  }
}

exports.handler = async (event) => {
  const sig = event.headers["stripe-signature"] || event.headers["Stripe-Signature"];
  const rawBody = event.isBase64Encoded ? Buffer.from(event.body, "base64").toString("utf8") : event.body;

  if (!verifyStripeSignature(rawBody, sig, WEBHOOK_SECRET)) {
    return { statusCode: 400, body: "Invalid signature" };
  }

  let stripeEvent;
  try {
    stripeEvent = JSON.parse(rawBody);
  } catch (e) {
    return { statusCode: 400, body: "Invalid JSON" };
  }

  if (stripeEvent.type === "checkout.session.completed") {
    const session = stripeEvent.data.object;
    const email = (session.customer_details && session.customer_details.email) || session.customer_email;

    if (email) {
      try {
        const res = await fetch(`${SUPABASE_URL}/rest/v1/lendly_paid_emails`, {
          method: "POST",
          headers: {
            apikey: SERVICE_ROLE_KEY,
            Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
            "Content-Type": "application/json",
            Prefer: "resolution=merge-duplicates",
          },
          body: JSON.stringify({
            email: email.toLowerCase(),
            checkout_session_id: session.id,
          }),
        });
        if (!res.ok) {
          console.error("Failed to record payment:", await res.text());
        }
      } catch (e) {
        console.error("Error reaching Supabase:", e.message);
      }
    }
  }

  return { statusCode: 200, body: "ok" };
};
