import { createHmac, timingSafeEqual } from "crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface SignatureEntry {
  timestamp: string;
  signature: string;
}

/**
 * Parsea el header stripe-signature en un array de entradas
 * Formato: t=timestamp,v1=signature1,v1=signature2,...
 */
function parseStripeSignatureHeader(signatureHeader: string): SignatureEntry[] {
  const entries: SignatureEntry[] = [];
  const parts = signatureHeader.split(",");

  // Extraer timestamp (debe haber solo uno)
  let timestamp: string | null = null;
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.startsWith("t=")) {
      const [, value] = trimmed.split("=");
      if (value) {
        timestamp = value;
        break;
      }
    }
  }

  if (!timestamp) {
    return entries;
  }

  // Extraer todas las firmas v1
  let hasV1 = false;
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.startsWith("v1=")) {
      const [, value] = trimmed.split("=");
      if (value) {
        entries.push({ timestamp, signature: value });
        hasV1 = true;
      }
    }
  }

  if (!hasV1) {
    return [];
  }

  return entries;
}

/**
 * Verifica la firma de Stripe usando HMAC SHA256
 */
function verifyStripeSignature(
  rawBody: string,
  signatureHeader: string,
  secret: string
): { valid: boolean; timestamp?: number } {
  try {
    const entries = parseStripeSignatureHeader(signatureHeader);

    if (entries.length === 0) {
      return { valid: false };
    }

    // Validar timestamp (tolerancia de 300 segundos)
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const TOLERANCE = 300;

    for (const entry of entries) {
      const timestamp = parseInt(entry.timestamp, 10);
      const signature = entry.signature;

      // Validar timestamp
      if (Math.abs(currentTimestamp - timestamp) > TOLERANCE) {
        continue;
      }

      // Crear signed_payload
      const signedPayload = `${timestamp}.${rawBody}`;

      // Usar el secreto directamente como string UTF-8
      const secretBuffer = Buffer.from(secret, "utf8");

      // Calcular HMAC SHA256
      const hmac = createHmac("sha256", secretBuffer);
      hmac.update(signedPayload);
      const expectedSignature = hmac.digest("hex");

      // Comparar usando timingSafeEqual
      const expectedBuffer = Buffer.from(expectedSignature, "hex");
      const receivedBuffer = Buffer.from(signature, "hex");

      if (expectedBuffer.length !== receivedBuffer.length) {
        continue;
      }

      if (timingSafeEqual(expectedBuffer, receivedBuffer)) {
        return { valid: true, timestamp };
      }
    }

    return { valid: false };
  } catch (error) {
    return { valid: false };
  }
}

/**
 * Parsea el JSON del body de forma segura para logging
 */
function safeJsonParseForLog(rawBody: string): {
  type?: string;
  id?: string;
} {
  try {
    const event = JSON.parse(rawBody);
    return {
      type: event.type,
      id: event.id,
    };
  } catch {
    return {};
  }
}

/**
 * Forward del webhook a Supabase con timeout de 10s
 */
async function forwardToSupabase(
  rawBody: string,
  stripeSignature: string
): Promise<{ success: boolean; status?: number }> {
  const supabaseUrl = process.env.SUPABASE_INTERNAL_WEBHOOK_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const internalSecret = process.env.INTERNAL_WEBHOOK_SHARED_SECRET;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("Missing SUPABASE_INTERNAL_WEBHOOK_URL or SUPABASE_SERVICE_ROLE_KEY");
    return { success: false };
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${serviceRoleKey}`,
  };

  if (internalSecret) {
    headers["x-internal-webhook-secret"] = internalSecret;
  }

  // Opcional: reenviar stripe-signature
  headers["stripe-signature"] = stripeSignature;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

    const response = await fetch(supabaseUrl, {
      method: "POST",
      headers,
      body: rawBody,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      // Leer response body para log (máx 300 chars)
      let errorBody = "";
      try {
        const text = await response.text();
        errorBody = text.length > 300 ? text.substring(0, 300) + "..." : text;
      } catch {
        errorBody = "(unable to read response body)";
      }
      console.error(
        `Failed to forward to Supabase. Status: ${response.status}, Body: ${errorBody}`
      );
      return { success: false, status: response.status };
    }

    return { success: true, status: response.status };
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      console.error("Timeout forwarding to Supabase (10s)");
    } else {
      console.error("Error forwarding to Supabase:", error);
    }
    return { success: false };
  }
}

export async function POST(request: Request) {
  try {
    // Leer raw body
    const rawBody = await request.text();

    // Leer header stripe-signature
    const stripeSignature = request.headers.get("stripe-signature");
    if (!stripeSignature) {
      return new Response(
        JSON.stringify({ error: "Missing stripe-signature header" }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Verificar firma
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!webhookSecret) {
      console.error("Missing STRIPE_WEBHOOK_SECRET");
      return new Response(
        JSON.stringify({ error: "Server configuration error" }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    const verification = verifyStripeSignature(
      rawBody,
      stripeSignature,
      webhookSecret
    );

    if (!verification.valid) {
      return new Response(JSON.stringify({ error: "Invalid signature" }), {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      });
    }

    // Parsear para logging (no crítico si falla)
    const eventInfo = safeJsonParseForLog(rawBody);
    if (eventInfo.type && eventInfo.id) {
      console.log(`Stripe webhook: ${eventInfo.type} (${eventInfo.id})`);
    }

    // Forward a Supabase
    const forwardResult = await forwardToSupabase(rawBody, stripeSignature);

    if (!forwardResult.success) {
      console.error(
        `Failed to forward to Supabase. Status: ${forwardResult.status || "N/A"}`
      );
      return new Response(
        JSON.stringify({ error: "Failed to forward webhook" }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Éxito: responder 200
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Unexpected error in webhook handler:", error);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }
}

// Rechazar métodos que no sean POST
export async function GET() {
  return new Response(JSON.stringify({ error: "Method not allowed" }), {
    status: 405,
    headers: {
      "Content-Type": "application/json",
    },
  });
}
