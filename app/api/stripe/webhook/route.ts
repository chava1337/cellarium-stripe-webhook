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

const FORWARD_TIMEOUT_MS = 25000;

type ForwardResult =
  | { success: true; status: number }
  | { success: false; status?: number; forwardError?: string; gatewayError?: { name: string; message: string; causeCode?: string } };

type CauseLike = { code?: string; errno?: number; syscall?: string; hostname?: string; address?: string; port?: number };

/**
 * Forward del webhook a Supabase con timeout configurado.
 * Headers: INTERNAL_EDGE_AUTH_TOKEN (Bearer) + x-internal-webhook-secret; stripe-signature reenviado.
 */
async function forwardToSupabase(
  rawBody: string,
  stripeSignature: string,
  contentType: string,
  pingMode: boolean
): Promise<ForwardResult> {
  const rawUrl = process.env.SUPABASE_INTERNAL_WEBHOOK_URL;
  const supabaseUrl = typeof rawUrl === "string" ? rawUrl.trim() : "";
  const internalSecret = process.env.INTERNAL_WEBHOOK_SHARED_SECRET;
  // INTERNAL ONLY: token dedicado para que Supabase Edge valide el forward
  const internalEdgeToken = process.env.INTERNAL_EDGE_AUTH_TOKEN?.trim();

  if (!internalEdgeToken) {
    console.error("INTERNAL_EDGE_AUTH_TOKEN missing");
    return { success: false, forwardError: "INTERNAL_EDGE_AUTH_TOKEN missing" };
  }

  if (!supabaseUrl) {
    console.error("Missing SUPABASE_INTERNAL_WEBHOOK_URL");
    return { success: false, forwardError: "Server configuration error" };
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(supabaseUrl);
  } catch (e) {
    console.error("Invalid SUPABASE_INTERNAL_WEBHOOK_URL:", (e as Error).message);
    return { success: false, forwardError: "Invalid SUPABASE_INTERNAL_WEBHOOK_URL" };
  }

  if (parsedUrl.protocol !== "https:") {
    console.error("SUPABASE_INTERNAL_WEBHOOK_URL must use https protocol");
    return { success: false, forwardError: "SUPABASE_INTERNAL_WEBHOOK_URL must use https protocol" };
  }

  const headers: Record<string, string> = {
    "Content-Type": contentType || "application/json",
    "stripe-signature": stripeSignature,
    "Stripe-Signature": stripeSignature,
    authorization: `Bearer ${internalEdgeToken}`,
  };

  if (internalSecret) {
    headers["x-internal-webhook-secret"] = internalSecret;
  }

  const body = pingMode
    ? JSON.stringify({ ping: true, ts: new Date().toISOString() })
    : rawBody;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FORWARD_TIMEOUT_MS);

    const response = await fetch(supabaseUrl, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    console.log("[PROXY] forwarded", {
      status: response.status,
      ok: response.ok,
      targetHost: parsedUrl.hostname,
      targetPath: parsedUrl.pathname,
    });

    if (!response.ok) {
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
    const err = error as Error & { cause?: CauseLike };
    const c = err.cause;
    const causeCode = c?.code ?? c?.errno?.toString() ?? c?.syscall ?? undefined;
    const safeDebug = {
      name: err.name,
      message: err.message,
      causeCode: c?.code,
      errno: c?.errno,
      syscall: c?.syscall,
      causeHostname: c?.hostname,
      causeAddress: c?.address,
      causePort: c?.port,
      urlProtocol: parsedUrl.protocol,
      urlHostname: parsedUrl.hostname,
      urlPathname: parsedUrl.pathname,
      timeoutMs: FORWARD_TIMEOUT_MS,
    };
    console.error("Forward fetch failed (safe debug):", safeDebug);

    return {
      success: false,
      status: 502,
      gatewayError: {
        name: err.name,
        message: err.message,
        causeCode: causeCode ?? c?.code,
      },
    };
  }
}

export async function POST(request: Request) {
  const requestId = randomUUID();
  const startedAt = new Date();

  console.log("[PROXY_WEBHOOK] handler_enter", {
    requestId,
    v: "proxy@d433e09",
    ts: startedAt.toISOString(),
  });

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

    const eventInfo = safeJsonParseForLog(rawBody);
    console.log("[PROXY] received", {
      eventType: eventInfo.type ?? "(unknown)",
      eventId: eventInfo.id ?? "(unknown)",
      hasSig: true,
      len: rawBody.length,
    });

    const contentType = request.headers.get("content-type") || "application/json";
    const pingMode = process.env.SUPABASE_PING_MODE === "true";

    const forwardResult = await forwardToSupabase(rawBody, stripeSignature, contentType, pingMode);

    if (!forwardResult.success) {
      if (forwardResult.gatewayError) {
        return new Response(
          JSON.stringify({
            error: "Failed to forward to Supabase",
            details: {
              name: forwardResult.gatewayError.name,
              message: forwardResult.gatewayError.message,
              causeCode: forwardResult.gatewayError.causeCode,
            },
          }),
          {
            status: 502,
            headers: {
              "Content-Type": "application/json",
            },
          }
        );
      }
      if (forwardResult.forwardError) {
        return new Response(
          JSON.stringify({ error: forwardResult.forwardError }),
          {
            status: 500,
            headers: {
              "Content-Type": "application/json",
            },
          }
        );
      }
      console.error(
        `Failed to forward to Supabase. Status: ${forwardResult.status ?? "N/A"}`
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
