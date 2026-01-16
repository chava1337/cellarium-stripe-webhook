# Cellarium Stripe Webhook

Proxy de webhooks de Stripe hacia Supabase Edge Function. Desplegable en Vercel.

## ¿Qué hace?

Este proxy recibe webhooks de Stripe, verifica su firma usando HMAC SHA256, y los reenvía a una Supabase Edge Function interna. Solo responde 200 a Stripe si el forward a Supabase fue exitoso (2xx), permitiendo que Stripe reintente automáticamente en caso de fallo.

## Stack

- Next.js 16
- App Router
- TypeScript
- Runtime Node.js
- Crypto nativo (sin Stripe SDK)

## Instalación

```bash
npm install
```

## Desarrollo

```bash
npm run dev
```

El servidor se ejecutará en `http://localhost:3000`

## Endpoints

### Health Check
```
GET /api/health
```
Retorna `{ ok: true }` - útil para verificar que el servicio está activo.

### Webhook de Stripe
```
POST /api/stripe/webhook
```
Endpoint principal que recibe webhooks de Stripe y los reenvía a Supabase.

## Variables de Entorno

### Requeridas

Configura estas variables de entorno antes de desplegar:

- **`STRIPE_WEBHOOK_SECRET`** - Secreto del webhook de Stripe (formato `whsec_*`)
  - Se usa tal cual como string UTF-8 (sin decodificación base64)
  - Obtener desde: Stripe Dashboard → Developers → Webhooks → [Tu endpoint] → Signing secret

- **`SUPABASE_INTERNAL_WEBHOOK_URL`** - URL completa de la Supabase Edge Function
  - Ejemplo: `https://[proyecto].supabase.co/functions/v1/[nombre-funcion]`

- **`SUPABASE_SERVICE_ROLE_KEY`** - Service Role Key de Supabase
  - Obtener desde: Supabase Dashboard → Settings → API → service_role key

### Opcionales (recomendado)

- **`INTERNAL_WEBHOOK_SHARED_SECRET`** - Secreto compartido para validación interna
  - Se envía como header `x-internal-webhook-secret` al forward
  - Útil para validación adicional en la Supabase Edge Function

## Cómo probar

### 1. Health Check

Verifica que el servicio está activo:

```bash
curl http://localhost:3000/api/health
```

**Respuesta esperada:**
```json
{"ok":true}
```

### 2. Test de método no permitido

```bash
curl -X GET http://localhost:3000/api/stripe/webhook
```

**Respuesta esperada:** Status 405 con `{"error":"Method not allowed"}`

### 3. Webhook completo

Para probar el webhook completo necesitas:

1. Variables de entorno configuradas en `.env.local`:
```env
STRIPE_WEBHOOK_SECRET=whsec_...
SUPABASE_INTERNAL_WEBHOOK_URL=https://...
SUPABASE_SERVICE_ROLE_KEY=...
```

2. Generar una firma válida de Stripe (usando el secreto correcto)

3. Enviar request con la firma:
```bash
curl -X POST http://localhost:3000/api/stripe/webhook \
  -H "Content-Type: application/json" \
  -H "stripe-signature: t=1234567890,v1=signature_hex_here" \
  -d '{"type":"payment_intent.succeeded","id":"evt_..."}'
```

**Nota:** En producción, Stripe enviará automáticamente los webhooks a:
```
https://tu-proyecto.vercel.app/api/stripe/webhook
```

## Deploy en Vercel

1. Conecta tu repositorio a Vercel
2. Configura las variables de entorno en el dashboard de Vercel
3. Despliega

La URL final del webhook será:
```
https://tu-proyecto.vercel.app/api/stripe/webhook
```

## Características

- ✅ Verificación de firma Stripe con HMAC SHA256
- ✅ Validación de timestamp (tolerancia 300s)
- ✅ Timeout de 10s al forward a Supabase
- ✅ Reintentos automáticos de Stripe en caso de fallo
- ✅ Logs mínimos (event.type y event.id)
- ✅ Sin CORS, sin middleware
- ✅ Runtime Node.js (no Edge)
