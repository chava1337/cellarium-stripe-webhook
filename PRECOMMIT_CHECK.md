# Preflight Check - Stripe Webhook Proxy

**Fecha de auditoría:** $(date)  
**Estado general:** ✅ **PASS** - Listo para producción

---

## 1. Verificación de Dependencias

### ✅ PASS - package.json
- **Verificado:** No contiene Stripe SDK
- **Dependencias:** Solo Next.js 16, React 19, TypeScript
- **Sin librerías extra:** Correcto
- **Archivo:** `package.json`

---

## 2. Verificación de app/api/stripe/webhook/route.ts

### ✅ PASS - NO Stripe SDK
- **Verificado:** Solo usa `crypto` nativo de Node.js
- **Línea 1:** `import { createHmac, timingSafeEqual } from "crypto";`
- **Sin dependencias externas de Stripe**

### ✅ PASS - Runtime Node.js (NO edge)
- **Línea 3:** `export const runtime = "nodejs";`
- **Línea 4:** `export const dynamic = "force-dynamic";`
- **Correcto:** Runtime Node.js configurado

### ✅ PASS - Raw Body Exacto
- **Línea 202:** `const rawBody = await request.text();`
- **Correcto:** Usa `request.text()` para obtener el body exacto sin parsing previo

### ✅ PASS - Verificación HMAC SHA256
- **Líneas 88-93:** Implementación correcta
  ```typescript
  const secretBuffer = Buffer.from(secret, "utf8");
  const hmac = createHmac("sha256", secretBuffer);
  hmac.update(signedPayload);
  const expectedSignature = hmac.digest("hex");
  ```
- **Correcto:** Usa `STRIPE_WEBHOOK_SECRET` tal cual como string UTF-8 (NO base64 decode)
- **Línea 88:** `Buffer.from(secret, "utf8")` - Sin decodificación base64

### ✅ PASS - Parse de stripe-signature
- **Función:** `parseStripeSignatureHeader()` (líneas 15-54)
- **Verificado:** Parsea correctamente `t=timestamp` y una o más `v1=signature`
- **Lógica:** 
  - Extrae timestamp de `t=`
  - Extrae todas las firmas `v1=`
  - Retorna vacío si falta `t=` o no hay `v1=`
- **Correcto:** Maneja múltiples firmas v1 correctamente

### ✅ PASS - Timestamp Tolerance 300s
- **Línea 73:** `const TOLERANCE = 300;`
- **Línea 80:** `if (Math.abs(currentTimestamp - timestamp) > TOLERANCE)`
- **Correcto:** Valida timestamp con tolerancia de 300 segundos

### ✅ PASS - Comparación con timingSafeEqual
- **Línea 103:** `if (timingSafeEqual(expectedBuffer, receivedBuffer))`
- **Líneas 96-97:** Convierte a buffers antes de comparar
- **Línea 99:** Verifica longitud antes de comparar
- **Correcto:** Usa comparación segura contra timing attacks

### ✅ PASS - Firma Inválida → 400
- **Líneas 239-245:** Retorna 400 cuando `!verification.valid`
- **Correcto:** Responde con status 400 para firmas inválidas

### ✅ PASS - Forward a Supabase
- **Headers verificados:**
  - ✅ `Authorization: Bearer ${serviceRoleKey}` (línea 150)
  - ✅ `x-internal-webhook-secret` si existe `INTERNAL_WEBHOOK_SHARED_SECRET` (líneas 153-155)
  - ✅ `stripe-signature` reenviado (línea 158)
- **Body idéntico:** 
  - ✅ Línea 167: `body: rawBody` - Envía el rawBody exacto
- **Timeout 10s:**
  - ✅ Línea 162: `setTimeout(() => controller.abort(), 10000)`
  - ✅ Línea 161: `AbortController` implementado correctamente

### ✅ PASS - Supabase no responde 2xx → 500
- **Líneas 173-186:** Detecta `!response.ok` y retorna `{ success: false, status }`
- **Líneas 257-269:** Responde 500 cuando `!forwardResult.success`
- **Correcto:** Permite reintentos automáticos de Stripe

### ✅ PASS - Logs Mínimos
- **Líneas 249-252:** Solo loguea `event.type` y `event.id` después de verificar firma
- **Función:** `safeJsonParseForLog()` - Parse seguro que no falla si el JSON es inválido
- **Correcto:** Logs mínimos y solo después de verificación

### ✅ PASS - GET u otros métodos → 405
- **Líneas 294-301:** `export async function GET()` retorna 405
- **Correcto:** Rechaza métodos que no sean POST

### ✅ PASS - Sin CORS, sin middleware
- **Verificado:** No hay configuración de CORS en ningún archivo
- **Verificado:** No existe `middleware.ts` en el proyecto
- **Correcto:** Sin CORS, sin middleware

### ✅ PASS - Sin funciones muertas o confusas
- **Funciones helper claras:**
  - ✅ `parseStripeSignatureHeader()` - Nombre claro
  - ✅ `verifyStripeSignature()` - Nombre claro
  - ✅ `safeJsonParseForLog()` - Nombre claro
  - ✅ `forwardToSupabase()` - Nombre claro
- **Sin funciones extractStripeSecret o base64 decode:**
  - ✅ Verificado: No existe ninguna función que decodifique base64
  - ✅ Verificado: No existe `extractStripeSecret`

---

## 3. Verificación de app/api/health/route.ts

### ✅ PASS - Health Endpoint
- **Runtime:** `export const runtime = "nodejs";` ✅
- **Dynamic:** `export const dynamic = "force-dynamic";` ✅
- **GET:** Retorna `{ ok: true }` con status 200 ✅
- **Archivo:** `app/api/health/route.ts`

---

## 4. Variables de Entorno Requeridas

### Requeridas:
1. **STRIPE_WEBHOOK_SECRET**
   - Formato: `whsec_*`
   - Uso: Secreto del webhook de Stripe (usado tal cual como string UTF-8)
   - Ubicación en código: Línea 219 de `route.ts`

2. **SUPABASE_INTERNAL_WEBHOOK_URL**
   - Formato: URL completa de la Supabase Edge Function
   - Uso: URL destino para el forward del webhook
   - Ubicación en código: Línea 139 de `route.ts`

3. **SUPABASE_SERVICE_ROLE_KEY**
   - Formato: Service Role Key de Supabase
   - Uso: Autenticación Bearer en el forward
   - Ubicación en código: Línea 140 de `route.ts`

### Opcionales (recomendadas):
4. **INTERNAL_WEBHOOK_SHARED_SECRET**
   - Formato: String secreto compartido
   - Uso: Header `x-internal-webhook-secret` para validación interna
   - Ubicación en código: Línea 141 de `route.ts`

---

## 5. Ruta Final Esperada

**Endpoint de webhook:**
```
POST /api/stripe/webhook
```

**Endpoint de health:**
```
GET /api/health
```

**URL completa en Vercel:**
```
https://tu-proyecto.vercel.app/api/stripe/webhook
```

---

## 6. Comandos de Prueba Local

### Health Check
```bash
curl http://localhost:3000/api/health
```

**Respuesta esperada:**
```json
{"ok":true}
```

### Webhook (requiere configuración completa)
```bash
curl -X POST http://localhost:3000/api/stripe/webhook \
  -H "Content-Type: application/json" \
  -H "stripe-signature: t=1234567890,v1=signature_here" \
  -d '{"type":"test.event","id":"evt_test"}'
```

**Nota:** Para probar completamente, necesitas:
- Variables de entorno configuradas
- Firma válida de Stripe (generada con el secreto correcto)
- URL de Supabase funcionando

### Test de método no permitido
```bash
curl -X GET http://localhost:3000/api/stripe/webhook
```

**Respuesta esperada:**
```json
{"error":"Method not allowed"}
```
**Status:** 405

---

## 7. Cambios Aplicados Durante Auditoría

### ✅ Renombrado de funciones para claridad:
1. `parseSignatureHeader()` → `parseStripeSignatureHeader()`
   - **Razón:** Nombre más descriptivo y específico
   - **Líneas afectadas:** 15, 65

2. `parseEventForLogging()` → `safeJsonParseForLog()`
   - **Razón:** Nombre más claro y conciso
   - **Líneas afectadas:** 117, 249

**Resultado:** Código más legible y mantenible, sin cambios funcionales.

---

## 8. Resumen Final

### ✅ TODOS LOS CHECKS PASARON

**Estado:** **PRODUCTION-READY**

- ✅ Sin Stripe SDK
- ✅ Runtime Node.js correcto
- ✅ Verificación HMAC SHA256 correcta
- ✅ Parse de signature correcto
- ✅ Forward a Supabase correcto
- ✅ Manejo de errores correcto
- ✅ Logs mínimos
- ✅ Sin CORS, sin middleware
- ✅ Código limpio y legible
- ✅ Sin funciones muertas o confusas
- ✅ Sin decodificación base64 incorrecta

**El código está listo para commit y deploy en producción.**
