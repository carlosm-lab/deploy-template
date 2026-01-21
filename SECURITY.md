# Política de Seguridad - VercelDeploy

## Reportar Vulnerabilidades

Si encuentra una vulnerabilidad de seguridad, por favor repórtela responsablemente:

- **GitHub**: Usar [Security Advisories](../../security/advisories/new)
- **Respuesta esperada**: 48 horas

## Content Security Policy (CSP)

Este proyecto implementa una CSP **muy restrictiva** por diseño:

### ✅ Permitido
- Scripts desde el mismo origen (`'self'`)
- Estilos desde el mismo origen (`'self'`)
- Fuentes locales
- Imágenes locales
- Conexiones al mismo origen

### ❌ Bloqueado
- Scripts inline (sin `'unsafe-inline'`)
- Estilos inline
- Google Analytics, Plausible, u otros analytics de terceros
- Widgets de chat (Crisp, Intercom, Zendesk)
- CDNs externos
- Iframes externos
- Data URIs para imágenes

### Modificar CSP

Si necesita añadir scripts/estilos externos:

1. Buscar `Content-Security-Policy` en `app.py`
2. Buscar `Content-Security-Policy` en `vercel.json`
3. Añadir el dominio específico, ejemplo:
   ```
   script-src 'self' https://www.googletagmanager.com;
   ```

## HSTS

El header HSTS está configurado con:
- `max-age=31536000` (1 año)
- `includeSubDomains`

Para añadir preload:
1. Registrar dominio en https://hstspreload.org/
2. Esperar confirmación
3. Agregar `preload` al header

## Rate Limiting

- **Desarrollo local**: Flask-Limiter con memoria
- **Producción (Vercel)**: 
  - **OBLIGATORIO**: Redis (Upstash) configurado via `REDIS_URL`
  - La aplicación **FALLARÁ al iniciar** si no está configurado

🚨 **CRÍTICO: Sin `REDIS_URL` configurado, la aplicación no iniciará en producción.**

## Variables de Entorno Requeridas

| Variable | Producción | Descripción |
|----------|------------|-------------|
| `SECRET_KEY` | ✅ **Obligatorio** | Clave criptográfica de 64 caracteres hex |
| `REDIS_URL` | ✅ **Obligatorio** | URL de Redis para rate limiting |
| `HEALTH_CHECK_TOKEN` | ✅ **Obligatorio** | Token para proteger /healthz y /ready |

## Seguridad en Uploads (cuando se implementen)

> ⚠️ **IMPORTANTE:** Esta sección describe requisitos futuros.

Cuando se añadan endpoints de upload de archivos:

1. **Validar MIME type** del archivo, no confiar en extensión
2. **Limitar tipos permitidos** (whitelist, no blacklist)
3. **Escanear contenido** de archivos para detectar SVG con scripts
4. **Almacenar fuera de webroot** o en bucket S3/GCS
5. **Generar nombres aleatorios** para evitar path traversal
6. **Actualizar CSP** si se sirven imágenes de dominio externo

## Cache del Service Worker

### Invalidación Manual

Para forzar actualización en todos los usuarios:

1. Abrir `/static/sw.js`
2. Incrementar versión en `CACHE_NAME`: `deploy-template-v10` → `v11`
3. Hacer deploy

### Automática (Recomendado)

Usar variable de entorno `VERCEL_GIT_COMMIT_SHA` en el build:
- El SW incluye timestamp del deploy
- Cache se invalida automáticamente en cada deploy
