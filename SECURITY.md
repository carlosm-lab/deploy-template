# Política de Seguridad - VercelDeploy

## Reportar Vulnerabilidades

Si encuentra una vulnerabilidad de seguridad, por favor repórtela responsablemente:

- **Email**: security@verceldeploy.com
- **Respuesta esperada**: 48 horas

## Content Security Policy (CSP)

Este proyecto implementa una CSP **muy restrictiva** por diseño. Esto significa:

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

1. **Editar** `app.py` línea ~235
2. **Editar** `vercel.json` línea ~80-81
3. Añadir el dominio específico, ejemplo:
   ```
   script-src 'self' https://www.googletagmanager.com;
   ```

### CSP Report-Only (Recomendado para staging)

Para detectar violaciones sin bloquear, cambie:
```
Content-Security-Policy-Report-Only: ...
```

## HSTS

El header HSTS está configurado **sin** `preload` por defecto.

Para añadir preload:
1. Registrar dominio en https://hstspreload.org/
2. Esperar confirmación
3. Cambiar header a incluir `preload`

## Rate Limiting

En **desarrollo local**: Flask-Limiter (memoria)  
En **producción (Vercel)**: Configurar en Vercel Dashboard > Security > Rate Limiting

⚠️ El rate limiting de Flask-Limiter NO funciona en serverless (memoria aislada).
