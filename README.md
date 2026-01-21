# Deploy Template - Flask

Plantilla profesional para pre-desplegar en Vercel y reservar dominios.

![Preview](screen.png)

## Características de Seguridad

- ✅ SECRET_KEY obligatoria en producción (fallo explícito si falta)
- ✅ Headers HTTP seguros (CSP, HSTS, X-Frame-Options)
- ✅ Rate limiting en desarrollo local (Flask-Limiter)
- ✅ Logging estructurado JSON con request IDs y nivel configurable
- ✅ Anonimización IP compatible con GDPR
- ✅ Manejo de errores sin filtrar información (con ID de referencia)
- ✅ CSRF preparado para formularios futuros
- ✅ PWA con Service Worker (Network-First para contenido dinámico)
- ✅ Página offline.html para PWA
- ✅ URLs dinámicas para SEO files (robots.txt, sitemap.xml, security.txt)

## Rate Limiting en Producción

En desarrollo local, Flask-Limiter provee rate limiting en memoria. **En producción (Vercel)**, Redis es **obligatorio**:

> ⚠️ **La aplicación FALLARÁ al iniciar si `REDIS_URL` no está configurado en producción.**

### Configuración con Upstash (Gratis)
1. Crear cuenta en [upstash.com](https://upstash.com/)
2. Crear base de datos Redis
3. Copiar "Redis URL" (formato: `redis://default:xxx@xxx.upstash.io:6379`)
4. Agregar como `REDIS_URL` en Vercel Dashboard

## Estructura

```
deploy/
├── app.py               # Aplicación Flask
├── requirements.txt     # Dependencias producción
├── requirements-dev.txt # Dependencias desarrollo
├── runtime.txt          # Versión Python para Vercel (3.12)
├── vercel.json          # Configuración Vercel + headers
├── SECURITY.md          # Documentación de seguridad
├── static/
│   ├── css/             # Estilos (Tailwind + custom)
│   ├── js/main.js       # JavaScript
│   ├── manifest.json    # PWA manifest
│   ├── offline.html     # Página offline PWA
│   └── favicon.svg      # Icono
└── templates/
    ├── base.html        # Plantilla base
    ├── index.html       # Página principal
    └── errors/          # Páginas 403/404/500
```

## Variables de Entorno

| Variable | Producción | Descripción |
|----------|------------|-------------|
| `SECRET_KEY` | ✅ **Obligatorio** | Clave para firmar sesiones |
| `REDIS_URL` | ✅ **Obligatorio** | URL de Redis para rate limiting |
| `HEALTH_CHECK_TOKEN` | ✅ **Obligatorio** | Token para proteger `/healthz` |
| `BASE_URL` | ⚠️ **Recomendado** | URL base para SEO files (robots.txt, sitemap.xml) |
| `SITE_NAME` | ❌ Opcional | Nombre del sitio (default: VercelDeploy) |
| `SECURITY_CONTACT` | ❌ Opcional | URL de contacto para security.txt |
| `FLASK_DEBUG` | ❌ Opcional | Modo debug (default: false) |
| `LOG_LEVEL` | ❌ Opcional | Nivel de logging (default: INFO) |

### Generar Tokens

```bash
# SECRET_KEY (64 caracteres hex)
python -c "import secrets; print(secrets.token_hex(32))"

# HEALTH_CHECK_TOKEN (32 caracteres hex)
python -c "import secrets; print(secrets.token_hex(16))"
```

## Desarrollo Local

```bash
# 1. Crear entorno virtual
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# 2. Instalar dependencias (desarrollo)
pip install -r requirements-dev.txt

# 3. Crear .env.local (ignorado por git)
echo "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env.local

# 4. Ejecutar
python app.py
```

## Despliegue en Vercel

### 1. Configurar Variables en Vercel

Dashboard > Settings > Environment Variables:
- `SECRET_KEY` = (valor generado)

### 2. Desplegar

```bash
vercel
```

## Testing

```bash
# Ejecutar tests
pytest tests/ -v

# Con coverage
pytest tests/ -v --cov=app --cov-report=term-missing

# Auditoría de dependencias
pip-audit
```

## Endpoints

| Ruta | Descripción |
|------|-------------|
| `/` | Página principal |
| `/healthz` | Health check (protegible con token) |
| `/status` | Redirige a /healthz (deprecated) |

---

## ⚠️ Pre-Launch Checklist

> **Importante:** Antes de desplegar a producción con dominio real:

- [x] **robots.txt**: Configurado con `Allow: /` ✅
- [x] **meta robots**: Configurado con `index, follow` ✅
- [x] **sitemap.xml**: Configurado con entrada válida ✅
- [x] **security.txt**: Actualizado con dominio real ✅
- [x] **offline.html**: Página PWA offline creada ✅
- [ ] **SECRET_KEY**: Configurar en Vercel Dashboard (obligatorio)
- [ ] **Rate Limiting**: Configurar en Vercel Dashboard > Security
- [ ] **Dominio personalizado**: Actualizar URLs en sitemap, robots, security.txt

---

## Seguridad

Ver [SECURITY.md](SECURITY.md) para documentación detallada sobre:
- Content Security Policy (CSP) y cómo modificarlo
- HSTS y proceso de preload
- Rate limiting en producción

---

## Licencia

MIT
