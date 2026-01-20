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

## Rate Limiting en Producción

En desarrollo local, Flask-Limiter provee rate limiting en memoria. **En producción (Vercel)**, debes configurar rate limiting a nivel de plataforma:

### Opción 1: Vercel Dashboard (Recomendado)
1. Ve a **Project Settings > Security > Rate Limiting**
2. Configura reglas por ruta o IP

### Opción 2: Vercel Firewall (Enterprise)
Para reglas avanzadas, usa Vercel Firewall en el plan Enterprise.

### Opción 3: Redis (Upstash)
Para rate limiting distribuido, configura `ENABLE_RATE_LIMIT=true` y usa Upstash Redis como storage.

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

| Variable | Requerida | Descripción |
|----------|-----------|-------------|
| `SECRET_KEY` | ✅ **Sí** | Clave para firmar sesiones |
| `HEALTH_CHECK_TOKEN` | ❌ No | Token para proteger `/healthz` |
| `FLASK_DEBUG` | ❌ No | Modo debug (default: false) |
| `LOG_LEVEL` | ❌ No | Nivel de logging (default: INFO) |
| `ENABLE_RATE_LIMIT` | ❌ No | Forzar rate limit en producción |
| `SITE_NAME` | ❌ No | Nombre del sitio (default: VercelDeploy) |

### Generar SECRET_KEY

```bash
python -c "import secrets; print(secrets.token_hex(32))"
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
