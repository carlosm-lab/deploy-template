# Deploy Template - Flask

Plantilla profesional para pre-desplegar en Vercel y reservar dominios.

![Preview](screen.png)

## Características de Seguridad

- ✅ SECRET_KEY obligatoria en producción (fallo explícito si falta)
- ✅ Headers HTTP seguros (CSP, HSTS, X-Frame-Options)
- ✅ Rate limiting configurable (desarrollo local)
- ✅ Logging estructurado JSON con request IDs y nivel configurable
- ✅ Anonimización IP compatible con GDPR
- ✅ Manejo de errores sin filtrar información
- ✅ CSRF preparado para formularios futuros
- ✅ PWA manifest integrado

## Estructura

```
deploy/
├── app.py               # Aplicación Flask
├── requirements.txt     # Dependencias producción
├── requirements-dev.txt # Dependencias desarrollo
├── runtime.txt          # Versión Python para Vercel
├── vercel.json          # Configuración Vercel + headers
├── static/
│   ├── css/             # Estilos (Tailwind + custom)
│   ├── js/main.js       # JavaScript
│   ├── manifest.json    # PWA manifest
│   └── favicon.svg      # Icono
└── templates/
    ├── base.html        # Plantilla base
    ├── index.html       # Página principal
    └── errors/          # Páginas 404/500
```

## Variables de Entorno

| Variable | Requerida | Descripción |
|----------|-----------|-------------|
| `SECRET_KEY` | ✅ **Sí** | Clave para firmar sesiones |
| `HEALTH_CHECK_TOKEN` | ❌ No | Token para proteger `/healthz` |
| `FLASK_DEBUG` | ❌ No | Modo debug (default: false) |
| `LOG_LEVEL` | ❌ No | Nivel de logging (default: INFO) |
| `ENABLE_RATE_LIMIT` | ❌ No | Forzar rate limit en producción |

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

> **Importante:** Antes de usar este sitio como producción real, revisar:

- [ ] **robots.txt**: Cambiar `Disallow: /` a `Allow: /` cuando el sitio esté listo
- [ ] **meta robots**: Cambiar `noindex, nofollow` a `index, follow` en `base.html`
- [ ] **SECRET_KEY**: Verificar que está configurada en Vercel Dashboard
- [ ] **security.txt**: Actualizar email y URL en `static/.well-known/security.txt`
- [ ] **Dominio**: Configurar dominio personalizado en Vercel
- [ ] **Analytics**: Agregar tracking si es necesario
- [ ] **Sitemap**: Actualizar `static/sitemap.xml` con URLs reales

---

## Licencia

MIT
