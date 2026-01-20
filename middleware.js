// =============================================================================
// Vercel Edge Middleware - Rate Limiting
// =============================================================================
// Implementa rate limiting real en Vercel Edge Runtime
// Límite: 100 requests/minuto por IP
// 
// SEGURIDAD: Este middleware tiene límites estrictos para prevenir memory leaks:
// - Máximo 10,000 IPs rastreadas simultáneamente
// - Limpieza determinista cada 100 requests
// - Evicción LRU cuando se excede el límite
// =============================================================================

const RATE_LIMIT = 100;
const WINDOW_MS = 60 * 1000; // 1 minuto

// Límites de memoria para prevenir DoS
const MAX_IPS = 10000;
const CLEANUP_INTERVAL = 100;

// In-memory store con tracking de orden de inserción para LRU
const ipRequests = new Map();
let requestCounter = 0;

/**
 * Limpieza determinista de entradas expiradas y evicción LRU
 * @param {number} windowStart - Timestamp del inicio de la ventana actual
 */
function cleanupEntries(windowStart) {
    // Fase 1: Eliminar entradas expiradas
    for (const [ip, data] of ipRequests.entries()) {
        const validTimestamps = data.timestamps.filter(t => t > windowStart);
        if (validTimestamps.length === 0) {
            ipRequests.delete(ip);
        } else {
            data.timestamps = validTimestamps;
        }
    }

    // Fase 2: Evicción LRU si excede límite
    if (ipRequests.size > MAX_IPS) {
        // Ordenar por último acceso (oldest first)
        const sortedEntries = [...ipRequests.entries()]
            .sort((a, b) => a[1].lastAccess - b[1].lastAccess);

        const toRemove = ipRequests.size - MAX_IPS;
        for (let i = 0; i < toRemove; i++) {
            ipRequests.delete(sortedEntries[i][0]);
        }
    }
}

export default function middleware(request) {
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
        || request.headers.get('x-real-ip')
        || 'unknown';

    const now = Date.now();
    const windowStart = now - WINDOW_MS;

    // Incrementar contador y ejecutar limpieza si corresponde
    requestCounter++;
    if (requestCounter >= CLEANUP_INTERVAL) {
        requestCounter = 0;
        cleanupEntries(windowStart);
    }

    // Obtener o crear datos para esta IP
    let data = ipRequests.get(ip);
    if (!data) {
        data = { timestamps: [], lastAccess: now };
        ipRequests.set(ip, data);
    }

    // Actualizar último acceso para LRU
    data.lastAccess = now;

    // Filtrar requests fuera de la ventana de tiempo
    data.timestamps = data.timestamps.filter(timestamp => timestamp > windowStart);

    // Verificar límite
    if (data.timestamps.length >= RATE_LIMIT) {
        const retryAfter = Math.ceil((data.timestamps[0] + WINDOW_MS - now) / 1000);
        return new Response(JSON.stringify({
            error: 'rate_limit_exceeded',
            message: 'Too many requests. Please try again later.',
            retry_after: retryAfter
        }), {
            status: 429,
            headers: {
                'Content-Type': 'application/json',
                'Retry-After': String(retryAfter),
                'X-RateLimit-Limit': String(RATE_LIMIT),
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': String(Math.ceil((data.timestamps[0] + WINDOW_MS) / 1000))
            }
        });
    }

    // Agregar request actual al historial
    data.timestamps.push(now);

    // Agregar headers de rate limit info a la respuesta
    // (El request continúa al backend)
    return;
}

// Configuración: aplicar a todas las rutas excepto static
export const config = {
    matcher: [
        /*
         * Match all request paths except:
         * - /static/* (archivos estáticos)
         * - /favicon.ico, /favicon.svg
         * - /_next/* (Next.js internals, por compatibilidad futura)
         */
        '/((?!static|_next|favicon).*)',
    ],
};
