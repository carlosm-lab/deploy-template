// =============================================================================
// Vercel Edge Middleware - Rate Limiting
// =============================================================================
// Implementa rate limiting real en Vercel Edge Runtime
// Límite: 100 requests/minuto por IP
// =============================================================================

const RATE_LIMIT = 100;
const WINDOW_MS = 60 * 1000; // 1 minuto

// Simple in-memory store (Edge tiene memoria compartida entre requests)
const ipRequests = new Map();

export default function middleware(request) {
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
        || request.headers.get('x-real-ip')
        || 'unknown';

    const now = Date.now();
    const windowStart = now - WINDOW_MS;

    // Obtener historial de requests para esta IP
    let requests = ipRequests.get(ip) || [];

    // Filtrar requests fuera de la ventana de tiempo
    requests = requests.filter(timestamp => timestamp > windowStart);

    // Verificar límite
    if (requests.length >= RATE_LIMIT) {
        return new Response(JSON.stringify({
            error: 'rate_limit_exceeded',
            message: 'Too many requests. Please try again later.',
            retry_after: Math.ceil((requests[0] + WINDOW_MS - now) / 1000)
        }), {
            status: 429,
            headers: {
                'Content-Type': 'application/json',
                'Retry-After': String(Math.ceil((requests[0] + WINDOW_MS - now) / 1000)),
                'X-RateLimit-Limit': String(RATE_LIMIT),
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': String(Math.ceil((requests[0] + WINDOW_MS) / 1000))
            }
        });
    }

    // Agregar request actual al historial
    requests.push(now);
    ipRequests.set(ip, requests);

    // Limpiar IPs antiguas periódicamente (cada 1000 requests aproximadamente)
    if (Math.random() < 0.001) {
        for (const [storedIp, timestamps] of ipRequests.entries()) {
            const validTimestamps = timestamps.filter(t => t > windowStart);
            if (validTimestamps.length === 0) {
                ipRequests.delete(storedIp);
            } else {
                ipRequests.set(storedIp, validTimestamps);
            }
        }
    }

    // Continuar con el request, agregando headers de rate limit
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
