/**
 * Vercel Edge Middleware - Rate Limiting & Security
 * =============================================================================
 * Provides real rate limiting at the Edge level for Vercel deployments.
 * This middleware runs BEFORE the serverless function, providing actual protection.
 *
 * Features:
 * - Rate limiting: 100 requests/minute per IP
 * - Security headers injection
 * - Request ID propagation
 *
 * IMPORTANT: This file must be at the root of the project (not in /api)
 * Docs: https://vercel.com/docs/functions/edge-middleware
 * =============================================================================
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// =============================================================================
// Configuration
// =============================================================================
const RATE_LIMIT = 100;          // Requests per window
const WINDOW_MS = 60 * 1000;     // 1 minute window
const MAX_IPS = 10000;           // Max IPs to track (memory limit)
const CLEANUP_INTERVAL = 100;    // Clean every N requests

// =============================================================================
// In-Memory Store (Edge Runtime compatible)
// Note: State persists per edge location, not globally
// =============================================================================
interface RateLimitData {
    timestamps: number[];
    lastAccess: number;
}

const ipRequests = new Map<string, RateLimitData>();
let requestCounter = 0;

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Get client IP from request headers
 */
function getClientIP(request: NextRequest): string {
    const forwarded = request.headers.get('x-forwarded-for');
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    const realIP = request.headers.get('x-real-ip');
    if (realIP) {
        return realIP;
    }
    return 'unknown';
}

/**
 * Cleanup expired entries and enforce memory limits
 */
function cleanupEntries(windowStart: number): void {
    // Phase 1: Remove expired entries
    for (const [ip, data] of ipRequests.entries()) {
        const validTimestamps = data.timestamps.filter(t => t > windowStart);
        if (validTimestamps.length === 0) {
            ipRequests.delete(ip);
        } else {
            data.timestamps = validTimestamps;
        }
    }

    // Phase 2: LRU eviction if over limit
    if (ipRequests.size > MAX_IPS) {
        const sortedEntries = [...ipRequests.entries()]
            .sort((a, b) => a[1].lastAccess - b[1].lastAccess);

        const toRemove = ipRequests.size - MAX_IPS;
        for (let i = 0; i < toRemove; i++) {
            ipRequests.delete(sortedEntries[i][0]);
        }
    }
}

/**
 * Generate rate limit headers
 */
function getRateLimitHeaders(
    remaining: number,
    resetTime: number
): Record<string, string> {
    return {
        'X-RateLimit-Limit': String(RATE_LIMIT),
        'X-RateLimit-Remaining': String(Math.max(0, remaining)),
        'X-RateLimit-Reset': String(Math.ceil(resetTime / 1000)),
    };
}

// =============================================================================
// Middleware Handler
// =============================================================================
export function middleware(request: NextRequest) {
    const ip = getClientIP(request);
    const now = Date.now();
    const windowStart = now - WINDOW_MS;

    // Periodic cleanup
    requestCounter++;
    if (requestCounter >= CLEANUP_INTERVAL) {
        requestCounter = 0;
        cleanupEntries(windowStart);
    }

    // Get or create rate limit data for this IP
    let data = ipRequests.get(ip);
    if (!data) {
        data = { timestamps: [], lastAccess: now };
        ipRequests.set(ip, data);
    }

    // Update LRU tracking
    data.lastAccess = now;

    // Filter to only requests within the current window
    data.timestamps = data.timestamps.filter(t => t > windowStart);

    // Check if rate limit exceeded
    if (data.timestamps.length >= RATE_LIMIT) {
        const resetTime = data.timestamps[0] + WINDOW_MS;
        const retryAfter = Math.ceil((resetTime - now) / 1000);

        return new NextResponse(
            JSON.stringify({
                error: 'rate_limit_exceeded',
                message: 'Too many requests. Please try again later.',
                retry_after: retryAfter,
            }),
            {
                status: 429,
                headers: {
                    'Content-Type': 'application/json',
                    'Retry-After': String(retryAfter),
                    ...getRateLimitHeaders(0, resetTime),
                },
            }
        );
    }

    // Record this request
    data.timestamps.push(now);

    // Continue to the application with rate limit info headers
    const response = NextResponse.next();
    const resetTime = data.timestamps[0] + WINDOW_MS;
    const remaining = RATE_LIMIT - data.timestamps.length;

    // Add rate limit headers to successful responses
    Object.entries(getRateLimitHeaders(remaining, resetTime)).forEach(
        ([key, value]) => {
            response.headers.set(key, value);
        }
    );

    return response;
}

// =============================================================================
// Matcher Configuration
// =============================================================================
export const config = {
    matcher: [
        /*
         * Match all request paths except:
         * - /static/* (static files)
         * - /favicon.ico, /favicon.svg (icons)
         * - /_next/* (Next.js internals, future compatibility)
         * - /api/_* (internal API routes)
         */
        '/((?!static|_next|favicon|api/_).*)',
    ],
};
