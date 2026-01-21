/**
 * Offline Page Handler
 * =============================================================================
 * Script para la página offline de PWA.
 * Extraído de offline.html para cumplimiento CSP (script-src 'self').
 * =============================================================================
 */

(function () {
    'use strict';

    /**
     * Auto-reload when connection is restored.
     * Listens for the 'online' event and reloads the page.
     */
    function initAutoReload() {
        window.addEventListener('online', function () {
            // Show feedback before reload
            var statusText = document.querySelector('.status-text');
            if (statusText) {
                statusText.textContent = 'Conexión restaurada, recargando...';
            }

            // Small delay for user feedback
            setTimeout(function () {
                location.reload();
            }, 500);
        });
    }

    /**
     * Manual reload button handler.
     * Attached via event delegation to avoid inline onclick.
     */
    function initReloadButton() {
        var btn = document.getElementById('retry-btn');
        if (btn) {
            btn.addEventListener('click', function () {
                location.reload();
            });
        }
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            initAutoReload();
            initReloadButton();
        });
    } else {
        initAutoReload();
        initReloadButton();
    }
})();
