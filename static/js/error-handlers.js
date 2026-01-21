/**
 * Error Page Handlers
 * =============================================================================
 * Scripts para páginas de error (403, 404, 429, 500).
 * Reemplaza onclick inline para cumplimiento CSP (script-src 'self').
 * =============================================================================
 */

(function () {
    'use strict';

    /**
     * Initialize reload button handlers.
     * Uses event delegation for all buttons with data-action="reload".
     */
    function initReloadButtons() {
        document.addEventListener('click', function (event) {
            var target = event.target.closest('[data-action="reload"]');
            if (target) {
                event.preventDefault();
                location.reload();
            }
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initReloadButtons);
    } else {
        initReloadButtons();
    }
})();
