/**
 * Main JavaScript - Under Construction Template
 * Scripts para funcionalidades interactivas
 */

document.addEventListener('DOMContentLoaded', function () {
    'use strict';

    // ======================================
    // 1. Progress Bar Animation
    // ======================================

    /**
     * Animates progress bars on page load
     */
    function initProgressBars() {
        const progressBars = document.querySelectorAll('[data-progress]');

        progressBars.forEach(bar => {
            const targetWidth = bar.dataset.progress || '85%';
            bar.style.width = '0%';

            setTimeout(() => {
                bar.style.transition = 'width 1.5s ease-out';
                bar.style.width = targetWidth;
            }, 500);
        });
    }

    // ======================================
    // 2. Initialize
    // ======================================

    initProgressBars();

});

