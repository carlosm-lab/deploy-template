// Robot Lottie Animation - Lazy Loaded for better LCP
// M3: Deferred loading to not block initial paint
(function () {
    'use strict';

    function initRobotAnimation() {
        var robotContainer = document.getElementById('lottie-robot');
        if (robotContainer && typeof lottie !== 'undefined') {
            // Use requestIdleCallback for non-critical animation loading
            var loadAnimation = function () {
                fetch('/static/js/robot-animation.json')
                    .then(function (response) { return response.json(); })
                    .then(function (animationData) {
                        lottie.loadAnimation({
                            container: robotContainer,
                            renderer: 'svg',
                            loop: true,
                            autoplay: true,
                            animationData: animationData
                        });
                    })
                    .catch(function (err) {
                        console.error('Error loading robot animation:', err);
                    });
            };

            // Defer animation loading for better performance
            if ('requestIdleCallback' in window) {
                requestIdleCallback(loadAnimation, { timeout: 2000 });
            } else {
                setTimeout(loadAnimation, 100);
            }
        }
    }

    // Wait for DOM and window load to ensure LCP is not blocked
    if (document.readyState === 'complete') {
        initRobotAnimation();
    } else {
        window.addEventListener('load', initRobotAnimation);
    }
})();
