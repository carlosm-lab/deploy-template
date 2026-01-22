// Robot Lottie Animation
document.addEventListener('DOMContentLoaded', function () {
    var robotContainer = document.getElementById('lottie-robot');
    if (robotContainer && typeof lottie !== 'undefined') {
        fetch('/static/js/robot-animation.json')
            .then(response => response.json())
            .then(animationData => {
                lottie.loadAnimation({
                    container: robotContainer,
                    renderer: 'svg',
                    loop: true,
                    autoplay: true,
                    animationData: animationData
                });
            })
            .catch(err => console.error('Error loading robot animation:', err));
    }
});
