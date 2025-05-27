document.addEventListener('DOMContentLoaded', function() {
    const navToggle = document.getElementById('nav-toggle');
    const mobileNav = document.getElementById('mobile-nav');
    navToggle.addEventListener('click', function() {
        mobileNav.classList.toggle('hidden');
    });
    document.addEventListener('click', function(e) {
        if (!mobileNav.contains(e.target) && !navToggle.contains(e.target)) {
            mobileNav.classList.add('hidden');
        }
    });
});