document.addEventListener('DOMContentLoaded', function() {

    // Tag filter functionality
    const tagFilter = document.getElementById('tag-filter');
    if (tagFilter) {
        tagFilter.addEventListener('change', function() {
            const selectedTag = this.value;
            if (selectedTag) {
                window.location.href = '/devices?tag=' + encodeURIComponent(selectedTag);
            } else {
                window.location.href = '/devices';
            }
        });
    }

    // Expand/collapse site groups
    document.querySelectorAll('.site-header').forEach(header => {
        header.addEventListener('click', function(e) {
            const deviceList = this.closest('.site-group').querySelector('.device-list');
            const icon = this.querySelector('.expand-btn i');
            if (deviceList.classList.contains('hidden')) {
                deviceList.classList.remove('hidden');
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
            } else {
                deviceList.classList.add('hidden');
                icon.classList.remove('fa-chevron-up');
                icon.classList.add('fa-chevron-down');
            }
        });
    });

    // Scroll to Top Button
    const scrollToTopButton = document.createElement('button');
    scrollToTopButton.innerHTML = '<i class="fas fa-arrow-up"></i>';
    scrollToTopButton.style.fontSize = '26px';
    scrollToTopButton.className = 'fixed bottom-5 right-5 bg-gray-200 dark:bg-zinc-800 text-black dark:text-white p-3 rounded-full shadow-lg hidden';
    scrollToTopButton.style.width = '60px';
    scrollToTopButton.style.height = '60px';
    scrollToTopButton.style.borderRadius = '50%';
    document.body.appendChild(scrollToTopButton);

    const style = document.createElement('style');
    style.textContent = `
        @keyframes bob {
            0%, 100% {
                transform: translateY(0);
            }
            50% {
                transform: translateY(-5px);
            }
        }

        .bobbing {
            animation: bob 1.5s infinite;
        }
    `;
    document.head.appendChild(style);

    scrollToTopButton.classList.add('bobbing');

    window.addEventListener('scroll', () => {
        if (window.scrollY > 200) {
            scrollToTopButton.classList.remove('hidden');
        } else {
            scrollToTopButton.classList.add('hidden');
        }
    });

    scrollToTopButton.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
});