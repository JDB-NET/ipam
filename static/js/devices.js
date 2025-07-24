document.addEventListener('DOMContentLoaded', function() {

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

    // Search functionality
    const searchInput = document.getElementById('search');
    searchInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            const query = this.value.toLowerCase();
            document.querySelectorAll('.site-group').forEach(siteGroup => {
                let anyVisible = false;
                siteGroup.querySelectorAll('.device-list li').forEach(li => {
                    const deviceName = li.querySelector('span').textContent.toLowerCase();
                    const ipSpans = li.querySelectorAll('span.inline-block');
                    let match = deviceName.includes(query);
                    if (!match) {
                        ipSpans.forEach(ipSpan => {
                            if (ipSpan.textContent.toLowerCase().includes(query)) {
                                match = true;
                            }
                        });
                    }
                    li.style.display = match ? '' : 'none';
                    const card = li.querySelector('a');
                    if (match) {
                        anyVisible = true;
                        siteGroup.querySelector('.device-list').classList.remove('hidden');
                        const icon = siteGroup.querySelector('.expand-btn i');
                        if (icon && icon.classList.contains('fa-chevron-down')) {
                            icon.classList.remove('fa-chevron-down');
                            icon.classList.add('fa-chevron-up');
                        }
                        if (card) {
                            card.style.transition = 'background-color 0.3s';
                            card.style.backgroundColor = '#2563eb';
                            card.style.color = '#fff';
                            setTimeout(() => {
                                card.style.backgroundColor = '';
                                card.style.color = '';
                            }, 2000);
                        }
                    } else {
                        if (card) {
                            card.style.backgroundColor = '';
                            card.style.color = '';
                        }
                    }
                });
                siteGroup.style.display = anyVisible ? '' : 'none';
            });
        }
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