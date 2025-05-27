document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', (event) => {
            event.preventDefault();
        });

        const searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.placeholder = 'Search by IP or Hostname';
        searchInput.className = 'p-2 w-full rounded-lg bg-gray-800 text-gray-100 border border-gray-600 focus:outline-none focus:border-blue-400 mb-4 text-center';
        form.insertAdjacentElement('beforebegin', searchInput);

        searchInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault();
                const searchTerm = searchInput.value.toLowerCase();
                const rows = document.querySelectorAll('tbody tr');

                rows.forEach(row => {
                    const ipCell = row.querySelector('td:nth-child(1)').textContent.toLowerCase();
                    const hostnameCell = row.querySelector('td:nth-child(2)').textContent.toLowerCase();

                    if (ipCell.includes(searchTerm) || hostnameCell.includes(searchTerm)) {
                        row.style.backgroundColor = 'rgba(59, 130, 246, 0.5)';
                        row.scrollIntoView({ behavior: 'smooth', block: 'center' });

                        setTimeout(() => {
                            row.style.backgroundColor = '';
                        }, 3000);
                    } else {
                        row.style.backgroundColor = '';
                    }
                });
            }
        });
    }

    // Scroll to Top Button
    const scrollToTopButton = document.createElement('button');
    scrollToTopButton.innerHTML = '<i class="fas fa-arrow-up"></i>';
    scrollToTopButton.style.fontSize = '26px';
    scrollToTopButton.className = 'fixed bottom-5 right-5 bg-gray-800 text-white p-3 rounded-full shadow-lg hidden';
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