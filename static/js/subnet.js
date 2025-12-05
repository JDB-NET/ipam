document.addEventListener('DOMContentLoaded', () => {
    // Only target the form on the subnet page, not the header search form
    // Look for a form that's not in the header (header forms have action="/search")
    const allForms = document.querySelectorAll('form');
    let form = null;
    for (let f of allForms) {
        if (f.action !== '/search' && f.method === 'POST') {
            form = f;
            break;
        }
    }
    if (form) {
        // Check if search input already exists to prevent duplicates
        if (!document.querySelector('input[placeholder="Search by IP or Hostname"]')) {
            form.addEventListener('submit', (event) => {
                event.preventDefault();
            });

            const searchInput = document.createElement('input');
            searchInput.type = 'text';
            searchInput.placeholder = 'Search by IP or Hostname';
            searchInput.className = 'p-2 w-full rounded-lg bg-gray-200 dark:bg-zinc-800 border border-gray-600 focus:outline-none focus:border-blue-400 mb-4 text-center';
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
    }

    // Description toggle functionality
    const toggleBtn = document.getElementById('toggle-desc');
    const descCols = document.querySelectorAll('.desc-col');
    const descHeader = document.getElementById('desc-col-header');
    let shown = false;
    if (toggleBtn) {
        toggleBtn.addEventListener('click', function() {
            shown = !shown;
            descCols.forEach(col => col.classList.toggle('hidden', !shown));
            if (descHeader) descHeader.classList.toggle('hidden', !shown);
            toggleBtn.textContent = shown ? 'Hide Descriptions' : 'Show Descriptions';
        });
    }

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

    // Force scrollbar thumb to render on page load
    // This fixes the issue where scrollbar thumb is missing on initial page load
    // The scrollbar only renders its thumb after a scroll event has occurred
    requestAnimationFrame(() => {
        const isScrollable = document.documentElement.scrollHeight > document.documentElement.clientHeight;
        if (isScrollable && window.scrollY === 0) {
            // Trigger a minimal scroll to force scrollbar rendering, then scroll back
            window.scrollBy(0, 1);
            requestAnimationFrame(() => {
                window.scrollBy(0, -1);
            });
        }
    });

    // Scroll to IP anchor if present in URL hash
    if (window.location.hash) {
        const hash = window.location.hash.substring(1);
        const element = document.getElementById(hash);
        if (element) {
            setTimeout(() => {
                element.scrollIntoView({ behavior: 'smooth', block: 'center' });
                // Highlight the row briefly
                element.style.backgroundColor = 'rgba(59, 130, 246, 0.5)';
                setTimeout(() => {
                    element.style.backgroundColor = '';
                }, 3000);
            }, 100);
        }
    }
});