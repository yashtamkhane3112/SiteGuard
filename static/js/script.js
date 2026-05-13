document.addEventListener('DOMContentLoaded', function () {
if (window.siteGuardAppInitialized) {
    return;
}
window.siteGuardAppInitialized = true;

// Initialize Icons globally
if (typeof lucide !== 'undefined') {
    lucide.createIcons();
}

// 1. Mouse Spotlight Tracking for Cards (Landing Page)
document.querySelectorAll('.glow-card').forEach(card => {
    card.addEventListener('mousemove', e => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        card.style.setProperty('--mouse-x', `${x}px`);
        card.style.setProperty('--mouse-y', `${y}px`);
    });
});

// 2. Scroll Reveal Animation for all elements (Landing Page)
function reveal() {
    var reveals = document.querySelectorAll(".reveal");
    for (var i = 0; i < reveals.length; i++) {
        var windowHeight = window.innerHeight;
        var elementTop = reveals[i].getBoundingClientRect().top;
        var elementVisible = 50; 

        if (elementTop < windowHeight - elementVisible) {
            reveals[i].classList.add("active");
        }
    }
}
window.addEventListener("scroll", reveal);
reveal(); // Trigger on load

// 3. Guaranteed Number Counter Animation (Landing Page)
const runCounters = (section) => {
    const counters = section.querySelectorAll('.counter');
    counters.forEach(counter => {
        const target = parseFloat(counter.getAttribute('data-target'));
        const duration = 2000; 
        const frameRate = 1000 / 60; 
        const totalFrames = Math.round(duration / frameRate);
        let frame = 0;
        const increment = target / totalFrames;

        const timer = setInterval(() => {
            frame++;
            const currentVal = increment * frame;
            
            if (target % 1 !== 0) {
                counter.innerText = currentVal.toFixed(1); 
            } else {
                counter.innerText = Math.round(currentVal); 
            }

            if (frame >= totalFrames) {
                clearInterval(timer);
                counter.innerText = target; 
            }
        }, frameRate);
    });
};

const statObserver = new IntersectionObserver((entries, obs) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            runCounters(entry.target);
            obs.unobserve(entry.target); 
        }
    });
}, { threshold: 0.3 });

document.querySelectorAll('.count-section').forEach(section => {
    statObserver.observe(section);
});

// 4. Password Visibility Toggle (Auth Pages)
function bindToggle(toggleId, inputId) {
    const toggle = document.getElementById(toggleId);
    const input = document.getElementById(inputId);

    if (!toggle || !input) return;

    toggle.addEventListener('click', function () {
        const type = input.type === 'password' ? 'text' : 'password';
        input.type = type;

        this.setAttribute(
            'data-lucide',
            type === 'password' ? 'eye' : 'eye-off'
        );

        if (window.lucide) {
            const replacement = lucide.icons[type === 'password' ? 'eye' : 'eye-off'].toSvg({
                id: toggleId,
                class: this.getAttribute('class') || 'auth-input-icon-right',
                'data-lucide': type === 'password' ? 'eye' : 'eye-off',
            });
            this.outerHTML = replacement;
            lucide.createIcons();
            bindToggle(toggleId, inputId);
        }
    });
}

// 5. Password Strength Meter Logic (Sign Up Page)
const signupPassword = document.querySelector('#id_password1');
const segments = document.querySelectorAll('.strength-segment');
const strengthText = document.querySelector('.strength-text');

if (signupPassword && segments.length > 0 && strengthText) {
    signupPassword.addEventListener('input', (e) => {
        const val = e.target.value;
        let strength = 0;
        
        if (val.length >= 8) strength += 1;
        if (/[A-Z]/.test(val)) strength += 1;
        if (/[0-9]/.test(val)) strength += 1;
        if (/[^A-Za-z0-9]/.test(val)) strength += 1;

        segments.forEach(seg => seg.style.background = 'rgba(255, 255, 255, 0.1)');
        
        if (val.length === 0) {
            strengthText.innerText = '';
        } else if (strength <= 1) {
            segments[0].style.background = '#ef4444'; // Red
            strengthText.innerText = 'Weak';
            strengthText.style.color = '#ef4444';
        } else if (strength === 2 || strength === 3) {
            segments[0].style.background = '#f59e0b'; // Yellow
            segments[1].style.background = '#f59e0b';
            strengthText.innerText = 'Good';
            strengthText.style.color = '#f59e0b';
        } else if (strength >= 4) {
            segments.forEach(seg => seg.style.background = '#10b981'); // Green
            strengthText.innerText = 'Strong';
            strengthText.style.color = '#10b981';
        }
    });
}// ==========================================
// STATUS CHECKER PAGE LOGIC
// ==========================================
// ==========================================
// STATUS CHECKER LOGIC (Runs only if elements exist)
// ==========================================

const addUrlBtn = document.getElementById('addUrlBtn');
const urlContainer = document.getElementById('urlInputContainer');

if (addUrlBtn && urlContainer) {
    addUrlBtn.addEventListener('click', () => {
        const wrapper = document.createElement('div');
        wrapper.className = 'url-input-wrapper';
        wrapper.style.opacity = '0';
        wrapper.style.transform = 'translateY(-10px)';

        wrapper.innerHTML = `
            <i data-lucide="globe" class="url-icon"></i>
            <input type="text" class="url-input" placeholder="https://" style="padding-right: 45px;">
            <button class="btn-remove-url" type="button" title="Remove URL">
                <i data-lucide="x" style="width: 16px; height: 16px;"></i>
            </button>
        `;

        urlContainer.appendChild(wrapper);
        if (typeof lucide !== 'undefined') lucide.createIcons();

        setTimeout(() => {
            wrapper.style.opacity = '1';
            wrapper.style.transform = 'translateY(0)';
            wrapper.querySelector('input').focus();
        }, 10);

        const removeBtn = wrapper.querySelector('.btn-remove-url');
        removeBtn.addEventListener('click', () => {
            wrapper.style.opacity = '0';
            wrapper.style.transform = 'translateX(20px)';
            setTimeout(() => { wrapper.remove(); }, 300);
        });
    });
}

const checkAllBtn = document.getElementById('checkAllBtn');
const resultsGrid = document.getElementById('resultsGrid');

if (checkAllBtn && resultsGrid) {
    checkAllBtn.addEventListener('click', function() {
        const originalText = this.innerHTML;
        const originalWidth = this.offsetWidth;
        this.style.width = originalWidth + 'px';
        
        this.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status"></span> Checking...`;
        this.disabled = true;
        resultsGrid.classList.add('loading-skeleton');

        setTimeout(() => {
            this.innerHTML = `<i data-lucide="check-check" class="me-2" style="width: 16px; height: 16px;"></i> Complete`;
            this.style.background = '#10b981';
            if (typeof lucide !== 'undefined') lucide.createIcons();
            
            resultsGrid.classList.remove('loading-skeleton');

            setTimeout(() => {
                this.innerHTML = originalText;
                this.disabled = false;
                this.style.background = '';
                this.style.width = 'auto';
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }, 1500);

        }, 2000);
    });
}

// ==========================================
// REPORTS PAGE: ADVANCED INTERACTIVITY
// ==========================================

// 1. Heatmap Smart Tooltips
const heatmapBlocks = document.querySelectorAll('.heatmap-blocks .block');

if (heatmapBlocks.length > 0) {
    // Create a single floating tooltip div for the heatmap
    const heatTooltip = document.createElement('div');
    heatTooltip.className = 'custom-tooltip';
    heatTooltip.style.position = 'fixed'; // Use fixed for cursor tracking
    heatTooltip.style.pointerEvents = 'none';
    heatTooltip.style.zIndex = '9999';
    document.body.appendChild(heatTooltip);

    // Array of times to simulate the labels (00:00, 02:00, etc.)
    const hours = ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00', '12:00', '14:00', '16:00', '18:00', '20:00', '22:00'];

    heatmapBlocks.forEach((block, index) => {
        // Assign a simulated time based on its position in the row (12 blocks per row)
        const hourLabel = hours[index % 12];
        
        // Determine simulated data based on the CSS class
        let status = "Optimal";
        let timeStr = "~120ms";
        
        if (block.classList.contains('bg-ok')) { status = "Normal"; timeStr = "~250ms"; }
        if (block.classList.contains('bg-warn')) { status = "Slow"; timeStr = "~850ms"; }
        if (block.classList.contains('bg-critical')) { status = "Timeout"; timeStr = "5000ms+"; }

        // When mouse enters the block
        block.addEventListener('mouseenter', (e) => {
            heatTooltip.innerHTML = `<strong>${hourLabel}</strong><br><span style="color:#94a3b8; font-size:0.8rem;">Status: ${status} (${timeStr})</span>`;
            heatTooltip.style.opacity = '1';
        });

        // When mouse moves, make tooltip follow the cursor smoothly
        block.addEventListener('mousemove', (e) => {
            heatTooltip.style.left = (e.clientX) + 'px';
            // Offset it up so it doesn't cover the cursor
            heatTooltip.style.top = (e.clientY - 50) + 'px'; 
        });

        // When mouse leaves
        block.addEventListener('mouseleave', () => {
            heatTooltip.style.opacity = '0';
        });
    });
}

// 2. Simulate Export Button Download
const exportBtn = document.getElementById('exportBtn');
if (exportBtn) {
    exportBtn.addEventListener('click', function() {
        const originalText = this.innerHTML;
        this.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Preparing...`;
        
        setTimeout(() => {
            this.innerHTML = `<i data-lucide="check" class="me-2" style="width: 16px; height: 16px;"></i> Downloaded`;
            this.style.background = '#10b981';
            this.style.borderColor = '#10b981';
            if (typeof lucide !== 'undefined') lucide.createIcons();

            setTimeout(() => {
                this.innerHTML = originalText;
                this.style.background = '';
                this.style.borderColor = '';
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }, 2000);
        }, 1500);
    });
}
// ==========================================
// INCIDENTS PAGE LOGIC
// ==========================================
// ==========================================
// GLOBAL: MOBILE SIDEBAR TOGGLE
// ==========================================
bindToggle('togglePassword', 'id_password');
bindToggle('togglePassword1', 'id_password1');
bindToggle('togglePassword2', 'id_password2');

const mobileToggle = document.getElementById('mobileToggle');
const sidebar = document.getElementById('sidebar');
const overlay = document.getElementById('mobileOverlay');

if (mobileToggle && sidebar && overlay) {
    const mobileBreakpoint = 992;

    const syncSidebarAccessibility = (isOpen) => {
        mobileToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        sidebar.setAttribute('aria-hidden', isOpen ? 'false' : 'true');
        overlay.setAttribute('aria-hidden', isOpen ? 'false' : 'true');
    };

    const openSidebar = () => {
        if (window.innerWidth > mobileBreakpoint) return;
        sidebar.classList.add('open');
        overlay.classList.add('open');
        document.body.classList.add('sidebar-open');
        document.documentElement.classList.add('sidebar-open');
        syncSidebarAccessibility(true);
    };

    const closeSidebar = () => {
        sidebar.classList.remove('open');
        overlay.classList.remove('open');
        document.body.classList.remove('sidebar-open');
        document.documentElement.classList.remove('sidebar-open');
        syncSidebarAccessibility(false);
    };

    mobileToggle.setAttribute('aria-controls', 'sidebar');
    mobileToggle.setAttribute('aria-label', 'Toggle navigation menu');
    syncSidebarAccessibility(false);

    mobileToggle.addEventListener('click', () => {
        if (sidebar.classList.contains('open')) {
            closeSidebar();
        } else {
            openSidebar();
        }
    });

    overlay.addEventListener('click', () => {
        closeSidebar();
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && sidebar.classList.contains('open')) {
            closeSidebar();
        }
    });

    window.addEventListener('resize', () => {
        if (window.innerWidth > mobileBreakpoint && sidebar.classList.contains('open')) {
            closeSidebar();
        }
    });

    sidebar.querySelectorAll('a').forEach((link) => {
        link.addEventListener('click', () => {
            if (window.innerWidth <= mobileBreakpoint) {
                closeSidebar();
            }
        });
    });
}
// 1. Interactive Filters
const filterPills = document.querySelectorAll('.filter-pill');
const incidentCards = document.querySelectorAll('.incident-card');
const noIncidentsMsg = document.getElementById('noIncidentsMsg');

if (filterPills.length > 0 && incidentCards.length > 0) {
    filterPills.forEach(pill => {
        pill.addEventListener('click', function() {
            // Remove active class from all, add to clicked
            filterPills.forEach(p => p.classList.remove('active'));
            this.classList.add('active');

            const filterValue = this.getAttribute('data-filter');
            let visibleCount = 0;

            incidentCards.forEach(card => {
                const status = card.getAttribute('data-status');
                if (filterValue === 'all' || filterValue === status) {
                    card.style.display = 'block';
                    // Trigger a small reflow animation
                    card.style.opacity = '0';
                    setTimeout(() => card.style.opacity = '1', 50);
                    visibleCount++;
                } else {
                    card.style.display = 'none';
                }
            });

            // Show empty state if nothing matches
            if (noIncidentsMsg) {
                noIncidentsMsg.style.display = visibleCount === 0 ? 'block' : 'none';
            }
        });
    });
}

// 2. Animated Accordions (Expand/Collapse Timelines)
// This function is triggered by the onclick attribute in the HTML
function toggleIncident(headerElement) {
    const bodyElement = headerElement.nextElementSibling;
    const chevron = headerElement.querySelector('.chevron-icon');
    if (!bodyElement) return;
    
    // Toggle expanded classes
    const isExpanded = bodyElement.classList.contains('expanded');
    
    if (isExpanded) {
        bodyElement.classList.remove('expanded');
        headerElement.classList.remove('expanded');
        headerElement.setAttribute('aria-expanded', 'false');
        bodyElement.style.maxHeight = '0px';
        if(chevron) chevron.style.transform = 'rotate(0deg)';
    } else {
        bodyElement.classList.add('expanded');
        headerElement.classList.add('expanded');
        headerElement.setAttribute('aria-expanded', 'true');
        bodyElement.style.maxHeight = bodyElement.scrollHeight + 40 + 'px';
        if(chevron) chevron.style.transform = 'rotate(90deg)'; 
    }
}

document.querySelectorAll('.incident-header[role="button"]').forEach((header) => {
    const body = header.nextElementSibling;
    const chevron = header.querySelector('.chevron-icon');
    header.classList.remove('expanded');
    if (body) {
        body.classList.remove('expanded');
    }
    header.setAttribute('aria-expanded', 'false');
    if (body) {
        body.style.maxHeight = '0px';
    }
    if (chevron) {
        chevron.style.transform = 'rotate(0deg)';
    }
    header.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            toggleIncident(header);
        }
    });
});

// 3. Number Counters for Incident Stats
const incidentCounters = document.querySelectorAll('.incident-stat-card .counter');
if (incidentCounters.length > 0) {
    const speed = 30;
    incidentCounters.forEach(counter => {
        const updateCount = () => {
            const target = +counter.getAttribute('data-target');
            const count = +counter.innerText;
            const inc = target / speed;

            if (count < target) {
                counter.innerText = Math.ceil(count + inc);
                setTimeout(updateCount, 40);
            } else {
                counter.innerText = target;
            }
        };
        updateCount();
    });
}
// 3. Number Counter Animations (Stats)
const animateCounters = () => {
    document.querySelectorAll('.counter').forEach(counter => {
        const targetAttr = counter.getAttribute('data-target');
        if(!targetAttr) return;
        
        const target = parseFloat(targetAttr);
        const count = parseFloat(counter.innerText.replace(/[^0-9.]/g, '')) || 0;
        const suffix = counter.getAttribute('data-suffix') || '';
        const inc = target / 30; // Animation speed

        const updateCount = () => {
            const currentCount = parseFloat(counter.innerText.replace(/[^0-9.]/g, '')) || 0;
            if (currentCount < target) {
                counter.innerText = (target % 1 !== 0) ? (currentCount + inc).toFixed(1) + suffix : Math.ceil(currentCount + inc) + suffix;
                setTimeout(updateCount, 20);
            } else {
                counter.innerText = target + suffix;
            }
        };
        updateCount();
    });
};
// Run counters immediately on dashboard load
animateCounters();

// 4. "Check Status" Button Simulation
const statusSearchInput = document.getElementById('websiteUrl');
const statusCards = Array.from(document.querySelectorAll('[data-site-card]'));
const statusEmptyState = document.getElementById('statusSearchEmptyState');

if (statusSearchInput && statusCards.length) {
    const filterStatusCards = (scrollToFirstMatch = false) => {
        const query = statusSearchInput.value.trim().toLowerCase();
        let firstMatch = null;
        let visibleCount = 0;

        statusCards.forEach((card) => {
            const haystack = card.dataset.siteSearch || '';
            const isMatch = !query || haystack.includes(query);
            if (card._hideTimer) {
                window.clearTimeout(card._hideTimer);
                card._hideTimer = null;
            }

            card.classList.toggle('result-card-filtered-out', !isMatch);
            card.setAttribute('aria-hidden', isMatch ? 'false' : 'true');

            if (isMatch) {
                card.style.display = '';
            } else {
                card._hideTimer = window.setTimeout(() => {
                    card.style.display = 'none';
                }, 160);
            }

            if (isMatch) {
                visibleCount += 1;
                if (!firstMatch) firstMatch = card;
            }
        });

        if (statusEmptyState) {
            statusEmptyState.style.display = visibleCount === 0 ? 'flex' : 'none';
        }

        if (scrollToFirstMatch && firstMatch) {
            firstMatch.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    };

    statusSearchInput.addEventListener('input', () => filterStatusCards(false));
    statusSearchInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            filterStatusCards(true);
        }
    });
}

// 5. Table Live Search
const searchInput = document.getElementById('globalSearch');
if (searchInput) {
    searchInput.addEventListener('keyup', function(e) {
        const term = e.target.value.toLowerCase();
        let hasVisibleRows = false;
        document.querySelectorAll('#activityTable tbody tr.activity-row').forEach(row => {
            if (row.textContent.toLowerCase().includes(term)) { 
                row.style.display = ''; 
                hasVisibleRows = true; 
            } else { 
                row.style.display = 'none'; 
            }
        });
        const noRes = document.getElementById('noResultsRow');
        if (noRes) noRes.style.display = hasVisibleRows ? 'none' : '';
    });
}

// 6. Draw Uptime Timeline Blocks
const container = document.getElementById('timelineContainer');
if(container) {
    const totalSegments = 48;
    const errorIndices = [12, 28]; 
    const warnIndices = [11, 24];  

    for (let i = 0; i < totalSegments; i++) {
        const segment = document.createElement('div');
        let statusClass = 'segment-up';
        let statusText = 'UP (112ms)';
        
        if (errorIndices.includes(i)) {
            statusClass = 'segment-down'; statusText = 'DOWN (Timeout)';
        } else if (warnIndices.includes(i)) {
            statusClass = 'segment-warn'; statusText = 'SLOW (850ms)';
        }

        segment.className = `segment ${statusClass}`;
        segment.addEventListener('click', function() { window.location.href = 'logs.html'; });
        
        const date = new Date();
        date.setMinutes(date.getMinutes() - ((totalSegments - 1 - i) * 30));
        const timeString = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        const tooltip = document.createElement('div');
        tooltip.className = 'custom-tooltip';
        tooltip.innerText = `${timeString} - ${statusText}`;
        segment.appendChild(tooltip);
        container.appendChild(segment);
    }
}

// 7. Global Search Suggestions
const globalSearchInput = document.getElementById('globalSearch');
const searchSuggestionsPanel = document.getElementById('searchSuggestionsPanel');

if (globalSearchInput && searchSuggestionsPanel) {
    let searchTimer = null;

    const renderSuggestions = (items, recentSearches = []) => {
        if ((!items || items.length === 0) && (!recentSearches || recentSearches.length === 0)) {
            searchSuggestionsPanel.innerHTML = '<div class="search-suggestions-state">No results found.</div>';
            searchSuggestionsPanel.classList.remove('d-none');
            return;
        }

        const parts = [];
        if (items && items.length) {
            items.forEach((item) => {
                parts.push(`
                    <a class="search-suggestion-item" href="${item.url}">
                        <span>${item.label}<br><span class="search-suggestion-meta">${item.group}${item.meta ? ` • ${item.meta}` : ''}</span></span>
                    </a>
                `);
            });
        } else if (recentSearches && recentSearches.length) {
            recentSearches.forEach((item) => {
                parts.push(`
                    <a class="search-suggestion-item" href="/search/?q=${encodeURIComponent(item)}">
                        <span>${item}<br><span class="search-suggestion-meta">Recent search</span></span>
                    </a>
                `);
            });
        }

        searchSuggestionsPanel.innerHTML = parts.join('');
        searchSuggestionsPanel.classList.remove('d-none');
    };

    globalSearchInput.addEventListener('input', () => {
        const query = globalSearchInput.value.trim();
        const endpoint = globalSearchInput.dataset.searchSuggestionsUrl;

        clearTimeout(searchTimer);
        if (!endpoint) return;

        searchSuggestionsPanel.innerHTML = '<div class="search-suggestions-state">Loading...</div>';
        searchSuggestionsPanel.classList.remove('d-none');

        searchTimer = setTimeout(async () => {
            try {
                const response = await fetch(`${endpoint}?q=${encodeURIComponent(query)}`, {
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                });
                const data = await response.json();
                renderSuggestions(data.results, data.recent_searches);
            } catch (error) {
                searchSuggestionsPanel.innerHTML = '<div class="search-suggestions-state">Search is temporarily unavailable.</div>';
                searchSuggestionsPanel.classList.remove('d-none');
            }
        }, 200);
    });

    globalSearchInput.addEventListener('focus', () => {
        if (!globalSearchInput.value.trim()) {
            const endpoint = globalSearchInput.dataset.searchSuggestionsUrl;
            if (!endpoint) return;
            fetch(`${endpoint}?q=`, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then((response) => response.json())
                .then((data) => renderSuggestions([], data.recent_searches))
                .catch(() => {});
        }
    });

    document.addEventListener('click', (event) => {
        if (!searchSuggestionsPanel.contains(event.target) && event.target !== globalSearchInput) {
            searchSuggestionsPanel.classList.add('d-none');
        }
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
            event.preventDefault();
            globalSearchInput.focus();
        }
    });
}

// 8. Alert Read Collapse
document.querySelectorAll('.alert-read-form').forEach((form) => {
    form.addEventListener('submit', (event) => {
        const card = form.closest('.alert-incident-card');
        if (!card) return;
        event.preventDefault();
        card.classList.add('is-collapsing');
        window.setTimeout(() => form.submit(), 180);
    });
});

const skeletonItems = document.querySelectorAll('[data-skeleton-item]');
if (skeletonItems.length > 0) {
    skeletonItems.forEach((item) => item.classList.add('ui-skeleton-loading'));
    window.setTimeout(() => {
        skeletonItems.forEach((item) => item.classList.remove('ui-skeleton-loading'));
    }, 320);
}

const loadingForms = document.querySelectorAll('[data-submit-loading]');
loadingForms.forEach((form) => {
    form.addEventListener('submit', () => {
        const button = form.querySelector('[data-loading-button]');
        if (!button || button.disabled) return;
        button.dataset.originalText = button.innerHTML;
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Processing...';
    });
});
});
