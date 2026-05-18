document.addEventListener('DOMContentLoaded', function () {
if (document.documentElement.dataset.siteguardUiInitialized === 'true') {
    return;
}
document.documentElement.dataset.siteguardUiInitialized = 'true';

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
    const icon = toggle ? (toggle.querySelector('[data-password-icon]') || toggle) : null;

    if (!toggle || !input || toggle.dataset.bound === 'true') return;
    toggle.dataset.bound = 'true';
    toggle.setAttribute('aria-controls', inputId);

    const syncToggleState = () => {
        const isVisible = input.type === 'text';
        const iconName = isVisible ? 'eye-off' : 'eye';
        toggle.setAttribute('aria-pressed', isVisible ? 'true' : 'false');
        toggle.setAttribute('aria-label', isVisible ? 'Hide password' : 'Show password');

        if (icon && window.lucide && lucide.icons[iconName]) {
            icon.innerHTML = lucide.icons[iconName].toSvg({
                'data-password-icon': 'true',
                'aria-hidden': 'true',
            });
        } else if (icon) {
            icon.setAttribute('data-lucide', iconName);
        }
    };

    const toggleVisibility = () => {
        input.type = input.type === 'password' ? 'text' : 'password';
        syncToggleState();
        if (window.lucide) {
            lucide.createIcons();
        }
    };

    syncToggleState();

    toggle.addEventListener('click', function () {
        toggleVisibility();
    });

    toggle.addEventListener('keydown', function (event) {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            toggleVisibility();
        }
    });
}
window.bindToggle = bindToggle;

function animateCounter(counter) {
    if (!counter || counter.dataset.counterAnimated === 'true') return;

    const targetAttr = counter.getAttribute('data-target');
    if (targetAttr === null || targetAttr === '') return;

    const target = parseFloat(targetAttr);
    if (Number.isNaN(target)) return;

    const suffix = counter.getAttribute('data-suffix') || '';
    const hasDecimals = target % 1 !== 0;
    const duration = hasDecimals ? 45 : 30;
    let current = 0;

    counter.dataset.counterAnimated = 'true';

    const updateCount = () => {
        const increment = target / duration;
        current = Math.min(target, current + increment);
        counter.innerText = hasDecimals
            ? `${current.toFixed(1)}${suffix}`
            : `${Math.ceil(current)}${suffix}`;

        if (current < target) {
            window.setTimeout(updateCount, 20);
            return;
        }

        counter.innerText = `${target}${suffix}`;
    };

    updateCount();
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
    heatTooltip.className = 'custom-tooltip heatmap-tooltip';
    heatTooltip.style.pointerEvents = 'none';
    heatTooltip.style.zIndex = '9999';
    heatTooltip.setAttribute('aria-hidden', 'true');
    document.body.appendChild(heatTooltip);

    const clamp = (value, min, max) => Math.min(Math.max(value, min), max);
    const hideHeatTooltip = () => {
        heatTooltip.style.opacity = '0';
        heatTooltip.setAttribute('aria-hidden', 'true');
        heatTooltip.dataset.pinned = 'false';
        heatTooltip.dataset.blockIndex = '';
        heatTooltip.removeAttribute('data-placement');
    };

    const positionHeatTooltip = (anchorRect, pointerX, pointerY) => {
        const viewportPadding = 12;
        const tooltipRect = heatTooltip.getBoundingClientRect();
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        const anchorCenterX = pointerX ?? (anchorRect.left + (anchorRect.width / 2));
        const preferredTop = (pointerY ?? anchorRect.top) - tooltipRect.height - 12;
        const fallbackTop = anchorRect.bottom + 12;
        const placement = preferredTop >= viewportPadding ? 'top' : 'bottom';
        const resolvedTop = placement === 'top'
            ? preferredTop
            : clamp(fallbackTop, viewportPadding, viewportHeight - tooltipRect.height - viewportPadding);
        const resolvedLeft = clamp(
            anchorCenterX - (tooltipRect.width / 2),
            viewportPadding,
            viewportWidth - tooltipRect.width - viewportPadding
        );

        heatTooltip.dataset.placement = placement;
        heatTooltip.style.left = `${resolvedLeft}px`;
        heatTooltip.style.top = `${resolvedTop}px`;
    };

    const showHeatTooltip = (block, hourLabel, status, timeStr, pointerX, pointerY, pinned = false) => {
        heatTooltip.innerHTML = `<strong>${hourLabel}</strong><span>Status: ${status} (${timeStr})</span>`;
        heatTooltip.style.opacity = '1';
        heatTooltip.setAttribute('aria-hidden', 'false');
        heatTooltip.dataset.pinned = pinned ? 'true' : 'false';
        positionHeatTooltip(block.getBoundingClientRect(), pointerX, pointerY);
    };

    const heatmapHeaderLabels = Array.from(document.querySelectorAll('.heatmap-labels-top span')).map((label) => label.textContent.trim());

    heatmapBlocks.forEach((block, index) => {
        if (block.dataset.heatmapTooltipBound === 'true') return;
        block.dataset.heatmapTooltipBound = 'true';

        const row = block.closest('.heatmap-row');
        const blocksInRow = row ? Array.from(row.querySelectorAll('.heatmap-blocks .block')) : [];
        const blockIndex = blocksInRow.indexOf(block);
        const hourLabel = heatmapHeaderLabels[blockIndex] || `Window ${blockIndex + 1}`;
        const siteLabel = row ? (row.querySelector('.heatmap-label')?.textContent || '').trim() : '';
        const rawCellLabel = block.getAttribute('title') || '';
        
        let status = "Optimal";
        let timeStr = rawCellLabel || "~120ms";
        
        if (block.classList.contains('bg-ok')) { status = "Normal"; }
        if (block.classList.contains('bg-warn')) { status = "Slow"; }
        if (block.classList.contains('bg-critical')) { status = "Timeout"; }
        if (block.classList.contains('bg-good')) { status = "Fast"; }

        block.addEventListener('mouseenter', (e) => {
            if (heatTooltip.dataset.pinned === 'true') return;
            showHeatTooltip(block, `${siteLabel} • ${hourLabel}`, status, timeStr, e.clientX, e.clientY, false);
        });

        block.addEventListener('mousemove', (e) => {
            if (heatTooltip.dataset.pinned === 'true') return;
            showHeatTooltip(block, `${siteLabel} • ${hourLabel}`, status, timeStr, e.clientX, e.clientY, false);
        });

        block.addEventListener('mouseleave', () => {
            if (heatTooltip.dataset.pinned === 'true') return;
            hideHeatTooltip();
        });

        block.addEventListener('click', (e) => {
            e.preventDefault();
            const isPinnedToBlock = heatTooltip.dataset.pinned === 'true' && heatTooltip.dataset.blockIndex === String(index);
            if (isPinnedToBlock) {
                hideHeatTooltip();
                return;
            }

            heatTooltip.dataset.blockIndex = String(index);
            showHeatTooltip(block, `${siteLabel} • ${hourLabel}`, status, timeStr, null, null, true);
        });

        block.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                block.click();
            }
        });
    });

    document.addEventListener('click', (event) => {
        if (!event.target.closest('.heatmap-blocks .block')) {
            hideHeatTooltip();
        }
    });

    window.addEventListener('resize', hideHeatTooltip);
    window.addEventListener('scroll', hideHeatTooltip, { passive: true });
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
    const sidebarLinks = sidebar.querySelectorAll('a');

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

    if (mobileToggle.dataset.sidebarBound !== 'true') {
        mobileToggle.dataset.sidebarBound = 'true';
        mobileToggle.addEventListener('click', () => {
            if (sidebar.classList.contains('open')) {
                closeSidebar();
            } else {
                openSidebar();
            }
        });
    }

    if (overlay.dataset.sidebarBound !== 'true') {
        overlay.dataset.sidebarBound = 'true';
        overlay.addEventListener('click', closeSidebar);
    }

    if (!document.body.dataset.sidebarEscapeBound) {
        document.body.dataset.sidebarEscapeBound = 'true';
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && sidebar.classList.contains('open')) {
                closeSidebar();
            }
        });
    }

    if (!document.body.dataset.sidebarResizeBound) {
        document.body.dataset.sidebarResizeBound = 'true';
        window.addEventListener('resize', () => {
            if (window.innerWidth > mobileBreakpoint && sidebar.classList.contains('open')) {
                closeSidebar();
            }
        });
    }

    sidebarLinks.forEach((link) => {
        if (link.dataset.sidebarBound === 'true') return;
        link.dataset.sidebarBound = 'true';
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

window.toggleIncident = toggleIncident;

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
    if (header.dataset.incidentBound !== 'true') {
        header.dataset.incidentBound = 'true';
        header.addEventListener('click', () => toggleIncident(header));
        header.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggleIncident(header);
            }
        });
    }
});

document.querySelectorAll('[data-stop-propagation]').forEach((element) => {
    if (element.dataset.stopPropagationBound === 'true') return;
    element.dataset.stopPropagationBound = 'true';
    element.addEventListener('click', (event) => {
        event.stopPropagation();
    });
});

// 3. Number Counter Animations
document.querySelectorAll('.counter[data-target]').forEach((counter) => animateCounter(counter));

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

    if (statusSearchInput.dataset.bound !== 'true') {
        statusSearchInput.dataset.bound = 'true';
        statusSearchInput.addEventListener('input', () => filterStatusCards(false));
        statusSearchInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault();
                filterStatusCards(true);
            }
        });
    }
}

// 5. Table Live Search
const searchInput = document.getElementById('globalSearch');
if (searchInput && searchInput.dataset.tableSearchBound !== 'true') {
    searchInput.dataset.tableSearchBound = 'true';
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

// 6. Global Search Suggestions
const globalSearchInput = document.getElementById('globalSearch');
const searchSuggestionsPanel = document.getElementById('searchSuggestionsPanel');

if (globalSearchInput && searchSuggestionsPanel) {
    let searchTimer = null;
    let activeSearchController = null;
    let latestSearchRequestId = 0;

    const renderSuggestions = (items, recentSearches = []) => {
        if ((!items || items.length === 0) && (!recentSearches || recentSearches.length === 0)) {
            searchSuggestionsPanel.innerHTML = '<div class="search-suggestions-state">No results found.</div>';
            searchSuggestionsPanel.classList.remove('d-none');
            return;
        }

        const parts = [];
        if (items && items.length) {
            items.forEach((item) => {
                const metaText = item.meta ? `${item.group} - ${item.meta}` : item.group;
                parts.push(`
                    <a class="search-suggestion-item" href="${item.url}">
                        <span>${item.label}<br><span class="search-suggestion-meta">${metaText}</span></span>
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

    if (globalSearchInput.dataset.searchSuggestionsBound !== 'true') {
        globalSearchInput.dataset.searchSuggestionsBound = 'true';

        globalSearchInput.addEventListener('input', () => {
            const query = globalSearchInput.value.trim();
            const endpoint = globalSearchInput.dataset.searchSuggestionsUrl;
            const requestId = ++latestSearchRequestId;

            clearTimeout(searchTimer);
            if (!endpoint) return;
            if (activeSearchController) {
                activeSearchController.abort();
            }

            searchSuggestionsPanel.innerHTML = '<div class="search-suggestions-state">Loading...</div>';
            searchSuggestionsPanel.classList.remove('d-none');

            searchTimer = setTimeout(async () => {
                activeSearchController = typeof AbortController !== 'undefined' ? new AbortController() : null;
                try {
                    const response = await fetch(`${endpoint}?q=${encodeURIComponent(query)}`, {
                        headers: { 'X-Requested-With': 'XMLHttpRequest' },
                        signal: activeSearchController ? activeSearchController.signal : undefined,
                    });
                    const data = await response.json();
                    if (requestId !== latestSearchRequestId) {
                        return;
                    }
                    renderSuggestions(data.results, data.recent_searches);
                } catch (error) {
                    if (error && error.name === 'AbortError') {
                        return;
                    }
                    searchSuggestionsPanel.innerHTML = '<div class="search-suggestions-state">Search is temporarily unavailable.</div>';
                    searchSuggestionsPanel.classList.remove('d-none');
                } finally {
                    if (requestId === latestSearchRequestId) {
                        activeSearchController = null;
                    }
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
}

// 7. Alert Read Collapse
document.querySelectorAll('.alert-read-form').forEach((form) => {
    if (form.dataset.bound === 'true') return;
    form.dataset.bound = 'true';
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
    if (form.dataset.loadingBound === 'true') return;
    form.dataset.loadingBound = 'true';
    form.addEventListener('submit', () => {
        const button = form.querySelector('[data-loading-button]');
        if (!button || button.disabled) return;
        button.dataset.originalText = button.innerHTML;
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Processing...';
    });
});

const notificationMenu = document.getElementById('notificationMenu');
const notificationDropdown = notificationMenu
    ? notificationMenu.closest('.dropdown')?.querySelector('.premium-notification-dropdown')
    : null;

if (notificationMenu && notificationDropdown) {
    const syncNotificationDropdown = () => {
        const isMobile = window.innerWidth < 992;
        const viewportPadding = isMobile ? 8 : 12;
        notificationDropdown.style.maxHeight = `${Math.max(260, Math.min(560, window.innerHeight - (isMobile ? 84 : 120)))}px`;

        const notificationList = notificationDropdown.querySelector('.notification-list');
        if (notificationList) {
            notificationList.style.maxHeight = `${Math.max(180, Math.min(420, window.innerHeight - (isMobile ? 200 : 240)))}px`;
        }

        if (isMobile) {
            notificationDropdown.style.left = `${viewportPadding}px`;
            notificationDropdown.style.right = `${viewportPadding}px`;
            notificationDropdown.style.transform = 'none';
            return;
        }

        notificationDropdown.style.left = '';
        notificationDropdown.style.right = '';
        notificationDropdown.style.transform = '';

        const rect = notificationDropdown.getBoundingClientRect();
        let shiftX = 0;
        if (rect.right > window.innerWidth - viewportPadding) {
            shiftX = (window.innerWidth - viewportPadding) - rect.right;
        }
        if (rect.left + shiftX < viewportPadding) {
            shiftX += viewportPadding - (rect.left + shiftX);
        }
        notificationDropdown.style.transform = `translate3d(${shiftX}px, 0, 0)`;
    };

    const clearNotificationDropdownInlineStyles = () => {
        notificationDropdown.style.left = '';
        notificationDropdown.style.right = '';
        notificationDropdown.style.transform = '';
    };

    if (notificationMenu.dataset.dropdownBound !== 'true') {
        notificationMenu.dataset.dropdownBound = 'true';
        notificationMenu.addEventListener('shown.bs.dropdown', syncNotificationDropdown);
        notificationMenu.addEventListener('hidden.bs.dropdown', clearNotificationDropdownInlineStyles);
        window.addEventListener('resize', () => {
            if (notificationMenu.getAttribute('aria-expanded') === 'true') {
                syncNotificationDropdown();
            }
        });
        window.addEventListener('scroll', () => {
            if (notificationMenu.getAttribute('aria-expanded') === 'true') {
                syncNotificationDropdown();
            }
        }, { passive: true });
    }
}

document.querySelectorAll('[data-site-favicon]').forEach((image) => {
    if (image.dataset.faviconBound === 'true') return;
    image.dataset.faviconBound = 'true';

    const fallbackId = image.dataset.fallbackTarget;
    const fallback = fallbackId ? document.getElementById(fallbackId) : null;
    const setFallback = (showFallback) => {
        if (!fallback) return;
        image.classList.toggle('d-none', showFallback);
        fallback.classList.toggle('d-none', !showFallback);
    };

    image.addEventListener('error', () => setFallback(true));
    image.addEventListener('load', () => setFallback(false));

    if (!image.getAttribute('src')) {
        setFallback(true);
    }
});
});
