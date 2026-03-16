/* app.js — Stargazer Web UI main application
 *
 * Handles: sidebar navigation, gauge rendering, page routing.
 * API integration added in later phases.
 */

(function () {
    'use strict';

    /* ================================================================
     *  SIDEBAR TOGGLE (hamburger menu)
     * ================================================================ */
    var hamburger = document.querySelector('.topbar-hamburger');
    var sidebar = document.querySelector('.sidebar');

    if (hamburger && sidebar) {
        hamburger.addEventListener('click', function () {
            sidebar.classList.toggle('collapsed');
        });
    }

    /* ================================================================
     *  SIDEBAR NAVIGATION
     * ================================================================ */
    var categories = document.querySelectorAll('.nav-category');

    categories.forEach(function (cat) {
        var header = cat.querySelector('.nav-category-header');
        if (!header) return;

        header.addEventListener('click', function () {
            var hasArrow = cat.querySelector('.nav-arrow');

            if (hasArrow) {
                /* Toggle open/close */
                cat.classList.toggle('open');
            } else {
                /* Direct page link (e.g. Dashboard) */
                setActivePage(cat.dataset.page, cat, null);
            }
        });
    });

    /* Sub-item clicks */
    var subItems = document.querySelectorAll('.nav-sub-item');
    subItems.forEach(function (item) {
        item.addEventListener('click', function (e) {
            e.stopPropagation();
            var parentCat = item.closest('.nav-category');
            setActivePage(item.dataset.page, parentCat, item);
        });
    });

    var contentEl = document.getElementById('content');

    function setActivePage(page, category, subItem) {
        /* Clear all active states */
        categories.forEach(function (c) { c.classList.remove('active'); });
        subItems.forEach(function (s) { s.classList.remove('active'); });

        /* Set new active */
        if (category) category.classList.add('active');
        if (subItem) subItem.classList.add('active');

        /* SPA page routing — show target page, hide all others */
        var pages = document.querySelectorAll('.page');
        pages.forEach(function (p) {
            p.style.display = 'none';
        });

        /* Remove any lingering covers from interrupted transitions */
        document.querySelectorAll('.page-cover').forEach(function (el) { el.remove(); });

        /* Track active page for poll manager + persist for refresh */
        activePage = page;
        sessionStorage.setItem('sg_page', page);

        /* Clear topbar search on page switch */
        var topSearch = document.querySelector('.topbar-search input');
        if (topSearch && topSearch.value) {
            topSearch.value = '';
        }

        var target = document.getElementById('page-' + page);
        if (target) {
            target.style.display = '';
            var contentEl = document.getElementById('content');

            /* 1) Immediately show opaque cover with loading spinner.
             *    This blocks the old/empty content while data loads. */
            var cover = document.createElement('div');
            cover.className = 'page-cover page-cover-loading';

            var spinner = document.createElement('div');
            spinner.className = 'page-loading-spinner';
            spinner.textContent = 'LOADING...';
            cover.appendChild(spinner);

            contentEl.appendChild(cover);

            /* 2) Fetch data behind the cover */
            refreshPage(page).then(function () {
                /* 3) Data loaded — switch to scan-line reveal animation */
                requestAnimationFrame(function () {
                    requestAnimationFrame(function () {
                        cover.classList.remove('page-cover-loading');
                        cover.classList.add('page-cover-reveal');

                        /* Replace spinner with scan line */
                        cover.innerHTML = '';
                        var scanLine = document.createElement('div');
                        scanLine.className = 'page-scan-line';
                        cover.appendChild(scanLine);

                        cover.addEventListener('animationend', function () {
                            cover.remove();
                        });
                    });
                });
            });
        }

        /* Start/stop polling based on new page */
        startPolling();
    }

    /**
     * Refresh data for a page — calls API fetch/render per page type.
     * Also resets local UI state (search filters, hidden rows) so the
     * page appears freshly loaded.
     */
    function refreshPage(page) {
        var pageEl = document.getElementById('page-' + page);
        var promises = [];

        /* Page-specific data fetchers — collect promises for reveal timing */
        if (page === 'dashboard') { promises.push(renderGauges(), renderIfaces()); }
        else if (page === 'resources') { promises.push(renderResourceGauges(), renderResourceDetails()); }
        else if (page === 'home-network') { promises.push(renderNetworkOverview()); }
        else if (page === 'sys-settings') { promises.push(loadSettingsPage(pageEl, 'system')); }
        else if (page === 'sys-password') { promises.push(loadSettingsPage(pageEl, 'password-policy')); }
        else if (page === 'sys-firmware') { promises.push(loadFirmwareInfo()); }
        else if (pageEl) {
            var table = pageEl.querySelector('table[data-entity]');
            if (table) promises.push(loadEntityPage(table.dataset.entity, table));
            resetPageFilters(pageEl);
        }

        /* Resolve when all API fetches complete (or immediately for static pages) */
        return Promise.all(promises).catch(function () { /* ignore errors */ });
    }

    /**
     * Reset all search inputs and show all hidden rows on a page.
     */
    function resetPageFilters(pageEl) {
        /* Clear search inputs */
        pageEl.querySelectorAll('.toolbar-search input, .widget-search input').forEach(function (inp) {
            inp.value = '';
        });

        /* Show all hidden rows */
        pageEl.querySelectorAll('table.data-table tbody tr').forEach(function (row) {
            row.style.display = '';
        });
    }

    /* ================================================================
     *  API HELPER — central fetch wrapper for future backend calls
     * ================================================================ */

    var API_BASE = '/api';

    /*
     * api(endpoint, opts) — returns Promise<json>
     *
     * Usage:
     *   api('/system/resources').then(function (data) { ... });
     *   api('/config/interfaces/eth0', { method: 'PUT', body: {...} });
     *
     * In demo mode (no backend), returns null so callers fall through
     * to demo data. When the webui HTTP server is ready, remove the
     * demo fallback paths and rely solely on API responses.
     */
    function api(endpoint, opts) {
        var url = API_BASE + endpoint;
        var options = opts || {};
        options.headers = options.headers || {};

        /* Session is managed via HttpOnly cookie (sg_sid),
         * sent automatically by the browser. No manual token needed. */

        /* Only set Content-Type for plain object bodies (skip FormData) */
        if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
            options.headers['Content-Type'] = options.headers['Content-Type'] || 'application/json';
            options.body = JSON.stringify(options.body);
        }

        return fetch(url, options)
            .then(function (res) {
                if (res.status === 401) {
                    window.location.href = 'login.html';
                    return;
                }
                if (res.status === 403) {
                    showToast('Permission denied', 'error');
                    var e = new Error('Permission denied');
                    e.status = 403;
                    throw e;
                }
                if (!res.ok) {
                    return res.json().catch(function () { return {}; }).then(function (err) {
                        var e = new Error(err.error || ('HTTP ' + res.status));
                        e.status = res.status;
                        throw e;
                    });
                }
                return res.json();
            })
            .catch(function (err) {
                /* Network error or no backend — return null for demo fallback */
                if (!err.status) return null;
                throw err;
            });
    }

    /* ================================================================
     *  TOAST NOTIFICATIONS
     * ================================================================ */

    function showToast(message, type) {
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + (type || 'success');
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(function () {
            toast.classList.add('toast-fade');
            setTimeout(function () { toast.remove(); }, 300);
        }, 3000);
    }

    /* Map entity name to backend config type */
    function cfgType(entity) {
        var e = ENTITIES[entity];
        return e && e.configType ? e.configType : entity;
    }

    /* ================================================================
     *  GAUGE RENDERING (donut ring charts)
     * ================================================================ */

    /* Draw a donut gauge on a canvas element */
    function drawGauge(canvasId, percent, color) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return;

        var ctx = canvas.getContext('2d');
        var dpr = window.devicePixelRatio || 1;
        var size = 280;  /* canvas logical size */
        var cx = size / 2;
        var cy = size / 2;
        var radius = 112;
        var lineWidth = 20;

        canvas.width = size * dpr;
        canvas.height = size * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        /* Background track */
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.strokeStyle = '#e2e5ea';
        ctx.lineWidth = lineWidth;
        ctx.lineCap = 'round';
        ctx.stroke();

        /* Value arc */
        if (percent > 0) {
            var startAngle = -Math.PI / 2;
            var endAngle = startAngle + (Math.PI * 2) * (percent / 100);

            ctx.beginPath();
            ctx.arc(cx, cy, radius, startAngle, endAngle);
            ctx.strokeStyle = color;
            ctx.lineWidth = lineWidth;
            ctx.lineCap = 'round';
            ctx.stroke();
        }
    }

    /* Escape HTML special chars to prevent XSS when inserting API data */
    function esc(s) {
        if (s === null || s === undefined) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    /* Update gauge value text + detail text by element IDs */
    function setGaugeText(valId, value, unit, detailId, detail) {
        var valEl = document.getElementById(valId);
        var detailEl = document.getElementById(detailId);
        if (valEl) valEl.innerHTML = esc(value) + (unit ? '<span class="gauge-unit">' + esc(unit) + '</span>' : '');
        if (detailEl) detailEl.textContent = detail;
    }

    /* Color thresholds: green → orange → red */
    function gaugeColor(percent) {
        if (percent < 60) return '#4caf50';
        if (percent < 85) return '#e8956a';
        return '#e53935';
    }

    /* Temperature color: green < 60°C, orange < 80°C, red >= 80°C */
    function tempColor(deg) {
        if (deg < 60) return '#4caf50';
        if (deg < 80) return '#e8956a';
        return '#e53935';
    }

    /*
     * Fetch and render dashboard gauges.
     *
     * API contract (GET /api/system/resources):
     *   { cpu_pct, mem_pct, mem_used_mb, mem_total_mb,
     *     disk_pct, disk_used_mb, disk_total_mb,
     *     sessions, sessions_max, cpu_cores, cpu_mhz }
     *
     * Falls back to demo data when API is unavailable.
     */
    function renderGauges() {
        return api('/system/resources').then(function (data) {
            if (!data) {
                /* Demo fallback */
                data = {
                    cpu_pct: 12, mem_pct: 45, mem_used_mb: 920, mem_total_mb: 2048,
                    disk_pct: 23, disk_used_mb: 118, disk_total_mb: 512,
                    sessions: 37, sessions_max: 65536, cpu_cores: 4, cpu_mhz: 1800
                };
            }

            var sessPct = data.sessions_max > 0 ? Math.round(data.sessions / data.sessions_max * 100) : 0;

            drawGauge('gauge-cpu', data.cpu_pct, gaugeColor(data.cpu_pct));
            drawGauge('gauge-mem', data.mem_pct, gaugeColor(data.mem_pct));
            drawGauge('gauge-disk', data.disk_pct, gaugeColor(data.disk_pct));
            drawGauge('gauge-sessions', sessPct, gaugeColor(sessPct));

            setGaugeText('val-cpu', data.cpu_pct, '%', 'detail-cpu',
                data.cpu_cores + ' cores @ ' + data.cpu_mhz + ' MHz');
            setGaugeText('val-mem', data.mem_pct, '%', 'detail-mem',
                data.mem_used_mb + ' MB / ' + data.mem_total_mb + ' MB');
            setGaugeText('val-disk', data.disk_pct, '%', 'detail-disk',
                data.disk_used_mb + ' MB / ' + data.disk_total_mb + ' MB');
            setGaugeText('val-sessions', data.sessions, '', 'detail-sessions',
                'active connections');
        });
    }

    /* renderGauges() is called via setActivePage → refreshPage on initial load */

    /*
     * Fetch and render resource page gauges.
     *
     * API contract (GET /api/system/resources/detail):
     *   { temp_c, cpu_pct, load_avg, mem_pct, mem_used_mb, mem_total_mb,
     *     disk_pct, disk_used_mb, disk_total_mb }
     *
     * Falls back to demo data when API is unavailable.
     */
    /* Helper: format kB value to human-readable MB string */
    function fmtMB(kb) {
        return Math.round(kb / 1024) + ' MB';
    }

    function renderResourceDetails() {
        /* Fetch RAM details */
        var ramP = api('/system/resources/ram').then(function (d) {
            if (!d) return;
            var t = d.total || 0;
            var setText = function (id, val) {
                var el = document.getElementById(id);
                if (el) el.textContent = val;
            };
            var pct = t > 0 ? Math.round(d.used / t * 100) : 0;
            var aPct = t > 0 ? Math.round(d.available / t * 100) : 0;
            setText('ram-total', fmtMB(t));
            setText('ram-used', fmtMB(d.used) + ' (' + pct + '%)');
            setText('ram-free', fmtMB(d.free));
            setText('ram-buffers', fmtMB(d.buffers));
            setText('ram-cached', fmtMB(d.cached));
            setText('ram-available', fmtMB(d.available) + ' (' + aPct + '%)');
            setText('swap-total', fmtMB(d.swap_total));
            setText('swap-used', fmtMB(d.swap_used));
            setText('swap-free', fmtMB(d.swap_total - d.swap_used));
            setText('ram-slab', fmtMB(d.slab));
            /* Update bars */
            function setBar(id, valId, kb) {
                var bar = document.getElementById(id);
                var val = document.getElementById(valId);
                if (bar) bar.style.width = (t > 0 ? Math.round(kb / t * 100) : 0) + '%';
                if (val) val.textContent = fmtMB(kb);
            }
            setBar('bar-used', 'bar-used-val', d.used);
            setBar('bar-buf', 'bar-buf-val', d.buffers);
            setBar('bar-cache', 'bar-cache-val', d.cached);
            setBar('bar-free', 'bar-free-val', d.free);
            setBar('bar-swap', 'bar-swap-val', d.swap_used);
        });

        /* Fetch disk details */
        var diskP = api('/system/resources/disk').then(function (d) {
            if (!d) return;
            var setText = function (id, val) {
                var el = document.getElementById(id);
                if (el) el.textContent = val;
            };
            setText('disk-emmc-size', d.emmc_mb + ' MB');
            setText('disk-total', d.total_mb + ' MB');
            setText('disk-used', d.used_mb + ' MB');
            setText('disk-free', d.free_mb + ' MB');
        });

        /* Fetch process list */
        var procP = api('/system/resources/proctop').then(function (d) {
            if (!d) return;
            /* Update uptime */
            if (d.uptime) {
                var secs = parseFloat(d.uptime);
                var days = Math.floor(secs / 86400);
                var hrs = Math.floor((secs % 86400) / 3600);
                var mins = Math.floor((secs % 3600) / 60);
                var s = Math.floor(secs % 60);
                var upEl = document.getElementById('res-uptime');
                if (upEl) upEl.textContent = days + 'd ' + hrs + 'h ' + mins + 'm ' + s + 's';
            }
            /* Render process table */
            var tbody = document.getElementById('proctop-tbody');
            if (tbody && d.procs) {
                /* Sort by RSS descending */
                var sorted = d.procs.slice().sort(function (a, b) { return b.rss_kb - a.rss_kb; });
                var html = '';
                sorted.forEach(function (p) {
                    html += '<tr><td>' + esc(p.pid) + '</td>' +
                            '<td>' + esc(p.name) + '</td>' +
                            '<td>' + esc(p.cpu_ticks) + '</td>' +
                            '<td>' + esc(Math.round(p.rss_kb / 1024)) + ' MB</td>' +
                            '<td>' + esc(p.state) + '</td></tr>';
                });
                if (html === '') html = '<tr><td colspan="5" style="text-align:center;color:#999;padding:20px">No processes</td></tr>';
                tbody.innerHTML = html;
            }
        });

        return Promise.all([ramP, diskP, procP]);
    }

    function renderResourceGauges() {
        return api('/system/resources/detail').then(function (data) {
            if (!data) {
                data = {
                    temp_c: 52, cpu_pct: 12, load_avg: '0.48 0.56 0.32',
                    mem_pct: 45, mem_used_mb: 920, mem_total_mb: 2048,
                    disk_pct: 23, disk_used_mb: 118, disk_total_mb: 512
                };
            }

            var tempPct = Math.round((data.temp_c / 85) * 100);
            drawGauge('gauge-res-temp', tempPct, tempColor(data.temp_c));
            drawGauge('gauge-res-cpu', data.cpu_pct, gaugeColor(data.cpu_pct));
            drawGauge('gauge-res-mem', data.mem_pct, gaugeColor(data.mem_pct));
            drawGauge('gauge-res-disk', data.disk_pct, gaugeColor(data.disk_pct));

            var tempStatus = data.temp_c < 60 ? 'Normal' : data.temp_c < 80 ? 'Warm' : 'HOT';
            setGaugeText('val-res-temp', data.temp_c, '\u00B0C', 'detail-res-temp',
                tempStatus + ' (< 85\u00B0C)');
            setGaugeText('val-res-cpu', data.cpu_pct, '%', 'detail-res-cpu',
                'load avg: ' + data.load_avg);
            setGaugeText('val-res-mem', data.mem_pct, '%', 'detail-res-mem',
                data.mem_used_mb + ' / ' + data.mem_total_mb + ' MB');
            setGaugeText('val-res-disk', data.disk_pct, '%', 'detail-res-disk',
                data.disk_used_mb + ' / ' + data.disk_total_mb + ' MB');
        });
    }

    /* ================================================================
     *  POLL MANAGER — start/stop polling based on active page
     * ================================================================ */

    var POLL_INTERVAL = 5000; /* 5 seconds — tune per page if needed */
    var activePage = 'dashboard';
    var pollTimer = null;

    /* Poll functions per page — only pages with live data need entries */
    var PAGE_POLLERS = {
        'dashboard':    renderGauges,
        'resources':    renderResourceGauges
    };

    function startPolling() {
        stopPolling();
        var fn = PAGE_POLLERS[activePage];
        if (!fn) return;
        pollTimer = setInterval(fn, POLL_INTERVAL);
    }

    function stopPolling() {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    /* Pause polling when tab is hidden, resume when visible */
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) {
            stopPolling();
        } else {
            /* Immediate refresh + restart interval */
            var fn = PAGE_POLLERS[activePage];
            if (fn) fn();
            startPolling();
        }
    });

    /* Initial page load is deferred to the end of the file (after ENTITIES
     * and all handlers are defined) to avoid var-hoisting undefined errors. */

    /* ================================================================
     *  ROUTE FLOW WIDGET (sort + pagination)
     * ================================================================ */

    /* Convert "A.B.C.D" to 32-bit number for numeric sort */
    function ipToNum(ip) {
        var parts = ip.split('.');
        return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    }

    /* Status sort priority: ACTIVE first, STANDBY second, DISABLED last */
    var STATUS_ORDER = { ACTIVE: 0, STANDBY: 1, DISABLED: 2 };

    /* Demo route data — 24 routes across all types/statuses */
    var routeData = [];

    /* Fetch real route data from API → populate routeData */
    function fetchRouteData() {
        return api('/config/network_route_static').then(function (data) {
            if (!data || !data.entries) return;
            routeData = data.entries.map(function (e) {
                return {
                    type:   'STATIC',
                    status: (e.status || 'enable') === 'enable' ? 'ACTIVE' : 'DISABLED',
                    iface:  e.device || '',
                    gw:     e.gateway || '',
                    dest:   e.dst || '0.0.0.0/0',
                    hits:   0
                };
            });
        });
    }

    /* Widget state */
    var rfState = {
        sortKey: 'dest',
        sortAsc: true,
        page: 0,
        pageSize: 10,
        search: ''
    };

    /* Parse "A.B.C.D/N" → { ip: number, prefix: number } */
    function parseCIDR(cidr) {
        var parts = cidr.split('/');
        return { ip: ipToNum(parts[0]), prefix: parseInt(parts[1], 10) || 0 };
    }

    /* Compare two routes by a given key */
    function compareRoutes(a, b, key, asc) {
        var va, vb, diff;
        if (key === 'dest') {
            var ca = parseCIDR(a.dest);
            var cb = parseCIDR(b.dest);
            diff = ca.ip - cb.ip;
            if (diff === 0) diff = ca.prefix - cb.prefix;
            /* Secondary sort: status priority (ACTIVE < STANDBY < DISABLED) */
            if (diff === 0) diff = STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
        } else if (key === 'status') {
            diff = STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
            if (diff === 0) {
                var da = parseCIDR(a.dest), db = parseCIDR(b.dest);
                diff = da.ip - db.ip;
            }
        } else if (key === 'type') {
            va = a.type; vb = b.type;
            diff = va < vb ? -1 : va > vb ? 1 : 0;
            if (diff === 0) {
                var da2 = parseCIDR(a.dest), db2 = parseCIDR(b.dest);
                diff = da2.ip - db2.ip;
            }
        } else if (key === 'iface') {
            va = a.iface; vb = b.iface;
            diff = va < vb ? -1 : va > vb ? 1 : 0;
            if (diff === 0) {
                var da3 = parseCIDR(a.dest), db3 = parseCIDR(b.dest);
                diff = da3.ip - db3.ip;
            }
        } else if (key === 'hits') {
            diff = a.hits - b.hits;
        } else {
            diff = 0;
        }
        return asc ? diff : -diff;
    }

    /* Format number with commas: 1248502 → "1,248,502" */
    function fmtNum(n) {
        return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    /* Build HTML for one route row */
    function routeRowHTML(r) {
        var typeCls = r.type.toLowerCase();
        var statusCls = r.status === 'ACTIVE' ? 'active' :
                        r.status === 'STANDBY' ? 'standby' : 'route-disabled';
        var dotCls = r.status === 'ACTIVE' ? 'up' :
                     r.status === 'DISABLED' ? 'down' : 'disabled';

        var html = '<div class="route-row">';
        html += '<span class="route-type ' + esc(typeCls) + '">' + esc(r.type) + '</span>';
        html += '<span class="route-status ' + esc(statusCls) + '"><span class="status-dot ' + esc(dotCls) + '"></span>' + esc(r.status) + '</span>';
        html += '<span class="route-hits">' + esc(fmtNum(r.hits)) + '</span>';
        html += '<span class="route-iface">' + esc(r.iface) + '</span>';
        html += '<span class="route-arrow">&rarr;</span>';
        if (r.gw) {
            html += '<span class="route-gw">' + esc(r.gw) + '</span>';
            html += '<span class="route-arrow">&rarr;</span>';
        }
        html += '<span class="route-dest">' + esc(r.dest) + '</span>';
        html += '</div>';
        return html;
    }

    /* Render the route flow widget */
    function renderRouteFlows() {
        var body = document.getElementById('route-flow-body');
        if (!body || !rfState) return Promise.resolve();

        return fetchRouteData().then(function () {
            renderRouteRows();
        });
    }

    function renderRouteRows() {
        var body = document.getElementById('route-flow-body');
        var info = document.getElementById('rf-pager-info');
        var pageNum = document.getElementById('rf-page-num');
        var prevBtn = document.getElementById('rf-prev');
        var nextBtn = document.getElementById('rf-next');
        if (!body || !rfState) return;

        /* Filter by search term */
        var filtered = routeData;
        if (rfState.search) {
            var q = rfState.search.toLowerCase();
            filtered = routeData.filter(function (r) {
                return r.type.toLowerCase().indexOf(q) !== -1 ||
                       r.status.toLowerCase().indexOf(q) !== -1 ||
                       r.iface.toLowerCase().indexOf(q) !== -1 ||
                       r.gw.toLowerCase().indexOf(q) !== -1 ||
                       r.dest.toLowerCase().indexOf(q) !== -1 ||
                       String(r.hits).indexOf(q) !== -1;
            });
        }

        /* Sort */
        var sorted = filtered.slice().sort(function (a, b) {
            return compareRoutes(a, b, rfState.sortKey, rfState.sortAsc);
        });

        /* Paginate */
        var total = sorted.length;
        var totalPages = Math.ceil(total / rfState.pageSize);
        if (rfState.page >= totalPages) rfState.page = totalPages - 1;
        if (rfState.page < 0) rfState.page = 0;

        var start = rfState.page * rfState.pageSize;
        var end = Math.min(start + rfState.pageSize, total);
        var pageRoutes = sorted.slice(start, end);

        /* Render rows */
        var html = '';
        for (var i = 0; i < pageRoutes.length; i++) {
            html += routeRowHTML(pageRoutes[i]);
        }
        body.innerHTML = html;

        /* Pager info */
        info.textContent = total === 0 ? 'No routes' : 'Showing ' + (start + 1) + '-' + end + ' of ' + total;
        pageNum.textContent = totalPages === 0 ? '0 / 0' : (rfState.page + 1) + ' / ' + totalPages;
        prevBtn.disabled = rfState.page === 0;
        nextBtn.disabled = rfState.page >= totalPages - 1;

        /* Update header sort indicators */
        var cols = document.querySelectorAll('#route-flow-widget .rf-col[data-sort]');
        cols.forEach(function (col) {
            var key = col.dataset.sort;
            col.classList.toggle('rf-sort-active', key === rfState.sortKey);
            /* Show arrow only on active sort column */
            var label = col.dataset.sort.toUpperCase();
            if (key === rfState.sortKey) {
                col.textContent = label + ' ' + (rfState.sortAsc ? '\u25B2' : '\u25BC');
            } else {
                col.textContent = label;
            }
        });
    }

    /* Bind sort header clicks */
    var rfCols = document.querySelectorAll('#route-flow-widget .rf-col[data-sort]');
    rfCols.forEach(function (col) {
        col.addEventListener('click', function () {
            var key = col.dataset.sort;
            if (rfState.sortKey === key) {
                rfState.sortAsc = !rfState.sortAsc;
            } else {
                rfState.sortKey = key;
                rfState.sortAsc = true;
            }
            rfState.page = 0;
            renderRouteRows();
        });
    });

    /* Bind pager controls */
    var rfPrev = document.getElementById('rf-prev');
    var rfNext = document.getElementById('rf-next');
    var rfPageSize = document.getElementById('rf-page-size');

    if (rfPrev) rfPrev.addEventListener('click', function () {
        if (rfState.page > 0) { rfState.page--; renderRouteRows(); }
    });
    if (rfNext) rfNext.addEventListener('click', function () {
        rfState.page++;
        renderRouteRows();
    });
    if (rfPageSize) rfPageSize.addEventListener('change', function () {
        rfState.pageSize = parseInt(this.value, 10);
        rfState.page = 0;
        renderRouteRows();
    });

    /* Route flow search */
    var rfSearchInput = document.getElementById('rf-search');
    if (rfSearchInput) rfSearchInput.addEventListener('input', function () {
        rfState.search = this.value;
        rfState.page = 0;
        renderRouteRows();
    });

    /* renderRouteFlows() fetches data + renders; renderRouteRows() re-renders cached data */

    /* ================================================================
     *  INTERFACES TABLE (sort + search)
     * ================================================================ */

    /* Parse speed string to Mbps for numeric sort */
    function speedToMbps(s) {
        if (!s || s === '-') return 0;
        var m = s.match(/([\d.]+)\s*(Gbps|Mbps)/i);
        if (!m) return 0;
        var val = parseFloat(m[1]);
        if (m[2].toLowerCase() === 'gbps') val *= 1000;
        return val;
    }

    /* Demo interface data */
    var ifaceData = [];

    /* Fetch real interface data from API → populate ifaceData */
    function fetchIfaceData() {
        return api('/config/system_interface').then(function (data) {
            if (!data || !data.entries) return;
            ifaceData = data.entries.map(function (e) {
                var accessList = e.allowaccess
                    ? e.allowaccess.split(' ').map(function (s) { return s.toUpperCase(); })
                    : [];
                return {
                    name:   e.id || '',
                    type:   'Physical',
                    ip:     e.ip || '-',
                    status: (e.status || 'down').toUpperCase(),
                    speed:  '-',
                    access: accessList
                };
            });
        });
    }

    var ifState = {
        sortKey: 'name',
        sortAsc: true,
        search: ''
    };

    /* Compare interfaces */
    function compareIfaces(a, b, key, asc) {
        var va, vb, diff;
        if (key === 'ip') {
            var ipA = ipToNum(a.ip.split('/')[0]);
            var ipB = ipToNum(b.ip.split('/')[0]);
            diff = ipA - ipB;
        } else if (key === 'speed') {
            diff = speedToMbps(a.speed) - speedToMbps(b.speed);
        } else if (key === 'status') {
            /* UP first, DOWN last */
            va = a.status === 'UP' ? 0 : 1;
            vb = b.status === 'UP' ? 0 : 1;
            diff = va - vb;
        } else if (key === 'access') {
            diff = a.access.length - b.access.length;
        } else {
            /* name, type — string sort */
            va = a[key] || '';
            vb = b[key] || '';
            diff = va < vb ? -1 : va > vb ? 1 : 0;
        }
        return asc ? diff : -diff;
    }

    /* Build one table row */
    function ifaceRowHTML(iface) {
        var dotCls = iface.status === 'UP' ? 'up' : 'down';
        var tags = '';
        for (var i = 0; i < iface.access.length; i++) {
            tags += '<span class="tag">' + esc(iface.access[i]) + '</span>';
        }
        return '<tr>' +
            '<td><span class="status-dot ' + esc(dotCls) + '"></span>' + esc(iface.name) + '</td>' +
            '<td>' + esc(iface.type) + '</td>' +
            '<td>' + esc(iface.ip) + '</td>' +
            '<td>' + esc(iface.status) + '</td>' +
            '<td>' + esc(iface.speed) + '</td>' +
            '<td>' + tags + '</td>' +
            '</tr>';
    }

    function renderIfaces() {
        var tbody = document.getElementById('iface-tbody');
        if (!tbody || !ifState) return Promise.resolve();

        return fetchIfaceData().then(function () {
            renderIfaceRows();
        });
    }

    function renderIfaceRows() {
        var tbody = document.getElementById('iface-tbody');
        if (!tbody || !ifState) return;

        /* Filter */
        var filtered = ifaceData;
        if (ifState.search) {
            var q = ifState.search.toLowerCase();
            filtered = ifaceData.filter(function (iface) {
                return iface.name.toLowerCase().indexOf(q) !== -1 ||
                       iface.type.toLowerCase().indexOf(q) !== -1 ||
                       iface.ip.toLowerCase().indexOf(q) !== -1 ||
                       iface.status.toLowerCase().indexOf(q) !== -1 ||
                       iface.speed.toLowerCase().indexOf(q) !== -1 ||
                       iface.access.join(' ').toLowerCase().indexOf(q) !== -1;
            });
        }

        /* Sort */
        var sorted = filtered.slice().sort(function (a, b) {
            return compareIfaces(a, b, ifState.sortKey, ifState.sortAsc);
        });

        /* Group by type */
        var groups = {};
        var groupOrder = [];
        for (var i = 0; i < sorted.length; i++) {
            var t = sorted[i].type;
            if (!groups[t]) { groups[t] = []; groupOrder.push(t); }
            groups[t].push(sorted[i]);
        }

        /* Render */
        var html = '';
        for (var g = 0; g < groupOrder.length; g++) {
            var gName = groupOrder[g];
            var items = groups[gName];
            html += '<tr class="group-header"><td colspan="6">' +
                    esc(gName.toUpperCase()) + ' INTERFACES' +
                    '<span class="group-count">' + esc(items.length) + '</span>' +
                    '</td></tr>';
            for (var j = 0; j < items.length; j++) {
                html += ifaceRowHTML(items[j]);
            }
        }

        if (sorted.length === 0) {
            html = '<tr><td colspan="6" style="text-align:center;color:#999;padding:20px;">No matching interfaces</td></tr>';
        }

        tbody.innerHTML = html;

        /* Update sort indicators on headers */
        var ths = document.querySelectorAll('#iface-table thead th[data-sort]');
        ths.forEach(function (th) {
            var key = th.dataset.sort;
            var labels = { name: 'NAME', type: 'TYPE', ip: 'IP / NETMASK', status: 'STATUS', speed: 'SPEED', access: 'ACCESS' };
            th.classList.toggle('th-sort-active', key === ifState.sortKey);
            if (key === ifState.sortKey) {
                th.innerHTML = labels[key] + ' <span class="sort-arrow">' + (ifState.sortAsc ? '&#9650;' : '&#9660;') + '</span>';
            } else {
                th.textContent = labels[key];
            }
        });
    }

    /* Bind sort clicks on interface table headers */
    var ifThs = document.querySelectorAll('#iface-table thead th[data-sort]');
    ifThs.forEach(function (th) {
        th.addEventListener('click', function () {
            var key = th.dataset.sort;
            if (ifState.sortKey === key) {
                ifState.sortAsc = !ifState.sortAsc;
            } else {
                ifState.sortKey = key;
                ifState.sortAsc = true;
            }
            renderIfaceRows();
        });
    });

    /* Interface search */
    var ifSearchInput = document.getElementById('iface-search');
    if (ifSearchInput) ifSearchInput.addEventListener('input', function () {
        ifState.search = this.value;
        renderIfaceRows();
    });

    /* renderIfaces() fetches data + renders; renderIfaceRows() re-renders cached data */

    /* ================================================================
     *  GENERIC TABLE SORT — click any <th> to sort that column
     *  Works on all .data-table elements with static HTML rows.
     *  Skips: checkbox columns, dashboard iface-table, route-flow widget.
     * ================================================================ */

    function naturalCompare(a, b) {
        /* Try numeric first */
        var na = parseFloat(a), nb = parseFloat(b);
        if (!isNaN(na) && !isNaN(nb)) return na - nb;
        /* IP / CIDR: 192.168.1.0/24 — compare octets then prefix */
        if (/^\d+\.\d+\.\d+\.\d+/.test(a) && /^\d+\.\d+\.\d+\.\d+/.test(b)) {
            var pa = a.replace(/\/.*/, '').split('.'), pb = b.replace(/\/.*/, '').split('.');
            for (var i = 0; i < 4; i++) {
                var d = (parseInt(pa[i]) || 0) - (parseInt(pb[i]) || 0);
                if (d !== 0) return d;
            }
            return a < b ? -1 : a > b ? 1 : 0;
        }
        /* String fallback (case-insensitive) */
        var la = a.toLowerCase(), lb = b.toLowerCase();
        return la < lb ? -1 : la > lb ? 1 : 0;
    }

    function sortTable(table, colIdx, asc) {
        var tbody = table.querySelector('tbody');
        if (!tbody) return;
        var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr:not(.group-header)'));
        if (rows.length === 0) return;

        rows.sort(function (ra, rb) {
            var cellA = ra.cells[colIdx], cellB = rb.cells[colIdx];
            if (!cellA || !cellB) return 0;
            var ta = cellA.textContent.trim(), tb = cellB.textContent.trim();
            var cmp = naturalCompare(ta, tb);
            return asc ? cmp : -cmp;
        });

        /* Remove group headers — they don't apply after column sort */
        tbody.querySelectorAll('tr.group-header').forEach(function (gh) { gh.remove(); });
        /* Re-append in sorted order */
        rows.forEach(function (r) { tbody.appendChild(r); });
    }

    function updateSortIndicators(allThs, activeTh, asc) {
        allThs.forEach(function (h) {
            h.classList.remove('th-sort-active');
            var arrow = h.querySelector('.sort-arrow');
            if (arrow) arrow.remove();
        });
        activeTh.classList.add('th-sort-active');
        var arrowSpan = document.createElement('span');
        arrowSpan.className = 'sort-arrow';
        arrowSpan.innerHTML = asc ? '&#9650;' : '&#9660;';
        activeTh.appendChild(arrowSpan);
    }

    /* Bind sort click on every sortable <th> across all data-tables */
    document.querySelectorAll('table.data-table').forEach(function (table) {
        /* Skip dashboard tables that have their own custom sort */
        if (table.id === 'iface-table') return;
        if (table.closest('#route-flow-widget')) return;

        var sortState = { col: -1, asc: true };
        var headerRow = table.querySelector('thead tr');
        if (!headerRow) return;
        var allThs = Array.prototype.slice.call(headerRow.children);

        allThs.forEach(function (th, idx) {
            /* Skip checkbox column */
            if (th.classList.contains('th-checkbox')) return;

            th.addEventListener('click', function () {
                if (sortState.col === idx) {
                    sortState.asc = !sortState.asc;
                } else {
                    sortState.col = idx;
                    sortState.asc = true;
                }
                sortTable(table, idx, sortState.asc);
                updateSortIndicators(allThs, th, sortState.asc);
            });
        });
    });

    /* ================================================================
     *  MODAL TOGGLE (16-bit drop-in)
     * ================================================================ */
    var backdrop = document.getElementById('modal-backdrop');
    var activeModal = null;

    function openModal(id) {
        var form = document.getElementById(id);
        if (!form) return;
        /* Close any already-open modal first */
        if (activeModal) closeModal(true);
        activeModal = form;
        form.classList.remove('closing');
        form.classList.add('visible');
        backdrop.classList.add('visible');
    }

    function closeModal(instant) {
        if (!activeModal) return;
        var form = activeModal;
        backdrop.classList.remove('visible');
        if (instant) {
            form.classList.remove('visible', 'closing');
            activeModal = null;
        } else {
            form.classList.add('closing');
            setTimeout(function () {
                form.classList.remove('visible', 'closing');
                activeModal = null;
            }, 150);
        }
    }

    /* Bind all toggle buttons */
    document.querySelectorAll('[data-toggle-form]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var id = btn.dataset.toggleForm;
            var form = document.getElementById(id);
            if (form && form.classList.contains('visible')) {
                closeModal(false);
            } else {
                /* Refresh all dynamic selects when opening a create form */
                populateIfaceSelects();
                populateProfileSelect();
                populateAddrSelects();
                populateSvcSelects();
                openModal(id);
            }
        });
    });

    /* Click backdrop to close */
    if (backdrop) {
        backdrop.addEventListener('click', function () {
            closeModal(false);
        });
    }

    /* Escape key to close */
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && activeModal) closeModal(false);
    });

    /* ================================================================
     *  ENTITY REGISTRY — maps entity types to forms & field config
     * ================================================================ */

    var ENTITIES = {
        interfaces: {
            formId: 'form-iface',
            configType: 'system_interface',
            createTitle: 'NEW INTERFACE',
            editTitle: 'EDIT INTERFACE',
            hasStatus: true,
            statusLabels: { on: 'UP', off: 'DOWN', dotOn: 'up', dotOff: 'down' },
            fields: [
                { label: 'Name',             key: 'id',          col: 0, bulkEditable: false },
                { label: 'Mode',             key: 'mode',        col: 1, bulkEditable: false },
                { label: 'IP / Netmask',     key: 'ip',          col: 2, bulkEditable: false },
                { label: 'Status',           key: 'status',      col: 3, bulkEditable: true },
                { label: 'MTU',              key: 'mtu',         col: 4, bulkEditable: true },
                { label: 'Admin Access',     key: 'allowaccess', col: 5, bulkEditable: true },
                { label: 'Description',      key: 'description', col: -1, bulkEditable: false }
            ]
        },
        dhcp: {
            formId: 'form-dhcp',
            configType: 'network_dhcp-server',
            createTitle: 'NEW DHCP POOL',
            editTitle: 'EDIT DHCP POOL',
            hasStatus: true,
            statusLabels: { on: 'Enabled', off: 'Disabled', dotOn: 'up', dotOff: 'disabled' },
            fields: [
                { label: 'Pool Name',    key: 'id',            col: 0, bulkEditable: false },
                { label: 'Interface',    key: 'interface',     col: 1, bulkEditable: false },
                { label: 'Range Start',  key: 'start-ip',      col: 2, bulkEditable: false },
                { label: 'Range End',    key: 'end-ip',        col: 3, bulkEditable: false },
                { label: 'Gateway',      key: 'gateway',       col: 4, bulkEditable: false },
                { label: 'Netmask',      key: 'netmask',       col: -1, bulkEditable: false },
                { label: 'DNS Server 1', key: 'dns-server',    col: 5, bulkEditable: false },
                { label: 'Domain',       key: 'domain-name',   col: -1, bulkEditable: false },
                { label: 'Lease Time',   key: 'lease-time',    col: 6, bulkEditable: true },
                { label: 'Status',       key: 'status',        col: 7, bulkEditable: true }
            ]
        },
        routes: {
            formId: 'form-route',
            configType: 'network_route_static',
            createTitle: 'NEW STATIC ROUTE',
            editTitle: 'EDIT STATIC ROUTE',
            hasStatus: true,
            statusLabels: { on: 'ACTIVE', off: 'DISABLED', dotOn: 'up', dotOff: 'down' },
            fields: [
                { label: 'Destination',     key: 'dst',      col: 0, bulkEditable: false },
                { label: 'Gateway',         key: 'gateway',  col: 1, bulkEditable: false },
                { label: 'Interface',       key: 'device',   col: 2, bulkEditable: false },
                { label: 'Admin Distance',  key: 'distance', col: 3, bulkEditable: true },
                { label: 'Status',          key: 'status',   col: 4, bulkEditable: true },
                { label: 'Comment',         key: 'comment',  col: -1, bulkEditable: false }
            ]
        },
        nat: {
            formId: 'form-nat',
            configType: 'network_nat',
            createTitle: 'NEW NAT RULE',
            editTitle: 'EDIT NAT RULE',
            hasStatus: true,
            statusLabels: { on: 'Enabled', off: 'Disabled', dotOn: 'up', dotOff: 'disabled' },
            fields: [
                { label: '#',                    key: 'id',           col: 0, bulkEditable: false, editDisabled: true },
                { label: 'Type',                 key: 'type',         col: 1, bulkEditable: false },
                { label: 'Original Source',      key: 'srcaddr',      col: 2, bulkEditable: false },
                { label: 'Original Destination', key: 'dstaddr',      col: 3, bulkEditable: false },
                { label: 'Destination Port',     key: 'dstport',      col: -1, bulkEditable: false },
                { label: 'Translated Address',   key: 'mapped-ip',    col: -1, bulkEditable: false },
                { label: 'Translated Port',      key: 'mapped-port',  col: -1, bulkEditable: false },
                { label: 'Source Interface',      key: 'srcintf',      col: 4, bulkEditable: false },
                { label: 'Destination Interface', key: 'dstintf',      col: -1, bulkEditable: false },
                { label: 'Status',               key: 'status',       col: 5, bulkEditable: true }
            ]
        },
        policies: {
            formId: 'form-policy',
            configType: 'firewall_policy',
            createTitle: 'NEW FIREWALL POLICY',
            editTitle: 'EDIT FIREWALL POLICY',
            hasStatus: true,
            statusLabels: { on: 'Enabled', off: 'Disabled', dotOn: 'up', dotOff: 'disabled' },
            fields: [
                { label: 'ID',                  key: 'id',       col: 0, bulkEditable: false, editDisabled: true },
                { label: 'Name',                key: 'name',     col: 1, bulkEditable: false },
                { label: 'Incoming Interface',  key: 'srcintf',  col: 2, bulkEditable: false },
                { label: 'Outgoing Interface',  key: 'dstintf',  col: 3, bulkEditable: false },
                { label: 'Source',              key: 'srcaddr',  col: 4, bulkEditable: false },
                { label: 'Destination',         key: 'dstaddr',  col: 5, bulkEditable: false },
                { label: 'Service',             key: 'service',  col: 6, bulkEditable: false },
                { label: 'Action',              key: 'action',   col: 7, bulkEditable: true },
                { label: 'Status',              key: 'status',   col: 8, bulkEditable: true },
                { label: 'Schedule',            key: 'schedule', col: -1, bulkEditable: false },
                { label: 'Comment',             key: 'comment',  col: -1, bulkEditable: false }
            ]
        },
        addresses: {
            formId: 'form-address',
            configType: 'firewall_address',
            createTitle: 'NEW ADDRESS OBJECT',
            editTitle: 'EDIT ADDRESS OBJECT',
            hasStatus: false,
            fields: [
                { label: 'Name',        key: 'name',    col: 0, bulkEditable: false },
                { label: 'Type',        key: 'type',    col: 1, bulkEditable: false },
                { label: 'Subnet / IP', key: 'subnet',  col: 2, bulkEditable: false },
                { label: 'Comment',     key: 'comment', col: 3, bulkEditable: false }
            ]
        },
        services: {
            formId: 'form-service',
            configType: 'firewall_service',
            createTitle: 'NEW SERVICE',
            editTitle: 'EDIT SERVICE',
            hasStatus: false,
            fields: [
                { label: 'Name',         key: 'name',     col: 0, bulkEditable: false },
                { label: 'Protocol',     key: 'protocol', col: 1, bulkEditable: false },
                { label: 'Port / Range', key: 'port-range', col: 2, bulkEditable: false },
                { label: 'Comment',      key: 'comment',  col: 3, bulkEditable: false }
            ]
        },
        admins: {
            formId: 'form-admin',
            configType: 'system_admin',
            createTitle: 'NEW ADMINISTRATOR',
            editTitle: 'EDIT ADMINISTRATOR',
            hasStatus: false,
            customCreate: true,  /* uses /api/admin/create instead of generic config */
            fields: [
                { label: 'Username',                  key: 'id',                       col: 0, bulkEditable: false },
                { label: 'Profile',                   key: 'profile',                  col: 1, bulkEditable: true },
                { label: 'Enforce Change Password',   key: 'enforce-change-password',  col: -1, bulkEditable: false },
                { label: 'Enforce Password Policy',   key: 'enforce-password-policy',  col: -1, bulkEditable: false }
            ]
        },
        profiles: {
            formId: 'form-profile',
            configType: 'system_admin-profile',
            createTitle: 'NEW ADMIN PROFILE',
            editTitle: 'EDIT ADMIN PROFILE',
            hasStatus: false,
            fields: [
                { label: 'Profile Name', key: 'id',          col: 0, bulkEditable: false },
                { label: 'Permissions',  key: 'permissions', col: 1, bulkEditable: false },
                { label: 'Description',  key: 'description', col: 2, bulkEditable: false }
            ]
        }
    };

    /* Look up entity name from a form id */
    function entityForForm(formId) {
        for (var k in ENTITIES) {
            if (ENTITIES[k].formId === formId) return k;
        }
        return null;
    }

    /* ================================================================
     *  SELECTION STATE — multi-select with checkbox
     * ================================================================ */

    var selection = {
        entity: null,
        ids: {},       /* rowId → true */
        count: 0,

        clear: function () {
            document.querySelectorAll('.row-select:checked').forEach(function (cb) {
                cb.checked = false;
                cb.closest('tr').classList.remove('row-selected');
            });
            document.querySelectorAll('.select-all:checked').forEach(function (cb) {
                cb.checked = false;
                cb.indeterminate = false;
            });
            this.ids = {};
            this.count = 0;
            this.entity = null;
            hideBulkBar();
        },

        toggle: function (entity, rowId, row) {
            if (this.entity && this.entity !== entity) this.clear();
            this.entity = entity;
            if (this.ids[rowId]) {
                delete this.ids[rowId];
                this.count--;
                row.classList.remove('row-selected');
            } else {
                this.ids[rowId] = true;
                this.count++;
                row.classList.add('row-selected');
            }
            updateBulkBar();
            syncSelectAll(entity);
        }
    };

    function syncSelectAll(entity) {
        var table = document.querySelector('table[data-entity="' + entity + '"]');
        if (!table) return;
        var sa = table.querySelector('.select-all');
        if (!sa) return;
        var rows = table.querySelectorAll('tbody tr[data-row-id]');
        var total = 0, checked = 0;
        rows.forEach(function (r) {
            var cb = r.querySelector('.row-select');
            if (cb) { total++; if (cb.checked) checked++; }
        });
        sa.checked = total > 0 && checked === total;
        sa.indeterminate = checked > 0 && checked < total;
    }

    /* Checkbox events — delegated */
    document.addEventListener('change', function (e) {
        if (e.target.classList.contains('select-all')) {
            var table = e.target.closest('table[data-entity]');
            if (!table) return;
            var entity = table.dataset.entity;
            var checked = e.target.checked;
            if (!checked) { selection.clear(); return; }
            selection.clear();
            selection.entity = entity;
            table.querySelectorAll('tbody tr[data-row-id]').forEach(function (row) {
                var cb = row.querySelector('.row-select');
                if (!cb) return;
                cb.checked = true;
                row.classList.add('row-selected');
                selection.ids[row.dataset.rowId] = true;
                selection.count++;
            });
            updateBulkBar();
        }
        if (e.target.classList.contains('row-select')) {
            var row = e.target.closest('tr');
            var table = e.target.closest('table[data-entity]');
            if (!row || !table) return;
            e.target.checked ? row.classList.add('row-selected') : row.classList.remove('row-selected');
            selection.toggle(table.dataset.entity, row.dataset.rowId, row);
        }
    });

    /* ================================================================
     *  BULK ACTION BAR
     * ================================================================ */

    var bulkBar = document.getElementById('bulk-action-bar');
    var bulkCount = document.getElementById('bulk-count');
    var bulkActions = document.getElementById('bulk-actions');
    var bulkCloseBtn = document.getElementById('bulk-close');

    function updateBulkBar() {
        if (selection.count === 0) { hideBulkBar(); return; }
        var config = ENTITIES[selection.entity];
        if (!config) return;

        bulkCount.textContent = selection.count + ' selected';
        bulkActions.innerHTML = '';

        /* Delete always available */
        addBulkBtn('Delete', 'delete', 'btn-danger');

        /* Enable/Disable for entities with status */
        if (config.hasStatus) {
            addBulkBtn('Enable', 'enable', '');
            addBulkBtn('Disable', 'disable', '');
        }

        /* Bulk-editable fields */
        config.fields.forEach(function (f) {
            if (f.bulkEditable && f.key !== 'status') {
                addBulkBtn('Set ' + f.label, 'bulk-' + f.key, '');
            }
        });

        bulkBar.style.display = 'flex';
    }

    function addBulkBtn(label, action, cls) {
        var btn = document.createElement('button');
        btn.className = 'btn' + (cls ? ' ' + cls : '');
        btn.textContent = label;
        btn.dataset.bulkAction = action;
        btn.addEventListener('click', function () { handleBulkAction(action); });
        bulkActions.appendChild(btn);
    }

    function hideBulkBar() {
        if (bulkBar) bulkBar.style.display = 'none';
    }

    if (bulkCloseBtn) {
        bulkCloseBtn.addEventListener('click', function () { selection.clear(); });
    }

    function handleBulkAction(action) {
        if (action === 'delete') {
            forEachSelected(function (row) { demoDeleteRow(row); });
            selection.clear();
        } else if (action === 'enable' || action === 'disable') {
            var en = action === 'enable';
            forEachSelected(function (row) { demoSetStatus(row, en, selection.entity); });
        } else if (action.indexOf('bulk-') === 0) {
            var key = action.replace('bulk-', '');
            var config = ENTITIES[selection.entity];
            var field = null;
            config.fields.forEach(function (f) { if (f.key === key) field = f; });
            if (!field) return;
            var val = prompt('New value for ' + field.label + ':');
            if (val === null) return;
            forEachSelected(function (row) {
                var cell = row.cells[field.col + 1]; /* +1 for checkbox */
                if (cell) cell.textContent = val;
            });
        }
    }

    function forEachSelected(fn) {
        var table = document.querySelector('table[data-entity="' + selection.entity + '"]');
        if (!table) return;
        for (var id in selection.ids) {
            /* Use attribute selector with escaped value to prevent selector injection */
            var rows = table.querySelectorAll('tr[data-row-id]');
            rows.forEach(function (row) {
                if (row.dataset.rowId === id) fn(row);
            });
        }
    }

    /* ================================================================
     *  DOUBLE-CLICK TO EDIT
     * ================================================================ */

    document.addEventListener('dblclick', function (e) {
        var row = e.target.closest('tr');
        if (!row || row.classList.contains('group-header')) return;
        if (row.closest('thead')) return; /* ignore header row dblclick */
        if (e.target.closest('.td-checkbox')) return; /* ignore checkbox dblclick */
        var table = row.closest('table[data-entity]');
        if (!table) return;

        var entity = table.dataset.entity;
        var config = ENTITIES[entity];
        if (!config) return;

        /* ARP: only static rows */
        if (config.editableFilter && !config.editableFilter(row)) return;

        openEditModal(entity, row);
    });

    function openEditModal(entity, row) {
        var config = ENTITIES[entity];
        var form = document.getElementById(config.formId);
        if (!form) return;

        /* Set title to edit mode — include entry name for context */
        var titleSpan = form.querySelector('.modal-title-text');
        var rowId = row.dataset.rowId || '';
        if (titleSpan) titleSpan.textContent = config.editTitle + (rowId ? ' — ' + rowId : '');

        form.dataset.editMode = 'true';
        form.dataset.editRowId = row.dataset.rowId || '';

        /* Hide create-only fields (e.g. password rows on admin edit) */
        form.querySelectorAll('.admin-create-only').forEach(function (el) {
            el.style.display = 'none';
        });

        openModal(config.formId);

        /* Refresh dynamic selects, THEN populate form.
         * Must wait for selects to be filled before selectOption()
         * can match values — otherwise the options don't exist yet. */
        Promise.all([
            populateIfaceSelects(),
            populateProfileSelect(),
            populateAddrSelects(),
            populateSvcSelects()
        ]).then(function () {
            fetchEntityData(entity, row, form);
        });
    }

    /*
     * Fetch entity data and populate modal form.
     *
     * API contract (GET /api/config/{entity}/{id}):
     *   Returns JSON object with field keys matching ENTITIES[entity].fields[].key
     *   e.g. { name: "eth0", alias: "LAN", type: "Physical", ip: "192.168.1.1/24", ... }
     *
     * Demo fallback: reads values from the table row cells.
     */
    function fetchEntityData(entity, row, form) {
        var body = form.querySelector('.modal-body');
        if (!body) return;
        var config = ENTITIES[entity];
        var grid = body.querySelector('.form-grid');

        /* Hide form fields, show loading */
        if (grid) grid.style.display = 'none';
        var loader = document.createElement('div');
        loader.className = 'modal-loading';
        loader.textContent = 'LOADING...';
        body.appendChild(loader);

        /* Build label→input map from form rows (stable regardless of field order) */
        var labelMap = {};
        var formRows = body.querySelectorAll('.form-row');
        formRows.forEach(function (fr) {
            var lbl = fr.querySelector('.form-label');
            var inp = fr.querySelector('.form-input');
            if (lbl && inp) {
                labelMap[lbl.textContent.trim().toLowerCase()] = inp;
            }
        });

        var rowId = row.dataset.rowId || '';

        /* Try API first, fall back to reading from DOM */
        api('/config/' + cfgType(entity) + '/' + rowId).then(function (data) {
            if (data) {
                /* Populate from API response */
                populateForm(config, labelMap, data, body);
            } else {
                /* Demo fallback: read from table row cells */
                var rowData = {};
                config.fields.forEach(function (field) {
                    var cell = row.cells[field.col + 1]; /* +1 for checkbox col */
                    if (cell) rowData[field.key] = cellText(cell);
                });
                populateForm(config, labelMap, rowData, body);
            }

            loader.remove();
            if (grid) grid.style.display = '';
        });
    }

    /* Populate form inputs from a data object using label-based matching */
    function populateForm(config, labelMap, data, formBody) {
        config.fields.forEach(function (field) {
            if (field.editDisabled) return;
            var inp = labelMap[field.label.toLowerCase()];
            if (!inp) return;
            var val = data[field.key];
            if (val === undefined || val === null) return;
            if (inp.tagName === 'SELECT') {
                selectOption(inp, String(val));
            } else {
                inp.value = val;
            }
        });

        /* Populate checkbox groups (e.g. Admin Access = "ping http https").
         * These use .form-row-full with individual checkboxes, not .form-input,
         * so they're not in labelMap. Match by field label → row label. */
        if (formBody) {
            formBody.querySelectorAll('.form-row-full').forEach(function (fr) {
                var lbl = fr.querySelector('.form-label');
                if (!lbl) return;
                var rowLabel = lbl.textContent.trim().toLowerCase();
                /* Find matching entity field */
                var field = null;
                config.fields.forEach(function (f) {
                    if (f.label.toLowerCase() === rowLabel) field = f;
                });
                if (!field) return;
                var val = data[field.key];
                if (!val) return;
                /* val is space-separated (allowaccess) or comma-separated (permissions) */
                var tokens = String(val).toLowerCase().split(/[\s,]+/);
                fr.querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
                    var cbLabel = cb.parentElement.textContent.trim().toLowerCase();
                    cb.checked = tokens.indexOf(cbLabel) !== -1;
                });
            });
        }
    }

    /* Extract clean text from a table cell (strip status dots, tags, etc.) */
    function cellText(cell) {
        var clone = cell.cloneNode(true);
        clone.querySelectorAll('.status-dot').forEach(function (d) { d.remove(); });
        return clone.textContent.trim();
    }

    /* Select matching option in a <select> */
    function selectOption(sel, val) {
        var lv = val.toLowerCase();
        /* First pass: exact match on value attribute */
        for (var i = 0; i < sel.options.length; i++) {
            if (sel.options[i].value.toLowerCase() === lv) {
                sel.selectedIndex = i;
                return;
            }
        }
        /* Second pass: exact match on display text */
        for (var i = 0; i < sel.options.length; i++) {
            if (sel.options[i].text.toLowerCase() === lv) {
                sel.selectedIndex = i;
                return;
            }
        }
    }

    /* Reset modal on close — restore create title and clear fields.
     * Deferred until AFTER the 150ms close animation so the title
     * doesn't flash "NEW …" while the modal is still visible. */
    var _origCloseModal = closeModal;
    function resetModalFields(modal) {
        var ent = entityForForm(modal.id);
        if (ent) {
            var ts = modal.querySelector('.modal-title-text');
            if (ts) ts.textContent = ENTITIES[ent].createTitle;
        }
        modal.dataset.editMode = '';
        modal.querySelectorAll('.modal-body .form-input').forEach(function (inp) {
            if (inp.tagName === 'SELECT') inp.selectedIndex = 0;
            else if (inp.type === 'checkbox') inp.checked = false;
            else inp.value = '';
        });
        modal.querySelectorAll('.modal-body input[type="checkbox"]').forEach(function (cb) {
            cb.checked = false;
        });
        /* Re-show create-only fields hidden during edit */
        modal.querySelectorAll('.admin-create-only').forEach(function (el) {
            el.style.display = '';
        });
    }
    closeModal = function (instant) {
        if (activeModal) {
            var modal = activeModal;
            if (instant) {
                resetModalFields(modal);
            } else {
                /* Reset after the close animation (150ms) */
                setTimeout(function () { resetModalFields(modal); }, 160);
            }
        }
        _origCloseModal(instant);
    };

    /* ================================================================
     *  RIGHT-CLICK CONTEXT MENU
     * ================================================================ */

    var ctxMenu = document.getElementById('context-menu');
    var ctxRow = null;
    var ctxEntity = null;

    document.addEventListener('contextmenu', function (e) {
        var row = e.target.closest('tr');
        if (!row || row.classList.contains('group-header')) { hideCtx(); return; }
        var table = row.closest('table[data-entity]');
        if (!table) { hideCtx(); return; }

        e.preventDefault();
        var entity = table.dataset.entity;
        var config = ENTITIES[entity];
        if (!config) return;

        ctxRow = row;
        ctxEntity = entity;

        var isEditable = !config.editableFilter || config.editableFilter(row);
        var items = ctxMenu.querySelectorAll('.context-menu-item');
        items.forEach(function (it) {
            var act = it.dataset.action;
            if (act === 'edit' || act === 'delete') {
                it.classList.toggle('ctx-hidden', !isEditable);
            } else if (act === 'enable' || act === 'disable') {
                it.classList.toggle('ctx-hidden', !config.hasStatus || !isEditable);
            }
        });
        /* Hide separator if no status actions */
        var sep = ctxMenu.querySelector('.context-menu-separator');
        if (sep) sep.classList.toggle('ctx-hidden', !config.hasStatus || !isEditable);

        /* Position at cursor, clamp to viewport */
        ctxMenu.style.display = 'block';
        var x = e.clientX, y = e.clientY;
        var rect = ctxMenu.getBoundingClientRect();
        if (x + rect.width > window.innerWidth) x = window.innerWidth - rect.width - 4;
        if (y + rect.height > window.innerHeight) y = window.innerHeight - rect.height - 4;
        ctxMenu.style.left = x + 'px';
        ctxMenu.style.top = y + 'px';
    });

    function hideCtx() {
        if (ctxMenu) ctxMenu.style.display = 'none';
    }

    document.addEventListener('click', hideCtx);
    document.addEventListener('scroll', hideCtx, true);

    if (ctxMenu) ctxMenu.addEventListener('click', function (e) {
        var item = e.target.closest('.context-menu-item');
        if (!item || !ctxRow) return;
        var act = item.dataset.action;
        e.stopPropagation(); /* prevent the document click from firing */

        if (act === 'edit') openEditModal(ctxEntity, ctxRow);
        else if (act === 'delete') demoDeleteRow(ctxRow);
        else if (act === 'enable') demoSetStatus(ctxRow, true, ctxEntity);
        else if (act === 'disable') demoSetStatus(ctxRow, false, ctxEntity);

        hideCtx();
    });

    /* ================================================================
     *  ENTITY ACTIONS (visual feedback + API calls)
     * ================================================================ */

    /*
     * Delete entity row.
     *
     * API contract: DELETE /api/config/{entity}/{id}
     * On success: remove row with fade animation.
     * On failure: alert user, keep row visible.
     */
    function demoDeleteRow(row) {
        var table = row.closest('table[data-entity]');
        var entity = table ? table.dataset.entity : null;
        var rowId = row.dataset.rowId || '';

        if (!confirm('Delete "' + rowId + '"?')) return;

        /* Visual feedback immediately */
        row.style.transition = 'opacity 0.25s, background 0.25s';
        row.style.background = 'rgba(198, 40, 40, 0.1)';
        row.style.opacity = '0';

        if (entity) {
            api('/config/' + cfgType(entity) + '/' + rowId, { method: 'DELETE' })
                .then(function (data) {
                    /* API succeeded or no backend — remove row */
                    setTimeout(function () { row.remove(); }, 250);
                    showToast('Entry deleted', 'success');
                })
                .catch(function (err) {
                    /* API error — revert visual state */
                    row.style.background = '';
                    row.style.opacity = '1';
                    showToast(err.message || 'Delete failed', 'error');
                });
        } else {
            setTimeout(function () { row.remove(); }, 250);
        }
    }

    /*
     * Enable/disable entity row status.
     *
     * API contract: PUT /api/config/{entity}/{id}  { status: "enabled"|"disabled" }
     * On success: update status dot + label text.
     * On failure: alert user, keep original status.
     */
    function demoSetStatus(row, enable, entity) {
        /* Determine the right label + dot class for this entity */
        var cfg = (entity && ENTITIES[entity] && ENTITIES[entity].statusLabels)
            ? ENTITIES[entity].statusLabels
            : null;
        var label  = enable ? (cfg ? cfg.on  : 'Enabled')  : (cfg ? cfg.off  : 'Disabled');
        var dotCls = enable ? (cfg && cfg.dotOn  ? cfg.dotOn  : 'up')
                            : (cfg && cfg.dotOff ? cfg.dotOff : 'disabled');

        /* Find the LAST cell containing a status-dot (status columns are at the end) */
        var cells = row.cells;
        var targetCell = null;
        for (var i = 0; i < cells.length; i++) {
            if (cells[i].querySelector('.status-dot')) targetCell = cells[i];
        }
        if (!targetCell) return;

        /* Save previous state for rollback on API failure */
        var prevDotCls = targetCell.querySelector('.status-dot').className;
        var prevLabel = targetCell.lastChild && targetCell.lastChild.nodeType === 3
            ? targetCell.lastChild.textContent : '';

        /* Optimistic update */
        targetCell.querySelector('.status-dot').className = 'status-dot ' + dotCls;
        var txt = targetCell.lastChild;
        if (txt && txt.nodeType === 3) {
            txt.textContent = label;
        }

        /* Send to API */
        var rowId = row.dataset.rowId || '';
        if (entity) {
            /* Interface uses up/down, everything else uses enable/disable */
            var statusVal;
            if (cfgType(entity) === 'system_interface') {
                statusVal = enable ? 'up' : 'down';
            } else {
                statusVal = enable ? 'enable' : 'disable';
            }
            api('/config/' + cfgType(entity) + '/' + rowId, {
                method: 'PUT',
                body: { status: statusVal }
            }).catch(function (err) {
                /* Rollback on failure */
                targetCell.querySelector('.status-dot').className = prevDotCls;
                if (txt && txt.nodeType === 3) txt.textContent = prevLabel;
                showToast(err.message || 'Update failed', 'error');
            });
        }
    }

    /* Clear selection on page navigation — hook into existing sub-item clicks */
    subItems.forEach(function (item) {
        item.addEventListener('click', function () {
            selection.clear();
            hideCtx();
        });
    });
    categories.forEach(function (cat) {
        var header = cat.querySelector('.nav-category-header');
        if (header) header.addEventListener('click', function () {
            selection.clear();
            hideCtx();
        });
    });

    /* ================================================================
     *  USER DROPDOWN (topbar admin menu)
     * ================================================================ */

    var userBtn = document.getElementById('topbar-user');
    var userDrop = document.getElementById('user-dropdown');

    if (userBtn && userDrop) {
        userBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            userDrop.classList.toggle('open');
        });

        document.addEventListener('click', function () {
            userDrop.classList.remove('open');
        });

        userDrop.addEventListener('click', function (e) {
            var item = e.target.closest('.user-dropdown-item');
            if (!item) return;
            var action = item.dataset.action;
            userDrop.classList.remove('open');

            if (action === 'logout') {
                /* POST logout to clear server session + cookie */
                api('/auth/logout', { method: 'POST' }).catch(function () {});
                window.location.href = 'login.html';
            } else if (action === 'profile') {
                /* Navigate to admin page then open edit modal for current user */
                var cat = document.querySelector('[data-page="sys-admin"]');
                var parentCat = cat ? cat.closest('.nav-category') : null;
                if (parentCat) parentCat.classList.add('open');
                setActivePage('sys-admin', parentCat, cat);
                /* Wait for page data to load, then open edit for current user.
                 * refreshPage returns a promise, so we wait for it. */
                var nameEl2 = document.querySelector('.user-name');
                var me = nameEl2 ? nameEl2.textContent : 'admin';
                /* refreshPage is called by setActivePage — use a polling
                 * approach that waits for the row to appear (max 5s) */
                var attempts = 0;
                var findMyRow = setInterval(function () {
                    attempts++;
                    var table = document.querySelector('table[data-entity="admins"]');
                    if (table) {
                        var row = null;
                        table.querySelectorAll('tr[data-row-id]').forEach(function (r) {
                            if (r.dataset.rowId === me) row = r;
                        });
                        if (row) {
                            clearInterval(findMyRow);
                            openEditModal('admins', row);
                        }
                    }
                    if (attempts >= 50) clearInterval(findMyRow); /* 5s timeout */
                }, 100);
            } else if (action === 'password') {
                /* Open inline password change dialog */
                showPasswordChangeDialog();
            }
        });
    }

    /* ================================================================
     *  CHANGE PASSWORD DIALOG (topbar dropdown)
     * ================================================================ */

    function showPasswordChangeDialog() {
        /* Reuse modal system — create a temporary form */
        var id = 'form-change-pw';
        var existing = document.getElementById(id);
        if (existing) existing.remove();

        var form = document.createElement('div');
        form.className = 'add-form form-card';
        form.id = id;
        form.innerHTML =
            '<div class="form-section"><span class="modal-title-text">CHANGE PASSWORD</span>' +
            '<span class="modal-close" data-toggle-form="' + id + '">&#10005;</span></div>' +
            '<div class="modal-body"><div class="form-grid">' +
            '<div class="form-row"><label class="form-label">New Password</label>' +
            '<input class="form-input" type="password" id="cp-new" placeholder="New password"></div>' +
            '<div class="form-row"><label class="form-label">Confirm Password</label>' +
            '<input class="form-input" type="password" id="cp-confirm" placeholder="Confirm new password"></div>' +
            '</div></div>' +
            '<div class="modal-footer"><button class="btn btn-primary" id="cp-save">Change Password</button>' +
            '<button class="btn" data-toggle-form="' + id + '">Cancel</button></div>';

        document.getElementById('content').appendChild(form);

        /* Wire close buttons */
        form.querySelectorAll('[data-toggle-form]').forEach(function (btn) {
            btn.addEventListener('click', function () { closeModal(false); form.remove(); });
        });

        /* Wire save */
        document.getElementById('cp-save').addEventListener('click', function () {
            var newPw = document.getElementById('cp-new').value;
            var confirm = document.getElementById('cp-confirm').value;
            if (!newPw) { showToast('Enter a new password', 'error'); return; }
            if (newPw !== confirm) { showToast('Passwords do not match', 'error'); return; }

            api('/auth/change-password', {
                method: 'POST',
                body: { password: newPw }
            }).then(function () {
                showToast('Password changed', 'success');
                closeModal(false);
                form.remove();
            }).catch(function (err) {
                showToast(err.message || 'Password change failed', 'error');
            });
        });

        openModal(id);
    }

    /* ================================================================
     *  TABLE SEARCH / FILTER
     * ================================================================ */

    /**
     * Filter rows of a <table> by query string.
     * Hides non-matching <tr> rows; skips .group-header rows (always visible
     * if at least one child in the group matches).
     */
    function filterTable(table, query) {
        if (!table) return;
        var q = query.toLowerCase();
        var rows = table.querySelectorAll('tbody tr');
        var groupHeader = null;
        var groupHasMatch = false;

        rows.forEach(function (row) {
            if (row.classList.contains('group-header')) {
                /* Flush previous group visibility */
                if (groupHeader) groupHeader.style.display = groupHasMatch ? '' : 'none';
                groupHeader = row;
                groupHasMatch = false;
                return;
            }

            if (!q) {
                row.style.display = '';
                groupHasMatch = true;
                return;
            }

            var text = row.textContent.toLowerCase();
            var match = text.indexOf(q) !== -1;
            row.style.display = match ? '' : 'none';
            if (match) groupHasMatch = true;
        });

        /* Flush last group */
        if (groupHeader) groupHeader.style.display = groupHasMatch ? '' : 'none';
    }

    /**
     * Find the closest data-table sibling to a search input.
     * Walks up to the toolbar/widget-search/page-header, then looks for the
     * next table.data-table in the page container.
     */
    function findTargetTable(input) {
        /* Toolbar search: filter ALL tables on the page (covers multi-table pages like DHCP) */
        var toolbar = input.closest('.toolbar');
        if (toolbar) {
            var page = toolbar.closest('.page');
            if (page) {
                var tables = page.querySelectorAll('table.data-table');
                if (tables.length > 0) return tables;
            }
            return null;
        }

        /* Widget-search / page-header: find the nearest sibling table */
        var wrapper = input.closest('.page-header');
        if (!wrapper) wrapper = input.closest('.widget-search');
        if (!wrapper) return null;

        var sibling = wrapper.nextElementSibling;
        while (sibling) {
            if (sibling.matches && sibling.matches('table.data-table')) return sibling;
            if (sibling.matches && sibling.matches('.scroll-box')) {
                var inner = sibling.querySelector('table.data-table');
                if (inner) return inner;
            }
            /* Stop at next section boundary */
            if (sibling.matches && (sibling.matches('.toolbar') || sibling.matches('.page-header'))) break;
            sibling = sibling.nextElementSibling;
        }
        return null;
    }

    /**
     * Apply filter to a target (single table or NodeList of tables).
     */
    function applyFilter(target, query) {
        if (!target) return;
        if (target.nodeType) {
            /* Single element */
            filterTable(target, query);
        } else {
            /* NodeList */
            target.forEach(function (tbl) { filterTable(tbl, query); });
        }
    }

    /**
     * Backend search — called on Enter / search-btn click.
     * Hits GET /api/config/<entity>?q=<query> for each entity table on the page.
     * Falls back to client-side filter when backend is unavailable (demo mode).
     */
    function backendSearch(table, query) {
        if (!table || !table.nodeType) return;
        var entity = table.dataset.entity;
        if (!entity) { filterTable(table, query); return; }

        if (!query) {
            /* Empty search: reload full data from backend */
            api('/config/' + cfgType(entity))
                .then(function (data) {
                    if (data && data.entries) renderEntityRows(table, entity, data.entries);
                    else filterTable(table, '');  /* demo fallback: show all rows */
                })
                .catch(function () { filterTable(table, ''); });
            return;
        }

        api('/config/' + cfgType(entity) + '?q=' + encodeURIComponent(query))
            .then(function (data) {
                if (data && data.entries) renderEntityRows(table, entity, data.entries);
                else filterTable(table, query);  /* demo fallback */
            })
            .catch(function () { filterTable(table, query); });
    }

    /**
     * Render rows returned from backend search into a table.
     * Rebuilds <tbody> from API response data.
     */
    function renderEntityRows(table, entity, rows) {
        var config = ENTITIES[entity];
        var tbody = table.querySelector('tbody');
        if (!tbody || !config) return;

        if (rows.length === 0) {
            var colCount = table.querySelectorAll('thead th').length;
            tbody.innerHTML = '<tr><td colspan="' + colCount + '" style="text-align:center;color:#999;padding:20px;">No results found</td></tr>';
            return;
        }

        var html = '';
        rows.forEach(function (row, idx) {
            html += '<tr data-row-id="' + esc(row.id || row.name || idx) + '">';
            /* Checkbox column */
            html += '<td class="td-checkbox"><input type="checkbox" class="row-select"></td>';
            config.fields.forEach(function (f) {
                if (f.col === -1) return; /* form-only field, skip in table */
                var val = row[f.key] || '';
                if (f.key === 'status' && config.hasStatus) {
                    var isOn = (val === config.statusLabels.on || val === 'Enabled' || val === 'UP' || val === 'ACTIVE' || val === 'enable' || val === 'up');
                    var dotClass = isOn ? config.statusLabels.dotOn : config.statusLabels.dotOff;
                    var label = isOn ? config.statusLabels.on : config.statusLabels.off;
                    html += '<td><span class="status-dot ' + esc(dotClass) + '"></span>' + esc(label) + '</td>';
                } else {
                    html += '<td>' + esc(val) + '</td>';
                }
            });
            html += '</tr>';
        });
        tbody.innerHTML = html;
    }

    /**
     * Dispatch backend search for all entity tables found by target.
     */
    function applyBackendSearch(target, query) {
        if (!target) return;
        if (target.nodeType) {
            backendSearch(target, query);
        } else {
            target.forEach(function (tbl) { backendSearch(tbl, query); });
        }
    }

    /* Wire up all toolbar-search and widget-search inputs */
    document.querySelectorAll('.toolbar-search input, .widget-search input:not(#iface-search):not(#rf-search)').forEach(function (input) {
        var target = findTargetTable(input);

        /* Typing: instant client-side prefill filter */
        input.addEventListener('input', function () {
            applyFilter(target, this.value);
        });

        /* Enter: hit backend for real data */
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                applyBackendSearch(target, this.value);
            }
        });

        /* Search button click: hit backend for real data */
        var btn = input.parentElement.querySelector('.search-btn');
        if (btn) {
            btn.addEventListener('click', function () {
                applyBackendSearch(target, input.value);
            });
        }
    });

    /* Topbar global search — typing filters client-side, Enter/btn hits backend */
    var topbarSearchInput = document.querySelector('.topbar-search input');
    if (topbarSearchInput) {
        function filterCurrentPage(query) {
            var pageEl = document.getElementById('page-' + activePage);
            if (!pageEl) return;
            pageEl.querySelectorAll('table.data-table').forEach(function (tbl) {
                filterTable(tbl, query);
            });
        }

        function searchCurrentPage(query) {
            var pageEl = document.getElementById('page-' + activePage);
            if (!pageEl) return;
            pageEl.querySelectorAll('table.data-table').forEach(function (tbl) {
                backendSearch(tbl, query);
            });
        }

        /* Typing: client-side prefill */
        topbarSearchInput.addEventListener('input', function () {
            filterCurrentPage(this.value);
        });

        /* Enter: backend search */
        topbarSearchInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                searchCurrentPage(this.value);
            }
        });

        /* Topbar search button click: backend search */
        var topbarSearchBtn = document.querySelector('.topbar-search .search-btn');
        if (topbarSearchBtn) {
            topbarSearchBtn.addEventListener('click', function () {
                searchCurrentPage(topbarSearchInput.value);
            });
        }
    }

    /* Add Enter key support to dashboard search inputs (already have input handlers) */
    ['rf-search', 'iface-search'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) {
            el.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') e.preventDefault();
            });
        }
    });

    /* ================================================================
     *  FILE UPLOAD — show selected filename
     * ================================================================ */
    document.querySelectorAll('.file-upload-input').forEach(function (inp) {
        inp.addEventListener('change', function () {
            var nameEl = inp.parentElement.querySelector('.file-upload-name');
            if (nameEl) {
                nameEl.textContent = inp.files.length ? inp.files[0].name : 'No file selected';
            }
        });
    });

    /* ================================================================
     *  FORM SAVE — wire modal Save buttons to POST/PUT API calls
     * ================================================================ */

    function formSubmit(entity) {
        var config = ENTITIES[entity];
        if (!config) return;
        var form = document.getElementById(config.formId);
        if (!form) return;
        var body = form.querySelector('.modal-body');
        if (!body) return;

        /* Build label→input map */
        var labelMap = {};
        body.querySelectorAll('.form-row').forEach(function (fr) {
            var lbl = fr.querySelector('.form-label');
            var inp = fr.querySelector('.form-input');
            if (lbl && inp) {
                labelMap[lbl.textContent.trim().toLowerCase()] = inp;
            }
        });

        /* Build payload from fields — only include non-empty values.
         * Sending empty strings for optional fields would wipe existing
         * values on edit, or fail validation on create for required fields. */
        var payload = {};
        config.fields.forEach(function (f) {
            var inp = labelMap[f.label.toLowerCase()];
            if (!inp) return;
            /* Skip hidden rows (e.g. password fields hidden during edit) */
            var row = inp.closest('.form-row');
            if (row && row.style.display === 'none') return;
            if (inp.tagName === 'SELECT') {
                var val = inp.options[inp.selectedIndex].value || inp.options[inp.selectedIndex].text;
                if (val) payload[f.key] = val;
            } else if (inp.type === 'checkbox') {
                payload[f.key] = inp.checked;
            } else {
                if (inp.value !== '') payload[f.key] = inp.value;
            }
        });

        /* Also capture checkbox groups (e.g. Admin Access) */
        body.querySelectorAll('.form-row-full').forEach(function (fr) {
            var lbl = fr.querySelector('.form-label');
            if (!lbl) return;
            var cbs = fr.querySelectorAll('input[type="checkbox"]');
            if (cbs.length === 0) return;
            var vals = [];
            cbs.forEach(function (cb) {
                if (cb.checked) {
                    var parent = cb.parentElement;
                    vals.push(parent.textContent.trim().toLowerCase());
                }
            });
            /* Find matching field by label */
            var cbKey = lbl.textContent.trim().toLowerCase();
            config.fields.forEach(function (f) {
                if (f.label.toLowerCase() === cbKey) {
                    if (vals.length > 0) {
                        var sep = (f.key === 'permissions') ? ',' : ' ';
                        payload[f.key] = vals.join(sep);
                    } else {
                        /* All unchecked — send empty to clear the field.
                         * Without this, the backend keeps the old value. */
                        payload[f.key] = '';
                    }
                }
            });
        });

        var isEdit = form.dataset.editMode === 'true';
        var rowId = form.dataset.editRowId || '';

        /* Admin entity uses dedicated API with password handling */
        if (config.customCreate && !isEdit) {
            if (!payload.id) {
                showToast('Username is required', 'error');
                return;
            }
            var adminBody = {
                username: payload.id || '',
                profile: payload.profile || ''
            };
            /* Include enforce-* fields if present */
            if (payload['enforce-change-password'])
                adminBody['enforce-change-password'] = payload['enforce-change-password'];
            if (payload['enforce-password-policy'])
                adminBody['enforce-password-policy'] = payload['enforce-password-policy'];
            /* Read password fields directly from form (not in entity fields) */
            var pwInp = body.querySelector('input[type="password"]');
            var cfInp = body.querySelectorAll('input[type="password"]')[1];
            if (pwInp && pwInp.value) {
                if (cfInp && cfInp.value !== pwInp.value) {
                    showToast('Passwords do not match', 'error');
                    return;
                }
                adminBody.password = pwInp.value;
            } else {
                showToast('Password is required for new admin', 'error');
                return;
            }
            api('/admin/create', { method: 'POST', body: adminBody })
                .then(function () {
                    closeModal(false);
                    showToast('Administrator created', 'success');
                    refreshPage(activePage);
                })
                .catch(function (err) {
                    showToast(err.message || 'Create failed', 'error');
                });
            return;
        }

        var method, url;
        if (isEdit) {
            method = 'PUT';
            url = '/config/' + config.configType + '/' + rowId;
        } else {
            method = 'POST';
            url = '/config/' + config.configType;
            /* Ensure an identifier exists for types without name/id.
             * Routes and NAT use numeric IDs — generate next available
             * by counting existing entries + 1. */
            if (!payload.name && !payload.id) {
                var pageEl = document.getElementById('page-' + activePage);
                var table = pageEl ? pageEl.querySelector('table[data-entity]') : null;
                var rows = table ? table.querySelectorAll('tbody tr[data-row-id]') : [];
                var maxId = 0;
                rows.forEach(function (r) {
                    var n = parseInt(r.dataset.rowId, 10);
                    if (!isNaN(n) && n > maxId) maxId = n;
                });
                payload.id = String(maxId + 1);
            }
        }

        api(url, { method: method, body: payload })
            .then(function () {
                closeModal(false);
                showToast(isEdit ? 'Entry updated' : 'Entry created', 'success');
                refreshPage(activePage);
            })
            .catch(function (err) {
                showToast(err.message || 'Save failed', 'error');
            });
    }

    /* Wire all modal Save buttons */
    document.querySelectorAll('.modal-footer .btn-primary').forEach(function (btn) {
        btn.addEventListener('click', function (e) {
            var form = btn.closest('.add-form');
            if (!form) return;
            var entity = entityForForm(form.id);
            if (!entity) return;
            e.preventDefault();
            formSubmit(entity);
        });
    });

    /* ================================================================
     *  SETTINGS APPLY/RESET — wire settings pages to PUT API calls
     * ================================================================ */

    var SETTINGS_MAP = {
        'system': [
            { configType: 'system_settings', fields: { 'hostname': 'Hostname', 'ip-forward': 'IP Forward', 'timezone': 'Timezone' } },
            { configType: 'system_ntp', fields: { 'status': 'NTP Sync', 'server': 'NTP Server' } },
            { configType: 'network_dns', fields: { 'primary': 'Primary DNS', 'secondary': 'Secondary DNS' } }
        ],
        'password-policy': [
            { configType: 'system_password-policy', fields: { 'min-length': 'Minimum Length', 'min-uppercase': 'Min Uppercase', 'min-lowercase': 'Min Lowercase', 'min-digit': 'Min Digits', 'min-special': 'Min Special Chars' } }
        ]
    };

    function settingsLabelMap(card) {
        var labelMap = {};
        card.querySelectorAll('.form-row').forEach(function (fr) {
            var lbl = fr.querySelector('.form-label');
            var inp = fr.querySelector('.form-input');
            if (lbl && inp) labelMap[lbl.textContent.trim()] = inp;
        });
        return labelMap;
    }

    function settingsApply(card, settingsName) {
        var maps = SETTINGS_MAP[settingsName];
        if (!maps) return;
        var labelMap = settingsLabelMap(card);
        var pending = maps.length;
        var hadError = false;

        maps.forEach(function (m) {
            var payload = {};
            for (var key in m.fields) {
                var inp = labelMap[m.fields[key]];
                if (inp) {
                    payload[key] = inp.tagName === 'SELECT'
                        ? (inp.options[inp.selectedIndex].value || inp.options[inp.selectedIndex].text)
                        : inp.value;
                }
            }
            var isSingle = SINGLE_CONFIGS.indexOf(m.configType) !== -1;
            var url = '/config/' + m.configType + (isSingle ? '/0' : '');
            api(url, { method: 'PUT', body: payload })
                .then(function () {
                    pending--;
                    if (pending === 0 && !hadError) showToast('Settings saved', 'success');
                })
                .catch(function (err) {
                    hadError = true;
                    pending--;
                    showToast(err.message || 'Save failed', 'error');
                });
        });
    }

    /* Single-type configs use id "0" (not a table with entries) */
    var SINGLE_CONFIGS = ['system_settings', 'system_ntp', 'network_dns',
                          'system_password-policy'];

    function settingsLoad(card, settingsName) {
        var maps = SETTINGS_MAP[settingsName];
        if (!maps) return Promise.resolve();
        var labelMap = settingsLabelMap(card);

        return Promise.all(maps.map(function (m) {
            /* Single-type: GET /api/config/TYPE/0 returns the entry directly.
             * Table-type: GET /api/config/TYPE returns {entries:[...]}. */
            var isSingle = SINGLE_CONFIGS.indexOf(m.configType) !== -1;
            var url = '/config/' + m.configType + (isSingle ? '/0' : '');

            return api(url).then(function (data) {
                if (!data) return;
                for (var key in m.fields) {
                    var inp = labelMap[m.fields[key]];
                    if (inp && data[key] !== undefined) {
                        if (inp.tagName === 'SELECT') selectOption(inp, String(data[key]));
                        else inp.value = data[key];
                    }
                }
            });
        }));
    }

    function loadSettingsPage(pageEl, settingsName) {
        if (!pageEl) return Promise.resolve();
        var card = pageEl.querySelector('.form-card[data-settings]');
        if (!card) card = pageEl.querySelector('.form-card');
        if (card) return settingsLoad(card, settingsName);
        return Promise.resolve();
    }

    /* Wire settings Apply/Reset buttons */
    document.querySelectorAll('[data-settings]').forEach(function (card) {
        var settingsName = card.dataset.settings;
        var actions = card.querySelector('.form-actions');
        if (!actions) return;

        var applyBtn = actions.querySelector('.btn-primary');
        var resetBtn = actions.querySelector('.btn:not(.btn-primary)');

        if (applyBtn) {
            applyBtn.addEventListener('click', function () {
                settingsApply(card, settingsName);
            });
        }
        if (resetBtn) {
            resetBtn.addEventListener('click', function () {
                settingsLoad(card, settingsName);
            });
        }
    });

    /* ================================================================
     *  DIAGNOSTIC TOOLS — wire tool buttons to POST API calls
     * ================================================================ */

    function runDiagTool(tool, params) {
        var output = document.getElementById('diag-output');
        if (!output) return;
        output.textContent = 'Running...';
        output.style.color = '';

        api('/diagnose/' + tool, { method: 'POST', body: params })
            .then(function (data) {
                if (data && data.output) {
                    output.textContent = data.output;
                    output.style.color = '#333';
                } else {
                    output.textContent = 'No response from backend';
                    output.style.color = '#999';
                }
            })
            .catch(function (err) {
                output.textContent = 'Error: ' + (err.message || 'unknown');
                output.style.color = '#c62828';
            });
    }

    document.querySelectorAll('[data-tool]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var tool = btn.dataset.tool;
            var params = {};

            /* Walk backward from button's form-row to collect inputs until a form-section */
            var row = btn.closest('.form-row');
            var el = row;
            while (el) {
                if (el.classList && el.classList.contains('form-section')) break;
                if (el.classList && el.classList.contains('form-row')) {
                    var lbl = el.querySelector('.form-label');
                    var inp = el.querySelector('.form-input');
                    if (lbl && inp) {
                        var key = lbl.textContent.trim().toLowerCase();
                        var val = inp.tagName === 'SELECT' ? inp.value : inp.value.trim();
                        if (key.indexOf('interface') !== -1) params.iface = val;
                        else params.target = val;
                    }
                }
                el = el.previousElementSibling;
            }

            if (!params.target) {
                showToast('Enter a target', 'error');
                return;
            }

            runDiagTool(tool, params);
        });
    });

    /* ================================================================
     *  FIRMWARE — upload + reboot to NAND
     * ================================================================ */

    var fwInstallBtn = document.querySelector('#page-sys-firmware .form-actions .btn-primary');
    if (fwInstallBtn) {
        fwInstallBtn.addEventListener('click', function () {
            var fileInput = document.querySelector('#page-sys-firmware .file-upload-input');
            if (!fileInput || !fileInput.files.length) {
                showToast('Select a firmware file', 'error');
                return;
            }

            var file = fileInput.files[0];

            /* Validate file extension */
            if (!file.name.match(/\.itb$/i)) {
                showToast('Invalid firmware file: must be .itb format', 'error');
                return;
            }

            /* Reject files larger than 64MB */
            if (file.size > 64 * 1024 * 1024) {
                showToast('Firmware file too large (max 64 MB)', 'error');
                return;
            }

            var formData = new FormData();
            formData.append('firmware', fileInput.files[0]);

            fwInstallBtn.textContent = 'Uploading...';
            fwInstallBtn.disabled = true;

            api('/system/firmware/upgrade', { method: 'POST', body: formData })
                .then(function (data) {
                    if (!data) {
                        showToast('No backend available', 'error');
                        fwInstallBtn.textContent = 'Install Firmware';
                        fwInstallBtn.disabled = false;
                        return;
                    }
                    /* Poll progress */
                    var pollId = setInterval(function () {
                        api('/system/firmware/progress').then(function (prog) {
                            if (!prog) { clearInterval(pollId); return; }
                            fwInstallBtn.textContent = 'Installing... ' + (prog.percent || 0) + '%';
                            if (prog.percent >= 100 || prog.done) {
                                clearInterval(pollId);
                                fwInstallBtn.textContent = 'Install Firmware';
                                fwInstallBtn.disabled = false;
                                showToast('Firmware installed', 'success');
                            }
                        });
                    }, 2000);
                })
                .catch(function (err) {
                    showToast(err.message || 'Upload failed', 'error');
                    fwInstallBtn.textContent = 'Install Firmware';
                    fwInstallBtn.disabled = false;
                });
        });
    }

    /* Reboot to NAND recovery */
    document.querySelectorAll('#page-sys-firmware .btn').forEach(function (btn) {
        if (btn.textContent.trim() === 'Reboot to NAND') {
            btn.addEventListener('click', function () {
                if (!confirm('Reboot to recovery?')) return;
                api('/system/reboot', { method: 'POST', body: { device: 'nand' } })
                    .then(function () { showToast('Rebooting to recovery...', 'success'); })
                    .catch(function (err) { showToast(err.message || 'Reboot failed', 'error'); });
            });
        }
    });

    /* ================================================================
     *  PAGE-LOAD DATA FETCHING
     * ================================================================ */

    function loadEntityPage(entity, table) {
        var config = ENTITIES[entity];
        if (!config) return Promise.resolve();
        /* Show loading placeholder while fetching */
        var tbody = table.querySelector('tbody');
        var colCount = table.querySelectorAll('thead th').length;
        if (tbody) tbody.innerHTML = '<tr><td colspan="' + colCount + '" style="text-align:center;color:#999;padding:20px">Loading...</td></tr>';
        return api('/config/' + config.configType).then(function (data) {
            renderEntityRows(table, entity, data && data.entries ? data.entries : []);
        });
    }

    /* ================================================================
     *  SESSION KEEPALIVE — poll whoami every 60s for idle timeout
     * ================================================================ */

    var KEEPALIVE_INTERVAL = 60000; /* 60 seconds */
    var lastPermissions = null;

    function keepaliveCheck() {
        /* Use raw fetch to avoid api() auto-redirect on 401 */
        fetch(API_BASE + '/auth/whoami')
            .then(function (res) {
                if (res.status === 401) {
                    showToast('Session expired — redirecting to login', 'error');
                    setTimeout(function () {
                        window.location.href = 'login.html';
                    }, 3000);
                    return null;
                }
                if (!res.ok) return null;
                return res.json();
            })
            .then(function (data) {
                if (!data) return;
                /* Update topbar with actual logged-in user */
                if (data.username) {
                    var nameEl = document.querySelector('.user-name');
                    var avatarEl = document.querySelector('.user-avatar');
                    var headerEl = document.querySelector('.user-dropdown-header strong');
                    if (nameEl) nameEl.textContent = data.username;
                    if (avatarEl) avatarEl.textContent = data.username.charAt(0).toUpperCase();
                    if (headerEl) headerEl.textContent = data.username;
                    var profileEl = document.querySelector('.user-dropdown-header span');
                    if (profileEl && data.profile) profileEl.textContent = data.profile;
                }
                /* Detect permission changes */
                if (lastPermissions !== null && data.permissions !== lastPermissions) {
                    showToast('Permissions updated — refreshing', 'success');
                    setTimeout(function () { location.reload(); }, 1500);
                }
                lastPermissions = data.permissions || '';
            })
            .catch(function () {
                /* Network error — show warning but don't redirect */
            });
    }

    /* Start keepalive — initial check + interval */
    keepaliveCheck();
    setInterval(keepaliveCheck, KEEPALIVE_INTERVAL);

    /* ================================================================
     *  NETWORK OVERVIEW — fetch live stats for summary cards
     * ================================================================ */

    function renderNetworkOverview() {
        return Promise.all([
            fetchIfaceData(),
            fetchRouteData(),
            api('/config/network_dhcp-server')
        ]).then(function (results) {
            var dhcpData = results[2];

            /* ── Summary cards ── */
            var up = 0, total = ifaceData.length;
            ifaceData.forEach(function (iface) {
                if (iface.status === 'UP') up++;
            });
            var el = document.getElementById('net-ifaces-up');
            if (el) el.innerHTML = esc(up) + '<span class="gauge-unit"> / ' + esc(total) + '</span>';
            var det = document.getElementById('net-ifaces-detail');
            if (det) det.textContent = (total - up) + ' interface' + (total - up !== 1 ? 's' : '') + ' down';

            var active = 0, disabled = 0;
            routeData.forEach(function (r) {
                if (r.status === 'ACTIVE') active++;
                else disabled++;
            });
            var rel = document.getElementById('net-routes-up');
            if (rel) rel.textContent = active;
            var rdet = document.getElementById('net-routes-detail');
            if (rdet) rdet.textContent = disabled + ' disabled';

            var tp = document.getElementById('net-throughput');
            if (tp) tp.innerHTML = '--<span class="gauge-unit"> Mbps</span>';
            var tpd = document.getElementById('net-throughput-detail');
            if (tpd) tpd.textContent = 'not yet available';

            var arp = document.getElementById('net-arp');
            if (arp) arp.textContent = '--';
            var arpd = document.getElementById('net-arp-detail');
            if (arpd) arpd.textContent = 'not yet available';

            /* ── Interface Traffic table ── */
            var ttbody = document.getElementById('net-traffic-tbody');
            if (ttbody) {
                var html = '';
                ifaceData.forEach(function (iface) {
                    var dotCls = iface.status === 'UP' ? 'up' : 'down';
                    html += '<tr>' +
                        '<td><span class="status-dot ' + esc(dotCls) + '"></span>' + esc(iface.name) + '</td>' +
                        '<td>' + esc(iface.ip) + '</td>' +
                        '<td>' + esc(iface.speed) + '</td>' +
                        '<td>' + esc(iface.status) + '</td>' +
                        '</tr>';
                });
                ttbody.innerHTML = html || '<tr><td colspan="4" style="text-align:center;color:#999;padding:12px">No interfaces</td></tr>';
            }

            /* ── DHCP Pools table ── */
            var dtbody = document.getElementById('net-dhcp-tbody');
            if (dtbody) {
                var dhtml = '';
                if (dhcpData && dhcpData.entries) {
                    dhcpData.entries.forEach(function (pool) {
                        var range = (pool['start-ip'] || '') + ' - ' + (pool['end-ip'] || '');
                        var st = pool.status || 'enable';
                        var dotCls = st === 'enable' ? 'up' : 'disabled';
                        var label = st === 'enable' ? 'Enabled' : 'Disabled';
                        dhtml += '<tr>' +
                            '<td>' + esc(pool.id) + '</td>' +
                            '<td>' + esc(pool['interface'] || '') + '</td>' +
                            '<td>' + esc(range) + '</td>' +
                            '<td><span class="status-dot ' + esc(dotCls) + '"></span>' + esc(label) + '</td>' +
                            '</tr>';
                    });
                }
                dtbody.innerHTML = dhtml || '<tr><td colspan="4" style="text-align:center;color:#999;padding:12px">No DHCP pools configured</td></tr>';
            }

            /* ── Route Flows widget ── */
            renderRouteRows();
        });
    }

    /* ================================================================
     *  DYNAMIC SELECT POPULATION — fetch real data for form dropdowns
     * ================================================================ */

    /* Populate all .iface-select dropdowns with real interface names */
    function populateIfaceSelects() {
        return api('/config/system_interface').then(function (data) {
            if (!data || !data.entries) return;
            var selects = document.querySelectorAll('.iface-select');
            selects.forEach(function (sel) {
                /* Preserve 'any' option if present */
                var hasAny = sel.querySelector('option[value="any"]') ||
                             (sel.options.length > 0 && sel.options[0].text === 'any');
                var anyOpt = hasAny ? sel.options[0] : null;
                sel.innerHTML = '';
                if (anyOpt) sel.appendChild(anyOpt);
                data.entries.forEach(function (e) {
                    var opt = document.createElement('option');
                    opt.value = e.id || '';
                    opt.textContent = e.id || '';
                    sel.appendChild(opt);
                });
            });
        });
    }

    /* Populate admin profile select with real profiles */
    function populateProfileSelect() {
        var sel = document.getElementById('admin-profile-select');
        if (!sel) return Promise.resolve();
        return api('/config/system_admin-profile').then(function (data) {
            if (!data || !data.entries) return;
            sel.innerHTML = '';
            data.entries.forEach(function (e) {
                var opt = document.createElement('option');
                opt.value = e.id || '';
                opt.textContent = e.id || '';
                sel.appendChild(opt);
            });
        });
    }

    /* Populate address object selects (firewall policy src/dst) */
    function populateAddrSelects() {
        return api('/config/firewall_address').then(function (data) {
            if (!data || !data.entries) return;
            document.querySelectorAll('.addr-select').forEach(function (sel) {
                /* Keep 'all' option, remove the rest, re-add from API */
                var allOpt = sel.querySelector('option[value="all"]');
                sel.innerHTML = '';
                if (allOpt) sel.appendChild(allOpt);
                data.entries.forEach(function (e) {
                    var eid = e.id || e.name || '';
                    var opt = document.createElement('option');
                    opt.value = eid;
                    opt.textContent = eid;
                    sel.appendChild(opt);
                });
            });
        });
    }

    /* Populate service selects (firewall policy service) */
    function populateSvcSelects() {
        return api('/config/firewall_service').then(function (data) {
            if (!data || !data.entries) return;
            document.querySelectorAll('.svc-select').forEach(function (sel) {
                var allOpt = sel.querySelector('option[value="all"]');
                sel.innerHTML = '';
                if (allOpt) sel.appendChild(allOpt);
                data.entries.forEach(function (e) {
                    var eid = e.id || e.name || '';
                    var opt = document.createElement('option');
                    opt.value = eid;
                    opt.textContent = eid;
                    sel.appendChild(opt);
                });
            });
        });
    }

    /* Run on page load — populate all dynamic selects */
    populateIfaceSelects();
    populateProfileSelect();
    populateAddrSelects();
    populateSvcSelects();

    function loadFirmwareInfo() {
        return api('/system/firmware').then(function (data) {
            if (!data) return;
            var page = document.getElementById('page-sys-firmware');
            if (!page) return;
            var values = page.querySelectorAll('.form-value');
            if (data.version && values[0]) values[0].textContent = data.version;
            if (data.build && values[1]) values[1].textContent = data.build;
            if (data.kernel && values[2]) values[2].textContent = data.kernel;
            if (data.installed && values[3]) values[3].textContent = data.installed;
            if (data.recovery && values[5]) values[5].textContent = data.recovery;
        });
    }

    /* ================================================================
     *  INITIAL PAGE LOAD — must be AFTER all var definitions (ENTITIES etc.)
     * ================================================================ */
    var initPage = sessionStorage.getItem('sg_page') || 'dashboard';
    if (!document.getElementById('page-' + initPage)) initPage = 'dashboard';
    var initSub = document.querySelector('.nav-sub-item[data-page="' + initPage + '"]');
    var initCat = initSub ? initSub.closest('.nav-category') : null;
    if (initCat) initCat.classList.add('open');
    setActivePage(initPage, initCat, initSub);

})();
