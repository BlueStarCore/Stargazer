/* app.js — Stargazer Web UI main application
 *
 * Handles: sidebar navigation, gauge rendering, page routing.
 * API integration added in later phases.
 */

(function () {
    'use strict';

    /* ================================================================
     *  SHARED HELPERS
     * ================================================================ */

    /* Debounce — schedule fn to run after `wait` ms of no calls.
     * Used to throttle search input handlers and other high-frequency
     * events that trigger expensive DOM work. */
    function debounce(fn, wait) {
        var t = null;
        return function () {
            var ctx = this, args = arguments;
            if (t) clearTimeout(t);
            t = setTimeout(function () { fn.apply(ctx, args); }, wait);
        };
    }

    /* Sort toggle — flip ascending if same key clicked, otherwise
     * switch to that key with ascending=true.  Uses any state object
     * exposing { sortKey, sortAsc } (route flow, iface table) or
     * { col, asc } (generic data table). */
    function toggleSort(state, key, keyField, ascField) {
        var kf = keyField || 'sortKey';
        var af = ascField || 'sortAsc';
        if (state[kf] === key) {
            state[af] = !state[af];
        } else {
            state[kf] = key;
            state[af] = true;
        }
    }

    /* Status string normalization — backend uses many spellings:
     * 'enable'/'enabled'/'ACTIVE'/'UP'/'up'/'Enabled'.  This collapses
     * them into a single boolean check. */
    var STATUS_ON_VALUES = {
        'enable': 1, 'enabled': 1, 'Enabled': 1,
        'up': 1, 'UP': 1, 'ACTIVE': 1, 'active': 1
    };
    function isStatusEnabled(val, onLabel) {
        if (!val) return false;
        if (onLabel && val === onLabel) return true;
        return !!STATUS_ON_VALUES[val];
    }

    /* TTL cache for /config/* fetches.  Modal opens used to refetch
     * 4 endpoints (interface, profile, address, service) every time;
     * with a 5s TTL the same modal-open burst hits the IPC layer once. */
    var apiCache = {};
    var API_TTL_MS = 5000;
    function cachedApi(path) {
        var now = Date.now();
        var entry = apiCache[path];
        if (entry && (now - entry.t) < API_TTL_MS) {
            /* A cache hit is still "valid data" → count it as a successful api()
             * so the page reveal mechanism (setActivePage) removes the loading cover
             * immediately, instead of waiting the 8s watchdog when a tab uses cachedApi (e.g. Rules tab). */
            if (entry.v != null) apiSuccessCount++;
            return Promise.resolve(entry.v);
        }
        return api(path).then(function (data) {
            apiCache[path] = { t: Date.now(), v: data };
            return data;
        });
    }
    function invalidateApiCache(pathPrefix) {
        if (!pathPrefix) { apiCache = {}; return; }
        Object.keys(apiCache).forEach(function (k) {
            if (k.indexOf(pathPrefix) === 0) delete apiCache[k];
        });
    }

    /* Catalog signature fetch — SERVER-SIDE search (IPC response limited to 64KB;
     * large rulesets cannot be loaded in full, must be filtered by keyword on the backend).
     * Returns {items:[], truncated:0|1}. Compatible with old servers that return an array.
     * Top-level: shared by both the IPS 5-tab module and the "Add Signatures" modal. */
    function fetchCatalog(q) {
        var path = '/ips/signatures';
        if (q) path += '?q=' + encodeURIComponent(q);
        return cachedApi(path).then(function (data) {
            if (Array.isArray(data)) return { items: data, categories: [], truncated: 0 };
            return { items: (data && data.items) || [],
                     categories: (data && data.categories) || [],
                     truncated: (data && data.truncated) ? 1 : 0 };
        });
    }

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

    var subItems = document.querySelectorAll('.nav-sub-item');

    /* Forward declarations — selection / hideCtx are defined later
     * but referenced in nav handlers; check at call time. */
    function navClearTransient() {
        if (typeof selection !== 'undefined' && selection && selection.clear)
            selection.clear();
        if (typeof hideCtx === 'function')
            hideCtx();
        /* Clear stale drag state on page navigation */
        if (typeof dragRow !== 'undefined') {
            dragRow = null;
            dragEntity = null;
        }
    }

    categories.forEach(function (cat) {
        var header = cat.querySelector('.nav-category-header');
        if (!header) return;

        function handleCategoryActivate() {
            navClearTransient();

            /* Direct page link (e.g. Dashboard) — no sub-arrow */
            if (!cat.querySelector('.nav-arrow')) {
                setActivePage(cat.dataset.page, cat, null);
                return;
            }

            /* Sidebar collapsed: sub-items are hidden, so toggling
             * .open is invisible.  Navigate straight to the category's
             * first sub-page instead. */
            if (sidebar && sidebar.classList.contains('collapsed')) {
                var firstSub = cat.querySelector('.nav-sub-item');
                if (firstSub) {
                    setActivePage(firstSub.dataset.page, cat, firstSub);
                }
                return;
            }

            /* Sidebar expanded: toggle the dropdown */
            cat.classList.toggle('open');
            /* Update ARIA state */
            var isOpen = cat.classList.contains('open');
            header.setAttribute('aria-expanded', String(isOpen));
        }

        header.addEventListener('click', handleCategoryActivate);

        /* Keyboard: Enter or Space activates the category */
        header.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleCategoryActivate();
            }
        });
    });

    subItems.forEach(function (item) {
        item.addEventListener('click', function (e) {
            e.stopPropagation();
            navClearTransient();
            var parentCat = item.closest('.nav-category');
            setActivePage(item.dataset.page, parentCat, item);
        });
    });

    /* ── setActivePage helpers ──────────────────────────────────── */

    function clearNavActive() {
        categories.forEach(function (c) { c.classList.remove('active'); });
        subItems.forEach(function (s) { s.classList.remove('active'); });
    }

    function hideAllPages() {
        document.querySelectorAll('.page').forEach(function (p) {
            p.style.display = 'none';
        });
        document.querySelectorAll('.page-cover').forEach(function (el) { el.remove(); });
    }

    function clearTopbarSearch() {
        var topSearch = document.querySelector('.topbar-search input');
        if (topSearch && topSearch.value) topSearch.value = '';
    }

    /* Show full-page loading cover while data fetches behind it,
     * then transition to a scan-line reveal animation. */
    function showLoadingCover(parent) {
        var cover = document.createElement('div');
        cover.className = 'page-cover page-cover-loading';
        var spinner = document.createElement('div');
        spinner.className = 'page-loading-spinner';
        /* Trailing dots are appended by ::after — animated cycle */
        spinner.textContent = 'LOADING';
        cover.appendChild(spinner);
        parent.appendChild(cover);
        return cover;
    }

    function revealCover(cover) {
        requestAnimationFrame(function () {
            requestAnimationFrame(function () {
                cover.classList.remove('page-cover-loading');
                cover.classList.add('page-cover-reveal');
                cover.innerHTML = '';
                var scanLine = document.createElement('div');
                scanLine.className = 'page-scan-line';
                cover.appendChild(scanLine);
                cover.addEventListener('animationend', function () {
                    cover.remove();
                });
            });
        });
    }

    /* Hard timeout — cover always reveals after this long even if
     * the API hangs.  Prevents the page from being permanently
     * blocked when the backend is unreachable. */
    var MAX_COVER_MS = 8000;

    function setActivePage(page, category, subItem) {
        clearNavActive();
        if (category) category.classList.add('active');
        if (subItem) subItem.classList.add('active');

        hideAllPages();
        activePage = page;
        sessionStorage.setItem('sg_page', page);
        clearTopbarSearch();

        var loadDone = Promise.resolve();
        var target = document.getElementById('page-' + page);
        if (target) {
            target.style.display = '';
            var cover = showLoadingCover(document.getElementById('content'));
            var startSuccessCount = apiSuccessCount;
            var revealed = false;

            /* loadDone resolves when the cover has actually been
             * revealed — not just when refreshPage's API promise
             * settled.  Callers (e.g. nav-search smooth-scroll) need
             * this so they don't scroll under a still-visible cover. */
            var resolveDone;
            loadDone = new Promise(function (r) { resolveDone = r; });

            function doReveal() {
                if (revealed) return;
                revealed = true;
                revealCover(cover);
                resolveDone();
            }

            /* Watchdog — reveals the cover if data never arrives. */
            var watchdog = setTimeout(doReveal, MAX_COVER_MS);

            var pending = refreshPage(page);

            /* Static pages (no API fetches): nothing to wait for —
             * reveal immediately. */
            if (!pending.hasFetches) {
                clearTimeout(watchdog);
                doReveal();
            } else {
                pending.then(function () {
                    /* Reveal as soon as at least one api() call
                     * returned non-null data.  Otherwise keep the
                     * cover up until the watchdog fires. */
                    if (apiSuccessCount === startSuccessCount) return;
                    clearTimeout(watchdog);
                    doReveal();
                }).catch(function () { /* fall through to watchdog */ });
            }
        }

        startPolling();
        return loadDone;
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
        else if (page === 'sec-ips') { promises.push(initIpsPage(pageEl)); }
        else if (page === 'sec-ips-profiles') {
            var profTable = pageEl ? pageEl.querySelector('table[data-entity]') : null;
            if (profTable) promises.push(loadEntityPage(profTable.dataset.entity, profTable));
            if (pageEl) resetPageFilters(pageEl);
            /* Refresh profile dropdown on policy form so new profiles appear */
            invalidateApiCache('/config/security_ips-profile');
            populateIpsProfileSelects();
        }
        else if (page === 'sys-settings') { promises.push(loadSettingsPage(pageEl, 'system')); }
        else if (page === 'sys-password') { promises.push(loadSettingsPage(pageEl, 'password-policy')); }
        else if (page === 'sys-firmware') { promises.push(loadFirmwareInfo()); }
        else if (page === 'sec-ssl') {
            var sslTable = pageEl ? pageEl.querySelector('table[data-entity]') : null;
            if (sslTable) promises.push(loadEntityPage(sslTable.dataset.entity, sslTable));
            if (pageEl) resetPageFilters(pageEl);
            /* Refresh SSL-profile dropdown on policy form so new profiles appear */
            invalidateApiCache('/config/security_ssl-inspection-profile');
            populateSslProfileSelects();
            initSslPageExtras(pageEl);
        }
        else if (page === 'sys-certificates') { promises.push(initCertPage(pageEl)); }
        else if (page === 'interfaces') {
            var ifTable = pageEl ? pageEl.querySelector('table[data-entity]') : null;
            var ifLoad = ifTable ? loadEntityPage(ifTable.dataset.entity, ifTable) : Promise.resolve();
            if (pageEl) resetPageFilters(pageEl);
            /* Overlay live kernel IPs after config data renders — DHCP
             * interfaces store 0.0.0.0/0 in the DB; live data has the
             * actual assigned address. */
            var ifLive = ifLoad.then(function () {
                return api('/system/interfaces/live').then(function (live) {
                    if (!live || !live.interfaces || !ifTable) return;
                    var liveMap = {};
                    live.interfaces.forEach(function (iface) {
                        liveMap[iface.name] = iface;
                    });
                    ifTable.querySelectorAll('tbody tr').forEach(function (tr) {
                        var name = tr.dataset.rowId;
                        var li = liveMap[name];
                        if (!li) return;
                        var liveIp = (li.ip && li.ip !== '-') ? li.ip : null;
                        if (!liveIp) return;
                        var ipCell = tr.querySelector('td[data-key="ip"]');
                        if (ipCell) ipCell.textContent = liveIp;
                    });
                }).catch(function () {}); /* live overlay is best-effort */
            });
            promises.push(ifLive);
        }
        else if (page === 'dhcp') {
            var dhcpTable = pageEl ? pageEl.querySelector('table[data-entity="dhcp"]') : null;
            if (dhcpTable) promises.push(loadEntityPage('dhcp', dhcpTable));
            promises.push(renderDhcpLeases());
            if (pageEl) resetPageFilters(pageEl);
        }
        else if (page === 'fw-sessions') { promises.push(renderSessions()); }
        else if (pageEl) {
            var table = pageEl.querySelector('table[data-entity]');
            if (table) promises.push(loadEntityPage(table.dataset.entity, table));
            resetPageFilters(pageEl);
        }

        /* Return both the wait-promise AND a flag telling callers
         * whether any actual data fetching was scheduled.  Pages with
         * no fetches (Network Tools, Sessions stub, etc.) shouldn't
         * have to wait through the cover-watchdog timeout. */
        var done = Promise.all(promises).catch(function () { /* ignore */ });
        done.hasFetches = promises.length > 0;
        return done;
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
     * Returns null when backend is unreachable so callers can keep
     * their placeholder state instead of showing fake data.
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

        /* Invalidate the read cache on any mutation. /config/<type> is
         * the populate-selects path; if a CFG_SET / CFG_DEL hits any
         * /config/* endpoint we drop the entire config slice so the
         * next modal open re-fetches. */
        var method = (options.method || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD' &&
            endpoint.indexOf('/config/') === 0) {
            invalidateApiCache('/config/');
        }

        return fetch(url, options)
            .then(function (res) {
                if (res.status === 401) {
                    /* Suppress redirect if we deliberately triggered a reboot
                     * (firmware upgrade) — the caller handles the transition. */
                    if (window.__sg_fwRebooting) return null;
                    window.location.href = 'login.html';
                    return;
                }
                if (res.status === 403) {
                    /* Surface mgmtd's verbatim reason (e.g. "Immutable object
                     * cannot be modified") rather than a generic string. */
                    return res.json().catch(function () { return {}; }).then(function (err) {
                        var msg = err.error || 'Permission denied';
                        showToast(msg, 'error');
                        var e = new Error(msg);
                        e.status = 403;
                        throw e;
                    });
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
            .then(function (data) {
                /* Bump success counter + clear any banner state. */
                if (data != null) {
                    apiSuccessCount++;
                    ConnStatus.report('ok');
                }
                return data;
            })
            .catch(function (err) {
                /* Network error / backend unreachable: report and
                 * return null so callers can show placeholder data
                 * instead of crashing. */
                if (!err.status) {
                    ConnStatus.report('unreachable');
                    return null;
                }
                /* HTTP error response — server reachable but unhappy. */
                ConnStatus.report('error');
                throw err;
            });
    }

    /* Counts successful (non-null) api() responses.  setActivePage
     * snapshots this at navigation and waits until it grows before
     * revealing the page-cover. */
    var apiSuccessCount = 0;

    /* ─────────────────────────────────────────────────────────────
     *  ConnStatus — single source of truth for connection state.
     *
     *  Every api() response (success / network error / HTTP error)
     *  is funneled into ConnStatus.report().  The banner element
     *  in the topbar reflects the current state automatically; no
     *  individual call site has to update UI.
     *
     *  States:
     *    'ok'           — banner hidden
     *    'error'        — last HTTP request returned 4xx/5xx (not auth)
     *    'unreachable'  — last network call failed entirely
     *    'reconnect'    — recovered from a bad state, brief flash
     *  ───────────────────────────────────────────────────────────── */
    var ConnStatus = (function () {
        var state = 'ok';
        var bannerEl = null;
        var dotEl = null;
        var textEl = null;
        var reconnectTimer = null;

        var MESSAGES = {
            ok:          '',
            error:       'BACKEND ERROR — last request failed',
            unreachable: 'BACKEND UNREACHABLE — retrying…',
            reconnect:   'CONNECTION RESTORED'
        };

        function ensureRefs() {
            if (!bannerEl) {
                bannerEl = document.getElementById('conn-banner');
                if (bannerEl) {
                    dotEl  = bannerEl.querySelector('.conn-banner-dot');
                    textEl = bannerEl.querySelector('.conn-banner-text');
                }
            }
            return bannerEl;
        }

        function render() {
            if (!ensureRefs()) return;
            if (state === 'ok') {
                bannerEl.hidden = true;
                bannerEl.removeAttribute('data-state');
                return;
            }
            bannerEl.hidden = false;
            bannerEl.setAttribute('data-state', state);
            if (textEl) textEl.textContent = MESSAGES[state] || '';
        }

        function set(next) {
            if (state === next) return;
            var prev = state;
            state = next;
            render();

            /* Auto-clear the brief "reconnect" flash after 2.5s */
            if (next === 'reconnect') {
                if (reconnectTimer) clearTimeout(reconnectTimer);
                reconnectTimer = setTimeout(function () {
                    if (state === 'reconnect') set('ok');
                }, 2500);
            }
            return prev;
        }

        /* Called by api() on every response.  result is one of:
         *   'ok'          — got data
         *   'error'       — HTTP error response (server reachable)
         *   'unreachable' — network/fetch failure */
        function report(result) {
            if (result === 'ok') {
                /* If we were previously bad, briefly show "restored" */
                if (state === 'unreachable' || state === 'error') {
                    set('reconnect');
                } else if (state === 'reconnect') {
                    /* keep flash, will auto-clear */
                } else {
                    set('ok');
                }
                return;
            }
            set(result);
        }

        return { report: report, get: function () { return state; } };
    })();

    /* ================================================================
     *  TOAST NOTIFICATIONS
     * ================================================================ */

    var activeToasts = [];

    function repositionToasts() {
        for (var i = 0; i < activeToasts.length; i++) {
            activeToasts[i].style.top = (20 + i * 56) + 'px';
        }
    }

    function showToast(message, type) {
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + (type || 'success');
        toast.textContent = message;
        document.body.appendChild(toast);
        activeToasts.push(toast);
        repositionToasts();
        setTimeout(function () {
            toast.classList.add('toast-fade');
            setTimeout(function () {
                toast.remove();
                var idx = activeToasts.indexOf(toast);
                if (idx !== -1) activeToasts.splice(idx, 1);
                repositionToasts();
            }, 300);
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

    /* Draw a donut gauge on a canvas element.
     * Caches canvas setup (width/height/transform) to avoid triggering
     * a full re-composite on every 5s poll cycle. */
    var gaugeCache = {};

    function drawGauge(canvasId, percent, color) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return;

        var dpr = window.devicePixelRatio || 1;
        var size = 280;  /* canvas logical size */
        var cx = size / 2;
        var cy = size / 2;
        var radius = 112;
        var lineWidth = 20;

        /* Only set canvas dimensions once per element */
        var cached = gaugeCache[canvasId];
        if (!cached || cached.dpr !== dpr) {
            canvas.width = size * dpr;
            canvas.height = size * dpr;
            var ctx = canvas.getContext('2d');
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            gaugeCache[canvasId] = { dpr: dpr, ctx: ctx };
            cached = gaugeCache[canvasId];
        }

        var ctx = cached.ctx;
        ctx.clearRect(0, 0, size, size);

        /* Background track */
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.strokeStyle = COLOR_TRACK;
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

    /* Server data is rendered via textContent / DOM nodes, not innerHTML.
     * SgCommon.escHTML is available if an innerHTML sink is ever needed. */

    /* Cache element references by id — getElementById hits DOM
     * lookup tables; on a 5s poll cycle this is wasted work because
     * gauge ids are static.  setEl() looks up once and reuses. */
    var elCache = {};
    function setEl(id) {
        var el = elCache[id];
        if (el && el.isConnected) return el;
        el = document.getElementById(id);
        if (el) elCache[id] = el;
        return el;
    }

    /* Update a gauge value (with optional unit) and its detail line.
     * Replaces innerHTML string-concat with DOM API: keeps the
     * gauge-unit span structure without parsing HTML each call. */
    function setGaugeText(valId, value, unit, detailId, detail) {
        var valEl = setEl(valId);
        var detailEl = setEl(detailId);
        if (valEl) {
            valEl.textContent = '';
            valEl.appendChild(document.createTextNode(String(value)));
            if (unit) valEl.appendChild(makeSpan('gauge-unit', unit));
            valEl.classList.remove('loading');
        }
        if (detailEl) {
            detailEl.textContent = detail;
            detailEl.classList.remove('loading');
        }
    }

    /* Threshold colors — duplicate the CSS variables here so canvas
     * draws and CSS rules stay visually consistent.  If the theme
     * changes, update both. */
    var COLOR_OK    = '#4caf50';  /* var(--color-success)  */
    var COLOR_WARN  = '#e8956a';  /* var(--color-warning)  */
    var COLOR_BAD   = '#e53935';  /* var(--color-danger)   */
    var COLOR_TRACK = '#e2e5ea';  /* var(--border-light)   */

    var GAUGE_WARN_PCT = 60;  /* % usage that flips ok→warn */
    var GAUGE_BAD_PCT  = 85;  /* % usage that flips warn→bad */
    var TEMP_WARN_C    = 60;  /* °C that flips ok→warn */
    var TEMP_BAD_C     = 80;  /* °C that flips warn→bad */

    function gaugeColor(percent) {
        if (percent < GAUGE_WARN_PCT) return COLOR_OK;
        if (percent < GAUGE_BAD_PCT)  return COLOR_WARN;
        return COLOR_BAD;
    }

    function tempColor(deg) {
        if (deg < TEMP_WARN_C) return COLOR_OK;
        if (deg < TEMP_BAD_C)  return COLOR_WARN;
        return COLOR_BAD;
    }

    /*
     * Fetch and render dashboard gauges.
     *
     * API contract (GET /api/system/resources):
     *   { cpu_pct, mem_pct, mem_used_mb, mem_total_mb,
     *     disk_pct, disk_used_mb, disk_total_mb,
     *     sessions, sessions_max, cpu_cores, cpu_mhz }
     *
     * Keeps initial placeholder state when API is unavailable.
     */
    function renderGauges() {
        return api('/system/resources').then(function (data) {
            if (!data) {
                ['detail-cpu','detail-mem','detail-disk','detail-sessions'].forEach(function (id) {
                    var el = setEl(id);
                    if (el) { el.textContent = 'No data'; el.classList.remove('loading'); }
                });
                return;
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

    /*
     * Fetch and render resource page gauges.
     *
     * API contract (GET /api/system/resources/detail):
     *   { temp_c, cpu_pct, load_avg, mem_pct, mem_used_mb, mem_total_mb,
     *     disk_pct, disk_used_mb, disk_total_mb }
     *
     * Keeps initial placeholder state when API is unavailable.
     */
    /* Helper: format kB value to human-readable MB string */
    function fmtMB(kb) {
        return Math.round(kb / 1024) + ' MB';
    }

    /* ── renderResourceDetails helpers ──────────────────────────── */

    /* Set textContent on a cached element by id.  Strips the
     * `loading` class so the element stops pulsing once real
     * data has arrived. */
    function setText(id, val) {
        var el = setEl(id);
        if (!el) return;
        el.textContent = val;
        el.classList.remove('loading');
    }

    /* Set a usage bar's width and value cell. */
    function setBar(barId, valId, kb, totalKb) {
        var bar = setEl(barId);
        var val = setEl(valId);
        var pct = totalKb > 0 ? Math.round(kb / totalKb * 100) : 0;
        if (bar) bar.style.width = pct + '%';
        if (val) val.textContent = fmtMB(kb);
    }

    function renderRamDetails(d) {
        var t = d.total || 0;
        var pct  = t > 0 ? Math.round(d.used / t * 100) : 0;
        var aPct = t > 0 ? Math.round(d.available / t * 100) : 0;
        setText('ram-total',     fmtMB(t));
        setText('ram-used',      fmtMB(d.used) + ' (' + pct + '%)');
        setText('ram-free',      fmtMB(d.free));
        setText('ram-buffers',   fmtMB(d.buffers));
        setText('ram-cached',    fmtMB(d.cached));
        setText('ram-available', fmtMB(d.available) + ' (' + aPct + '%)');
        setText('swap-total',    fmtMB(d.swap_total));
        setText('swap-used',     fmtMB(d.swap_used));
        setText('swap-free',     fmtMB(d.swap_total - d.swap_used));
        setText('ram-slab',      fmtMB(d.slab));
        setBar('bar-used',  'bar-used-val',  d.used,      t);
        setBar('bar-buf',   'bar-buf-val',   d.buffers,   t);
        setBar('bar-cache', 'bar-cache-val', d.cached,    t);
        setBar('bar-free',  'bar-free-val',  d.free,      t);
        setBar('bar-swap',  'bar-swap-val',  d.swap_used, t);
    }

    function renderDiskDetails(d) {
        setText('disk-emmc-size', d.emmc_mb + ' MB');
        setText('disk-total',     d.total_mb + ' MB');
        setText('disk-used',      d.used_mb  + ' MB');
        setText('disk-free',      d.free_mb  + ' MB');

        /* The DATA partition is intentionally small (~512 MiB); the bulk of
         * the eMMC is the LOGS partition (sg-partinit grows it to fill the
         * disk on first boot). Surface it so the eMMC size is accounted for. */
        var logsCard = setEl('disk-logs-card');
        if (d.logs_present) {
            if (logsCard) logsCard.style.display = '';
            setText('disk-logs-total', d.logs_total_mb + ' MB');
            setText('disk-logs-used',  d.logs_used_mb  + ' MB');
            setText('disk-logs-free',  d.logs_free_mb  + ' MB');
            var bar = setEl('disk-logs-bar');
            if (bar) {
                var pct = d.logs_total_mb > 0
                    ? Math.round(d.logs_used_mb / d.logs_total_mb * 100) : 0;
                bar.style.width = pct + '%';
            }
        } else if (logsCard) {
            logsCard.style.display = 'none';
        }

        /* Allocated = data + logs (+ small system partitions are not measured
         * here). Shown against eMMC size so the difference is explained. */
        var alloc = (d.total_mb || 0) + (d.logs_present ? (d.logs_total_mb || 0) : 0);
        setText('disk-emmc-alloc', alloc + ' MB of ' + d.emmc_mb + ' MB partitioned');
    }

    /* Format uptime seconds → "1d 2h 3m 4s" */
    function fmtUptime(secs) {
        var days = Math.floor(secs / 86400);
        var hrs  = Math.floor((secs % 86400) / 3600);
        var mins = Math.floor((secs % 3600) / 60);
        var s    = Math.floor(secs % 60);
        return days + 'd ' + hrs + 'h ' + mins + 'm ' + s + 's';
    }

    /* Build a process row using DOM API. */
    function proctopRowEl(p) {
        var tr = document.createElement('tr');
        tr.appendChild(makeTd(p.pid));
        tr.appendChild(makeTd(p.name));
        tr.appendChild(makeTd(p.cpu_ticks));
        tr.appendChild(makeTd(Math.round(p.rss_kb / 1024) + ' MB'));
        tr.appendChild(makeTd(p.state));
        return tr;
    }

    /* Top-processes table state: the full RSS-sorted list lives here so the
     * search filter and pager operate on the data array (not on DOM rows that
     * the 5s poll rebuilds). The page index survives polls — only a search or
     * page-size change resets it to the first page. */
    var procData = [];
    var proctopState = { page: 0, pageSize: 10, search: '' };

    function renderProcTop(d) {
        if (d.uptime) setText('res-uptime', fmtUptime(parseFloat(d.uptime)));

        if (!d.procs) return;
        procData = d.procs.slice().sort(function (a, b) {
            return b.rss_kb - a.rss_kb;
        });
        renderProcTopRows();
    }

    function renderProcTopRows() {
        var tbody = setEl('proctop-tbody');
        if (!tbody) return;

        var filtered = procData;
        if (proctopState.search) {
            var q = proctopState.search.toLowerCase();
            filtered = filtered.filter(function (p) {
                return String(p.name || '').toLowerCase().indexOf(q) !== -1 ||
                       String(p.pid).indexOf(q) !== -1 ||
                       String(p.state || '').toLowerCase().indexOf(q) !== -1;
            });
        }

        var total = filtered.length;
        var totalPages = Math.max(1, Math.ceil(total / proctopState.pageSize));
        if (proctopState.page >= totalPages) proctopState.page = totalPages - 1;
        if (proctopState.page < 0) proctopState.page = 0;

        var start = proctopState.page * proctopState.pageSize;
        var end = Math.min(start + proctopState.pageSize, total);
        var pageRows = filtered.slice(start, end);

        tbody.innerHTML = '';
        if (pageRows.length === 0) {
            tbody.appendChild(buildEmptyRow(5));
        } else {
            var frag = document.createDocumentFragment();
            pageRows.forEach(function (p) { frag.appendChild(proctopRowEl(p)); });
            tbody.appendChild(frag);
        }

        var info = setEl('proctop-pager-info');
        var pageNum = setEl('proctop-page-num');
        var prevBtn = setEl('proctop-prev');
        var nextBtn = setEl('proctop-next');
        if (info) info.textContent = total === 0 ? 'No processes' :
            'Showing ' + (start + 1) + '–' + end + ' of ' + total;
        if (pageNum) pageNum.textContent = (proctopState.page + 1) + ' / ' + totalPages;
        if (prevBtn) prevBtn.disabled = proctopState.page === 0;
        if (nextBtn) nextBtn.disabled = proctopState.page >= totalPages - 1;
    }

    /* Bind top-processes pager + search controls */
    (function () {
        var prev = document.getElementById('proctop-prev');
        var next = document.getElementById('proctop-next');
        var size = document.getElementById('proctop-page-size');
        var search = document.getElementById('proctop-search');
        if (prev) prev.addEventListener('click', function () {
            if (proctopState.page > 0) { proctopState.page--; renderProcTopRows(); }
        });
        if (next) next.addEventListener('click', function () {
            proctopState.page++;
            renderProcTopRows();
        });
        if (size) size.addEventListener('change', function () {
            proctopState.pageSize = parseInt(this.value, 10) || 10;
            proctopState.page = 0;
            renderProcTopRows();
        });
        if (search) search.addEventListener('input', debounce(function () {
            proctopState.search = search.value;
            proctopState.page = 0;
            renderProcTopRows();
        }, 150));
    })();

    /* Per-core utilisation is a rate, so it needs the delta between two
     * polls — remember each core's busy/total jiffie counters from the
     * previous fetch.  The first poll has no baseline, so usage shows
     * "—" until the second poll arrives. */
    var lastCoreJiffies = {};

    function percoreRowEl(c, pct) {
        var tr = document.createElement('tr');
        tr.appendChild(makeTd('Core ' + c.core));
        tr.appendChild(makeTd(c.freq_mhz > 0 ? c.freq_mhz + ' MHz' : '—'));
        tr.appendChild(makeTd(pct == null ? '—' : pct.toFixed(2) + '%'));
        tr.appendChild(makeTd(c.temp_c > 0 ? c.temp_c + '°C' : '—'));
        tr.appendChild(makeTd(''));
        return tr;
    }

    function renderPerCore(d) {
        var tbody = setEl('percore-tbody');
        if (!tbody || !d.cores) return;

        if (d.cores.length === 0) {
            tbody.innerHTML = '';
            tbody.appendChild(buildEmptyRow(5));
            return;
        }

        var frag = document.createDocumentFragment();
        d.cores.forEach(function (c) {
            var pct = null;
            var prev = lastCoreJiffies[c.core];
            if (prev) {
                var dt = c.total - prev.total;
                var db = c.busy - prev.busy;
                if (dt > 0)
                    pct = Math.max(0, Math.min(100, db / dt * 100));
            }
            lastCoreJiffies[c.core] = { busy: c.busy, total: c.total };
            frag.appendChild(percoreRowEl(c, pct));
        });
        tbody.innerHTML = '';
        tbody.appendChild(frag);
    }

    function renderResourceDetails() {
        var ramP  = api('/system/resources/ram').then(function (d) { if (d) renderRamDetails(d); }).catch(function () {});
        var diskP = api('/system/resources/disk').then(function (d) { if (d) renderDiskDetails(d); }).catch(function () {});
        var procP = api('/system/resources/proctop').then(function (d) { if (d) renderProcTop(d); }).catch(function () {});
        var coreP = api('/system/resources/percore').then(function (d) { if (d) renderPerCore(d); }).catch(function () {});
        return Promise.all([ramP, diskP, procP, coreP]);
    }

    function renderResourceGauges() {
        return api('/system/resources/detail').then(function (data) {
            if (!data) {
                ['detail-res-temp','detail-res-cpu','detail-res-mem','detail-res-disk'].forEach(function (id) {
                    var el = setEl(id);
                    if (el) { el.textContent = 'No data'; el.classList.remove('loading'); }
                });
                return;
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
        'resources':    function () { renderResourceGauges(); renderResourceDetails(); }
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

    /* Routes loaded from /api/config/network_route_static — populated
     * by fetchRouteData() and rendered via renderRouteRows(). */
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

    /* Build a span with class + text content. */
    function makeSpan(cls, text) {
        var s = document.createElement('span');
        s.className = cls;
        if (text != null) s.textContent = text;
        return s;
    }

    /* Build a DOM element for one route row.  Replaces the previous
     * string-concat builder for XSS safety. */
    function routeRowEl(r) {
        var typeCls = r.type.toLowerCase();
        var statusCls = r.status === 'ACTIVE' ? 'active' :
                        r.status === 'STANDBY' ? 'standby' : 'route-disabled';
        var dotCls = r.status === 'ACTIVE' ? 'up' :
                     r.status === 'DISABLED' ? 'down' : 'disabled';

        var div = document.createElement('div');
        div.className = 'route-row';

        div.appendChild(makeSpan('route-type ' + typeCls, r.type));

        var status = makeSpan('route-status ' + statusCls, null);
        status.appendChild(makeSpan('status-dot ' + dotCls, null));
        status.appendChild(document.createTextNode(r.status));
        div.appendChild(status);

        div.appendChild(makeSpan('route-hits', fmtNum(r.hits)));
        div.appendChild(makeSpan('route-iface', r.iface));
        div.appendChild(makeSpan('route-arrow', '\u2192'));  /* → */

        if (r.gw) {
            div.appendChild(makeSpan('route-gw', r.gw));
            div.appendChild(makeSpan('route-arrow', '\u2192'));
        }
        div.appendChild(makeSpan('route-dest', r.dest));
        return div;
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

        /* Render rows via DOM API + DocumentFragment (single attach) */
        body.innerHTML = '';
        if (total === 0) {
            var empty = document.createElement('div');
            empty.className = 'rf-empty';
            empty.textContent = 'No routes configured';
            body.appendChild(empty);
        } else {
            var frag = document.createDocumentFragment();
            for (var i = 0; i < pageRoutes.length; i++) {
                frag.appendChild(routeRowEl(pageRoutes[i]));
            }
            body.appendChild(frag);
        }

        /* Pager info */
        info.textContent = total === 0 ? 'No routes' : 'Showing ' + (start + 1) + '-' + end + ' of ' + total;
        pageNum.textContent = totalPages === 0 ? '0 / 0' : (rfState.page + 1) + ' / ' + totalPages;
        prevBtn.disabled = rfState.page === 0;
        nextBtn.disabled = rfState.page >= totalPages - 1;

        /* Update header sort indicators */
        var rfLabels = { type: 'TYPE', status: 'STATUS', hits: 'HITS', iface: 'IFACE', dest: 'DESTINATION' };
        var cols = document.querySelectorAll('#route-flow-widget .rf-col[data-sort]');
        cols.forEach(function (col) {
            var key = col.dataset.sort;
            col.classList.toggle('rf-sort-active', key === rfState.sortKey);
            /* Show arrow only on active sort column */
            var label = rfLabels[key] || key.toUpperCase();
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
            toggleSort(rfState, col.dataset.sort);
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

    /* Route flow search (debounced — full re-render per keystroke) */
    var rfSearchInput = document.getElementById('rf-search');
    if (rfSearchInput) rfSearchInput.addEventListener('input', debounce(function () {
        rfState.search = rfSearchInput.value;
        rfState.page = 0;
        renderRouteRows();
    }, 150));

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

    /* Interfaces loaded from /api/config/system_interface — populated
     * by fetchIfaceData() and rendered via renderIfaceRows(). */
    var ifaceData = [];

    /* Fetch real interface data from API → populate ifaceData.
     * Two-pass: config DB for allowaccess/type, then live kernel
     * for actual operstate and assigned IP (e.g. DHCP interfaces). */
    function fetchIfaceData() {
        return api('/config/system_interface').then(function (data) {
            if (!data || !data.entries) return;
            ifaceData = data.entries
                .filter(function (e) { return e.system !== 'yes'; })
                .map(function (e) {
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
            /* Overlay live kernel state (non-fatal if unavailable) */
            return api('/system/interfaces/live').then(function (live) {
                if (!live || !live.interfaces) return;
                var liveMap = {};
                live.interfaces.forEach(function (iface) {
                    liveMap[iface.name] = iface;
                });
                ifaceData = ifaceData.map(function (iface) {
                    var li = liveMap[iface.name];
                    if (!li) return iface;
                    /* Live IP: real kernel address (DHCP or static).
                     * Config DB IP: only trust it if it's not the 0.0.0.0/0
                     * placeholder written when no static address is set. */
                    var liveIp = (li.ip && li.ip !== '-') ? li.ip : null;
                    var dbIp   = (iface.ip && iface.ip !== '0.0.0.0/0' &&
                                  iface.ip !== '-') ? iface.ip : null;
                    return {
                        name:   iface.name,
                        type:   iface.type,
                        ip:     liveIp || dbIp || '-',
                        /* Status comes from DB admin state — physical
                         * carrier (operstate) is a diagnostic detail
                         * and should not override user config intent. */
                        status: iface.status,
                        speed:  iface.speed,
                        access: iface.access
                    };
                });
            }).catch(function () { /* live overlay is best-effort */ });
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

    /* Build a <td> with text content. */
    function makeTd(text) {
        var td = document.createElement('td');
        if (text != null) td.textContent = text;
        return td;
    }

    /* Build a DOM <tr> for one interface row.  Replaces the previous
     * string-concat builder for XSS safety. */
    function ifaceRowEl(iface) {
        var tr = document.createElement('tr');

        /* Name cell with status dot */
        var nameTd = document.createElement('td');
        nameTd.appendChild(makeSpan(
            'status-dot ' + (iface.status === 'UP' ? 'up' : 'down'), null));
        nameTd.appendChild(document.createTextNode(iface.name));
        tr.appendChild(nameTd);

        tr.appendChild(makeTd(iface.type));
        tr.appendChild(makeTd(iface.ip));
        tr.appendChild(makeTd(iface.status));
        tr.appendChild(makeTd(iface.speed));

        /* Allowaccess tags */
        var tagsTd = document.createElement('td');
        for (var i = 0; i < iface.access.length; i++) {
            tagsTd.appendChild(makeSpan('tag', iface.access[i]));
        }
        tr.appendChild(tagsTd);

        return tr;
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

        /* Render via DOM API + DocumentFragment */
        tbody.innerHTML = '';

        if (sorted.length === 0) {
            var ifColCount = document.querySelectorAll('#iface-table thead th').length;
            tbody.appendChild(buildEmptyRow(ifColCount || 6));
        } else {
            var frag = document.createDocumentFragment();
            for (var g = 0; g < groupOrder.length; g++) {
                var gName = groupOrder[g];
                var items = groups[gName];

                /* Group header row */
                var hdr = document.createElement('tr');
                hdr.className = 'group-header';
                var hdrTd = document.createElement('td');
                hdrTd.colSpan = 6;
                hdrTd.appendChild(document.createTextNode(
                    gName.toUpperCase() + ' INTERFACES'));
                hdrTd.appendChild(makeSpan('group-count', items.length));
                hdr.appendChild(hdrTd);
                frag.appendChild(hdr);

                for (var j = 0; j < items.length; j++) {
                    frag.appendChild(ifaceRowEl(items[j]));
                }
            }
            tbody.appendChild(frag);
        }

        /* Update sort indicators on headers */
        var ths = document.querySelectorAll('#iface-table thead th[data-sort]');
        ths.forEach(function (th) {
            var key = th.dataset.sort;
            var labels = { name: 'NAME', type: 'TYPE', ip: 'IP / NETMASK', status: 'STATUS', speed: 'SPEED', access: 'ACCESS' };
            th.classList.toggle('th-sort-active', key === ifState.sortKey);
            th.textContent = labels[key];
            if (key === ifState.sortKey) {
                th.appendChild(makeSpan('sort-arrow',
                    ' ' + (ifState.sortAsc ? '\u25B2' : '\u25BC')));
            }
        });
    }

    /* Bind sort clicks on interface table headers */
    var ifThs = document.querySelectorAll('#iface-table thead th[data-sort]');
    ifThs.forEach(function (th) {
        th.addEventListener('click', function () {
            toggleSort(ifState, th.dataset.sort);
            renderIfaceRows();
        });
    });

    /* Interface search (debounced) */
    var ifSearchInput = document.getElementById('iface-search');
    if (ifSearchInput) ifSearchInput.addEventListener('input', debounce(function () {
        ifState.search = ifSearchInput.value;
        renderIfaceRows();
    }, 150));

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

        /* Schwartzian transform — extract sort key once per row instead
         * of re-parsing cell.textContent on every comparator call
         * (sort is O(N log N) comparisons). */
        var keyed = rows.map(function (r) {
            var cell = r.cells[colIdx];
            return { row: r, key: cell ? cell.textContent.trim() : '' };
        });
        keyed.sort(function (a, b) {
            var cmp = naturalCompare(a.key, b.key);
            return asc ? cmp : -cmp;
        });

        /* Remove group headers — they don't apply after column sort */
        tbody.querySelectorAll('tr.group-header').forEach(function (gh) { gh.remove(); });

        /* Single DOM op via DocumentFragment instead of N appendChild calls */
        var frag = document.createDocumentFragment();
        keyed.forEach(function (k) { frag.appendChild(k.row); });
        tbody.appendChild(frag);
    }

    function updateSortIndicators(allThs, activeTh, asc) {
        allThs.forEach(function (h) {
            h.classList.remove('th-sort-active');
            var arrow = h.querySelector('.sort-arrow');
            if (arrow) arrow.remove();
        });
        activeTh.classList.add('th-sort-active');
        activeTh.appendChild(makeSpan('sort-arrow', asc ? '\u25B2' : '\u25BC'));
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
                toggleSort(sortState, idx, 'col', 'asc');
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
        /* Focus the first focusable element inside the modal */
        setTimeout(function () {
            var first = form.querySelector('input:not([type="hidden"]), select, button, textarea');
            if (first) first.focus();
        }, 50);
    }

    /* Focus trap — keep Tab cycling within the active modal */
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Tab' || !activeModal) return;
        var focusable = activeModal.querySelectorAll(
            'input:not([type="hidden"]):not([disabled]), select:not([disabled]), ' +
            'button:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])');
        if (focusable.length === 0) return;
        var first = focusable[0];
        var last = focusable[focusable.length - 1];
        if (e.shiftKey) {
            if (document.activeElement === first) {
                e.preventDefault();
                last.focus();
            }
        } else {
            if (document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        }
    });

    /* Reset all editable inputs in a modal back to their defaults.
     * Used by closeModal *after* the slide-out animation completes
     * so the user doesn't see fields wipe under their cursor. */
    function resetModalForm(form) {
        form.dataset.editMode = 'false';
        form.dataset.editRowId = '';
        applyFormLock(form, false);   /* clear any read-only lock from a prior immutable open */
        form.querySelectorAll('.admin-create-only').forEach(function (el) {
            el.style.display = '';
        });
        form.querySelectorAll('.form-input').forEach(function (inp) {
            if (inp.tagName === 'SELECT') {
                inp.selectedIndex = 0;
            } else if (inp.type === 'checkbox') {
                inp.checked = false;
            } else {
                inp.value = inp.defaultValue || '';
            }
        });
        form.querySelectorAll('.form-row-full input[type="checkbox"]').forEach(function (cb) {
            cb.checked = false;
        });
        /* Re-sync conditional rows after reset (selects back to index 0) */
        syncAddressFormRows();
        syncPolicyFormRows();
    }

    function closeModal(instant) {
        if (!activeModal) return;
        var form = activeModal;
        backdrop.classList.remove('visible');

        if (instant) {
            form.classList.remove('visible', 'closing');
            activeModal = null;
            resetModalForm(form);
            return;
        }

        /* Slide-out animation runs first; reset fields only after it
         * finishes so the values stay visible while the modal fades. */
        form.classList.add('closing');
        setTimeout(function () {
            form.classList.remove('visible', 'closing');
            activeModal = null;
            resetModalForm(form);
        }, 150);
    }

    /* Address form: exactly one value field is active per type —
     * subnet for ipmask, fqdn for fqdn.  The inactive row is hidden;
     * buildPayloadFromForm skips hidden rows, so the payload never
     * carries the wrong field (mgmtd rejects mixed entries). */
    function syncAddressFormRows() {
        var form = document.getElementById('form-address');
        if (!form) return;
        var sel = form.querySelector('.form-row[data-key="type"] select');
        var sub = form.querySelector('.form-row[data-key="subnet"]');
        var fq  = form.querySelector('.form-row[data-key="fqdn"]');
        if (!sel || !sub || !fq) return;
        var isFqdn = sel.value === 'fqdn';
        sub.style.display = isFqdn ? 'none' : '';
        fq.style.display  = isFqdn ? '' : 'none';
    }
    (function () {
        var form = document.getElementById('form-address');
        var sel = form ? form.querySelector('.form-row[data-key="type"] select') : null;
        if (sel) sel.addEventListener('change', syncAddressFormRows);
    })();

    function syncPolicyFormRows() {
        var form = document.getElementById('form-policy');
        if (!form) return;
        var actionSel  = form.querySelector('.form-row[data-key="action"] select');
        if (!actionSel) return;
        var isDeny = actionSel.value === 'deny' || actionSel.value === 'drop';

        /* IPS: the ips-status toggle decides whether to show the profile dropdown. DENY/DROP hide
         * both the toggle and the profile (only valid for accept — matches backend). */
        var ipsStatRow = form.querySelector('.form-row[data-key="ips-status"]');
        var ipsRow     = form.querySelector('.form-row[data-key="ips-profile"]');
        var ipsOn = false;
        if (ipsStatRow) {
            var cb = ipsStatRow.querySelector('input[type="checkbox"]');
            ipsOn = !!(cb && cb.checked);
            ipsStatRow.style.display = isDeny ? 'none' : '';
        }
        if (ipsRow) ipsRow.style.display = (isDeny || !ipsOn) ? 'none' : '';

        /* SSL inspection is also only valid on accept — DENY/DROP hide + reset. */
        var sslRow = form.querySelector('.form-row[data-key="ssl-profile"]');
        if (sslRow) {
            sslRow.style.display = isDeny ? 'none' : '';
            if (isDeny) {
                var sslSel = sslRow.querySelector('select');
                if (sslSel) sslSel.value = 'no-inspection';
            }
        }
    }
    (function () {
        var form = document.getElementById('form-policy');
        if (!form) return;
        var sel = form.querySelector('.form-row[data-key="action"] select');
        if (sel) sel.addEventListener('change', syncPolicyFormRows);
        var ipsCb = form.querySelector('.form-row[data-key="ips-status"] input[type="checkbox"]');
        if (ipsCb) ipsCb.addEventListener('change', syncPolicyFormRows);
    })();

    /* Bind all toggle buttons */
    document.querySelectorAll('[data-toggle-form]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var id = btn.dataset.toggleForm;
            var form = document.getElementById(id);
            if (form && form.classList.contains('visible')) {
                closeModal(false);
            } else {
                /* Reset modal title to "create" mode — closeModal
                 * already cleared editMode/editRowId. */
                if (form) {
                    var entity = entityForForm(id);
                    if (entity) {
                        var titleSpan = form.querySelector('.modal-title-text');
                        if (titleSpan)
                            titleSpan.textContent = ENTITIES[entity].createTitle;
                    }
                }
                /* Refresh all dynamic selects when opening a create form */
                populateIfaceSelects();
                populateProfileSelect();
                populateAddrSelects();
                populateSvcSelects();
                populateIpsProfileSelects();
                openModal(id);
                /* closeModal reset the type select — re-sync the
                 * type-dependent rows (address form: subnet vs fqdn) */
                syncAddressFormRows();
            }
        });
    });

    /* Click backdrop to close */
    if (backdrop) {
        backdrop.addEventListener('click', function () {
            closeModal(false);
        });
    }

    /* Escape key to close modal or dismiss bulk selection */
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            if (activeModal) { closeModal(false); return; }
            if (selection.count > 0) selection.clear();
        }
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
            noCreate: true,   /* hardware-backed, mgmtd auto-detects */
            allBuiltin: true, /* all entries are builtin, no delete */
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
            orderable: true,
            hasStatus: true,
            statusLabels: { on: 'Enabled', off: 'Disabled', dotOn: 'up', dotOff: 'disabled' },
            fields: [
                { label: '#',                    key: 'id',           col: 0, bulkEditable: false, editDisabled: true },
                { label: 'Sequence',             key: 'sequence',     col: 1, bulkEditable: false },
                { label: 'Type',                 key: 'type',         col: 2, bulkEditable: false },
                { label: 'Protocol',             key: 'protocol',     col: -1, bulkEditable: false },
                { label: 'Original Source',      key: 'srcaddr',      col: 3, bulkEditable: false },
                { label: 'Original Destination', key: 'dstaddr',      col: 4, bulkEditable: false },
                { label: 'Destination Port',     key: 'dstport',      col: -1, bulkEditable: false },
                { label: 'Translated Address',   key: 'mapped-ip',    col: -1, bulkEditable: false },
                { label: 'Translated Port',      key: 'mapped-port',  col: -1, bulkEditable: false },
                { label: 'Source Interface',      key: 'srcintf',      col: 5, bulkEditable: false },
                { label: 'Destination Interface', key: 'dstintf',      col: -1, bulkEditable: false },
                { label: 'Status',               key: 'status',       col: 6, bulkEditable: true }
            ]
        },
        policies: {
            formId: 'form-policy',
            configType: 'firewall_policy',
            createTitle: 'NEW FIREWALL POLICY',
            editTitle: 'EDIT FIREWALL POLICY',
            orderable: true,
            hasStatus: true,
            statusLabels: { on: 'Enabled', off: 'Disabled', dotOn: 'up', dotOff: 'disabled' },
            fields: [
                { label: '#',                   key: 'id',       col: 0, bulkEditable: false, editDisabled: true },
                { label: 'Sequence',            key: 'sequence', col: 1, bulkEditable: false },
                { label: 'Name',                key: 'name',     col: 2, bulkEditable: false },
                { label: 'Incoming Interface',  key: 'srcintf',  col: 3, bulkEditable: false },
                { label: 'Outgoing Interface',  key: 'dstintf',  col: 4, bulkEditable: false },
                { label: 'Source',              key: 'srcaddr',  col: 5, bulkEditable: false },
                { label: 'Destination',         key: 'dstaddr',  col: 6, bulkEditable: false },
                { label: 'Service',             key: 'service',  col: 7, bulkEditable: false },
                { label: 'Action',              key: 'action',   col: 8, bulkEditable: true },
                { label: 'Status',              key: 'status',   col: 9, bulkEditable: true },
                { label: 'Schedule',            key: 'schedule', col: -1, bulkEditable: false },
                { label: 'IPS',                 key: 'ips-status',  col: -1, bulkEditable: false },
                { label: 'IPS Profile',         key: 'ips-profile', col: -1, bulkEditable: false },
                { label: 'SSL Inspection',      key: 'ssl-profile', col: -1, bulkEditable: false },
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
                /* The ADDRESS column shows whichever value field the
                 * type uses: subnet (ipmask) or fqdn. */
                { label: 'Subnet / IP', key: 'subnet',  altKey: 'fqdn', col: 2, bulkEditable: false },
                { label: 'FQDN',        key: 'fqdn',    col: -1, bulkEditable: false },
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
        ipsProfiles: {
            formId: 'form-ips-profile',
            configType: 'security_ips-profile',
            createTitle: 'NEW IPS PROFILE',
            editTitle: 'EDIT IPS PROFILE',
            hasStatus: true,
            statusLabels: { on: 'Enabled', off: 'Disabled', dotOn: 'enable', dotOff: 'disable' },
            fields: [
                { label: 'Name',       key: 'name',       col: 0, bulkEditable: false },
                { label: 'Categories', key: 'categories', col: 1, bulkEditable: false },
                { label: 'Status',     key: 'status',     col: 2, bulkEditable: true },
                { label: 'Comment',    key: 'comment',    col: 3, bulkEditable: false }
            ]
        },
        sslProfiles: {
            formId: 'form-ssl-profile',
            configType: 'security_ssl-inspection-profile',
            createTitle: 'NEW SSL INSPECTION PROFILE',
            editTitle: 'EDIT SSL INSPECTION PROFILE',
            hasStatus: true,
            statusLabels: { on: 'Enabled', off: 'Disabled', dotOn: 'enable', dotOff: 'disable' },
            fields: [
                { label: 'Name',            key: 'name',                  col: 0, bulkEditable: false },
                { label: 'Inspection Mode', key: 'inspection-mode',       col: 1, bulkEditable: false },
                { label: 'Status',          key: 'status',                col: 2, bulkEditable: true },
                { label: 'No-SNI',          key: 'no-sni',                col: -1, bulkEditable: false },
                { label: 'Untrusted Cert',  key: 'untrusted-server-cert', col: -1, bulkEditable: false },
                { label: 'Unsupported',     key: 'unsupported',           col: -1, bulkEditable: false },
                { label: 'Exempt',          key: 'exempt',                col: -1, bulkEditable: false },
                { label: 'Comment',         key: 'comment',               col: 3, bulkEditable: false }
            ]
        },
        ipsRulesets: {
            formId: 'form-ips-ruleset',
            configType: 'security_ips-ruleset',
            createTitle: 'ADD RULESET URL',
            editTitle: 'EDIT RULESET',
            hasStatus: true,
            statusLabels: { on: 'Enabled', off: 'Disabled', dotOn: 'enable', dotOff: 'disable' },
            fields: [
                { label: 'Name',    key: 'name',    col: 0, bulkEditable: false },
                { label: 'URL',     key: 'url',     col: 1, bulkEditable: false },
                { label: 'Status',  key: 'enabled', col: 2, bulkEditable: true }
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
            noCreate: true,   /* only builtin profiles (read-write, read-only) */
            allBuiltin: true, /* all entries are builtin, no delete */
            hasStatus: false,
            fields: [
                { label: 'Profile Name', key: 'id',          col: 0, bulkEditable: false },
                { label: 'Permissions',  key: 'permissions', col: 1, bulkEditable: false },
                { label: 'Description',  key: 'description', col: 2, bulkEditable: false }
            ]
        }
    };

    /* Reverse map formId → entity name, built once at startup.
     * Replaces a linear ENTITIES scan that ran on every modal open
     * and again inside the toggle-form click handler. */
    var FORM_ID_TO_ENTITY = {};
    Object.keys(ENTITIES).forEach(function (k) {
        if (ENTITIES[k].formId) FORM_ID_TO_ENTITY[ENTITIES[k].formId] = k;
    });

    function entityForForm(formId) {
        return FORM_ID_TO_ENTITY[formId] || null;
    }

    /* Hide Create buttons for entities that don't support creation
     * (hardware-backed interfaces, builtin admin profiles). */
    for (var ek in ENTITIES) {
        if (ENTITIES[ek].noCreate) {
            var fid = ENTITIES[ek].formId;
            document.querySelectorAll('.btn-create[data-toggle-form="' + fid + '"]').forEach(function (btn) {
                btn.style.display = 'none';
            });
        }
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
            if (!rowId) return; /* ignore placeholder rows */
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
            if (cb && !cb.disabled) { total++; if (cb.checked) checked++; }
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
                if (!cb || cb.disabled) return; /* skip builtin rows */
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

        /* Delete — hidden for all-builtin entities (no deletable rows) */
        if (!config.allBuiltin) {
            addBulkBtn('Delete', 'delete', 'btn-danger');
        }

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

    /* Styled confirm dialog — replaces native confirm() for visual
     * consistency and security mindset.  Returns a Promise<boolean>. */
    function confirmAction(message) {
        return new Promise(function (resolve) {
            var overlay = document.createElement('div');
            overlay.className = 'confirm-overlay';

            var box = document.createElement('div');
            box.className = 'confirm-box';
            box.setAttribute('role', 'alertdialog');
            box.setAttribute('aria-modal', 'true');
            box.setAttribute('aria-label', 'Confirmation');

            var msg = document.createElement('div');
            msg.className = 'confirm-message';
            msg.textContent = message;
            box.appendChild(msg);

            var actions = document.createElement('div');
            actions.className = 'confirm-actions';

            var confirmBtn = document.createElement('button');
            confirmBtn.className = 'btn btn-primary';
            confirmBtn.textContent = 'Confirm';
            confirmBtn.style.background = 'var(--color-danger)';
            confirmBtn.style.borderColor = 'var(--color-danger-dark)';

            var cancelBtn = document.createElement('button');
            cancelBtn.className = 'btn';
            cancelBtn.textContent = 'Cancel';

            actions.appendChild(confirmBtn);
            actions.appendChild(cancelBtn);
            box.appendChild(actions);
            overlay.appendChild(box);
            document.body.appendChild(overlay);

            var escHandler = function (e) {
                if (e.key === 'Escape') close(false);
            };
            function close(result) {
                document.removeEventListener('keydown', escHandler);
                overlay.remove();
                resolve(result);
            }
            confirmBtn.addEventListener('click', function () { close(true); });
            cancelBtn.addEventListener('click', function () { close(false); });
            overlay.addEventListener('click', function (e) {
                if (e.target === overlay) close(false);
            });
            document.addEventListener('keydown', escHandler);
            setTimeout(function () { cancelBtn.focus(); }, 0);
        });
    }

    /* Inline input prompt — replaces native prompt() for visual
     * consistency with the rest of the UI.  Returns a Promise that
     * resolves with the entered string or null on cancel. */
    function promptInput(title, placeholder) {
        return new Promise(function (resolve) {
            var overlay = document.createElement('div');
            overlay.className = 'inline-prompt-overlay';

            var box = document.createElement('div');
            box.className = 'inline-prompt';

            var t = document.createElement('div');
            t.className = 'inline-prompt-title';
            t.textContent = title;
            box.appendChild(t);

            var input = document.createElement('input');
            input.type = 'text';
            input.className = 'inline-prompt-input form-input';
            if (placeholder) input.placeholder = placeholder;
            box.appendChild(input);

            var actions = document.createElement('div');
            actions.className = 'inline-prompt-actions';

            var ok = document.createElement('button');
            ok.className = 'btn btn-primary';
            ok.textContent = 'OK';

            var cancel = document.createElement('button');
            cancel.className = 'btn';
            cancel.textContent = 'Cancel';

            actions.appendChild(ok);
            actions.appendChild(cancel);
            box.appendChild(actions);
            overlay.appendChild(box);
            document.body.appendChild(overlay);

            var escHandler = function (e) {
                if (e.key === 'Escape') close(null);
            };
            function close(value) {
                document.removeEventListener('keydown', escHandler);
                overlay.remove();
                resolve(value);
            }
            ok.addEventListener('click', function () { close(input.value); });
            cancel.addEventListener('click', function () { close(null); });
            overlay.addEventListener('click', function (e) {
                if (e.target === overlay) close(null);
            });
            input.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') close(input.value);
            });
            document.addEventListener('keydown', escHandler);
            setTimeout(function () { input.focus(); }, 0);
        });
    }

    function handleBulkAction(action) {
        if (action === 'delete') {
            confirmAction('Delete ' + selection.count + ' selected entries?').then(function (confirmed) {
                if (!confirmed) return;
                var deletePromises = [];
                var failCount = 0;
                forEachSelected(function (row) {
                    var table = row.closest('table[data-entity]');
                    var entity = table ? table.dataset.entity : null;
                    var rowId = row.dataset.rowId || '';
                    if (row.dataset.builtin === 'yes') return;
                    row.style.transition = 'opacity 0.25s, background 0.25s';
                    row.style.background = 'rgba(198, 40, 40, 0.1)';
                    row.style.opacity = '0';
                    if (entity) {
                        deletePromises.push(
                            api('/config/' + cfgType(entity) + '/' + rowId, { method: 'DELETE' })
                                .then(function () { setTimeout(function () { row.remove(); }, 250); })
                                .catch(function () {
                                    row.style.background = '';
                                    row.style.opacity = '1';
                                    failCount++;
                                })
                        );
                    } else {
                        setTimeout(function () { row.remove(); }, 250);
                    }
                });
                Promise.all(deletePromises).then(function () {
                    selection.clear();
                    if (failCount > 0) {
                        showToast(failCount + ' delete(s) failed', 'error');
                    } else {
                        showToast('Entries deleted', 'success');
                    }
                });
            });
            return;
        }
        if (action === 'enable' || action === 'disable') {
            var en = action === 'enable';
            forEachSelected(function (row) {
                setRowStatus(row, en, selection.entity);
            });
            return;
        }
        if (action.indexOf('bulk-') === 0) {
            var key = action.replace('bulk-', '');
            var config = ENTITIES[selection.entity];
            var colOffset = config.orderable ? 2 : 1;
            var field = null;
            config.fields.forEach(function (f) { if (f.key === key) field = f; });
            if (!field) return;
            promptInput('New value for ' + field.label, '').then(function (val) {
                if (val === null) return;
                var updatePromises = [];
                forEachSelected(function (row) {
                    var cell = row.cells[field.col + colOffset];
                    if (cell) cell.textContent = val;
                    var rowId = row.dataset.rowId;
                    if (rowId) {
                        var body = {};
                        body[field.key] = val;
                        updatePromises.push(
                            api('/config/' + cfgType(selection.entity) + '/' + rowId, {
                                method: 'PUT', body: body
                            }).catch(function () { return { failed: true }; })
                        );
                    }
                });
                Promise.all(updatePromises).then(function (results) {
                    var failed = results.filter(function (r) { return r && r.failed; }).length;
                    if (failed > 0) {
                        showToast(failed + ' update(s) failed', 'error');
                        refreshPage(activePage);
                    } else {
                        showToast('Updated ' + results.length + ' entries', 'success');
                    }
                });
            });
        }
    }

    function forEachSelected(fn) {
        var table = document.querySelector('table[data-entity="' + selection.entity + '"]');
        if (!table) return;
        for (var id in selection.ids) {
            /* Direct lookup — O(1) per id instead of scanning all rows.
             * CSS.escape guards against selector injection. */
            var sel = 'tr[data-row-id="' + CSS.escape(id) + '"]';
            var row = table.querySelector(sel);
            if (row) fn(row);
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
        if (!row.dataset.rowId) return; /* ignore placeholder rows (No results) */
        var table = row.closest('table[data-entity]');
        if (!table) return;

        var entity = table.dataset.entity;
        var config = ENTITIES[entity];
        if (!config) return;

        /* ARP: only static rows */
        if (config.editableFilter && !config.editableFilter(row)) return;

        openEditModal(entity, row);
    });

    /* ── openEditModal helpers ──────────────────────────────────── */

    function setModalEditMode(form, config, rowId) {
        var titleSpan = form.querySelector('.modal-title-text');
        if (titleSpan) {
            titleSpan.textContent = config.editTitle + (rowId ? ' — ' + rowId : '');
        }
        form.dataset.editMode = 'true';
        form.dataset.editRowId = rowId;
    }

    /* Hide rows tagged .admin-create-only on edit (e.g. password
     * fields that should only appear during create). */
    function hideCreateOnlyFields(form) {
        form.querySelectorAll('.admin-create-only').forEach(function (el) {
            el.style.display = 'none';
        });
    }

    /* Refresh all dynamic <select> dropdowns in parallel.  All four
     * are independent fetches so Promise.all batches them. */
    function refreshAllDynamicSelects() {
        return Promise.all([
            populateIfaceSelects(),
            populateProfileSelect(),
            populateAddrSelects(),
            populateSvcSelects(),
            populateIpsProfileSelects()
        ]);
    }

    /* Lock a form to read-only — used for immutable entries (e.g. the
     * built-in default-deny policy). Greys + disables every field and the
     * Save button so the user can view but not change it; the title gains a
     * "(read-only)" suffix. Called with locked=false to clear the state. */
    function applyFormLock(form, locked) {
        form.classList.toggle('form-locked', locked);
        var lockBody = form.querySelector('.modal-body');
        if (lockBody) {
            lockBody.querySelectorAll('input, select, textarea').forEach(function (el) {
                el.disabled = locked;
            });
        }
        var save = form.querySelector('.modal-footer .btn-primary');
        if (save) save.disabled = locked;
        if (locked) {
            var t = form.querySelector('.modal-title-text');
            if (t && t.textContent.indexOf('(read-only)') === -1)
                t.textContent += '  (read-only)';
        }
    }

    function openEditModal(entity, row) {
        var config = ENTITIES[entity];
        var form = document.getElementById(config.formId);
        if (!form) return;

        var rowId = row.dataset.rowId || '';
        setModalEditMode(form, config, rowId);
        hideCreateOnlyFields(form);
        applyFormLock(form, row.dataset.immutable === 'yes');
        openModal(config.formId);

        /* Selects must be filled BEFORE populateForm runs, otherwise
         * selectOption() can't match values to options. */
        refreshAllDynamicSelects().then(function () {
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
        loader.textContent = 'LOADING';
        body.appendChild(loader);

        /* schema-key → input map (matching consolidated in helper) */
        var keyMap = buildKeyInputMap(body, config);

        var rowId = row.dataset.rowId || '';

        /* Try API first, fall back to reading from DOM */
        api('/config/' + cfgType(entity) + '/' + rowId).then(function (data) {
            if (data) {
                populateForm(config, keyMap, data, body);
            } else {
                /* Demo fallback: read from table row cells */
                var colOffset = config.orderable ? 2 : 1;
                var rowData = {};
                config.fields.forEach(function (field) {
                    var cell = row.cells[field.col + colOffset]; /* +1 checkbox, +1 drag handle if orderable */
                    if (cell) rowData[field.key] = cellText(cell);
                });
                populateForm(config, keyMap, rowData, body);
            }

            loader.remove();
            if (grid) grid.style.display = '';
        });
    }

    /* Populate form inputs from a data object via the key→input map. */
    function populateForm(config, keyMap, data, formBody) {
        config.fields.forEach(function (field) {
            if (field.editDisabled) return;
            var inp = keyMap[field.key];
            if (!inp) return;
            var val = data[field.key];
            if (val === undefined || val === null) return;
            if (inp.tagName === 'SELECT') {
                selectOption(inp, String(val));
            } else if (inp.type === 'checkbox') {
                inp.checked = inp.dataset.on
                    ? (String(val) === inp.dataset.on)
                    : (val === true || val === 'true' || val === 'enable' || val === '1');
            } else {
                inp.value = val;
            }
        });

        /* Populate checkbox groups (e.g. Admin Access = "ping http https",
         * Permissions = "monitor,admin").  Each .form-row-full carries
         * data-key matching the schema field; each <input type="checkbox">
         * carries its own value attribute. */
        if (formBody) {
            formBody.querySelectorAll('.form-row-full[data-key]').forEach(function (fr) {
                var val = data[fr.dataset.key];
                if (!val) return;
                /* Space-separated (allowaccess) or comma-separated (permissions) */
                var tokens = String(val).toLowerCase().split(/[\s,]+/);
                fr.querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
                    cb.checked = tokens.indexOf(cb.value) !== -1;
                });
            });
        }

        /* Old (legacy) policy has no ips-status but has a real ips-profile →
         * infer the toggle is ON so edit+save doesn't accidentally turn IPS off. */
        if (formBody && data['ips-status'] === undefined) {
            var ipsCb = formBody.querySelector(
                '.form-row[data-key="ips-status"] input[type="checkbox"]');
            if (ipsCb) {
                var ipp = data['ips-profile'];
                ipsCb.checked = !!(ipp && ipp !== 'none' && ipp !== '');
            }
        }

        /* Editing sets the type select programmatically (no change
         * event) — re-sync type-dependent rows */
        syncAddressFormRows();
        syncPolicyFormRows();
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

    /* ================================================================
     *  RIGHT-CLICK CONTEXT MENU
     * ================================================================ */

    var ctxMenu = document.getElementById('context-menu');
    var ctxRow = null;
    var ctxEntity = null;

    document.addEventListener('contextmenu', function (e) {
        var row = e.target.closest('tr');
        if (!row || row.classList.contains('group-header')) { hideCtx(); return; }
        if (!row.dataset.rowId) { hideCtx(); return; } /* no-data placeholder */
        var table = row.closest('table[data-entity]');
        if (!table) { hideCtx(); return; }

        e.preventDefault();
        var entity = table.dataset.entity;
        var config = ENTITIES[entity];
        if (!config) return;

        ctxRow = row;
        ctxEntity = entity;

        var isEditable = !config.editableFilter || config.editableFilter(row);
        var isBuiltin = row.dataset.builtin === 'yes';
        var isLocked = isBuiltin || row.dataset.immutable === 'yes';
        var items = ctxMenu.querySelectorAll('.context-menu-item');
        items.forEach(function (it) {
            var act = it.dataset.action;
            if (act === 'delete') {
                /* Immutable/builtin entries can't be deleted (backend rejects). */
                it.classList.toggle('ctx-hidden', !isEditable || isLocked);
            } else if (act === 'edit') {
                /* Edit stays available — openEditModal opens it read-only. */
                it.classList.toggle('ctx-hidden', !isEditable);
            } else if (act === 'enable' || act === 'disable') {
                it.classList.toggle('ctx-hidden', !config.hasStatus || !isEditable || isLocked);
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

    /* Scroll handler is rAF-throttled to avoid layout writes per
     * scroll event (capture phase fires for any nested scroller). */
    var ctxScrollPending = false;
    function ctxScrollHandler() {
        if (ctxScrollPending) return;
        ctxScrollPending = true;
        requestAnimationFrame(function () {
            ctxScrollPending = false;
            hideCtx();
        });
    }

    document.addEventListener('click', hideCtx);
    document.addEventListener('scroll', ctxScrollHandler, true);

    if (ctxMenu) ctxMenu.addEventListener('click', function (e) {
        var item = e.target.closest('.context-menu-item');
        if (!item || !ctxRow) return;
        var act = item.dataset.action;
        e.stopPropagation(); /* prevent the document click from firing */

        if (act === 'edit') openEditModal(ctxEntity, ctxRow);
        else if (act === 'delete') deleteRow(ctxRow);
        else if (act === 'enable') setRowStatus(ctxRow, true, ctxEntity);
        else if (act === 'disable') setRowStatus(ctxRow, false, ctxEntity);

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
    function deleteRow(row) {
        var table = row.closest('table[data-entity]');
        var entity = table ? table.dataset.entity : null;
        var rowId = row.dataset.rowId || '';

        if (row.dataset.builtin === 'yes') {
            showToast('Cannot delete built-in entry "' + rowId + '"', 'error');
            return;
        }

        confirmAction('Delete "' + rowId + '"?').then(function (confirmed) {
            if (!confirmed) return;

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
        });
    }

    /*
     * Enable/disable entity row status.
     *
     * API contract: PUT /api/config/{entity}/{id}  { status: "enabled"|"disabled" }
     * On success: update status dot + label text.
     * On failure: alert user, keep original status.
     */
    function setRowStatus(row, enable, entity) {
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

    /* Selection/context cleanup on nav is wired into the original
     * nav handlers via navClearTransient() — no duplicate listeners. */

    /* ================================================================
     *  DRAG-TO-REORDER — policies & NAT sequence reordering
     * ================================================================ */

    var dragRow = null, dragEntity = null;

    function clearDropIndicator(tbody) {
        tbody.querySelectorAll('.drop-above, .drop-below').forEach(function (el) {
            el.classList.remove('drop-above', 'drop-below');
        });
    }

    document.querySelectorAll('table[data-entity]').forEach(function (table) {
        var entity = table.dataset.entity;
        var config = ENTITIES[entity];
        if (!config || !config.orderable) return;
        var tbody = table.querySelector('tbody');
        if (!tbody) return;

        tbody.addEventListener('dragstart', function (e) {
            var row = e.target.closest('tr');
            if (!row || !row.draggable) return;
            dragRow = row;
            dragEntity = entity;
            row.classList.add('drag-active');
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', '');
        });

        tbody.addEventListener('dragover', function (e) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            var target = e.target.closest('tr');
            if (!target || target === dragRow || !target.dataset.rowId) return;
            clearDropIndicator(tbody);
            var rect = target.getBoundingClientRect();
            var mid = rect.top + rect.height / 2;
            target.classList.add(e.clientY < mid ? 'drop-above' : 'drop-below');
        });

        tbody.addEventListener('dragleave', function (e) {
            var target = e.target.closest('tr');
            if (target) target.classList.remove('drop-above', 'drop-below');
        });

        tbody.addEventListener('drop', function (e) {
            e.preventDefault();
            clearDropIndicator(tbody);
            var target = e.target.closest('tr');
            if (!target || target === dragRow || !target.dataset.rowId) return;
            if (!dragRow) return;

            var targetSeq = parseInt(target.dataset.seq, 10);
            if (isNaN(targetSeq)) return;

            /* Table sorted descending: higher seq = top.
             * Drop ABOVE target → higher priority → targetSeq + 1
             * Drop BELOW target → take target's seq, rotate pushes target down */
            var rect = target.getBoundingClientRect();
            var mid = rect.top + rect.height / 2;
            var newSeq = (e.clientY < mid) ? targetSeq + 1 : targetSeq;
            if (newSeq < 1) newSeq = 1;
            if (newSeq > 9999) newSeq = 9999;

            /* The immutable default-deny catch-all must stay at the bottom:
             * dropping a policy below it would collide at sequence 1 and the
             * catch-all would then shadow every rule (over-block). */
            if (target.dataset.immutable === 'yes' && e.clientY >= mid) {
                showToast('Cannot move a policy below the default-deny policy.', 'error');
                return;
            }

            var rowId = dragRow.dataset.rowId;
            api('/config/' + cfgType(dragEntity) + '/' + rowId + '/move', {
                method: 'PATCH',
                body: { sequence: newSeq }
            }).then(function () {
                showToast('Reordered', 'success');
                refreshPage(activePage);
            }).catch(function (err) {
                showToast(err.message || 'Reorder failed', 'error');
            });
        });

        tbody.addEventListener('dragend', function () {
            if (dragRow) dragRow.classList.remove('drag-active');
            clearDropIndicator(tbody);
            dragRow = null;
            dragEntity = null;
        });
    });

    /* ================================================================
     *  USER DROPDOWN (topbar admin menu)
     * ================================================================ */

    var userBtn = document.getElementById('topbar-user');
    var userDrop = document.getElementById('user-dropdown');

    if (userBtn && userDrop) {
        function toggleUserDropdown(e) {
            e.stopPropagation();
            var isOpen = userDrop.classList.toggle('open');
            userBtn.setAttribute('aria-expanded', String(isOpen));
            if (isOpen) {
                var firstItem = userDrop.querySelector('.user-dropdown-item');
                if (firstItem) firstItem.focus();
            }
        }

        userBtn.addEventListener('click', toggleUserDropdown);

        /* Keyboard: Enter/Space to toggle, Escape to close */
        userBtn.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                toggleUserDropdown(e);
            } else if (e.key === 'Escape') {
                userDrop.classList.remove('open');
                userBtn.setAttribute('aria-expanded', 'false');
            }
        });

        /* Arrow key navigation within dropdown */
        userDrop.addEventListener('keydown', function (e) {
            var items = Array.prototype.slice.call(
                userDrop.querySelectorAll('.user-dropdown-item'));
            var idx = items.indexOf(document.activeElement);
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                var next = (idx + 1) % items.length;
                items[next].focus();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                var prev = (idx - 1 + items.length) % items.length;
                items[prev].focus();
            } else if (e.key === 'Escape') {
                userDrop.classList.remove('open');
                userBtn.setAttribute('aria-expanded', 'false');
                userBtn.focus();
            } else if (e.key === 'Enter' || e.key === ' ') {
                /* Let the click handler on the item fire */
            }
        });

        document.addEventListener('click', function () {
            userDrop.classList.remove('open');
            userBtn.setAttribute('aria-expanded', 'false');
        });

        userDrop.addEventListener('click', function (e) {
            var item = e.target.closest('.user-dropdown-item');
            if (!item) return;
            var action = item.dataset.action;
            userDrop.classList.remove('open');

            if (action === 'logout') {
                /* Stop keepalive before redirect — avoids one last
                 * fetch firing against the now-invalid session. */
                if (window.__sg_stopKeepalive) window.__sg_stopKeepalive();
                stopPolling();
                /* POST logout to clear server session + cookie */
                api('/auth/logout', { method: 'POST' }).catch(function () {});
                window.location.href = 'login.html';
            } else if (action === 'profile') {
                /* Navigate to admin page then open edit modal for the
                 * current user — wait for the page's load promise so
                 * the table row exists, then look it up directly. */
                var cat = document.querySelector('[data-page="sys-admin"]');
                var parentCat = cat ? cat.closest('.nav-category') : null;
                if (parentCat) parentCat.classList.add('open');
                var nameEl2 = document.querySelector('.user-name');
                var me = nameEl2 ? nameEl2.textContent : 'admin';
                setActivePage('sys-admin', parentCat, cat).then(function () {
                    var table = document.querySelector('table[data-entity="admins"]');
                    if (!table) return;
                    var row = table.querySelector(
                        'tr[data-row-id="' + CSS.escape(me) + '"]');
                    if (row) openEditModal('admins', row);
                });
            } else if (action === 'password') {
                /* Open inline password change dialog */
                showPasswordChangeDialog();
            }
        });
    }

    /* ================================================================
     *  CHANGE PASSWORD DIALOG (topbar dropdown)
     * ================================================================ */

    /* Build a single .form-row with label + input. */
    function makeFormRow(labelText, input) {
        var row = document.createElement('div');
        row.className = 'form-row';
        var lbl = document.createElement('label');
        lbl.className = 'form-label';
        lbl.textContent = labelText;
        row.appendChild(lbl);
        row.appendChild(input);
        return row;
    }

    function makePasswordInput(idAttr, placeholder) {
        var inp = document.createElement('input');
        inp.className = 'form-input';
        inp.type = 'password';
        inp.id = idAttr;
        inp.placeholder = placeholder;
        return inp;
    }

    function showPasswordChangeDialog() {
        var id = 'form-change-pw';
        var existing = document.getElementById(id);
        if (existing) existing.remove();

        /* Header */
        var titleSpan = makeSpan('modal-title-text', 'CHANGE PASSWORD');
        var closeX = makeSpan('modal-close', '\u2715');  /* ✕ */
        closeX.dataset.toggleForm = id;
        var section = document.createElement('div');
        section.className = 'form-section';
        section.appendChild(titleSpan);
        section.appendChild(closeX);

        /* Body */
        var newPwInp = makePasswordInput('cp-new', 'New password');
        var confirmPwInp = makePasswordInput('cp-confirm', 'Confirm new password');
        var grid = document.createElement('div');
        grid.className = 'form-grid';
        grid.appendChild(makeFormRow('New Password', newPwInp));
        grid.appendChild(makeFormRow('Confirm Password', confirmPwInp));
        var body = document.createElement('div');
        body.className = 'modal-body';
        body.appendChild(grid);

        /* Footer */
        var saveBtn = document.createElement('button');
        saveBtn.className = 'btn btn-primary';
        saveBtn.id = 'cp-save';
        saveBtn.textContent = 'Change Password';
        var cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn';
        cancelBtn.dataset.toggleForm = id;
        cancelBtn.textContent = 'Cancel';
        var footer = document.createElement('div');
        footer.className = 'modal-footer';
        footer.appendChild(saveBtn);
        footer.appendChild(cancelBtn);

        /* Form root */
        var form = document.createElement('div');
        form.className = 'add-form form-card';
        form.id = id;
        form.appendChild(section);
        form.appendChild(body);
        form.appendChild(footer);
        document.getElementById('content').appendChild(form);

        function closeAndRemove() { closeModal(false); form.remove(); }
        closeX.addEventListener('click', closeAndRemove);
        cancelBtn.addEventListener('click', closeAndRemove);

        saveBtn.addEventListener('click', function () {
            var validationErr = SgCommon.validatePasswordChange(
                newPwInp.value, confirmPwInp.value);
            if (validationErr) { showToast(validationErr, 'error'); return; }

            api('/auth/change-password', {
                method: 'POST',
                body: { password: newPwInp.value }
            }).then(function () {
                showToast('Password changed', 'success');
                closeAndRemove();
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
    /* Per-row lowercase text cache.  Search inputs fire on every
     * keystroke and previously called row.textContent on every row,
     * which allocates the row's full text each call.  WeakMap keys
     * the cache by row element so it auto-clears when the tbody is
     * re-rendered (innerHTML reassignment drops the old <tr>s and
     * GC reaps the WeakMap entries). */
    var rowTextCache = new WeakMap();
    function rowText(row) {
        var t = rowTextCache.get(row);
        if (t === undefined) {
            t = row.textContent.toLowerCase();
            rowTextCache.set(row, t);
        }
        return t;
    }

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

            var match = rowText(row).indexOf(q) !== -1;
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
    /* Build a single status cell (status dot + label) using the DOM
     * API.  Used by renderEntityRows for the per-entity status column. */
    function buildStatusCell(val, statusLabels) {
        var td = document.createElement('td');
        var isOn = isStatusEnabled(val, statusLabels.on);
        var dot = document.createElement('span');
        dot.className = 'status-dot ' + (isOn ? statusLabels.dotOn : statusLabels.dotOff);
        td.appendChild(dot);
        td.appendChild(document.createTextNode(isOn ? statusLabels.on : statusLabels.off));
        return td;
    }

    /* Build the empty-state row shown when an entity has no entries.
     * Uses a CSS class instead of inline style. */
    function formatDuration(secs) {
        secs = Math.floor(secs);
        var h = Math.floor(secs / 3600);
        var m = Math.floor((secs % 3600) / 60);
        var s = secs % 60;
        if (h > 0)
            return h + 'h ' + m + 'm';
        if (m > 0)
            return m + 'm ' + s + 's';
        return s + 's';
    }

    function buildEmptyRow(colCount) {
        var tr = document.createElement('tr');
        var td = document.createElement('td');
        td.colSpan = colCount;
        td.className = 'table-empty';
        td.textContent = 'No results found';
        tr.appendChild(td);
        return tr;
    }

    /* Build the loading-state row shown while a fetch is in flight.
     * Trailing dots are appended by the .table-empty.loading ::after
     * pseudo-element via CSS — keeps the JS plain. */
    function buildLoadingRow(colCount) {
        var tr = document.createElement('tr');
        var td = document.createElement('td');
        td.colSpan = colCount;
        td.className = 'table-empty loading';
        td.textContent = 'Loading';
        tr.appendChild(td);
        return tr;
    }

    function renderEntityRows(table, entity, rows) {
        var config = ENTITIES[entity];
        var tbody = table.querySelector('tbody');
        if (!tbody || !config) return;

        /* Sort by sequence for ordered types (policies, NAT).
         * Higher sequence = higher priority = checked first in
         * iptables, so show highest sequence at top (descending).
         * Entries without sequence sort last. */
        if (config.configType === 'firewall_policy' ||
            config.configType === 'network_nat') {
            rows = rows.slice().sort(function (a, b) {
                var sa = parseInt(a.sequence, 10);
                var sb = parseInt(b.sequence, 10);
                if (isNaN(sa)) sa = -1;
                if (isNaN(sb)) sb = -1;
                return sb - sa;
            });
        }

        /* Empty the cached row text before re-rendering — old rows
         * are about to be GC'd and stale entries would consume
         * memory until next page nav. */
        rowTextCache = new WeakMap();

        if (rows.length === 0) {
            var colCount = table.querySelectorAll('thead th').length;
            tbody.innerHTML = '';
            tbody.appendChild(buildEmptyRow(colCount));
            return;
        }

        /* Build rows via DOM API and append once via DocumentFragment.
         * No more innerHTML string concatenation — every value reaches
         * the DOM via textContent (XSS-safe regardless of esc() bugs). */
        var frag = document.createDocumentFragment();
        rows.forEach(function (row, idx) {
            var isBuiltin = (row.builtin === 'yes') || config.allBuiltin;
            var isImmutable = (row.immutable === 'yes');
            var isLocked = isBuiltin || isImmutable;

            var tr = document.createElement('tr');
            tr.dataset.rowId = String(row.id || row.name || idx);
            if (isBuiltin) tr.dataset.builtin = 'yes';
            if (isImmutable) tr.dataset.immutable = 'yes';

            /* Checkbox column — disabled for builtin entries */
            var tdCb = document.createElement('td');
            tdCb.className = 'td-checkbox';
            var cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.className = 'row-select';
            if (isLocked) {
                cb.disabled = true;
                cb.title = isImmutable ? 'Immutable (default-deny)' : 'Built-in entry';
            }
            tdCb.appendChild(cb);
            tr.appendChild(tdCb);

            /* Drag handle column — only for orderable entities */
            if (config.orderable) {
                var tdDrag = document.createElement('td');
                tdDrag.className = 'td-drag';
                if (!isLocked) {
                    tdDrag.textContent = '\u2807';  /* ⠇ drag handle */
                    tr.draggable = true;
                }
                tr.appendChild(tdDrag);
                if (row.sequence !== undefined)
                    tr.dataset.seq = String(row.sequence);
            }

            config.fields.forEach(function (f) {
                if (f.col === -1) return;
                /* altKey: alternate source field for type-dependent
                 * columns (e.g. address objects: subnet OR fqdn). */
                var val = row[f.key] || (f.altKey ? row[f.altKey] : '') || '';
                if (f.key === 'status' && config.hasStatus) {
                    tr.appendChild(buildStatusCell(val, config.statusLabels));
                } else {
                    var td = document.createElement('td');
                    td.dataset.key = f.key;
                    td.textContent = val;
                    tr.appendChild(td);
                }
            });

            frag.appendChild(tr);
        });

        tbody.innerHTML = '';
        tbody.appendChild(frag);
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
    document.querySelectorAll('.toolbar-search input, .widget-search input:not(#iface-search):not(#rf-search):not(#proctop-search)').forEach(function (input) {
        var target = findTargetTable(input);

        /* Typing: client-side prefill filter (debounced) */
        input.addEventListener('input', debounce(function () {
            applyFilter(target, input.value);
        }, 150));

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

    /* ─────────────────────────────────────────────────────────────
     *  Topbar search → nav command palette
     *
     *  Typing in the topbar search box filters the sidebar nav and
     *  shows a dropdown of matching pages.  Enter or click navigates
     *  to the first/selected match.  Escape closes.
     *
     *  Index is built once at startup from the .nav-sub-item nodes
     *  so renaming labels in HTML automatically updates the index.
     *  ─────────────────────────────────────────────────────────────
     */
    var topbarSearchInput = document.querySelector('.topbar-search input');
    if (topbarSearchInput) {
        topbarSearchInput.placeholder = 'Search pages, sections...';

        /* Build a 3-level navigation index:
         *   level 2: .nav-sub-item       → page navigation
         *   level 3: <h2 class="page-title"> inside each page → scroll target
         *
         * Path is shown as "CAT > PAGE > SECTION" so users can see where
         * a result lives.  Level-2 entries skip the section component. */
        var navIndex = [];

        /* First pass: index every sub-nav item (level 2) and capture
         * its page → label so level-3 entries can show the path. */
        var pageLabels = {};
        document.querySelectorAll('.nav-sub-item').forEach(function (item) {
            var label = (item.querySelector('.sub-label') || {}).textContent || '';
            label = label.trim();
            var cat = item.closest('.nav-category');
            var catLabel = cat ? (cat.querySelector('.nav-label') || {}).textContent : '';
            catLabel = (catLabel || '').trim();
            var page = item.dataset.page;
            pageLabels[page] = { catLabel: catLabel, label: label, cat: cat, el: item };
            navIndex.push({
                catLabel: catLabel,
                label: label,
                section: '',
                page: page,
                el: item,
                cat: cat,
                anchor: null
            });
        });

        /* Second pass: index every <h2 class="page-title"> inside a
         * .page container as a level-3 entry.  The h1 (page title) is
         * already covered by the level-2 sub-nav scan. */
        document.querySelectorAll('.page h2.page-title').forEach(function (h2) {
            var pageEl = h2.closest('.page');
            if (!pageEl) return;
            var pageId = pageEl.id.replace(/^page-/, '');
            var meta = pageLabels[pageId];
            if (!meta) return;  /* h2 on a page with no nav entry */
            navIndex.push({
                catLabel: meta.catLabel,
                label: meta.label,
                section: h2.textContent.trim(),
                page: pageId,
                el: meta.el,
                cat: meta.cat,
                anchor: h2
            });
        });

        /* Build (or fetch existing) results dropdown anchored to the
         * search box.  Lives at body level to escape topbar overflow. */
        var navResults = document.getElementById('nav-search-results');
        if (!navResults) {
            navResults = document.createElement('div');
            navResults.id = 'nav-search-results';
            navResults.className = 'nav-search-results';
            navResults.hidden = true;
            document.body.appendChild(navResults);
        }

        var matches = [];
        var activeIdx = -1;

        function positionResults() {
            var rect = topbarSearchInput.getBoundingClientRect();
            navResults.style.left = rect.left + 'px';
            navResults.style.top  = (rect.bottom + 4) + 'px';
            navResults.style.minWidth = rect.width + 'px';
        }

        function renderResults() {
            navResults.innerHTML = '';
            if (matches.length === 0) {
                navResults.hidden = true;
                return;
            }
            var activeRow = null;
            matches.forEach(function (m, idx) {
                var row = document.createElement('div');
                row.className = 'nav-search-row';
                if (idx === activeIdx) {
                    row.classList.add('active');
                    activeRow = row;
                }

                /* Path: "CAT › PAGE [› SECTION]" */
                var path = document.createElement('span');
                path.className = 'nav-search-path';
                path.appendChild(makeSpan('nav-search-cat', m.catLabel));
                path.appendChild(document.createTextNode(' \u203A '));  /* › */
                path.appendChild(makeSpan('nav-search-label', m.label));
                if (m.section) {
                    path.appendChild(document.createTextNode(' \u203A '));
                    path.appendChild(makeSpan('nav-search-section', m.section));
                }
                row.appendChild(path);

                row.addEventListener('mousedown', function (e) {
                    e.preventDefault();   /* keep focus until we navigate */
                    navigateTo(m);
                });
                navResults.appendChild(row);
            });
            positionResults();
            navResults.hidden = false;

            /* Scroll the highlighted row into view when arrow keys
             * move past the visible area of the results dropdown. */
            if (activeRow) {
                activeRow.scrollIntoView({ block: 'nearest' });
            }
        }

        function navigateTo(match) {
            if (!match) return;
            if (match.cat) match.cat.classList.add('open');
            var done = setActivePage(match.page, match.cat, match.el);
            topbarSearchInput.value = '';
            matches = [];
            activeIdx = -1;
            navResults.hidden = true;
            topbarSearchInput.blur();

            /* Scroll to the section anchor after the page is loaded
             * and the cover has revealed.  smooth scroll feels nicer
             * than a jump cut. */
            if (match.anchor && done && done.then) {
                done.then(function () {
                    setTimeout(function () {
                        match.anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }, 50);
                });
            }
        }

        function runSearch(query) {
            var q = (query || '').trim().toLowerCase();
            if (!q) {
                matches = [];
                activeIdx = -1;
                navResults.hidden = true;
                return;
            }
            matches = navIndex.filter(function (m) {
                return m.label.toLowerCase().indexOf(q) !== -1 ||
                       m.catLabel.toLowerCase().indexOf(q) !== -1 ||
                       (m.section && m.section.toLowerCase().indexOf(q) !== -1);
            });
            activeIdx = matches.length > 0 ? 0 : -1;
            renderResults();
        }

        topbarSearchInput.addEventListener('input', debounce(function () {
            runSearch(topbarSearchInput.value);
        }, 80));

        topbarSearchInput.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                topbarSearchInput.value = '';
                matches = [];
                navResults.hidden = true;
                topbarSearchInput.blur();
                return;
            }
            if (matches.length === 0) return;
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                activeIdx = (activeIdx + 1) % matches.length;
                renderResults();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                activeIdx = (activeIdx - 1 + matches.length) % matches.length;
                renderResults();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                navigateTo(matches[activeIdx] || matches[0]);
            }
        });

        topbarSearchInput.addEventListener('blur', function () {
            /* Hide on blur, but mousedown on a row navigates first
             * because we preventDefault on the row's mousedown. */
            setTimeout(function () { navResults.hidden = true; }, 120);
        });

        topbarSearchInput.addEventListener('focus', function () {
            if (matches.length > 0) {
                positionResults();
                navResults.hidden = false;
            }
        });

        var topbarSearchBtn = document.querySelector('.topbar-search .search-btn');
        if (topbarSearchBtn) {
            topbarSearchBtn.addEventListener('click', function () {
                topbarSearchInput.focus();
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
                nameEl.title = inp.files.length ? inp.files[0].name : '';
            }
        });
    });

    /* ================================================================
     *  FORM SAVE — wire modal Save buttons to POST/PUT API calls
     * ================================================================ */

    /* ── formSubmit helpers ─────────────────────────────────────── */

    /* Build a schema-key → input element map for one modal body.
     *
     * Preferred path: each .form-row carries a data-key attribute that
     * matches its schema field key (decouples from label text and is
     * i18n-friendly).
     *
     * Fallback path: rows without data-key are matched by label text
     * (case-insensitive) against ENTITIES[*].fields[].label, so any
     * unmigrated form-row keeps working until its data-key lands. */
    function buildKeyInputMap(body, config) {
        var keyToInp = {};
        var unkeyedByLabel = {};

        body.querySelectorAll('.form-row').forEach(function (fr) {
            var inp = fr.querySelector('.form-input');
            if (!inp) return;
            if (fr.dataset.key) {
                keyToInp[fr.dataset.key] = inp;
                return;
            }
            var lbl = fr.querySelector('.form-label');
            if (lbl) {
                unkeyedByLabel[lbl.textContent.trim().toLowerCase()] = inp;
            }
        });

        config.fields.forEach(function (f) {
            if (keyToInp[f.key]) return;
            var fallback = unkeyedByLabel[f.label.toLowerCase()];
            if (fallback) keyToInp[f.key] = fallback;
        });

        return keyToInp;
    }

    /* Read the form into a payload object keyed by config field keys.
     * Empty values are dropped — sending empty strings would wipe DB
     * fields on edit and fail required-key validation on create. */
    function buildPayloadFromForm(config, body, keyMap) {
        var payload = {};
        config.fields.forEach(function (f) {
            var inp = keyMap[f.key];
            if (!inp) return;
            /* Skip hidden rows (e.g. password fields hidden during edit) */
            var row = inp.closest('.form-row');
            if (row && row.style.display === 'none') return;
            if (inp.tagName === 'SELECT') {
                var opt = inp.options[inp.selectedIndex];
                var val = opt ? (opt.value || opt.text) : '';
                if (val) payload[f.key] = val;
            } else if (inp.type === 'checkbox') {
                /* Switch enum (data-on/data-off) → enable/disable string; a regular
                 * checkbox → boolean. */
                if (inp.dataset.on || inp.dataset.off) {
                    payload[f.key] = inp.checked
                        ? (inp.dataset.on  || 'enable')
                        : (inp.dataset.off || 'disable');
                } else {
                    payload[f.key] = inp.checked;
                }
            } else if (inp.value !== '') {
                payload[f.key] = inp.value;
            }
        });

        /* Capture multi-checkbox groups (e.g. Admin Access, Permissions).
         * Each .form-row-full carries data-key matching the schema field;
         * each <input type="checkbox"> carries its own value attribute.
         * Empty groups send empty string to actively clear the backend
         * field — without this the old value would persist. */
        body.querySelectorAll('.form-row-full[data-key]').forEach(function (fr) {
            var fieldKey = fr.dataset.key;
            var cbs = fr.querySelectorAll('input[type="checkbox"]');
            if (cbs.length === 0) return;
            var vals = [];
            cbs.forEach(function (cb) {
                if (cb.checked && cb.value) vals.push(cb.value);
            });
            var sep = (fieldKey === 'permissions') ? ',' : ' ';
            payload[fieldKey] = vals.length > 0 ? vals.join(sep) : '';
        });

        return payload;
    }

    /* Auto-assign a numeric id for non-name-as-id types by scanning
     * the current entity table for the highest existing row id and
     * returning maxId + 1.  Mirrors webd_api.c:type_uses_name_as_id. */
    var NAME_AS_ID_TYPES = {
        'firewall_address': 1,
        'firewall_service': 1,
        'system_admin': 1,
        'system_admin-profile': 1
        /* security_ips-profile is numeric-id now (auto-assigned via nextNumericId) */
    };
    function nextNumericId() {
        var pageEl = document.getElementById('page-' + activePage);
        var table = pageEl ? pageEl.querySelector('table[data-entity]') : null;
        var rows = table ? table.querySelectorAll('tbody tr[data-row-id]') : [];
        var maxId = 0;
        rows.forEach(function (r) {
            var n = parseInt(r.dataset.rowId, 10);
            if (!isNaN(n) && n > maxId) maxId = n;
        });
        return String(maxId + 1);
    }

    /* Admin entity has its own create endpoint with password handling. */
    function submitAdminCreate(body, payload) {
        if (!payload.id) {
            showToast('Username is required', 'error');
            return;
        }
        var adminBody = {
            username: payload.id,
            profile: payload.profile || ''
        };
        if (payload['enforce-change-password'])
            adminBody['enforce-change-password'] = payload['enforce-change-password'];
        if (payload['enforce-password-policy'])
            adminBody['enforce-password-policy'] = payload['enforce-password-policy'];

        var pwInp = body.querySelector('input[type="password"]');
        var pwAll = body.querySelectorAll('input[type="password"]');
        var cfInp = pwAll[1];
        if (!pwInp || !pwInp.value) {
            showToast('Password is required for new admin', 'error');
            return;
        }
        if (pwInp.value.length < 8) {
            showToast('Password must be at least 8 characters', 'error');
            return;
        }
        if (cfInp && cfInp.value !== pwInp.value) {
            showToast('Passwords do not match', 'error');
            return;
        }
        adminBody.password = pwInp.value;

        api('/admin/create', { method: 'POST', body: adminBody })
            .then(function () {
                closeModal(false);
                showToast('Administrator created', 'success');
                refreshPage(activePage);
            })
            .catch(function (err) {
                showToast(err.message || 'Create failed', 'error');
            });
    }

    function submitConfigEntry(config, payload, isEdit, rowId) {
        var method, url;
        if (isEdit) {
            method = 'PUT';
            url = '/config/' + config.configType + '/' + rowId;
        } else {
            method = 'POST';
            url = '/config/' + config.configType;

            if (NAME_AS_ID_TYPES[config.configType]) {
                if (!payload.name) {
                    showToast('Name is required', 'error');
                    return;
                }
            } else {
                /* For types that have a 'name' schema field (e.g. firewall_policy),
                 * validate that the user provided a name before submitting. */
                var hasNameField = config.fields.some(function (f) {
                    return f.key === 'name' && !f.editDisabled;
                });
                if (hasNameField) {
                    if (!payload.name) {
                        showToast('Name is required', 'error');
                        return;
                    }
                    if (!/^[a-zA-Z0-9._-]+$/.test(payload.name)) {
                        showToast('Name must contain only letters, numbers, hyphens, underscores, or dots', 'error');
                        return;
                    }
                }
                /* Numeric-id types auto-assign; user-named types (e.g.
                 * network_dhcp-server) carry their name in payload.id
                 * already — only assign a numeric id when none was given. */
                if (!payload.id) {
                    payload.id = nextNumericId();
                } else if (!/^[a-zA-Z0-9._-]+$/.test(payload.id)) {
                    showToast('Name must contain only letters, numbers, hyphens, underscores, or dots', 'error');
                    return;
                }
            }
        }

        api(url, { method: method, body: payload })
            .then(function () {
                closeModal(false);
                showToast(isEdit ? 'Entry updated' : 'Entry created', 'success');

                /* Interface changes may restart network briefly.
                 * Delay + retry reload to avoid connection drop. */
                if (config.configType === 'system_interface') {
                    showToast('Network reconfiguring, please wait...', 'info');
                    var retryCount = 0;
                    function retryRefresh() {
                        refreshPage(activePage).catch(function () {
                            if (retryCount < 3) {
                                retryCount++;
                                setTimeout(retryRefresh, 1000);
                            }
                        });
                    }
                    setTimeout(retryRefresh, 2000);
                } else {
                    refreshPage(activePage);
                }
            })
            .catch(function (err) {
                showToast(err.message || 'Save failed', 'error');
            });
    }

    function formSubmit(entity) {
        var config = ENTITIES[entity];
        if (!config) return;
        var form = document.getElementById(config.formId);
        if (!form) return;
        if (form.classList.contains('form-locked')) {
            showToast('This entry is read-only and cannot be modified.', 'error');
            return;
        }
        var body = form.querySelector('.modal-body');
        if (!body) return;

        var keyMap = buildKeyInputMap(body, config);
        var payload = buildPayloadFromForm(config, body, keyMap);
        var isEdit = form.dataset.editMode === 'true';
        var rowId = form.dataset.editRowId || '';

        if (config.customCreate && !isEdit) {
            submitAdminCreate(body, payload);
            return;
        }
        submitConfigEntry(config, payload, isEdit, rowId);
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

    /* Settings page → list of (configType, fieldKeys) tuples.  Each
     * card pulls data from one or more backend types (e.g. the
     * "system" page reads system_settings + system_ntp + network_dns).
     * Field keys must match data-key attributes on the .form-row. */
    var SETTINGS_MAP = {
        'system': [
            { configType: 'system_settings',   fields: ['hostname', 'ip-forward', 'timezone', 'fqdn-ttl'] },
            { configType: 'system_ntp',        fields: ['server'] },
            { configType: 'network_dns',       fields: ['primary', 'secondary'] },
            { configType: 'system_session-ttl', fields: ['tcp-syn-sent', 'tcp-syn-recv', 'tcp-established', 'tcp-fin-wait', 'tcp-close-wait', 'tcp-last-ack', 'tcp-time-wait', 'tcp-close', 'udp', 'icmp', 'other'] }
        ],
        'password-policy': [
            { configType: 'system_password-policy',
              fields: ['min-length', 'min-uppercase', 'min-lowercase', 'min-digit', 'min-special'] }
        ],
        'security': [
            { configType: 'security_ips',
              fields: ['status', 'mode', 'snapshot-bytes'] }
        ],
        'security-schedule': [
            { configType: 'security_ips',
              fields: ['cron-enabled', 'cron-minutes', 'cron-hours', 'cron-dom',
                       'cron-months', 'cron-dow', 'cron-desc'] }
        ]
    };

    /* Build a data-key → input map for settings cards.  Same pattern
     * as buildKeyInputMap but unscoped to a schema (settings cards
     * don't have an ENTITIES entry). */
    function settingsKeyMap(card) {
        var map = {};
        card.querySelectorAll('.form-row[data-key]').forEach(function (fr) {
            var inp = fr.querySelector('.form-input');
            if (inp) map[fr.dataset.key] = inp;
        });
        return map;
    }

    function settingsApply(card, settingsName) {
        var maps = SETTINGS_MAP[settingsName];
        if (!maps) return;
        var keyMap = settingsKeyMap(card);
        var pending = maps.length;
        var hadError = false;

        maps.forEach(function (m) {
            var payload = {};
            m.fields.forEach(function (key) {
                var inp = keyMap[key];
                if (!inp) return;
                payload[key] = inp.tagName === 'SELECT'
                    ? (inp.options[inp.selectedIndex].value || inp.options[inp.selectedIndex].text)
                    : inp.value;
            });
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
                          'system_password-policy', 'system_session-ttl',
                          'security_ips'];

    function settingsLoad(card, settingsName) {
        var maps = SETTINGS_MAP[settingsName];
        if (!maps) return Promise.resolve();
        var keyMap = settingsKeyMap(card);

        return Promise.all(maps.map(function (m) {
            /* Single-type: GET /api/config/TYPE/0 returns the entry directly.
             * Table-type: GET /api/config/TYPE returns {entries:[...]}. */
            var isSingle = SINGLE_CONFIGS.indexOf(m.configType) !== -1;
            var url = '/config/' + m.configType + (isSingle ? '/0' : '');

            return api(url).then(function (data) {
                if (!data) return;
                m.fields.forEach(function (key) {
                    var inp = keyMap[key];
                    if (!inp || data[key] === undefined) return;
                    if (inp.tagName === 'SELECT') selectOption(inp, String(data[key]));
                    else inp.value = data[key];
                });
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

    /* SSL Inspection page: deep warning (FortiGate-style) + diagnostics. */
    function initSslPageExtras(pg) {
        if (!pg) return;
        var modeSel   = pg.querySelector('.form-row[data-key="inspection-mode"] .form-input');
        var statusSel = pg.querySelector('.form-row[data-key="status"] .form-input');
        var exemptInp = pg.querySelector('.form-row[data-key="exempt"] .form-input');
        var warn      = pg.querySelector('#ssl-deep-warning');
        var exSummary = pg.querySelector('#ssl-exempt-summary');

        function updateWarn() {
            var deep = modeSel && modeSel.value === 'deep';
            var on   = statusSel && statusSel.value === 'enable';
            if (warn) warn.style.display = (deep && on) ? '' : 'none';
            if (exSummary) {
                var ex = exemptInp && exemptInp.value.trim();
                exSummary.textContent = ex ? ex : '(none configured)';
            }
        }
        [modeSel, statusSel].forEach(function (s) {
            if (s && !s._sslWired) { s.addEventListener('change', updateWarn); s._sslWired = 1; }
        });
        if (exemptInp && !exemptInp._sslWired) {
            exemptInp.addEventListener('input', updateWarn); exemptInp._sslWired = 1;
        }
        updateWarn();

        var diagBtn = pg.querySelector('#ssl-diag-btn');
        var diagOut = pg.querySelector('#ssl-diag-output');
        if (diagBtn && !diagBtn._wired) {
            diagBtn._wired = 1;
            diagBtn.addEventListener('click', function () {
                if (diagOut) diagOut.textContent = 'Running…';
                api('/monitor/ssl').then(function (d) {
                    if (diagOut) diagOut.textContent = (d && d.output) ? d.output : '(no output)';
                }).catch(function () {
                    if (diagOut) diagOut.textContent = '(failed to run diagnostics)';
                });
            });
        }
    }

    /* Certificates page: view/export/download the SSL inspection CA. */
    function initCertPage(pg) {
        if (!pg) return Promise.resolve();
        var statusEl = pg.querySelector('#cert-ca-status');
        var pemCard  = pg.querySelector('#cert-pem-card');
        var pemEl    = pg.querySelector('#cert-pem');
        var exportBtn= pg.querySelector('#cert-export-btn');
        var dlBtn    = pg.querySelector('#cert-download-btn');
        var caPem = '';

        if (exportBtn && !exportBtn._wired) {
            exportBtn._wired = 1;
            exportBtn.addEventListener('click', function () {
                if (!caPem) { showToast('No CA yet — enable deep SSL inspection to generate one', 'error'); return; }
                if (pemEl) pemEl.textContent = caPem;
                if (pemCard) pemCard.style.display = '';
            });
        }
        if (dlBtn && !dlBtn._wired) {
            dlBtn._wired = 1;
            dlBtn.addEventListener('click', function () {
                if (!caPem) { showToast('No CA yet', 'error'); return; }
                var blob = new Blob([caPem], { type: 'application/x-pem-file' });
                var a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'stargazer-ca.crt';
                document.body.appendChild(a); a.click(); document.body.removeChild(a);
                URL.revokeObjectURL(a.href);
            });
        }

        return api('/monitor/ssl-cacert').then(function (d) {
            caPem = (d && d.output) ? d.output : '';
            if (statusEl) statusEl.textContent = caPem
                ? 'CA present (' + caPem.length + ' bytes PEM)'
                : 'CA not created — enable deep SSL inspection to generate automatically';
        }).catch(function () {
            caPem = '';
            if (statusEl) statusEl.textContent = 'CA not created — enable deep SSL inspection to generate automatically';
        });
    }

    /* ── IPS Monitor: status card + recent alert log ──────────────── */
    function loadIpsMonitor() {
        function setTxt(id, v) {
            var e = document.getElementById(id);
            if (e) e.textContent = v;
        }
        var p1 = api('/monitor/ips').then(function (d) {
            if (!d) return;
            setTxt('ips-stat-running',
                   d.ipsd_running === 'yes' ? 'Running' : 'Stopped');
            setTxt('ips-stat-status', d.status || '—');
            setTxt('ips-stat-mode', d.mode || '—');
            setTxt('ips-stat-snap',
                   parseInt(d.snapshot_bytes, 10) > 0 ? (d.snapshot_bytes + ' B') : '—');
            /* P0 — actual coverage: full=can DROP, alert-cap=ALERT only (narrowing
             * keyword not yet supported). */
            if (d.loaded !== undefined) {
                var full = parseInt(d.loaded_full || '0', 10);
                var alertCap = parseInt(d.loaded_alert || '0', 10);
                var total = parseInt(d.loaded || '0', 10);
                setTxt('ips-stat-rules',
                       total + ' (full ' + full + ', alert-cap ' + alertCap + ')');
                setTxt('ips-stat-coverage',
                       total ? (100 * full / total).toFixed(1) + '% enforce' : '—');
            } else {
                setTxt('ips-stat-rules', '—');
                setTxt('ips-stat-coverage', '—');
            }
            setTxt('ips-stat-alerts', d.alert_log_lines || '0');
        }).catch(function () {});
        var p2 = api('/monitor/ips-alerts').then(function (d) {
            var log = document.getElementById('ips-alert-log');
            if (log) log.textContent =
                (d && d.output && d.output.trim()) ? d.output
                                                   : '(no alerts yet)';
        }).catch(function () {
            var log = document.getElementById('ips-alert-log');
            if (log) log.textContent = '(failed to load alert log)';
        });
        return Promise.all([p1, p2]);
    }

    /* Refresh button on the IPS Monitor page (legacy, kept for compat) */
    (function () {
        var btn = document.getElementById('ips-refresh');
        if (btn) btn.addEventListener('click', function () { loadIpsMonitor(); });
    })();

    /* ================================================================
     *  IPS — 5-tab OPNsense-style page
     * ================================================================ */
    (function () {

        /* ── state ── */
        var _catalog  = null;   /* cached signature catalog array (current query) */
        var _catalogTrunc = 0;  /* 1 → server truncated results, need to narrow the keyword */
        var _rulesPage = 0;
        var _rulesFilter = { q: '', action: '' };
        var _rulesSearchTimer = null;
        var _alerts    = [];    /* last loaded alert array */

        /* ── helpers ── */
        var esc = SgCommon.escHTML;
        function pageEl() { return document.getElementById('page-sec-ips'); }

        /* ── tab switching ── */
        function ipsTabSwitch(tab) {
            var pg = pageEl(); if (!pg) return;
            pg.querySelectorAll('.page-tab[data-ips-tab]').forEach(function (b) {
                b.classList.toggle('active', b.dataset.ipsTab === tab);
            });
            pg.querySelectorAll('.ips-tab-pane').forEach(function (p) {
                p.style.display = (p.dataset.ipsPane === tab) ? '' : 'none';
            });
            /* Return the loader's promise so initIpsPage can await it — otherwise
             * the page reveal mechanism won't see a successful api() and would wait
             * the 8s watchdog (MAX_COVER_MS) before removing the loading cover. */
            if (tab === 'settings') {
                var card = pg.querySelector('[data-ips-pane="settings"] .form-card[data-settings]');
                return card ? settingsLoad(card, 'security') : Promise.resolve();
            } else if (tab === 'download') {
                return loadIpsRulesets();
            } else if (tab === 'rules') {
                return loadIpsRules();
            } else if (tab === 'alerts') {
                return loadIpsAlerts();
            } else if (tab === 'schedule') {
                var scard = pg.querySelector('[data-ips-pane="schedule"] .form-card[data-settings]');
                return scard ? settingsLoad(scard, 'security-schedule') : Promise.resolve();
            }
            return Promise.resolve();
        }

        /* ── initIpsPage: called once per navigation ── */
        window.initIpsPage = function (pg) {
            if (!pg) return Promise.resolve();
            if (!pg._ipsInited) {
                pg._ipsInited = true;

                /* Tab click handlers */
                pg.querySelectorAll('.page-tab[data-ips-tab]').forEach(function (b) {
                    b.addEventListener('click', function () { ipsTabSwitch(b.dataset.ipsTab); });
                });


                /* Reload Service button */
                var rbtn = pg.querySelector('#ips-reload-btn');
                if (rbtn) rbtn.addEventListener('click', function () {
                    rbtn.disabled = true;
                    api('/ips/reload', { method: 'POST' })
                        .then(function () { showToast('IPS service reloaded', 'success'); })
                        .catch(function () { showToast('Reload failed — check backend', 'error'); })
                        .finally(function () { rbtn.disabled = false; });
                });

                /* Settings tab Apply / Reset buttons — delegate to settingsApply */
                var settingsCard = pg.querySelector('[data-ips-pane="settings"] .form-card[data-settings]');
                if (settingsCard) {
                    var applyBtn = settingsCard.querySelector('.form-actions .btn-primary');
                    var resetBtn = settingsCard.querySelector('.form-actions .btn:not(.btn-primary)');
                    if (applyBtn) applyBtn.addEventListener('click', function () {
                        settingsApply(settingsCard, 'security');
                    });
                    if (resetBtn) resetBtn.addEventListener('click', function () {
                        settingsLoad(settingsCard, 'security');
                    });
                }

                /* Schedule tab Reset only — Apply is wired below with cron validation */
                var schedCard = pg.querySelector('[data-ips-pane="schedule"] .form-card[data-settings]');
                if (schedCard) {
                    var sreset = schedCard.querySelector('.form-actions .btn:not(.btn-primary)');
                    if (sreset) sreset.addEventListener('click', function () {
                        settingsLoad(schedCard, 'security-schedule');
                    });
                }

                /* Download tab: Reload button — rescan custom XML dir */
                var reloadRsBtn = pg.querySelector('#ips-rulesets-reload-btn');
                if (reloadRsBtn) reloadRsBtn.addEventListener('click', function () {
                    reloadRsBtn.disabled = true;
                    api('/ips/rulesets-reload', { method: 'POST' })
                        .then(function (d) {
                            showToast('Ruleset list refreshed', 'success');
                            loadIpsRulesets();
                            showIpsUpdateLog(pg, (d && d.output) ? d.output : 'Done');
                        })
                        .catch(function () { showToast('Reload failed', 'error'); })
                        .finally(function () { reloadRsBtn.disabled = false; });
                });

                /* Select-all checkbox */
                var rsAllCb = pg.querySelector('#ips-rulesets-all');
                if (rsAllCb) rsAllCb.addEventListener('change', function () {
                    pg.querySelectorAll('#ips-rulesets-tbody .rs-cb').forEach(function (cb) {
                        if (!cb.disabled) cb.checked = rsAllCb.checked;
                    });
                });

                /* Ruleset search */
                var rsSearch = pg.querySelector('#ips-rulesets-search');
                if (rsSearch) rsSearch.addEventListener('input', function () {
                    filterRulesetRows(rsSearch.value.trim().toLowerCase());
                });

                /* Download & Update — requires at least one checkbox selected */
                var updateBtn = pg.querySelector('#ips-update-now-btn');

                if (updateBtn) updateBtn.addEventListener('click', function () {
                    var checked = pg.querySelectorAll('#ips-rulesets-tbody .rs-cb:checked');
                    if (!checked.length) {
                        showToast('Select at least one ruleset to download', 'error');
                        return;
                    }
                    var ids = [];
                    checked.forEach(function (cb) { ids.push(cb.dataset.id); });
                    updateBtn.disabled = true;
                    updateBtn.textContent = 'Downloading…';
                    /* Request WAITS until the download completes: mgmtd forks an inner child that
                     * owns the connection and returns the EXACT result (success/error + reason).
                     * A large download can take a while — the button keeps the "Downloading…" state. */
                    api('/ips/update-now', { method: 'POST', body: { ids: ids.join(',') } })
                        .then(function (resp) {
                            showToast((resp && resp.output) ? resp.output
                                      : ('Downloaded ' + ids.length + ' ruleset'), 'success');
                        })
                        .catch(function (err) {
                            /* err.message carries the detailed reason from the backend:
                             * no internet / wrong DNS / broken syntax / empty file… */
                            showToast('Download failed: ' + (err.message || 'network error'), 'error');
                        })
                        .finally(function () {
                            updateBtn.disabled = false;
                            updateBtn.textContent = 'Download & Update Rules';
                            /* Detailed per-ruleset log + update timestamp +
                             * refresh catalog (new rules appear in the Rules tab). */
                            api('/ips/update-log').then(function (d) {
                                showIpsUpdateLog(pg, (d && d.output) ? d.output : '');
                            }).catch(function () {});
                            invalidateApiCache('/ips/signatures');
                            _catalog = null;
                            loadIpsRulesets();
                        });
                });

                /* ── Custom ruleset import modal ── */
                var customModal  = document.getElementById('modal-ips-custom');
                var customDesc   = document.getElementById('ips-custom-desc');
                var customUrl    = document.getElementById('ips-custom-url');
                var customSubmit = document.getElementById('ips-custom-submit');

                function openCustomModal() {
                    if (!customModal) return;
                    if (customDesc) customDesc.value = '';
                    if (customUrl)  customUrl.value  = '';
                    customModal.style.display = 'flex';
                    if (customDesc) customDesc.focus();
                }
                function closeCustomModal() {
                    if (customModal) customModal.style.display = 'none';
                }

                var addCustomBtn = pg.querySelector('#ips-custom-add-btn');
                if (addCustomBtn) addCustomBtn.addEventListener('click', openCustomModal);

                var customClose  = document.getElementById('ips-custom-modal-close');
                var customCancel = document.getElementById('ips-custom-cancel');
                if (customClose)  customClose.addEventListener('click', closeCustomModal);
                if (customCancel) customCancel.addEventListener('click', closeCustomModal);
                if (customModal)  customModal.addEventListener('click', function (e) {
                    if (e.target === customModal) closeCustomModal();
                });

                if (customSubmit) customSubmit.addEventListener('click', function () {
                    var desc = customDesc ? customDesc.value.trim() : '';
                    var url  = customUrl  ? customUrl.value.trim()  : '';
                    if (!desc) { showToast('Description is required', 'error'); return; }
                    if (!url)  { showToast('URL is required', 'error'); return; }
                    if (!/^https?:\/\/.+/.test(url)) {
                        showToast('URL must start with http:// or https://', 'error');
                        return;
                    }
                    /* Generate a safe ID from the description */
                    var genId = 'custom-' + desc.toLowerCase()
                        .replace(/[^a-z0-9]+/g, '-')
                        .replace(/^-+|-+$/g, '')
                        .slice(0, 32) + '-' + Date.now().toString(36);
                    customSubmit.disabled = true;
                    api('/config/security_ips-ruleset', {
                        method: 'POST',
                        body: { id: genId, description: desc, url: url,
                                enabled: 'enable', builtin: 'no' }
                    }).then(function () {
                        showToast('Custom ruleset added — select it and click Download & Update Rules', 'success');
                        closeCustomModal();
                        loadIpsRulesets();
                    }).catch(function (err) {
                        showToast((err && err.message) || 'Failed to add ruleset', 'error');
                    }).finally(function () { customSubmit.disabled = false; });
                });

                /* Delete custom ruleset via event delegation on the tbody */
                var rsTbody = pg.querySelector('#ips-rulesets-tbody');
                if (rsTbody) rsTbody.addEventListener('click', function (ev) {
                    var btn = ev.target.closest('[data-del-id]');
                    if (!btn) return;
                    var id = btn.dataset.delId;
                    if (!id) return;
                    if (!confirm('Delete custom ruleset "' + id + '"?')) return;
                    api('/config/security_ips-ruleset/' + encodeURIComponent(id),
                        { method: 'DELETE' })
                        .then(function () {
                            showToast('Ruleset deleted', 'success');
                            loadIpsRulesets();
                        })
                        .catch(function (err) { showToast(err.message || 'Delete failed', 'error'); });
                });

                /* Schedule: cron validation + live preview */
                var schedCard = pg.querySelector('[data-ips-pane="schedule"] .form-card');
                if (schedCard) {
                    var CRON_FIELDS = [
                        { key: 'cron-minutes', min: 0, max: 59,  label: 'Minutes' },
                        { key: 'cron-hours',   min: 0, max: 23,  label: 'Hours' },
                        { key: 'cron-dom',     min: 1, max: 31,  label: 'Day of month' },
                        { key: 'cron-months',  min: 1, max: 12,  label: 'Months' },
                        { key: 'cron-dow',     min: 0, max: 6,   label: 'Days of week' }
                    ];
                    function getCronVal(k) {
                        var row = schedCard.querySelector('[data-key="' + k + '"]');
                        var inp = row ? row.querySelector('.form-input') : null;
                        return inp ? inp.value.trim() : '';
                    }
                    function updateCronPreview() {
                        var vals = CRON_FIELDS.map(function (f) {
                            var v = getCronVal(f.key);
                            return v || (f.min === 0 && f.max >= 23 ? '0' : '*');
                        });
                        var lbl = schedCard.querySelector('#cron-preview-label');
                        if (lbl) lbl.textContent = vals.join(' ');
                    }
                    /* Attach preview listeners */
                    CRON_FIELDS.forEach(function (f) {
                        var row = schedCard.querySelector('[data-key="' + f.key + '"]');
                        var inp = row ? row.querySelector('.form-input') : null;
                        if (inp) inp.addEventListener('input', updateCronPreview);
                    });
                    /* Override Apply button with validation */
                    var sapply = schedCard.querySelector('.form-actions .btn-primary');
                    if (sapply) {
                        sapply.addEventListener('click', function () {
                            for (var fi = 0; fi < CRON_FIELDS.length; fi++) {
                                var err = validateCronField(
                                    getCronVal(CRON_FIELDS[fi].key),
                                    CRON_FIELDS[fi].min, CRON_FIELDS[fi].max,
                                    CRON_FIELDS[fi].label);
                                if (err) { showToast(err, 'error'); return; }
                            }
                            settingsApply(schedCard, 'security-schedule');
                        });
                    }
                }

                /* Rules tab: search + filter. Search re-fetches SERVER-SIDE
                 * (the catalog may be too large to load in full — backend filters by q). */
                var qEl = pg.querySelector('#ips-rules-search');
                if (qEl) qEl.addEventListener('input', function () {
                    _rulesFilter.q = qEl.value.trim().toLowerCase();
                    _rulesPage = 0;
                    clearTimeout(_rulesSearchTimer);
                    _rulesSearchTimer = setTimeout(loadIpsRules, 250);
                });
                var afEl = pg.querySelector('#ips-rules-action-filter');
                if (afEl) afEl.addEventListener('change', function () {
                    _rulesFilter.action = afEl.value;
                    _rulesPage = 0;
                    renderIpsRulesTable();
                });

                /* Rules refresh button */
                var rrBtn = pg.querySelector('#ips-rules-refresh');
                if (rrBtn) rrBtn.addEventListener('click', function () {
                    invalidateApiCache('/ips/signatures');
                    _catalog = null;
                    loadIpsRules();
                });

                /* Alerts tab buttons */
                var arBtn = pg.querySelector('#ips-alerts-refresh');
                if (arBtn) arBtn.addEventListener('click', loadIpsAlerts);
                var acBtn = pg.querySelector('#ips-alerts-clear');
                if (acBtn) acBtn.addEventListener('click', function () {
                    api('/ips/alerts-clear', { method: 'POST' })
                        .then(function () { _alerts = []; renderIpsAlertsTable(); showToast('Alerts cleared', 'success'); })
                        .catch(function () { showToast('Clear failed', 'error'); });
                });
                /* Alert info modal close buttons */
                var adClose  = pg.querySelector('#ips-alert-detail-close');
                var adClose2 = pg.querySelector('#ips-alert-detail-close2');
                function closeAlertModal() {
                    var m = pg.querySelector('#ips-alert-detail-modal');
                    if (m) m.style.display = 'none';
                }
                if (adClose)  adClose.addEventListener('click', closeAlertModal);
                if (adClose2) adClose2.addEventListener('click', closeAlertModal);

                /* Alert info modal — delegate Info button clicks */
                var alertTbody = pg.querySelector('#ips-alerts-tbody');
                if (alertTbody) alertTbody.addEventListener('click', function (e) {
                    var btn = e.target.closest('.ips-alert-info');
                    if (!btn) return;
                    var idx = parseInt(btn.dataset.idx, 10);
                    var a = _alerts[idx];
                    if (!a) return;
                    showAlertDetail(a);
                });
            }

            /* Load first (or current active) tab — RETURN its promise so
             * setActivePage reveals as soon as data arrives, instead of waiting the 8s watchdog. */
            var activeTab = pg.querySelector('.page-tab.active');
            var tab = activeTab ? activeTab.dataset.ipsTab : 'settings';
            return ipsTabSwitch(tab);
        };

        /* ── Download tab: rulesets ── */

        function showIpsUpdateLog(pg, text) {
            var logDiv = pg.querySelector('#ips-update-log');
            var logPre = pg.querySelector('#ips-update-log-content');
            if (logPre) logPre.textContent = text || '';
            if (logDiv) logDiv.style.display = '';
        }

        /* Returns an error string if the cron field value is out of range, else null.
         * Accepts: *, single integer, comma list, or range (e.g. 1-5). */
        function validateCronField(val, min, max, label) {
            if (!val || val === '*') return null;
            var parts = val.split(',');
            for (var i = 0; i < parts.length; i++) {
                var p = parts[i].trim();
                if (!p) return label + ': empty segment in "' + val + '"';
                if (p.indexOf('-') > 0) {   /* range: e.g. 1-5, not a negative number */
                    var bounds = p.split('-');
                    if (bounds.length !== 2) return label + ': invalid range "' + p + '"';
                    var lo = parseInt(bounds[0], 10), hi = parseInt(bounds[1], 10);
                    if (isNaN(lo) || isNaN(hi)) return label + ': non-numeric range "' + p + '"';
                    if (lo < min || hi > max || lo > hi)
                        return label + ': range "' + p + '" must be ' + min + '–' + max;
                } else if (p.indexOf('/') !== -1) {
                    // allow step syntax like */5 or 1-5/2 — validate step number only
                    var step = parseInt(p.split('/')[1], 10);
                    if (isNaN(step) || step < 1)
                        return label + ': invalid step in "' + p + '"';
                } else {
                    var n = parseInt(p, 10);
                    if (isNaN(n)) return label + ': "' + p + '" is not a number';
                    if (n < min || n > max)
                        return label + ': ' + n + ' out of range (' + min + '–' + max + ')';
                }
            }
            return null;
        }

        function loadIpsRulesets() {
            var pg = pageEl(); if (!pg) return Promise.resolve();
            var tbody = pg.querySelector('#ips-rulesets-tbody');
            if (!tbody) return Promise.resolve();
            tbody.innerHTML = '<tr><td colspan="4" class="table-empty">Loading…</td></tr>';
            return api('/config/security_ips-ruleset').then(function (data) {
                var entries = (data && data.entries) ? data.entries : [];
                if (!entries.length) {
                    tbody.innerHTML = '<tr><td colspan="4" class="table-empty">No rulesets configured. Click "+ Import Custom Rules" to add one.</td></tr>';
                    return;
                }
                var frag = document.createDocumentFragment();
                entries.forEach(function (e) {
                    var tr = document.createElement('tr');
                    tr.dataset.id = e.id;
                    tr.dataset.desc = (e.description || e.name || '').toLowerCase();

                    /* checkbox */
                    var td0 = document.createElement('td'); td0.className = 'td-checkbox';
                    var cb = document.createElement('input'); cb.type = 'checkbox'; cb.className = 'rs-cb';
                    cb.dataset.id = e.id;
                    td0.appendChild(cb); tr.appendChild(td0);

                    /* description */
                    var td1 = document.createElement('td');
                    td1.textContent = e.description || e.name || e.id;
                    if (e.builtin !== 'yes') {
                        var cBadge = document.createElement('span');
                        cBadge.textContent = ' (custom)';
                        cBadge.style.cssText = 'font-size:10px;color:#888';
                        td1.appendChild(cBadge);
                    }
                    tr.appendChild(td1);

                    /* last updated */
                    var td2 = document.createElement('td');
                    td2.style.fontSize = '12px';
                    td2.textContent = e['last-downloaded'] || 'not installed';
                    tr.appendChild(td2);

                    /* actions — delete for custom entries only */
                    var td3 = document.createElement('td');
                    td3.style.cssText = 'text-align:right;white-space:nowrap';
                    if (e.builtin !== 'yes') {
                        var delBtn = document.createElement('button');
                        delBtn.className = 'btn';
                        delBtn.textContent = 'Delete';
                        delBtn.style.cssText = 'font-size:11px;padding:2px 8px';
                        delBtn.dataset.delId = e.id;
                        td3.appendChild(delBtn);
                    }
                    tr.appendChild(td3);

                    frag.appendChild(tr);
                });
                tbody.innerHTML = '';
                tbody.appendChild(frag);
            }).catch(function () {
                tbody.innerHTML = '<tr><td colspan="4" class="table-empty">Failed to load rulesets</td></tr>';
            });
        }

        function filterRulesetRows(q) {
            var pg = pageEl(); if (!pg) return;
            pg.querySelectorAll('#ips-rulesets-tbody tr[data-id]').forEach(function (tr) {
                var desc = tr.dataset.desc || '';
                tr.style.display = (!q || desc.indexOf(q) !== -1) ? '' : 'none';
            });
        }

        /* ── Rules tab ── */
        var PAGE_SIZE = 50;

        function loadIpsRules() {
            var pg = pageEl(); if (!pg) return Promise.resolve();
            var tbody = pg.querySelector('#ips-rules-tbody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="table-empty">Loading catalog…</td></tr>';
            return fetchCatalog(_rulesFilter.q)
            .then(function (res) {
                _catalog = res.items || [];
                _catalogTrunc = res.truncated;
                _rulesPage = 0;
                renderIpsRulesTable();
            }).catch(function () {
                if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="table-empty">Failed to load</td></tr>';
            });
        }

        function filteredRules() {
            /* Keyword already filtered SERVER-SIDE (fetchCatalog) — here we only filter by
             * action (the server does not filter by action). */
            var af = _rulesFilter.action;
            return (_catalog || []).filter(function (r) {
                if (af && (r.action || 'alert') !== af) return false;
                return true;
            });
        }

        function renderIpsRulesTable() {
            var pg = pageEl(); if (!pg) return;
            var tbody = pg.querySelector('#ips-rules-tbody');
            var pager = pg.querySelector('#ips-rules-pager');
            if (!tbody) return;

            var rows = filteredRules();
            var total = rows.length;
            var pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
            if (_rulesPage >= pages) _rulesPage = pages - 1;
            var start = _rulesPage * PAGE_SIZE;
            var slice = rows.slice(start, start + PAGE_SIZE);

            var countLabel = pg.querySelector('#ips-rules-count-label');
            if (countLabel) {
                var allTotal = (_catalog || []).length;
                countLabel.textContent = total === allTotal
                    ? total + ' rule' + (total !== 1 ? 's' : '')
                    : total + ' / ' + allTotal + ' rules';
                if (_catalogTrunc)
                    countLabel.textContent += ' — too many to list, type to search';
            }

            if (!slice.length) {
                var emptyMsg = (_catalog && _catalog.length === 0)
                    ? 'No rules yet — go to the Download tab and download a ruleset first'
                    : 'No rules match the filter';
                tbody.innerHTML = '<tr><td colspan="6" class="table-empty">' + emptyMsg + '</td></tr>';
                if (pager) pager.innerHTML = '';
                return;
            }

            var frag = document.createDocumentFragment();
            slice.forEach(function (r) {
                var sidStr = String(r.sid || '');
                var action = (r.action === 'drop') ? 'Drop' : 'Alert';
                var actionCls = (action === 'Drop') ? 'verdict-drop' : 'verdict-alert';
                var src = r.category || '—';
                var cls = r.classtype || '—';
                var info = r.info || r.cve || '';

                var tr = document.createElement('tr');
                tr.innerHTML = [
                    '<td style="white-space:nowrap">' + esc(sidStr) + '</td>',
                    '<td class="' + actionCls + '">' + esc(action) + '</td>',
                    '<td style="white-space:nowrap;font-size:12px">' + esc(src) + '</td>',
                    '<td style="font-size:12px">' + esc(cls) + '</td>',
                    '<td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(r.name||r.msg||'') + '">' + esc(r.name||r.msg||'—') + '</td>',
                    '<td style="font-size:12px;color:#666">' + esc(info) + '</td>'
                ].join('');
                frag.appendChild(tr);
            });
            tbody.innerHTML = '';
            tbody.appendChild(frag);

            /* Pager */
            if (pager) {
                pager.innerHTML = '';
                var prev = document.createElement('button');
                prev.textContent = '‹ Prev';
                prev.disabled = (_rulesPage === 0);
                prev.addEventListener('click', function () { _rulesPage--; renderIpsRulesTable(); });
                pager.appendChild(prev);

                /* Show page numbers around current */
                var lo = Math.max(0, _rulesPage - 2);
                var hi = Math.min(pages - 1, _rulesPage + 2);
                for (var pi = lo; pi <= hi; pi++) {
                    (function(pi2) {
                        var pb = document.createElement('button');
                        pb.textContent = pi2 + 1;
                        if (pi2 === _rulesPage) pb.classList.add('active');
                        pb.addEventListener('click', function () { _rulesPage = pi2; renderIpsRulesTable(); });
                        pager.appendChild(pb);
                    })(pi);
                }

                var next = document.createElement('button');
                next.textContent = 'Next ›';
                next.disabled = (_rulesPage >= pages - 1);
                next.addEventListener('click', function () { _rulesPage++; renderIpsRulesTable(); });
                pager.appendChild(next);
            }
        }

        /* ── Alerts tab ── */
        function loadIpsAlerts() {
            var pg = pageEl(); if (!pg) return Promise.resolve();
            var tbody = pg.querySelector('#ips-alerts-tbody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="table-empty">Loading…</td></tr>';
            return api('/ips/alerts-json').then(function (data) {
                _alerts = Array.isArray(data) ? data : [];
                renderIpsAlertsTable();
            }).catch(function () {
                _alerts = [];
                var t = (pageEl() || {}).querySelector ? pageEl().querySelector('#ips-alerts-tbody') : null;
                if (t) t.innerHTML = '<tr><td colspan="8" class="table-empty">Failed to load alerts</td></tr>';
            });
        }

        function renderIpsAlertsTable() {
            var pg = pageEl(); if (!pg) return;
            var tbody = pg.querySelector('#ips-alerts-tbody');
            var cntEl = pg.querySelector('#ips-alerts-count');
            if (!tbody) return;
            if (!_alerts.length) {
                tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No alerts</td></tr>';
                if (cntEl) cntEl.textContent = '';
                return;
            }
            if (cntEl) cntEl.textContent = _alerts.length + ' alert(s)';
            var protoMap = { 6:'TCP', 17:'UDP', 1:'ICMP' };
            var frag = document.createDocumentFragment();
            _alerts.forEach(function (a, idx) {
                var tr = document.createElement('tr');
                tr.dataset.idx = idx;
                var vCls = a.verdict === 'DROP' ? 'verdict-drop' : (a.verdict === 'ALERT' ? 'verdict-alert' : '');
                var proto = protoMap[a.proto] || ('IP/' + a.proto);
                tr.innerHTML = [
                    '<td style="white-space:nowrap;font-size:11px">' + esc(a.ts || '') + '</td>',
                    '<td>' + esc(String(a.sid || '')) + '</td>',
                    '<td class="' + vCls + '">' + esc(a.verdict || '') + '</td>',
                    '<td>' + esc(proto) + '</td>',
                    '<td style="white-space:nowrap">' + esc((a.src||'') + ':' + (a.sport||'')) + '</td>',
                    '<td style="white-space:nowrap">' + esc((a.dst||'') + ':' + (a.dport||'')) + '</td>',
                    '<td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(a.msg||'') + '">' + esc(a.msg||'—') + '</td>',
                    '<td><button class="btn btn-info ips-alert-info" data-idx="' + idx + '">Info</button></td>'
                ].join('');
                frag.appendChild(tr);
            });
            tbody.innerHTML = '';
            tbody.appendChild(frag);
        }

        function showAlertDetail(a) {
            var pg = pageEl(); if (!pg) return;
            var modal = pg.querySelector('#ips-alert-detail-modal');
            var body  = pg.querySelector('#ips-alert-detail-body');
            if (!modal || !body) return;
            var protoMap = { 6:'TCP', 17:'UDP', 1:'ICMP' };
            var proto = protoMap[a.proto] || ('IP/' + a.proto);
            var mlScore = (a.score >= 0) ? (parseFloat(a.score).toFixed(3)) : 'N/A';
            body.innerHTML = [
                '<table class="data-table table-borderless" style="margin:0">',
                '<tr><td style="width:140px;color:#666;font-weight:600">Timestamp</td><td>' + esc(a.ts||'') + '</td></tr>',
                '<tr><td>SID</td><td>' + esc(String(a.sid||'')) + '</td></tr>',
                '<tr><td>Action</td><td class="' + (a.verdict==='DROP'?'verdict-drop':'verdict-alert') + '">' + esc(a.verdict||'') + '</td></tr>',
                '<tr><td>Protocol</td><td>' + esc(proto) + '</td></tr>',
                '<tr><td>Source</td><td>' + esc((a.src||'') + ':' + (a.sport||'')) + '</td></tr>',
                '<tr><td>Destination</td><td>' + esc((a.dst||'') + ':' + (a.dport||'')) + '</td></tr>',
                '<tr><td>Reason</td><td>' + esc(a.reason||'') + '</td></tr>',
                '<tr><td>ML Score</td><td>' + esc(mlScore) + '</td></tr>',
                '<tr><td>Message</td><td>' + esc(a.msg||'—') + '</td></tr>',
                '</table>'
            ].join('');
            modal.style.display = 'flex';
        }

    })();  /* end IPS 5-tab module */

    /* ================================================================
     *  IPS Profile — embedded Signatures & Filters (FortiGate-style)
     * ================================================================ */
    (function () {
        var modal    = document.getElementById('ips-sig-modal');
        if (!modal) return;
        var profForm = document.getElementById('form-ips-profile');
        var sigTbody = function () { return document.querySelector('#ips-sig-table tbody'); };
        var catalog  = [];
        var catalogTrunc = 0;      /* 1 → server truncated results */
        var pendingFilters = [];   /* filters buffered before profile is saved */
        var _searchTimer   = null; /* debounce handle */

        function curProfileName() {
            var row = profForm ? profForm.querySelector('.form-row[data-key="name"] .form-input') : null;
            return row ? row.value.trim() : '';
        }
        /* The profile's numeric id (filters are nested children "<profid>/<seq>").
         * Empty for a not-yet-saved new profile → only pending filters show. */
        function curProfileId() {
            return (profForm && profForm.dataset.editRowId) || '';
        }

        function renderProfileFilters() {
            var tb = document.querySelector('#ips-prof-filters tbody');
            if (!tb) return;
            var pid = curProfileId();

            function paint(dbRows) {
                if (!dbRows.length && !pendingFilters.length) {
                    tb.innerHTML = '<tr><td colspan="5" style="opacity:.6">No filters yet. Click "Create New" to add.</td></tr>';
                    return;
                }
                tb.innerHTML = '';
                dbRows.forEach(function (e) {
                    var typ = e.rule ? 'signature' : (e.category ? 'category' : '');
                    var val = e.rule || e.category || '';
                    var tr = document.createElement('tr');
                    tr.innerHTML =
                        '<td>' + typ + '</td>' +
                        '<td>' + val + '</td>' +
                        '<td>' + (e.action || 'default') + '</td>' +
                        '<td>' + (e.status || 'enable') + '</td>' +
                        '<td><button type="button" class="btn ips-del-filter" data-id="' + (e.id || '') + '">Delete</button></td>';
                    tb.appendChild(tr);
                });
                pendingFilters.forEach(function (pf, idx) {
                    var tr = document.createElement('tr');
                    tr.style.opacity = '0.65';
                    tr.innerHTML =
                        '<td>' + pf.type + '</td>' +
                        '<td>' + pf.value + '</td>' +
                        '<td>' + (pf.action || 'default') + '</td>' +
                        '<td style="color:#f0a800">pending</td>' +
                        '<td><button type="button" class="btn ips-del-pending" data-idx="' + idx + '">Delete</button></td>';
                    tb.appendChild(tr);
                });
            }

            if (!pid) {           /* new (unsaved) profile → only pending */
                paint([]);
                return;
            }
            api('/config/security_ips-filter').then(function (data) {
                var prefix = pid + '/';
                var rows = (data && data.entries ? data.entries : [])
                    .filter(function (e) { return e.id && e.id.indexOf(prefix) === 0; });
                paint(rows);
            }).catch(function () { paint([]); });
        }

        /* loadCatalog(q) — fetch SERVER-SIDE filtered (catalog may be > 64KB).
         * empty q = first chunk (may be truncated → suggest typing a keyword). */
        function loadCatalog(q) {
            var tb = sigTbody();
            if (tb) tb.innerHTML = '<tr><td colspan="6">Loading…</td></tr>';
            return fetchCatalog(q || '').then(function (res) {
                catalog = res.items || [];
                catalogTrunc = res.truncated;
                renderCatalog();
                /* Category dropdown comes from res.categories (the FULL list of every
                 * downloaded ruleset, not limited to 64KB) — only built the first time. */
                if (!q) populateCategorySelect(res.categories);
            }).catch(function () {
                if (tb) tb.innerHTML = '<tr><td colspan="6">Could not load catalog (no ruleset downloaded?).</td></tr>';
            });
        }

        function renderCatalog() {
            var tb = sigTbody();
            if (!tb) return;
            /* catalog already filtered by keyword on the backend → display directly */
            var rows = catalog.slice(0, 100);
            var total = catalog.length;
            var countEl = document.getElementById('ips-sig-count');
            if (countEl) {
                countEl.textContent = 'Showing ' + rows.length + ' of ' + total;
                if (catalogTrunc)
                    countEl.textContent += ' — too many to list, refine your search';
            }
            if (!rows.length) { tb.innerHTML = '<tr><td colspan="6">No signatures.</td></tr>'; return; }
            var frag = document.createDocumentFragment();
            rows.forEach(function (s) {
                var tr = document.createElement('tr');
                tr.innerHTML =
                    '<td><input type="checkbox" class="ips-sig-cb" data-sid="' + s.sid + '"></td>' +
                    '<td>' + s.sid + '</td>' +
                    '<td>' + (s.name || '') + '</td>' +
                    '<td>' + (s.category || '') + '</td>' +
                    '<td>' + (s.action || '') + '</td>' +
                    '<td>' + (s.cve || '') + '</td>';
                frag.appendChild(tr);
            });
            tb.innerHTML = '';
            tb.appendChild(frag);
        }

        function populateCategorySelect(categories) {
            var sel = document.getElementById('ips-filter-cat');
            if (!sel) return;
            var cats = {};
            /* Prefer the full list from the backend; fallback: derive from the loaded catalog. */
            if (categories && categories.length)
                categories.forEach(function (c) { if (c) cats[c] = 1; });
            else
                catalog.forEach(function (s) { if (s.category) cats[s.category] = 1; });
            sel.innerHTML = '<option value="all">all (every category)</option>';
            Object.keys(cats).sort().forEach(function (c) {
                var o = document.createElement('option');
                o.value = c; o.textContent = c;
                sel.appendChild(o);
            });
        }

        function setTab(tab) {
            document.querySelectorAll('.ips-tab').forEach(function (b) {
                b.classList.toggle('active', b.dataset.tab === tab);
            });
            var ps = document.getElementById('ips-pane-signature');
            var pf = document.getElementById('ips-pane-filter');
            if (ps) ps.style.display = (tab === 'signature') ? '' : 'none';
            if (pf) pf.style.display = (tab === 'filter') ? '' : 'none';
        }

        function openModal2() {
            modal.style.display = 'flex';
            setTab('signature');
            loadCatalog('');
        }
        function closeModal2() { modal.style.display = 'none'; }

        /* Buffer a filter entry locally; saved to DB when the profile is saved. */
        function addFilter(type, value, action) {
            pendingFilters.push({ type: type, value: value,
                                  action: action || 'default' });
            return Promise.resolve();
        }

        /* ── profile Save button — intercept when pending filters exist ──
         * Runs in capture phase (before the global bubble handler at line 3651).
         * If pendingFilters is empty we do nothing and the global handler fires. */
        var profSaveBtn = profForm ? profForm.querySelector('.modal-footer .btn-primary') : null;
        if (profSaveBtn) {
            profSaveBtn.addEventListener('click', function (e) {
                if (!pendingFilters.length) return; /* let global handler run */
                var profName = curProfileName();
                if (!profName) {
                    showToast('Enter a profile name before saving', 'error');
                    e.stopImmediatePropagation();
                    e.preventDefault();
                    return;
                }
                e.stopImmediatePropagation();
                e.preventDefault();

                var isEdit  = profForm.dataset.editMode === 'true';
                var rowId   = profForm.dataset.editRowId || '';
                var mbody   = profForm.querySelector('.modal-body');
                function fval(key) {
                    var el = mbody ? mbody.querySelector('[data-key="' + key + '"] .form-input') : null;
                    return el ? el.value.trim() : '';
                }
                var payload = { name: fval('name') || profName,
                                categories: fval('categories'),
                                comment:    fval('comment'),
                                status:     fval('status') || 'enable' };

                if (!payload.name) { showToast('Name is required', 'error'); return; }
                if (!/^[a-zA-Z0-9._-]+$/.test(payload.name)) {
                    showToast('Name must contain only letters, numbers, hyphens, underscores, or dots', 'error');
                    return;
                }

                var method, url;
                if (isEdit) {
                    method = 'PUT'; url = '/config/security_ips-profile/' + rowId;
                } else {
                    method = 'POST'; url = '/config/security_ips-profile';
                    payload.id = nextNumericId(); /* numeric profile id 1..31 */
                }

                var toFlush = pendingFilters.slice();
                var savedId = isEdit ? rowId : payload.id;
                api(url, { method: method, body: payload })
                    .then(function () {
                        pendingFilters = [];
                        if (!toFlush.length) return;
                        /* Filters are nested children "<profid>/<seq>". Continue
                         * the sequence after the profile's existing filters so we
                         * never clobber one (e.g. editing a profile that has 2/1). */
                        return api('/config/security_ips-filter').then(function (data) {
                            var prefix = savedId + '/';
                            var maxSeq = 0;
                            (data && data.entries ? data.entries : []).forEach(function (e) {
                                if (e.id && e.id.indexOf(prefix) === 0) {
                                    var s = parseInt(e.id.slice(prefix.length), 10);
                                    if (!isNaN(s) && s > maxSeq) maxSeq = s;
                                }
                            });
                            return Promise.all(toFlush.map(function (pf, i) {
                                var body = { id: prefix + (maxSeq + 1 + i),
                                             action: pf.action || 'default',
                                             status: 'enable' };
                                if (pf.type === 'category') body.category = pf.value;
                                else                        body.rule = pf.value;
                                return api('/config/security_ips-filter', {
                                    method: 'POST', body: body });
                            }));
                        });
                    })
                    .then(function () {
                        closeModal(false);
                        showToast('Profile saved with ' + toFlush.length + ' filter(s)', 'success');
                        refreshPage(activePage);
                    })
                    .catch(function (err) {
                        showToast((err && err.message) || 'Save failed', 'error');
                    });
            }, true /* capture phase */);
        }

        /* ── wiring ── */
        var addBtn = document.getElementById('ips-add-sig');
        if (addBtn) addBtn.addEventListener('click', openModal2);
        var closeBtn  = document.getElementById('ips-sig-close');
        var cancelBtn = document.getElementById('ips-sig-cancel');
        if (closeBtn)  closeBtn.addEventListener('click', closeModal2);
        if (cancelBtn) cancelBtn.addEventListener('click', closeModal2);

        document.querySelectorAll('.ips-tab').forEach(function (b) {
            b.addEventListener('click', function () { setTab(b.dataset.tab); });
        });

        var search = document.getElementById('ips-sig-search');
        if (search) search.addEventListener('input', function () {
            clearTimeout(_searchTimer);
            _searchTimer = setTimeout(function () { loadCatalog(search.value.trim()); }, 250);
        });
        var allCb = document.getElementById('ips-sig-all');
        if (allCb) allCb.addEventListener('change', function () {
            document.querySelectorAll('.ips-sig-cb').forEach(function (cb) {
                cb.checked = allCb.checked;
            });
        });

        var okBtn = document.getElementById('ips-sig-ok');
        if (okBtn) okBtn.addEventListener('click', function () {
            var action   = (document.getElementById('ips-sig-action') || {}).value || 'default';
            var activeTab = document.querySelector('.ips-tab.active');
            var tab      = activeTab ? activeTab.dataset.tab : 'signature';
            var jobs     = [];
            if (tab === 'signature') {
                document.querySelectorAll('.ips-sig-cb:checked').forEach(function (cb) {
                    jobs.push(addFilter('signature', cb.dataset.sid, action));
                });
                if (!jobs.length) { showToast('Select at least 1 signature', 'error'); return; }
            } else {
                var sel = document.getElementById('ips-filter-cat');
                var cat = sel ? sel.value : '';
                if (!cat) { showToast('Select a category', 'error'); return; }
                jobs.push(addFilter('category', cat, action));
            }
            Promise.all(jobs).then(function () {
                showToast('Added ' + jobs.length + ' item(s)', 'success');
                closeModal2();
                renderProfileFilters();
            }).catch(function (err) {
                showToast((err && err.message) || 'Add failed', 'error');
            });
        });

        /* Delete: saved filter from DB, or pending filter from local buffer */
        var ftbl = document.getElementById('ips-prof-filters');
        if (ftbl) ftbl.addEventListener('click', function (ev) {
            var pb = ev.target.closest('.ips-del-pending');
            if (pb) {
                var idx = parseInt(pb.dataset.idx, 10);
                if (!isNaN(idx)) { pendingFilters.splice(idx, 1); renderProfileFilters(); }
                return;
            }
            var db = ev.target.closest('.ips-del-filter');
            if (!db) return;
            var id = db.dataset.id;
            if (!id) return;
            api('/config/security_ips-filter/' + encodeURIComponent(id), { method: 'DELETE' })
                .then(function () { renderProfileFilters(); })
                .catch(function (err) { showToast(err.message || 'Delete failed', 'error'); });
        });

        /* Render filter list when profile form opens (create + edit). */
        document.querySelectorAll('[data-toggle-form="form-ips-profile"]').forEach(function (b) {
            b.addEventListener('click', function () {
                pendingFilters = [];
                setTimeout(renderProfileFilters, 60);
            });
        });
        var profTbl = document.querySelector('table[data-entity="ipsProfiles"]');
        if (profTbl) profTbl.addEventListener('click', function () {
            pendingFilters = [];
            setTimeout(renderProfileFilters, 120);
        });
    })();

    /* Wire settings Apply/Reset buttons — skip cards with data-custom-apply (wired elsewhere) */
    document.querySelectorAll('[data-settings]').forEach(function (card) {
        if (card.dataset.customApply !== undefined) return;
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

    /* In-flight diagnostic request state.
     * Tab switching does NOT cancel — the request runs in the background.
     * A new tool click aborts the previous request to avoid DOM races. */
    var diagAbortCtrl = null;
    var diagTimeoutId = null;

    function runDiagTool(tool, params) {
        var output    = document.getElementById('diag-output');
        var cancelBtn = document.getElementById('diag-cancel');
        if (!output) return;

        /* Abort any previous in-flight request (rapid re-click guard) */
        if (diagAbortCtrl) { diagAbortCtrl.abort(); diagAbortCtrl = null; }
        if (diagTimeoutId) { clearTimeout(diagTimeoutId); diagTimeoutId = null; }

        /* Disable all tool buttons, show Cancel while running */
        document.querySelectorAll('[data-tool]').forEach(function (b) {
            b.disabled = true;
        });
        if (cancelBtn) cancelBtn.style.display = 'inline-block';

        /* Animated indicator: CSS .diag-running adds a blinking dot */
        output.className = 'diag-output diag-running';
        output.textContent = 'Running...';
        output.style.color = '';

        diagAbortCtrl = new AbortController();
        /* Capture controller and timer for THIS request so resetState()
         * can distinguish between our cleanup and a newer request's state. */
        var myCtrl    = diagAbortCtrl;

        diagTimeoutId = setTimeout(function () {
            /* Only abort if this request is still the active one */
            if (diagAbortCtrl === myCtrl) diagAbortCtrl.abort();
        }, 35000);
        var myTimeout = diagTimeoutId;

        function resetState() {
            if (diagAbortCtrl === myCtrl) {
                /* We're still the active request — re-enable UI */
                document.querySelectorAll('[data-tool]').forEach(function (b) {
                    b.disabled = false;
                });
                if (cancelBtn) cancelBtn.style.display = 'none';
                diagAbortCtrl = null;
            }
            /* Always clear our own timer, never a newer request's timer */
            if (diagTimeoutId === myTimeout) {
                clearTimeout(diagTimeoutId);
                diagTimeoutId = null;
            }
            output.className = 'diag-output';
        }

        api('/diagnose/' + tool, { method: 'POST', body: params,
                                    signal: myCtrl.signal })
            .then(function (data) {
                resetState();
                if (data && data.output) {
                    output.textContent = data.output;
                    output.style.color = '#333';
                } else {
                    output.textContent = 'No response from backend';
                    output.style.color = '#999';
                }
            })
            .catch(function (err) {
                /* Aborted because a newer tool was clicked — silently discard.
                 * The new request already shows "Running..." in the output. */
                if (err.name === 'AbortError' && diagAbortCtrl !== myCtrl) return;
                resetState();
                if (err.name === 'AbortError') {
                    output.textContent = 'Cancelled.';
                    output.style.color = '#999';
                } else {
                    output.textContent = 'Error: ' + (err.message || 'unknown');
                    output.style.color = '#c62828';
                }
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

    /* Cancel button for in-flight diagnostic requests */
    var _diagCancelBtn = document.getElementById('diag-cancel');
    if (_diagCancelBtn) {
        _diagCancelBtn.addEventListener('click', function () {
            if (diagAbortCtrl) diagAbortCtrl.abort();
        });
    }

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
            if (!file.name.match(/\.tar\.gz$/i)) {
                showToast('Invalid firmware file: must be .tar.gz format', 'error');
                return;
            }

            /* Reject files larger than 64MB */
            if (file.size > 64 * 1024 * 1024) {
                showToast('Firmware file too large (max 64 MB)', 'error');
                return;
            }

            confirmAction('Installing firmware will reboot the device. Continue?').then(function (ok) {
                if (!ok) return;

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
                    /* Poll progress.  Capped at 30 minutes (900 ticks
                     * × 2s) — without a cap a stuck progress endpoint
                     * leaks the interval until reload.  Errors clear
                     * the interval too. */
                    var ticks = 0;
                    var wasInstalling = false;
                    var pollId = setInterval(function () {
                        if (++ticks > 900) {
                            clearInterval(pollId);
                            fwInstallBtn.textContent = 'Install Firmware';
                            fwInstallBtn.disabled = false;
                            showToast('Firmware install timed out', 'error');
                            return;
                        }
                        api('/system/firmware/progress')
                            .then(function (prog) {
                                if (!prog) { clearInterval(pollId); return; }
                                fwInstallBtn.textContent =
                                    'Installing... ' + (prog.percent || 0) + '%';
                                if (!prog.done && !prog.error) wasInstalling = true;
                                if (prog.percent >= 100 || prog.done) {
                                    clearInterval(pollId);
                                    if (prog.error) {
                                        fwInstallBtn.textContent = 'Install Firmware';
                                        fwInstallBtn.disabled = false;
                                        showToast('Firmware install failed: ' + (prog.message || 'unknown error'), 'error');
                                    } else {
                                        /* Take ownership of the reboot transition.
                                         * Block keepalive and api() from firing a
                                         * spurious "session expired" when webd
                                         * restarts with an empty session store. */
                                        window.__sg_fwRebooting = true;
                                        if (typeof window.__sg_stopKeepalive === 'function')
                                            window.__sg_stopKeepalive();
                                        fwInstallBtn.textContent = 'Rebooting…';
                                        fwInstallBtn.disabled = true;
                                        showToast('Firmware installed — device is rebooting. Redirecting to login…', 'success');
                                        setTimeout(function () { window.location.href = 'login.html'; }, 5000);
                                    }
                                }
                            })
                            .catch(function () {
                                clearInterval(pollId);
                                if (wasInstalling) {
                                    /* Network error after progress started — device rebooted
                                     * before JS saw done=true.  Own the transition cleanly. */
                                    window.__sg_fwRebooting = true;
                                    if (typeof window.__sg_stopKeepalive === 'function')
                                        window.__sg_stopKeepalive();
                                    fwInstallBtn.textContent = 'Rebooting…';
                                    fwInstallBtn.disabled = true;
                                    showToast('Device is rebooting — redirecting to login…', 'success');
                                    setTimeout(function () { window.location.href = 'login.html'; }, 5000);
                                } else {
                                    fwInstallBtn.textContent = 'Install Firmware';
                                    fwInstallBtn.disabled = false;
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
        });
    }

    /* ================================================================
     *  REBOOT — restart the device via POST /api/system/reboot
     * ================================================================ */
    var rebootBtn = document.getElementById('btn-reboot');
    if (rebootBtn) {
        rebootBtn.addEventListener('click', function () {
            confirmAction(
                'This will restart the device. All active sessions will be dropped. Continue?'
            ).then(function (ok) {
                if (!ok) return;
                rebootBtn.disabled = true;
                rebootBtn.textContent = 'Rebooting...';
                api('/system/reboot', { method: 'POST', body: {} })
                    .then(function () {
                        showToast('Device is rebooting — you will be disconnected', 'info');
                    })
                    .catch(function (err) {
                        showToast(err.message || 'Reboot failed', 'error');
                        rebootBtn.disabled = false;
                        rebootBtn.textContent = 'Reboot';
                    });
            });
        });
    }

    /* ================================================================
     *  PAGE-LOAD DATA FETCHING
     * ================================================================ */

    function loadEntityPage(entity, table) {
        var config = ENTITIES[entity];
        if (!config) return Promise.resolve();
        var tbody = table.querySelector('tbody');
        var colCount = table.querySelectorAll('thead th').length;
        if (tbody) {
            tbody.innerHTML = '';
            tbody.appendChild(buildLoadingRow(colCount));
        }
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
                    /* Firmware reboot in progress — the firmware handler owns
                     * the redirect, don't fire a spurious "session expired". */
                    if (window.__sg_fwRebooting) return null;
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

    /* Start keepalive — initial check + interval.
     * Tracked so we can stop it on logout to prevent stray fetches
     * after the session is gone. */
    var keepaliveTimer = null;
    keepaliveCheck();
    keepaliveTimer = setInterval(keepaliveCheck, KEEPALIVE_INTERVAL);
    window.__sg_stopKeepalive = function () {
        if (keepaliveTimer) {
            clearInterval(keepaliveTimer);
            keepaliveTimer = null;
        }
    };

    /* ================================================================
     *  NETWORK OVERVIEW — fetch live stats for summary cards
     * ================================================================ */

    /* ── Network overview helpers ───────────────────────────────── */

    /* Set "<value> / <total>" inside a gauge value cell. */
    function setGaugeFraction(elId, value, total) {
        var el = document.getElementById(elId);
        if (!el) return;
        el.textContent = '';
        el.appendChild(document.createTextNode(String(value)));
        el.appendChild(makeSpan('gauge-unit', ' / ' + total));
    }

    function renderNetSummary() {
        var totalIf = ifaceData.length;
        var upIf = 0;
        ifaceData.forEach(function (iface) { if (iface.status === 'UP') upIf++; });
        setGaugeFraction('net-ifaces-up', upIf, totalIf);
        var det = document.getElementById('net-ifaces-detail');
        if (det) {
            var down = totalIf - upIf;
            det.textContent = down + ' interface' + (down !== 1 ? 's' : '') + ' down';
        }

        var active = 0, disabled = 0;
        routeData.forEach(function (r) {
            if (r.status === 'ACTIVE') active++; else disabled++;
        });
        var rel = document.getElementById('net-routes-up');
        if (rel) rel.textContent = String(active);
        var rdet = document.getElementById('net-routes-detail');
        if (rdet) rdet.textContent = disabled + ' disabled';

        /* Throughput / ARP — no backend API yet */
        var tp = document.getElementById('net-throughput');
        if (tp) {
            tp.textContent = '--';
            tp.appendChild(makeSpan('gauge-unit', ' Mbps'));
        }
        var tpd = document.getElementById('net-throughput-detail');
        if (tpd) tpd.textContent = 'Unknown';
        var arp = document.getElementById('net-arp');
        if (arp) arp.textContent = '--';
        var arpd = document.getElementById('net-arp-detail');
        if (arpd) arpd.textContent = 'Unknown';
    }

    function renderNetTrafficTable() {
        var tbody = document.getElementById('net-traffic-tbody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (ifaceData.length === 0) {
            tbody.appendChild(buildEmptyRow(4));
            return;
        }
        var frag = document.createDocumentFragment();
        ifaceData.forEach(function (iface) {
            var tr = document.createElement('tr');
            var nameTd = document.createElement('td');
            nameTd.appendChild(makeSpan(
                'status-dot ' + (iface.status === 'UP' ? 'up' : 'down'), null));
            nameTd.appendChild(document.createTextNode(iface.name));
            tr.appendChild(nameTd);
            tr.appendChild(makeTd(iface.ip));
            tr.appendChild(makeTd(iface.speed));
            tr.appendChild(makeTd(iface.status));
            frag.appendChild(tr);
        });
        tbody.appendChild(frag);
    }

    function renderNetDhcpTable(dhcpData) {
        var tbody = document.getElementById('net-dhcp-tbody');
        if (!tbody) return;
        tbody.innerHTML = '';
        var entries = (dhcpData && dhcpData.entries) || [];
        if (entries.length === 0) {
            tbody.appendChild(buildEmptyRow(4));
            return;
        }
        var frag = document.createDocumentFragment();
        entries.forEach(function (pool) {
            var st = pool.status || 'enable';
            var enabled = (st === 'enable');
            var range = (pool['start-ip'] || '') + ' - ' + (pool['end-ip'] || '');

            var tr = document.createElement('tr');
            tr.appendChild(makeTd(pool.id));
            tr.appendChild(makeTd(pool['interface'] || ''));
            tr.appendChild(makeTd(range));

            var statusTd = document.createElement('td');
            statusTd.appendChild(makeSpan(
                'status-dot ' + (enabled ? 'up' : 'disabled'), null));
            statusTd.appendChild(document.createTextNode(
                enabled ? 'Enabled' : 'Disabled'));
            tr.appendChild(statusTd);

            frag.appendChild(tr);
        });
        tbody.appendChild(frag);
    }

    function renderDhcpLeases() {
        return api('/monitor/dhcp-leases').then(function (data) {
            var tbody = document.getElementById('dhcp-leases-tbody');
            if (!tbody) return;
            tbody.innerHTML = '';
            var leases = (data && data.leases) || [];
            if (leases.length === 0) {
                tbody.appendChild(buildEmptyRow(6));
                return;
            }
            var now = Math.floor(Date.now() / 1000);
            var frag = document.createDocumentFragment();
            leases.forEach(function (l) {
                var expires = l.expires || 0;
                var remaining = expires - now;
                var expStr = expires
                    ? new Date(expires * 1000).toLocaleString()
                    : '-';
                var remStr = remaining > 0
                    ? formatDuration(remaining)
                    : 'Expired';
                var tr = document.createElement('tr');
                tr.appendChild(makeTd(l.pool || ''));
                tr.appendChild(makeTd(l.ip || ''));
                tr.appendChild(makeTd(l.mac || ''));
                tr.appendChild(makeTd(l.hostname || ''));
                tr.appendChild(makeTd(expStr));
                tr.appendChild(makeTd(remStr));
                frag.appendChild(tr);
            });
            tbody.appendChild(frag);
        }).catch(function () {
            var tbody = document.getElementById('dhcp-leases-tbody');
            if (tbody) tbody.appendChild(buildEmptyRow(6));
        });
    }

    var sessionData = [];
    var sessState = { page: 0, pageSize: 25, search: '', proto: '', state: '' };

    function renderSessions() {
        return api('/monitor/sessions').then(function (data) {
            var summaryEl = document.getElementById('session-summary');
            if (summaryEl) {
                if (!data || !data.loaded) {
                    summaryEl.innerHTML = '<span style="color:var(--status-disabled)">Connection tracking not available</span>';
                } else {
                    /* Build with DOM nodes so server-supplied data.active
                     * can never reach innerHTML unescaped (XSS-safe, matching
                     * the rest of this file's textContent discipline). */
                    summaryEl.textContent = 'Active: ';
                    var strongEl = document.createElement('strong');
                    strongEl.textContent = String(parseInt(data.active, 10) || 0);
                    summaryEl.appendChild(strongEl);
                }
            }
            sessionData = (data && data.sessions) || [];
            sessState.page = 0;
            renderSessionRows();
        }).catch(function () {
            sessionData = [];
            renderSessionRows();
        });
    }

    function renderSessionRows() {
        var tbody = document.getElementById('sess-tbody');
        var info = document.getElementById('sess-pager-info');
        var pageNum = document.getElementById('sess-page-num');
        var prevBtn = document.getElementById('sess-prev');
        var nextBtn = document.getElementById('sess-next');
        if (!tbody) return;

        var filtered = sessionData;

        if (sessState.proto) {
            filtered = filtered.filter(function (s) { return s.proto === sessState.proto; });
        }

        if (sessState.state) {
            filtered = filtered.filter(function (s) {
                return (s.state || '-') === sessState.state;
            });
        }

        if (sessState.search) {
            var q = sessState.search.toLowerCase();
            filtered = filtered.filter(function (s) {
                return (s.src || '').toLowerCase().indexOf(q) !== -1 ||
                       (s.dst || '').toLowerCase().indexOf(q) !== -1 ||
                       (s.proto || '').toLowerCase().indexOf(q) !== -1;
            });
        }

        var total = filtered.length;
        var totalPages = Math.max(1, Math.ceil(total / sessState.pageSize));
        if (sessState.page >= totalPages) sessState.page = totalPages - 1;
        if (sessState.page < 0) sessState.page = 0;

        var start = sessState.page * sessState.pageSize;
        var end = Math.min(start + sessState.pageSize, total);
        var page = filtered.slice(start, end);

        tbody.innerHTML = '';
        if (page.length === 0) {
            tbody.appendChild(buildEmptyRow(10));
        } else {
            var frag = document.createDocumentFragment();
            page.forEach(function (s) {
                var stateStr = s.state || '-';
                var bytesStr = s.bytes ? formatBytes(parseInt(s.bytes, 10) || 0) : '-';

                var tr = document.createElement('tr');
                /* Carry the exact tuple so right-click / bulk delete address
                 * precisely the flow the operator sees (src/dst are ip:port). */
                tr.dataset.proto = s.proto || '';
                tr.dataset.src = s.src || '';
                tr.dataset.dst = s.dst || '';

                var cbTd = document.createElement('td');
                cbTd.className = 'td-checkbox';
                var cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.className = 'sess-row-select';
                cbTd.appendChild(cb);
                tr.appendChild(cbTd);

                tr.appendChild(makeTd((s.proto || '').toUpperCase()));
                tr.appendChild(makeTd(s.src || ''));
                tr.appendChild(makeTd(s.dst || ''));

                var stateTd = document.createElement('td');
                var cls = (stateStr === 'ESTABLISHED') ? 'status-dot up' :
                          (stateStr === '-' ? 'status-dot' : 'status-dot warn');
                stateTd.appendChild(makeSpan(cls, null));
                stateTd.appendChild(document.createTextNode(stateStr));
                tr.appendChild(stateTd);

                tr.appendChild(makeTd(s.policy || '-'));
                tr.appendChild(makeTd(s.iif || '-'));
                tr.appendChild(makeTd(s.oif || '-'));
                tr.appendChild(makeTd(s.pkts || '0'));
                tr.appendChild(makeTd(bytesStr));

                frag.appendChild(tr);
            });
            tbody.appendChild(frag);
        }

        if (info) info.textContent = total === 0 ? 'No sessions' :
            'Showing ' + (total === 0 ? 0 : start + 1) + '–' + end + ' of ' + total;
        if (pageNum) pageNum.textContent = totalPages === 0 ? '0 / 0' : (sessState.page + 1) + ' / ' + totalPages;
        if (prevBtn) prevBtn.disabled = sessState.page === 0;
        if (nextBtn) nextBtn.disabled = sessState.page >= totalPages - 1;

        /* Rows were rebuilt — any prior tick is gone from the DOM, so drop
         * the stale select-all + bulk-bar state. */
        var selAll = document.getElementById('sess-select-all');
        if (selAll) selAll.checked = false;
        updateSessBulkBar();
    }

    /* Bind session pager controls */
    var sessPrev = document.getElementById('sess-prev');
    var sessNext = document.getElementById('sess-next');
    var sessPageSize = document.getElementById('sess-page-size');
    var sessSearchInput = document.getElementById('sess-search');

    if (sessPrev) sessPrev.addEventListener('click', function () {
        if (sessState.page > 0) { sessState.page--; renderSessionRows(); }
    });
    if (sessNext) sessNext.addEventListener('click', function () {
        sessState.page++;
        renderSessionRows();
    });
    if (sessPageSize) sessPageSize.addEventListener('change', function () {
        sessState.pageSize = parseInt(this.value, 10);
        sessState.page = 0;
        renderSessionRows();
    });
    if (sessSearchInput) sessSearchInput.addEventListener('input', debounce(function () {
        sessState.search = sessSearchInput.value;
        sessState.page = 0;
        renderSessionRows();
    }, 150));

    var sessFilterProto = document.getElementById('sess-filter-proto');
    var sessFilterState = document.getElementById('sess-filter-state');
    var sessFilterClear = document.getElementById('sess-filter-clear');

    if (sessFilterProto) sessFilterProto.addEventListener('change', function () {
        sessState.proto = this.value;
        sessState.page = 0;
        renderSessionRows();
    });

    if (sessFilterState) sessFilterState.addEventListener('change', function () {
        sessState.state = this.value;
        sessState.page = 0;
        renderSessionRows();
    });

    if (sessFilterClear) sessFilterClear.addEventListener('click', function () {
        sessState.search = '';
        sessState.proto = '';
        sessState.state = '';
        sessState.page = 0;
        if (sessSearchInput) sessSearchInput.value = '';
        if (sessFilterProto) sessFilterProto.value = '';
        if (sessFilterState) sessFilterState.value = '';
        renderSessionRows();
    });

    /* ============================================================
     *  Session delete — right-click one, multi-select, or by filter.
     *  All route through POST /monitor/sessions/clear (mgmtd enforces
     *  admin and reports matched/deleted/failed honestly). Listeners are
     *  bound once here; per-row data lives on the <tr> from render.
     * ============================================================ */

    function sessionDelete(proto, src, dst) {
        return api('/monitor/sessions/clear', {
            method: 'POST',
            body: { proto: proto, src: src, dst: dst }
        });
    }

    /* One honest toast from a clear/delete result. kv_to_json makes every
     * value a string, so parse before comparing ("0" is truthy in JS). */
    function reportClear(r, verb) {
        var m = parseInt(r && r.matched, 10) || 0;
        var d = parseInt(r && r.deleted, 10) || 0;
        var f = parseInt(r && r.failed, 10) || 0;
        var incomplete = r && r.dump_complete === '0';
        if (m === 0) { showToast('No sessions matched', 'info'); return; }
        if (f > 0 || incomplete) {
            showToast(verb + ' ' + d + ' of ' + m +
                      (f ? ' · ' + f + ' failed' : '') +
                      (incomplete ? ' · incomplete' : ''), 'warn');
        } else {
            showToast(verb + ' ' + d + ' session' + (d === 1 ? '' : 's'), 'success');
        }
    }

    function selectedSessRows() {
        return Array.prototype.slice.call(
            document.querySelectorAll('#sess-tbody .sess-row-select:checked'))
            .map(function (cb) { return cb.closest('tr'); });
    }

    function updateSessBulkBar() {
        var bar = document.getElementById('sess-bulk-action-bar');
        if (!bar) return;
        var n = selectedSessRows().length;
        bar.style.display = n ? 'flex' : 'none';
        var count = document.getElementById('sess-bulk-count');
        if (count) count.textContent = n + ' selected';
    }

    function clearSessSelection() {
        document.querySelectorAll('#sess-tbody .sess-row-select:checked').forEach(function (cb) {
            cb.checked = false;
            var tr = cb.closest('tr');
            if (tr) tr.classList.remove('row-selected');
        });
        var selAll = document.getElementById('sess-select-all');
        if (selAll) selAll.checked = false;
        updateSessBulkBar();
    }

    /* Right-click a row → delete that exact flow. */
    var sessCtx = document.getElementById('sess-context-menu');
    var sessCtxRow = null;
    if (sessCtx) {
        document.addEventListener('contextmenu', function (e) {
            var row = e.target.closest('#sess-tbody tr');
            if (!row || !row.dataset.src) { sessCtx.style.display = 'none'; return; }
            e.preventDefault();
            sessCtxRow = row;
            sessCtx.style.display = 'block';
            var rect = sessCtx.getBoundingClientRect();
            sessCtx.style.left = Math.min(e.clientX, window.innerWidth - rect.width - 4) + 'px';
            sessCtx.style.top = Math.min(e.clientY, window.innerHeight - rect.height - 4) + 'px';
        });
        document.addEventListener('click', function () { sessCtx.style.display = 'none'; });
        sessCtx.addEventListener('click', function (e) {
            if (!e.target.closest('[data-action="delete-session"]') || !sessCtxRow) return;
            e.stopPropagation();
            sessCtx.style.display = 'none';
            var row = sessCtxRow;
            confirmAction('Delete session ' + row.dataset.src + ' → ' + row.dataset.dst + '?')
                .then(function (ok) {
                    if (!ok) return;
                    sessionDelete(row.dataset.proto, row.dataset.src, row.dataset.dst)
                        .then(function (res) { reportClear(res, 'Deleted'); renderSessions(); })
                        .catch(function (err) { showToast(err.message || 'Delete failed', 'error'); });
                });
        });
    }

    /* Checkbox selection → bulk bar. */
    var sessTbodyEl = document.getElementById('sess-tbody');
    if (sessTbodyEl) sessTbodyEl.addEventListener('change', function (e) {
        if (!e.target.classList || !e.target.classList.contains('sess-row-select')) return;
        var tr = e.target.closest('tr');
        if (tr) tr.classList.toggle('row-selected', e.target.checked);
        updateSessBulkBar();
    });

    var sessSelectAll = document.getElementById('sess-select-all');
    if (sessSelectAll) sessSelectAll.addEventListener('change', function () {
        var on = this.checked;
        document.querySelectorAll('#sess-tbody .sess-row-select').forEach(function (cb) {
            cb.checked = on;
            var tr = cb.closest('tr');
            if (tr) tr.classList.toggle('row-selected', on);
        });
        updateSessBulkBar();
    });

    var sessBulkCloseBtn = document.getElementById('sess-bulk-close');
    if (sessBulkCloseBtn) sessBulkCloseBtn.addEventListener('click', clearSessSelection);

    var sessBulkDeleteBtn = document.getElementById('sess-bulk-delete');
    if (sessBulkDeleteBtn) sessBulkDeleteBtn.addEventListener('click', function () {
        var rows = selectedSessRows();
        if (!rows.length) return;
        var tuples = rows.map(function (r) {
            return { proto: r.dataset.proto, src: r.dataset.src, dst: r.dataset.dst };
        });
        confirmAction('Delete ' + tuples.length + ' selected session' +
                      (tuples.length === 1 ? '' : 's') + '?').then(function (ok) {
            if (!ok) return;
            /* mgmtd caps a batch at 64 tuples; chunk well under that. */
            var chunks = [];
            for (var i = 0; i < tuples.length; i += 48)
                chunks.push(tuples.slice(i, i + 48));
            var tot = { matched: 0, deleted: 0, failed: 0, incomplete: false };
            var chain = Promise.resolve();
            chunks.forEach(function (ch) {
                chain = chain.then(function () {
                    return api('/monitor/sessions/clear', { method: 'POST', body: { tuples: ch } })
                        .then(function (res) {
                            tot.matched += parseInt(res.matched, 10) || 0;
                            tot.deleted += parseInt(res.deleted, 10) || 0;
                            tot.failed += parseInt(res.failed, 10) || 0;
                            if (res.dump_complete === '0') tot.incomplete = true;
                        })
                        .catch(function () { tot.failed += ch.length; });
                });
            });
            chain.then(function () {
                reportClear({
                    matched: String(tot.matched),
                    deleted: String(tot.deleted),
                    failed: String(tot.failed),
                    dump_complete: tot.incomplete ? '0' : '1'
                }, 'Deleted');
                clearSessSelection();
                renderSessions();
            });
        });
    });

    /* Clear-by-filter modal — fields match exactly what mgmtd can filter. */
    var sessClearBtn = document.getElementById('sess-clear-btn');
    if (sessClearBtn) sessClearBtn.addEventListener('click', function () {
        var pr = document.getElementById('scf-proto');
        if (pr) pr.value = (sessFilterProto && sessFilterProto.value) || '';   /* prefill */
        ['src', 'dst', 'policy', 'iif', 'oif'].forEach(function (k) {
            var el = document.getElementById('scf-' + k);
            if (el) el.value = '';
        });
        openModal('form-sess-clear');
    });

    var scfSubmit = document.getElementById('scf-submit');
    if (scfSubmit) scfSubmit.addEventListener('click', function () {
        var body = {};
        ['proto', 'src', 'dst', 'policy', 'iif', 'oif'].forEach(function (k) {
            var el = document.getElementById('scf-' + k);
            var v = el ? el.value.trim() : '';
            if (v) body[k] = v;
        });
        if (!Object.keys(body).length) { showToast('Set at least one field', 'error'); return; }
        confirmAction('Clear all sessions matching this filter?').then(function (ok) {
            if (!ok) return;
            api('/monitor/sessions/clear', { method: 'POST', body: body })
                .then(function (res) {
                    closeModal(false);
                    reportClear(res, 'Cleared');
                    renderSessions();
                })
                .catch(function (err) { showToast(err.message || 'Clear failed', 'error'); });
        });
    });

    function formatBytes(n) {
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
        return (n / (1024 * 1024)).toFixed(1) + ' MB';
    }

    function renderNetworkOverview() {
        return Promise.all([
            fetchIfaceData().catch(function () {}),
            fetchRouteData().catch(function () {}),
            api('/config/network_dhcp-server').catch(function () { return null; })
        ]).then(function (results) {
            renderNetSummary();
            renderNetTrafficTable();
            renderNetDhcpTable(results[2]);
            renderRouteRows();
        });
    }

    /* ================================================================
     *  DYNAMIC SELECT POPULATION — fetch real data for form dropdowns
     * ================================================================ */

    /* Replace a <select>'s contents with options from API entries.
     * Preserves a single hardcoded option (e.g. "any" / "all") when
     * preserveValue is given.  Each entry uses entry.id (or .name) as
     * both option value and label.  Idempotent — safe to call after
     * the cached API result returns the same data. */
    function populateSelectFrom(sel, entries, preserveValue) {
        if (!sel) return;
        var preserved = null;
        if (preserveValue) {
            for (var pi = 0; pi < sel.options.length; pi++) {
                if (sel.options[pi].value === preserveValue) {
                    preserved = sel.options[pi];
                    break;
                }
            }
        }
        sel.innerHTML = '';
        if (preserved) sel.appendChild(preserved);
        entries.forEach(function (e) {
            var eid = e.id || e.name || '';
            var opt = document.createElement('option');
            opt.value = eid;
            opt.textContent = eid;
            sel.appendChild(opt);
        });
    }

    function populateIfaceSelects() {
        return cachedApi('/config/system_interface').then(function (data) {
            if (!data || !data.entries) return;
            var userIfaces = data.entries.filter(function (e) { return e.system !== 'yes'; });
            document.querySelectorAll('.iface-select').forEach(function (sel) {
                populateSelectFrom(sel, userIfaces, 'any');
            });
        });
    }

    function populateProfileSelect() {
        var sel = document.getElementById('admin-profile-select');
        if (!sel) return Promise.resolve();
        return cachedApi('/config/system_admin-profile').then(function (data) {
            if (!data || !data.entries) return;
            populateSelectFrom(sel, data.entries, null);
        });
    }

    function populateAddrSelects() {
        return cachedApi('/config/firewall_address').then(function (data) {
            if (!data || !data.entries) return;
            document.querySelectorAll('.addr-select').forEach(function (sel) {
                populateSelectFrom(sel, data.entries, 'all');
            });
        });
    }

    function populateSvcSelects() {
        return cachedApi('/config/firewall_service').then(function (data) {
            if (!data || !data.entries) return;
            document.querySelectorAll('.svc-select').forEach(function (sel) {
                populateSelectFrom(sel, data.entries, 'all');
            });
        });
    }

    /* IPS profile select on the policy form. Drop "none" (replaced by the
     * ips-status toggle); the built-in "default" (all signatures) is always first. */
    function populateIpsProfileSelects() {
        return cachedApi('/config/security_ips-profile').then(function (data) {
            var entries = (data && data.entries) ? data.entries : [];
            document.querySelectorAll('.ips-profile-select').forEach(function (sel) {
                /* profiles are numeric-id now; default profile id is 1 */
                var cur = sel.value || '1';
                sel.innerHTML = '';
                entries.forEach(function (e) {
                    var eid = e.id || '';
                    if (!eid) return;
                    var opt = document.createElement('option');
                    opt.value = eid;                 /* the ref is the numeric id */
                    opt.textContent = (e.name ? e.name : ('profile ' + eid)) +
                                      ' (' + eid + ')';
                    sel.appendChild(opt);
                });
                selectOption(sel, cur);
            });
        }).catch(function () {});
    }

    /* SSL inspection profile select on the policy form. Default is the
     * built-in "no-inspection" (always first, always selected by default);
     * configured profiles follow. Built fresh so no-inspection is never
     * duplicated even though it's a real DB entry. */
    function populateSslProfileSelects() {
        return cachedApi('/config/security_ssl-inspection-profile').then(function (data) {
            var entries = (data && data.entries) ? data.entries : [];
            document.querySelectorAll('.ssl-profile-select').forEach(function (sel) {
                var cur = sel.value || 'no-inspection';
                sel.innerHTML = '';
                var def = document.createElement('option');
                def.value = 'no-inspection';
                def.textContent = 'no-inspection';
                sel.appendChild(def);
                entries.forEach(function (e) {
                    var eid = e.id || e.name || '';
                    if (!eid || eid === 'no-inspection') return;
                    var opt = document.createElement('option');
                    opt.value = eid;
                    opt.textContent = eid;
                    sel.appendChild(opt);
                });
                sel.value = cur;
                if (!sel.value) sel.value = 'no-inspection';
            });
        }).catch(function () {});
    }

    /* Run on page load — populate all dynamic selects */
    populateIfaceSelects();
    populateProfileSelect();
    populateAddrSelects();
    populateSvcSelects();
    populateIpsProfileSelects();
    populateSslProfileSelects();

    function loadFirmwareInfo() {
        return api('/system/firmware').then(function (data) {
            if (!data) return;
            var page = document.getElementById('page-sys-firmware');
            if (!page) return;
            ['version', 'build', 'kernel', 'installed'].forEach(function (key) {
                if (!data[key]) return;
                var el = page.querySelector('[data-fw="' + key + '"]');
                if (el) el.textContent = data[key];
            });
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
