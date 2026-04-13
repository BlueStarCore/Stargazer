# Stargazer NGFW — Web UI Structure

> For developer review. Covers architecture, file roles, data flow, patterns, and known constraints.

## File Map

```
webui/www/
  index.html              4 lines   Auto-redirect to login.html
  login.html            228 lines   Login page (standalone, inline CSS)
  home.html             860 lines   Main dashboard (SPA shell, all pages)

  css/
    fonts.css            14 lines   Shared @font-face (Press Start 2P)
    stargazer.css      2274 lines   All component styles, responsive, a11y

  js/
    sg-common.js        107 lines   Shared utilities (apiCall, escHTML, HiDPI canvas, password validation)
    login.js            610 lines   Login page: starry sky animation, auth form, forced password change
    app.js             4002 lines   Dashboard app: routing, gauges, tables, modals, CRUD, drag-reorder

  fonts/
    PressStart2P-latin.woff2  13KB  Self-hosted pixel font (latin subset)

  img/
    icon.png              4KB       App icon (225x225 PNG)
```

**Total: 8099 lines, ~250KB unminified. Zero external dependencies.**

---

## Architecture

### Page Flow

```
Browser
  → index.html (redirect)
  → login.html
       ├── css/fonts.css (shared font)
       ├── js/sg-common.js (apiCall, escHTML)
       └── js/login.js (sky animation, auth)
            │
            │ POST /api/auth/login → cookie sg_sid
            ▼
  → home.html (SPA)
       ├── css/fonts.css (same cached font)
       ├── css/stargazer.css (all styles)
       ├── js/sg-common.js (shared)
       └── js/app.js (everything)
```

### SPA Routing (home.html)

Single HTML file, all pages rendered as `<div class="page">` blocks toggled by JS.
No URL hash routing — page state stored in `sessionStorage.sg_page`.

```
home.html
  ├── .sidebar (nav categories + sub-items)
  ├── .topbar (search palette, conn status, user dropdown)
  └── .content
       ├── #page-dashboard      (gauges + interface table)
       ├── #page-resources      (SoC/RAM/disk details + process table)
       ├── #page-home-network   (overview cards + route flows + DHCP)
       ├── #page-interfaces     (CRUD table + modal)
       ├── #page-dhcp           (leases + pools CRUD)
       ├── #page-routes         (static routes CRUD)
       ├── #page-nat            (NAT rules CRUD, drag-reorder)
       ├── #page-fw-policies    (firewall policies CRUD, drag-reorder)
       ├── #page-fw-addresses   (address objects CRUD)
       ├── #page-fw-services    (service objects CRUD)
       ├── #page-fw-sessions    (stub — no backend yet)
       ├── #page-sys-settings   (hostname, DNS, NTP — apply/reset)
       ├── #page-sys-admin      (admin accounts CRUD)
       ├── #page-sys-profiles   (admin profiles, read-only)
       ├── #page-sys-password   (password policy — apply/reset)
       ├── #page-sys-firmware   (version info, upload, recovery)
       └── #page-diag-tools     (ping, traceroute, nslookup, arping)
```

---

## Data Flow

### API Communication

```
Browser ──fetch()──→ stargazer-webd (Mongoose HTTP, port 80/443)
                          │
                     Unix socket IPC
                          │
                          ▼
                     stargazer-mgmtd (root daemon, SQLite DB)
```

- **Auth**: HttpOnly cookie `sg_sid`, no manual token
- **Session**: 15 min idle timeout, keepalive via `GET /api/auth/whoami` every 60s
- **Caching**: `apiCache` with 5s TTL for `/config/*` selects; invalidated on mutation
- **Error handling**: `api()` returns `null` on network failure → callers show placeholder state
- **Connection status**: `ConnStatus` module tracks ok/error/unreachable/reconnect states → topbar pill

### API Endpoints Used

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | /api/auth/login | Authenticate |
| POST | /api/auth/logout | Clear session |
| POST | /api/auth/change-password | Change password |
| GET | /api/auth/whoami | Session keepalive + user info |
| GET | /api/config/{type} | List entries |
| GET | /api/config/{type}/{id} | Get single entry |
| POST | /api/config/{type} | Create entry |
| PUT | /api/config/{type}/{id} | Update entry |
| DELETE | /api/config/{type}/{id} | Delete entry |
| PATCH | /api/config/{type}/{id}/move | Reorder (sequence) |
| GET | /api/system/resources | Dashboard gauges |
| GET | /api/system/resources/detail | Resource page gauges |
| GET | /api/system/resources/ram | RAM breakdown |
| GET | /api/system/resources/disk | Disk info |
| GET | /api/system/resources/proctop | Top processes |
| GET | /api/system/firmware | Firmware version |
| POST | /api/system/firmware/upgrade | Upload firmware (stub) |
| POST | /api/system/reboot | System reboot |
| POST | /api/diagnose/{ping,traceroute,nslookup,arping} | Network tools |

---

## app.js Internal Structure (4002 lines)

```
IIFE wrapper
  │
  ├── Shared helpers (debounce, toggleSort, isStatusEnabled)
  ├── API cache (cachedApi, invalidateApiCache, 5s TTL)
  ├── Sidebar toggle + navigation (setActivePage, refreshPage)
  ├── API wrapper (api(), ConnStatus module)
  ├── Toast notifications (stacking, auto-dismiss)
  ├── Gauge rendering (drawGauge, gaugeCache, COLOR_* constants)
  ├── Resource details (renderRamDetails, renderDiskDetails, renderProcTop)
  ├── Poll manager (5s interval, visibility-aware, per-page pollers)
  ├── Route flow widget (sort, paginate, search)
  ├── Interface table (sort, search, group-by-type)
  ├── Generic table sort (naturalCompare, Schwartzian transform)
  ├── Modal lifecycle (openModal, closeModal, focus trap, escape handler)
  ├── ENTITIES registry (9 entity types, field configs, form IDs)
  ├── Selection state (multi-select checkboxes, bulk action bar)
  ├── Confirm dialog (confirmAction, styled replacement for confirm())
  ├── Inline prompt (promptInput, for bulk edit values)
  ├── Bulk actions (delete with Promise.all, enable/disable, bulk-set)
  ├── Double-click edit (openEditModal, fetchEntityData, populateForm)
  ├── Context menu (right-click, edit/delete/enable/disable)
  ├── Entity CRUD (deleteRow, setRowStatus, formSubmit, submitConfigEntry)
  ├── Drag-to-reorder (dragstart/over/drop/end, PATCH move API)
  ├── User dropdown (keyboard nav, profile/password/logout actions)
  ├── Change password dialog (dynamic modal creation)
  ├── Table search/filter (client-side + backend search)
  ├── Topbar search palette (nav index, arrow key navigation)
  ├── File upload (filename display + title tooltip)
  ├── Form save wiring (modal Save → formSubmit → API)
  ├── Settings pages (apply/reset, SETTINGS_MAP config)
  ├── Diagnostic tools (ping/trace/nslookup/arping)
  ├── Firmware (upload validation, confirm, progress polling)
  ├── Session keepalive (whoami polling, permission change detection)
  ├── Network overview (summary cards, traffic table, DHCP, route flows)
  ├── Dynamic select population (interfaces, profiles, addresses, services)
  └── Initial page load (restore from sessionStorage)
```

---

## ENTITIES Registry

Central config object mapping entity types to their forms, fields, and behavior:

```js
ENTITIES = {
  interfaces: { configType: 'system_interface',    noCreate, allBuiltin, hasStatus },
  dhcp:       { configType: 'network_dhcp-server', hasStatus },
  routes:     { configType: 'network_route_static', hasStatus },
  nat:        { configType: 'network_nat',          hasStatus, orderable },
  policies:   { configType: 'firewall_policy',      hasStatus, orderable },
  addresses:  { configType: 'firewall_address' },
  services:   { configType: 'firewall_service' },
  admins:     { configType: 'system_admin',         customCreate },
  profiles:   { configType: 'system_admin-profile',  noCreate, allBuiltin }
}
```

Each entity has `fields[]` array mapping schema keys to table columns and form inputs.

**Flags:**
- `orderable: true` → drag-to-reorder enabled, drag handle column rendered
- `hasStatus: true` → status dot + enable/disable context menu actions
- `noCreate: true` → Create button hidden
- `allBuiltin: true` → all entries are builtin (no delete, no drag)
- `customCreate: true` → uses custom endpoint instead of generic config API

---

## CSS Architecture (stargazer.css, 2274 lines)

### Theme System

All colors defined as CSS custom properties in `:root`:

```
Sky palette:     --sky-deep, --sky-navy, --sky-mid, --sky-light
Dawn accents:    --dawn-orange, --dawn-peach, --dawn-ember, --dawn-glow
Text:            --text-primary, --text-secondary, --text-dim
Backgrounds:     --bg-content, --bg-card, --bg-row-alt
Borders:         --border-light, --border-dark
Grays:           --gray-text, --gray-text-mid, --gray-text-dim, etc.
                 --gray-bg-alt, --gray-bg-alt2, --gray-bg-card,
                 --gray-bg-muted, --gray-bg-tag
Status:          --color-success (#4caf50), --color-danger (#e53935),
                 --color-warning (#e8956a)
Typography:      --font-pixel (Press Start 2P), --font-mono (system mono)
Layout:          --sidebar-w (280px), --topbar-h (60px)
```

### Section Breakdown

| Section | Lines | Purpose |
|---------|-------|---------|
| Reset & variables | ~75 | CSS reset, `:root` vars |
| Connection banner | ~60 | Topbar status pill |
| Nav search dropdown | ~50 | Search results panel |
| Layout shell | ~10 | Flexbox app shell |
| Sidebar | ~200 | Nav categories, collapse animation |
| Topbar | ~120 | Search, user dropdown |
| Content area | ~100 | Page headers, buttons, toolbar |
| Data tables | ~100 | FortiOS-style tables |
| Dashboard gauges | ~60 | Donut ring charts |
| Route flow widget | ~200 | Flow visualization |
| Form cards | ~150 | Settings forms |
| Modals | ~200 | Clip-path reveal, CRT scanlines |
| Checkboxes & selection | ~60 | Row select, bulk bar |
| Context menu | ~40 | Right-click menu |
| Resources page | ~80 | Memory bars, usage fills |
| Page transitions | ~100 | Loading cover, scan-line reveal |
| Responsive | ~40 | Sidebar collapse, 900px breakpoint |
| Drag-to-reorder | ~30 | Handle, active, drop indicators |
| Accessibility | ~60 | Focus-visible, sr-only |
| Confirm dialog | ~30 | Styled confirm() replacement |
| Utilities | ~30 | .mt-8, .table-scroll, .gauge-value-inline |
| Toast | ~20 | Fixed-position notifications |
| Mobile 600px | ~60 | Compact layout |

### Responsive Breakpoints

```
@media (max-width: 1200px)  → Table font-size reduction
@media (max-width: 1100px)  → Resource grid single-column
@media (max-width: 900px)   → Sidebar icon-only
@media (max-width: 600px)   → Mobile compact (padding, gauge size, form layout)
```

### z-index Stack

```
page-cover:          40
bulk-action-bar:     90
modal-backdrop:     100
context-menu:       150
modal (add-form):   200
user-dropdown:      350
confirm/prompt:    2000
toast:            10000
```

---

## Security Model (Frontend)

| Measure | Implementation |
|---------|----------------|
| Auth | HttpOnly cookie `sg_sid` (no JS access to token) |
| XSS | All DOM rendering via `textContent` + DOM API, no `innerHTML` with user data |
| HTML escape | `SgCommon.escHTML()` for any value going into attributes |
| Input validation | `maxlength`, `pattern`, `type=number min/max`, `minlength` on all form inputs |
| CSP | Server sends `Content-Security-Policy: default-src 'self'` |
| Destructive actions | `confirmAction()` dialog before delete, bulk delete, firmware install, reboot |
| Session timeout | 15 min idle, keepalive detects expiry → redirect to login |
| Rate limiting | Server-side 10 req/sec on login endpoint |
| Air-gapped | Zero external resources — all fonts, icons, JS self-hosted |
| Password policy | Client-side min 8 chars + server-side `pw_check_policy()` |

---

## Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| Total JS | ~189 KB | Unminified; ~95 KB minified estimate |
| Total CSS | ~57 KB | Unminified |
| Font | 13 KB | WOFF2, single file, shared via fonts.css |
| Images | 4 KB | Single icon.png |
| First paint | ~50ms | Font-display: swap, JS at end of body |
| Poll interval | 5s | Dashboard/resources only, visibility-aware |
| Keepalive | 60s | /auth/whoami |
| Canvas gauges | Cached context | `gaugeCache{}`, no canvas.width reset per frame |
| Login sky | Offscreen cache | Pre-rendered gradient + nebula, blit per frame |
| DOM queries | Cached | `elCache{}` for gauge elements |
| Search | Debounced 150ms | Client-side filter + Enter for backend search |

---

## Known Limitations

1. **Sessions page is a stub** — table exists but no backend API populates it
2. **Firmware upload returns 501** — backend endpoint not implemented yet
3. **Throughput/ARP metrics** — show "Unknown", no backend API wired
4. **No dark mode** — theme vars ready but no toggle implemented
5. **No breadcrumbs** — deep navigation relies on sidebar highlight only
6. **No table pagination** — entity tables render all rows (route flow widget has pagination)
7. **No form inline errors** — validation errors shown as toast only
8. **Touch drag** — HTML5 drag API does not work on mobile/touch devices
9. **CPU/SoC specs hardcoded** — MT7988A details in HTML, not fetched from API (hardware-specific, intentional)

---

## Review Checklist

- [ ] Does the data flow match the backend API contract?
- [ ] Are all ENTITIES fields mapped correctly to table columns?
- [ ] Does drag-to-reorder sequence logic match backend `seq_rotate()`?
- [ ] Are ARIA attributes semantically correct?
- [ ] Do responsive breakpoints work on target screen sizes?
- [ ] Is the z-index stack correct for all overlay combinations?
- [ ] Are all `free()` calls matched to `malloc()` in backend C code?
- [ ] Does `confirmAction()` clean up its event listener on all exit paths?
- [ ] Are CSS variables used consistently (no hardcoded hex outside `:root`)?
