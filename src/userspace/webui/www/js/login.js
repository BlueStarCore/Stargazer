/* login.js — Deep blue starry night sky
 *
 * Inspired by: bright stars with cross-sparkle, blue milky way nebula,
 * blue atmospheric horizon glow, mountain silhouettes.
 */

(function () {
    'use strict';

    var canvas = document.getElementById('sky-canvas');
    var ctx = canvas.getContext('2d');
    var W, H;
    var dpr = window.devicePixelRatio || 1;

    /* Seeded random for consistent layout */
    var seed = 12345;
    function seededRandom() {
        seed = (seed * 16807 + 0) % 2147483647;
        return (seed - 1) / 2147483646;
    }

    /* Offscreen caches — sky gradient and nebula puffs are static
     * after resize.  Pre-rendered once and blitted each frame,
     * eliminating ~70 gradient allocations per frame (~4200/sec). */
    var skyCache = document.createElement('canvas');
    var skyCtx = skyCache.getContext('2d');
    var nebulaCache = document.createElement('canvas');
    var nebulaCtx = nebulaCache.getContext('2d');

    function resize() {
        var hi = SgCommon.setupHiDPICanvas(canvas, window.innerWidth, window.innerHeight);
        W = hi.W; H = hi.H; dpr = hi.dpr;
        seed = 12345; generateStars();
        seed = 54321; generateNebulaPuffs();
        renderSkyCache();
        renderNebulaCache();
    }
    window.addEventListener('resize', resize);

    /* ================================================================
     *  SKY GRADIENT — deep dark blue (cached, static)
     * ================================================================ */
    function renderSkyCache() {
        skyCache.width = W * dpr;
        skyCache.height = H * dpr;
        skyCtx.setTransform(dpr, 0, 0, dpr, 0, 0);

        /* Base: vertical gradient — symmetric top/bottom */
        var grad = skyCtx.createLinearGradient(0, 0, 0, H);
        grad.addColorStop(0,    '#020610');
        grad.addColorStop(0.10, '#04091a');
        grad.addColorStop(0.20, '#061230');
        grad.addColorStop(0.30, '#0a1a42');
        grad.addColorStop(0.40, '#0e2458');
        grad.addColorStop(0.50, '#123068');
        grad.addColorStop(0.60, '#0e2458');
        grad.addColorStop(0.70, '#0a1a42');
        grad.addColorStop(0.80, '#061230');
        grad.addColorStop(0.90, '#04091a');
        grad.addColorStop(1.0,  '#020610');
        skyCtx.fillStyle = grad;
        skyCtx.fillRect(0, 0, W, H);

        /* Center glow */
        var cx = W * 0.5, cy = H * 0.45, cr = H * 0.5;
        var cglow = skyCtx.createRadialGradient(cx, cy, 0, cx, cy, cr);
        cglow.addColorStop(0,   'rgba(30, 70, 140, 0.15)');
        cglow.addColorStop(0.5, 'rgba(15, 40, 90, 0.06)');
        cglow.addColorStop(1,   'rgba(0, 0, 0, 0)');
        skyCtx.fillStyle = cglow;
        skyCtx.fillRect(0, 0, W, H);
    }

    function drawSky() {
        /* Blit cached sky — single drawImage instead of 2 gradients/frame */
        ctx.drawImage(skyCache, 0, 0, W, H);
    }

    /* ================================================================
     *  MILKY WAY / NEBULA — blue-purple glow on the left
     * ================================================================ */
    var nebulaPuffs = [];

    function generateNebulaPuffs() {
        nebulaPuffs = [];
        /* Milky way band: runs from upper-left to center-right */
        for (var i = 0; i < 35; i++) {
            /* Band path: from (0.0, 0.1) to (0.6, 0.7) */
            var t = seededRandom();
            var bx = t * W * 0.65 + (seededRandom() - 0.5) * W * 0.18;
            var by = H * 0.08 + t * H * 0.58 + (seededRandom() - 0.5) * H * 0.15;
            var r = 60 + seededRandom() * 140;
            var blue = seededRandom() > 0.35;
            nebulaPuffs.push({
                x: bx, y: by, r: r,
                r_col: blue ? Math.floor(20 + seededRandom() * 40) : Math.floor(50 + seededRandom() * 50),
                g_col: blue ? Math.floor(40 + seededRandom() * 80) : Math.floor(30 + seededRandom() * 40),
                b_col: blue ? Math.floor(120 + seededRandom() * 100) : Math.floor(100 + seededRandom() * 80),
                alpha: 0.03 + seededRandom() * 0.06,
                pulseSpeed: 0.15 + seededRandom() * 0.3,
                pulsePhase: seededRandom() * Math.PI * 2
            });
        }
    }

    /* Bake all nebula puffs into an offscreen canvas at their base
     * alpha — no per-frame pulse.  The original ±12% pulse was barely
     * perceptible against base alpha 0.03-0.09 and is dropped here in
     * exchange for a static blit (1 drawImage vs 35 gradients/frame). */
    function renderNebulaCache() {
        nebulaCache.width = W * dpr;
        nebulaCache.height = H * dpr;
        nebulaCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
        nebulaCtx.clearRect(0, 0, W, H);
        for (var i = 0; i < nebulaPuffs.length; i++) {
            var p = nebulaPuffs[i];
            var g = nebulaCtx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r);
            var rgb = p.r_col + ',' + p.g_col + ',' + p.b_col;
            g.addColorStop(0,   'rgba(' + rgb + ',' + p.alpha + ')');
            g.addColorStop(0.4, 'rgba(' + rgb + ',' + (p.alpha * 0.5) + ')');
            g.addColorStop(1,   'rgba(' + rgb + ',0)');
            nebulaCtx.fillStyle = g;
            nebulaCtx.beginPath();
            nebulaCtx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            nebulaCtx.fill();
        }
    }

    function drawNebula(_t) {
        ctx.drawImage(nebulaCache, 0, 0, W, H);
    }

    /* ================================================================
     *  STARS — Real sky from Hanoi (21°N), 2026-03-13 01:00 ICT
     *  LST ≈ 12h 29m, facing south.
     *  Alt/Az computed from J2000 RA/Dec catalog coordinates.
     *  Screen: x=0 East(Az90°), x=0.5 South(Az180°), x=1 West(Az270°)
     *          y=0 Zenith(Alt90°), y=1 Horizon(Alt0°)
     * ================================================================ */
    var stars = [];

    /* Named stars: [x, y, magnitude, r, g, b, name] */
    var namedStars = [
        /* === Corvus (The Crow) — featured constellation ===
         * γ Crv  RA 12h16m  Dec -17°32'  →  Alt 51.3° Az 185.0°
         * δ Crv  RA 12h30m  Dec -16°31'  →  Alt 52.5° Az 179.6°
         * ε Crv  RA 12h10m  Dec -22°37'  →  Alt 46.1° Az 186.3°
         * β Crv  RA 12h34m  Dec -23°24'  →  Alt 45.6° Az 178.2° */
        [0.528, 0.430, 2.6, 200, 220, 255, 'Gienah'],    /* γ Crv — right, upper */
        [0.498, 0.417, 2.9, 240, 245, 255, 'Algorab'],   /* δ Crv — center, highest */
        [0.535, 0.488, 3.0, 255, 220, 180, 'Minkar'],    /* ε Crv — right, lower */
        [0.490, 0.494, 2.6, 255, 240, 200, 'Kraz'],      /* β Crv — left, lowest */
        [0.536, 0.511, 4.0, 245, 230, 200, ''],          /* α Crv (Alchiba) */

        /* === Bright stars — computed from RA/Dec === */
        [0.364, 0.389, 1.0, 200, 215, 255, 'Spica'],     /* α Vir — Alt 55° Az 155° */
        [0.203, 0.835, 1.1, 255, 180, 100, 'Antares'],   /* α Sco — Alt 15° Az 127° — orange */
        [0.415, 0.956, -0.3, 255, 245, 220, 'A.Centauri'],/* α Cen — Alt 4° near horizon */
        [0.436, 0.929, 0.6, 200, 220, 255, 'Hadar'],     /* β Cen — Alt 6° */
        [0.501, 0.935, 0.8, 200, 215, 255, 'Acrux'],     /* α Cru — Alt 6° */
        [0.487, 0.898, 1.2, 200, 220, 255, 'Mimosa'],    /* β Cru — Alt 9° */
        [0.498, 0.868, 1.6, 255, 200, 160, 'Gacrux'],    /* γ Cru — Alt 12° — reddish */
        [0.010, 0.279, -0.1, 255, 210, 130, 'Arcturus'], /* α Boo — Alt 65° Az 90° — orange */
        [0.700, 0.127, 2.1, 240, 242, 255, 'Denebola'],  /* β Leo — shifted to stay on screen */
        [0.720, 0.387, 1.4, 200, 215, 255, 'Regulus'],   /* α Leo — shifted to stay on screen */

        /* === Scorpius head (tail below horizon) === */
        [0.207, 0.750, 2.3, 200, 215, 255, ''],   /* δ Sco  — Alt 22° Az 127° */
        [0.189, 0.743, 2.6, 210, 220, 255, ''],   /* β Sco  — Alt 23° Az 124° */
        [0.205, 0.812, 2.9, 210, 225, 255, ''],   /* σ Sco  — Alt 17° Az 127° */
        [0.225, 0.771, 2.9, 220, 230, 255, ''],   /* π Sco  — Alt 21° Az 130° */

        /* === Libra === */
        [0.244, 0.565, 2.8, 240, 245, 255, ''],   /* α Lib — Alt 39° Az 134° */
        [0.179, 0.570, 2.6, 220, 235, 200, ''],   /* β Lib — Alt 39° Az 122° */

        /* === Centaurus === */
        [0.377, 0.687, 2.1, 255, 215, 180, 'Menkent'], /* θ Cen — Alt 28° Az 158° */
        [0.440, 0.845, 2.3, 200, 215, 255, ''],   /* ε Cen — Alt 14° Az 169° */
        [0.364, 0.774, 2.3, 200, 220, 255, ''],   /* η Cen — Alt 20° Az 156° */
        [0.415, 0.789, 2.5, 200, 215, 255, ''],   /* ζ Cen — Alt 19° Az 165° */

        /* === Lupus === */
        [0.374, 0.830, 2.3, 215, 225, 255, ''],   /* α Lup — Alt 15° Az 157° */
        [0.346, 0.809, 2.7, 220, 230, 255, ''],   /* β Lup — Alt 17° Az 152° */

        /* === Virgo === */
        [0.454, 0.252, 2.7, 245, 245, 255, ''],   /* γ Vir (Porrima) — Alt 67° */
        [0.416, 0.367, 2.8, 255, 240, 200, ''],   /* ε Vir (Vindem.) — Alt 57° */
        [0.280, 0.143, 2.8, 255, 235, 190, ''],   /* ε Vir — Alt 77° */

        /* === Hydra tail === */
        [0.411, 0.509, 3.0, 255, 230, 190, ''],   /* γ Hya — Alt 44° Az 164° */
        [0.348, 0.591, 3.3, 240, 240, 250, ''],   /* π Hya — Alt 37° Az 153° */

        /* === Crater (near Corvus) === */
        [0.650, 0.441, 3.6, 255, 230, 180, ''],   /* δ Crt — Alt 50° Az 207° */
        [0.629, 0.464, 4.1, 240, 240, 250, ''],   /* γ Crt — Alt 48° Az 203° */
        [0.670, 0.500, 4.1, 255, 225, 175, ''],   /* α Crt — Alt 45° Az 211° */

        /* === Vela (near horizon, west of south) === */
        [0.710, 0.990, 1.8, 255, 235, 200, ''],   /* γ Vel — Alt 0.3° Az 218° */
        [0.659, 0.990, 2.0, 230, 240, 255, ''],   /* δ Vel — Alt 0.5° Az 209° */
        [0.637, 0.953, 2.5, 240, 240, 255, ''],   /* κ Vel — Alt 4° Az 205° */

        /* === Corvus internal star === */
        [0.493, 0.414, 4.3, 245, 245, 255, ''],   /* η Crv — inside quadrilateral */
    ];

    /* Corvus constellation lines: quadrilateral γ-δ-β-ε */
    var corvusLines = [
        ['Gienah', 'Algorab'],   /* γ → δ  top edge */
        ['Algorab', 'Kraz'],     /* δ → β  left side going down */
        ['Kraz', 'Minkar'],      /* β → ε  bottom edge */
        ['Minkar', 'Gienah'],    /* ε → γ  right side going up */
    ];

    function magToSize(mag) {
        /* Brighter (lower mag) = larger */
        if (mag <= 0) return 3.0;
        if (mag <= 1) return 2.4;
        if (mag <= 2) return 1.8;
        if (mag <= 2.5) return 1.3;
        if (mag <= 3) return 1.0;
        return 0.7;
    }

    function magToAlpha(mag) {
        if (mag <= 0) return 0.95;
        if (mag <= 1) return 0.85;
        if (mag <= 2) return 0.70;
        if (mag <= 2.5) return 0.55;
        if (mag <= 3) return 0.45;
        return 0.30;
    }

    function generateStars() {
        stars = [];

        /* Place named stars at real positions */
        for (var i = 0; i < namedStars.length; i++) {
            var ns = namedStars[i];
            /* type=2 → bright (cross sparkle), type=1 → small */
            var type = ns[2] <= 1.5 ? 2 : 1;
            stars.push({
                x: (ns[0] + 0.25) * W,  /* shift 25% right */
                y: ns[1] * H * 0.70,   /* compress sky into upper 70% */
                size: magToSize(ns[2]),
                baseAlpha: magToAlpha(ns[2]),
                twinkleSpeed: 0.3 + seededRandom() * 0.8,
                twinklePhase: seededRandom() * Math.PI * 2,
                type: type,
                r: ns[3], g: ns[4], b: ns[5],
                name: ns[6]
            });
        }

        /* ~500 faint background stars (magnitude 4-6) */
        for (var i = 0; i < 500; i++) {
            stars.push({
                x: seededRandom() * W,
                y: seededRandom() * H,
                size: 0.3 + seededRandom() * 0.6,
                baseAlpha: 0.12 + seededRandom() * 0.25,
                twinkleSpeed: 0.3 + seededRandom() * 1.5,
                twinklePhase: seededRandom() * Math.PI * 2,
                type: 0,
                r: 240, g: 240, b: 245,
                name: ''
            });
        }

        /* ~60 medium background stars (magnitude 3-4) */
        for (var i = 0; i < 60; i++) {
            var warm = seededRandom() > 0.88;
            stars.push({
                x: seededRandom() * W,
                y: seededRandom() * H,
                size: 0.6 + seededRandom() * 0.6,
                baseAlpha: 0.35 + seededRandom() * 0.25,
                twinkleSpeed: 0.4 + seededRandom() * 1.2,
                twinklePhase: seededRandom() * Math.PI * 2,
                type: 0,
                r: warm ? 255 : 238,
                g: warm ? 230 : 240,
                b: warm ? 195 : 252,
                name: ''
            });
        }

        /* Build name → star map for findStar() — avoids the O(N)
         * scan that ran 4× per frame for constellation lines. */
        starsByName = {};
        for (var i = 0; i < stars.length; i++) {
            if (stars[i].name) starsByName[stars[i].name] = stars[i];
        }
    }

    var starsByName = {};

    function drawStars(t) {
        /* Draw all stars */
        for (var i = 0; i < stars.length; i++) {
            var s = stars[i];
            var twinkle = Math.sin(t * s.twinkleSpeed + s.twinklePhase);
            var alpha = s.baseAlpha + twinkle * 0.06;
            if (alpha < 0.03) alpha = 0.03;
            if (alpha > 1) alpha = 1;

            if (s.type >= 1) {
                /* Bright/medium named stars — soft glow, no hard core */
                var glowR = s.type === 2 ? s.size * 6 : s.size * 4;
                var glowA = s.type === 2 ? alpha * 0.9 : alpha * 0.8;
                var glow = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, glowR);
                glow.addColorStop(0,    'rgba(' + s.r + ',' + s.g + ',' + s.b + ',' + glowA + ')');
                glow.addColorStop(0.15, 'rgba(' + s.r + ',' + s.g + ',' + s.b + ',' + (glowA * 0.6) + ')');
                glow.addColorStop(0.5,  'rgba(' + s.r + ',' + s.g + ',' + s.b + ',' + (glowA * 0.15) + ')');
                glow.addColorStop(1,    'rgba(' + s.r + ',' + s.g + ',' + s.b + ',0)');
                ctx.fillStyle = glow;
                ctx.beginPath();
                ctx.arc(s.x, s.y, glowR, 0, Math.PI * 2);
                ctx.fill();
            } else {
                /* Faint background stars — simple dot */
                ctx.beginPath();
                ctx.arc(s.x, s.y, s.size, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(' + s.r + ',' + s.g + ',' + s.b + ',' + alpha + ')';
                ctx.fill();
            }
        }

        /* Draw Corvus constellation lines */
        ctx.strokeStyle = 'rgba(120, 160, 220, 0.12)';
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 6]);
        for (var i = 0; i < corvusLines.length; i++) {
            var a = findStar(corvusLines[i][0]);
            var b = findStar(corvusLines[i][1]);
            if (a && b) {
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.stroke();
            }
        }
        ctx.setLineDash([]);
    }

    function findStar(name) {
        return starsByName[name] || null;
    }

    /* ================================================================
     *  SHOOTING STARS — bright white-blue trails
     * ================================================================ */
    var shootingStars = [];
    var SHOOT_MAX = 4;
    var SHOOT_INTERVAL = 3.5;
    var nextShootTime = 1.5;

    function spawnShootingStar() {
        var startX = -20 + Math.random() * W * 0.3;
        var startY = 15 + Math.random() * H * 0.35;
        var angle = 0.10 + Math.random() * 0.20;
        var speed = 220 + Math.random() * 280;

        shootingStars.push({
            x: startX, y: startY,
            vx: Math.cos(angle) * speed,
            vy: Math.sin(angle) * speed,
            life: 0,
            maxLife: 1.6 + Math.random() * 1.2,
            brightness: 0.7 + Math.random() * 0.3,
            history: []
        });
    }

    function updateShootingStars(dt) {
        nextShootTime -= dt;
        if (nextShootTime <= 0 && shootingStars.length < SHOOT_MAX) {
            spawnShootingStar();
            nextShootTime = SHOOT_INTERVAL * (0.4 + Math.random() * 0.8);
        }

        for (var i = shootingStars.length - 1; i >= 0; i--) {
            var s = shootingStars[i];
            s.life += dt;
            s.x += s.vx * dt;
            s.y += s.vy * dt;
            s.history.unshift({ x: s.x, y: s.y });
            if (s.history.length > 45) s.history.length = 45;

            if (s.life >= s.maxLife || s.x > W + 80 || s.y > H) {
                shootingStars.splice(i, 1);
                continue;
            }

            var lr = s.life / s.maxLife;
            var alpha = s.brightness;
            if (lr < 0.08) alpha *= lr / 0.08;
            if (lr > 0.6) alpha *= (1 - lr) / 0.4;

            /* Trail — white-blue fading to transparent */
            for (var j = 0; j < s.history.length - 1; j++) {
                var sa = alpha * (1 - j / s.history.length);
                if (sa < 0.01) break;
                var p1 = s.history[j], p2 = s.history[j + 1];
                var r = 220 + Math.floor(35 * (1 - j / s.history.length));
                var g = 235 + Math.floor(20 * (1 - j / s.history.length));
                var b = 255;
                var lw = 2.5 - (j / s.history.length) * 2.0;
                if (lw < 0.3) lw = 0.3;

                ctx.beginPath();
                ctx.moveTo(p1.x, p1.y);
                ctx.lineTo(p2.x, p2.y);
                ctx.strokeStyle = 'rgba(' + r + ',' + g + ',' + b + ',' + sa + ')';
                ctx.lineWidth = lw;
                ctx.lineCap = 'round';
                ctx.stroke();
            }

            /* Head glow — white-blue */
            if (alpha > 0.1) {
                var hg = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, 14);
                hg.addColorStop(0, 'rgba(240, 248, 255, ' + (alpha * 0.55) + ')');
                hg.addColorStop(0.3, 'rgba(180, 215, 255, ' + (alpha * 0.2) + ')');
                hg.addColorStop(1, 'rgba(100, 160, 255, 0)');
                ctx.fillStyle = hg;
                ctx.beginPath();
                ctx.arc(s.x, s.y, 14, 0, Math.PI * 2);
                ctx.fill();

                ctx.beginPath();
                ctx.arc(s.x, s.y, 1.5, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(255, 255, 255, ' + alpha + ')';
                ctx.fill();
            }
        }
    }

    /* ================================================================
     *  CINEMATIC BARS — dark top and bottom bands
     * ================================================================ */
    var BAR_H = 52;  /* px height of each bar */

    function drawBars() {
        /* Top bar */
        var topGrad = ctx.createLinearGradient(0, 0, 0, BAR_H + 12);
        topGrad.addColorStop(0, 'rgba(2, 4, 10, 0.95)');
        topGrad.addColorStop(0.7, 'rgba(2, 4, 10, 0.85)');
        topGrad.addColorStop(1, 'rgba(2, 4, 10, 0)');
        ctx.fillStyle = topGrad;
        ctx.fillRect(0, 0, W, BAR_H + 12);

        /* Bottom bar — gentle fade matching top */
        var botGrad = ctx.createLinearGradient(0, H - BAR_H - 12, 0, H);
        botGrad.addColorStop(0, 'rgba(2, 4, 10, 0)');
        botGrad.addColorStop(0.7, 'rgba(2, 4, 10, 0.85)');
        botGrad.addColorStop(1, 'rgba(2, 4, 10, 0.95)');
        ctx.fillStyle = botGrad;
        ctx.fillRect(0, H - BAR_H - 12, W, BAR_H + 12);
    }

    /* ================================================================
     *  RENDER LOOP
     * ================================================================ */
    var lastTime = 0;

    function frame(ts) {
        var t = ts / 1000;
        var dt = lastTime ? t - lastTime : 0.016;
        if (dt > 0.1) dt = 0.1;
        lastTime = t;

        drawSky();
        drawNebula(t);
        drawStars(t);
        updateShootingStars(dt);
        drawBars();

        requestAnimationFrame(frame);
    }

    resize();
    requestAnimationFrame(frame);

    /* ================================================================
     *  LOGIN FORM
     * ================================================================ */
    var form = document.getElementById('login-form');
    var errBox = document.getElementById('login-error');

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        var user = document.getElementById('login-user').value.trim();
        var pass = document.getElementById('login-pass').value;

        if (!user || !pass) {
            errBox.textContent = 'ENTER USERNAME AND PASSWORD';
            errBox.style.display = 'block';
            return;
        }

        var btn = form.querySelector('.login-btn');
        btn.textContent = 'CONNECTING...';
        btn.disabled = true;

        SgCommon.apiCall('/auth/login', {
            method: 'POST',
            body: { username: user, password: pass },
            on401: 'throw'
        })
        .then(function (data) {
            /* Session token is now set as HttpOnly cookie by server.
             * No need to store in sessionStorage. */

            /* Check if password change is required */
            if (data.change_password) {
                btn.textContent = 'PASSWORD CHANGE REQUIRED';
                btn.disabled = false;
                showChangePasswordForm(user, data.reason);
                return;
            }

            btn.textContent = 'AUTHENTICATED';
            setTimeout(function () {
                window.location.href = 'home.html';
            }, 400);
        })
        .catch(function (err) {
            /* Network error: backend unreachable */
            if (err.name === 'TypeError') {
                errBox.textContent = 'CANNOT CONNECT TO MANAGEMENT DAEMON';
                errBox.style.display = 'block';
                btn.textContent = 'LOGIN';
                btn.disabled = false;
                return;
            }
            errBox.textContent = err.message || 'INVALID CREDENTIALS';
            errBox.style.display = 'block';
            btn.textContent = 'LOGIN';
            btn.disabled = false;
        });
    });

    /* ================================================================
     *  ENFORCE CHANGE PASSWORD — inline form overlay
     * ================================================================ */

    function showChangePasswordForm(username, reason) {
        var container = document.getElementById('login-form');
        if (!container) return;

        var reasonText = reason === 'policy'
            ? 'Your password does not meet the current security policy.'
            : 'An administrator requires you to change your password.';

        /* Build change-password form via DOM API (no innerHTML concat) */
        container.innerHTML = '';

        var title = document.createElement('div');
        title.className = 'login-title';
        title.style.cssText = 'font-size:16px;margin-bottom:12px';
        title.textContent = 'CHANGE PASSWORD';
        container.appendChild(title);

        var desc = document.createElement('p');
        desc.style.cssText = 'color:#aab;font-size:13px;margin-bottom:16px';
        desc.textContent = reasonText;
        container.appendChild(desc);

        var newField = document.createElement('div');
        newField.className = 'login-field';
        var newInp = document.createElement('input');
        newInp.id = 'cp-new';
        newInp.type = 'password';
        newInp.placeholder = 'New Password';
        newInp.autocomplete = 'new-password';
        newField.appendChild(newInp);
        container.appendChild(newField);

        var confirmField = document.createElement('div');
        confirmField.className = 'login-field';
        var confirmInp = document.createElement('input');
        confirmInp.id = 'cp-confirm';
        confirmInp.type = 'password';
        confirmInp.placeholder = 'Confirm Password';
        confirmInp.autocomplete = 'new-password';
        confirmField.appendChild(confirmInp);
        container.appendChild(confirmField);

        var cpErr = document.createElement('div');
        cpErr.id = 'cp-error';
        cpErr.className = 'login-error';
        cpErr.style.display = 'none';
        container.appendChild(cpErr);

        var cpBtn = document.createElement('button');
        cpBtn.id = 'cp-btn';
        cpBtn.className = 'login-btn';
        cpBtn.type = 'button';
        cpBtn.textContent = 'CHANGE PASSWORD';
        container.appendChild(cpBtn);

        var backDiv = document.createElement('div');
        backDiv.style.cssText = 'text-align:center;margin-top:16px';
        var backLink = document.createElement('a');
        backLink.href = 'login.html';
        backLink.style.cssText = 'color:rgba(120,180,255,0.5);font-size:9px;text-decoration:none;letter-spacing:1px';
        backLink.textContent = 'BACK TO LOGIN';
        backDiv.appendChild(backLink);
        container.appendChild(backDiv);

        cpBtn.addEventListener('click', function () {
            var newPw = document.getElementById('cp-new').value;
            var confirmPw = document.getElementById('cp-confirm').value;

            var validationErr = SgCommon.validatePasswordChange(newPw, confirmPw);
            if (validationErr) {
                cpErr.textContent = validationErr;
                cpErr.style.display = 'block';
                return;
            }

            cpBtn.textContent = 'CHANGING...';
            cpBtn.disabled = true;
            cpErr.style.display = 'none';

            SgCommon.apiCall('/auth/change-password', {
                method: 'POST',
                body: { password: newPw },
                on401: 'throw'
            })
            .then(function () {
                cpBtn.textContent = 'PASSWORD CHANGED';
                setTimeout(function () {
                    window.location.href = 'home.html';
                }, 400);
            })
            .catch(function (err) {
                cpErr.textContent = err.message || 'PASSWORD CHANGE FAILED';
                cpErr.style.display = 'block';
                cpBtn.textContent = 'CHANGE PASSWORD';
                cpBtn.disabled = false;
            });
        });
    }
})();
