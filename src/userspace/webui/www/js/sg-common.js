/* sg-common.js — shared helpers for Stargazer Web UI
 *
 * Used by both login.js (pre-auth pages) and app.js (post-auth pages).
 * Exposes window.SgCommon with the smallest stable surface possible —
 * no DOM construction, no business logic.  Just plumbing that was
 * being reinvented in two places.
 */

(function () {
    'use strict';

    var API_BASE = '/api';

    /* HTML escape — covers the canonical 5 attribute/element entities.
     * Use for any value going into innerHTML or attribute strings. */
    function escHTML(s) {
        if (s == null) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    /*
     * apiCall — central fetch wrapper.  Handles JSON encoding, error
     * shaping, and 401-on-protected-paths redirect.
     *
     * Options:
     *   method:   HTTP method (default GET)
     *   body:     plain object → auto JSON.stringify
     *   on401:    'redirect' (default for app.js) or 'throw' (login.js)
     */
    function apiCall(endpoint, opts) {
        var url = API_BASE + endpoint;
        var options = opts || {};
        options.headers = options.headers || {};

        if (options.body && typeof options.body === 'object' &&
            !(options.body instanceof FormData)) {
            options.headers['Content-Type'] =
                options.headers['Content-Type'] || 'application/json';
            options.body = JSON.stringify(options.body);
        }

        var on401 = options.on401 || 'redirect';
        delete options.on401;

        return fetch(url, options).then(function (res) {
            if (res.status === 401) {
                if (on401 === 'redirect') {
                    window.location.href = 'login.html';
                    return;
                }
                /* on401 === 'throw': fall through to error path */
            }
            if (!res.ok) {
                return res.json().catch(function () { return {}; })
                    .then(function (err) {
                        var e = new Error(err.error || ('HTTP ' + res.status));
                        e.status = res.status;
                        throw e;
                    });
            }
            return res.json();
        });
    }

    /*
     * setupHiDPICanvas — resize a canvas to its CSS box × devicePixelRatio
     * and set the transform so subsequent draw calls use CSS pixels.
     * Returns {W, H, dpr}.  Used by both the dashboard gauges and the
     * login night-sky animation.
     */
    function setupHiDPICanvas(canvas, w, h) {
        var dpr = window.devicePixelRatio || 1;
        canvas.width = w * dpr;
        canvas.height = h * dpr;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        var ctx = canvas.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        return { W: w, H: h, dpr: dpr, ctx: ctx };
    }

    /*
     * validatePasswordChange — both login.js (forced change) and
     * app.js (admin self-service) need the same client-side checks
     * before round-tripping to the server.  Returns null on success
     * or an error message string.
     */
    function validatePasswordChange(newPw, confirmPw) {
        if (!newPw || !confirmPw) return 'ENTER NEW PASSWORD AND CONFIRMATION';
        if (newPw.length < 8) return 'PASSWORD MUST BE AT LEAST 8 CHARACTERS';
        if (newPw !== confirmPw) return 'PASSWORDS DO NOT MATCH';
        return null;
    }

    window.SgCommon = {
        API_BASE: API_BASE,
        escHTML: escHTML,
        apiCall: apiCall,
        setupHiDPICanvas: setupHiDPICanvas,
        validatePasswordChange: validatePasswordChange
    };
})();
