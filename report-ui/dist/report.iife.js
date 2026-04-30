!function() {
    "use strict";
    const e = 2.8, t = '500 11.5px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    function n(e, t, n) {
        return Math.min(n, Math.max(t, e));
    }
    function a(e, t = !1) {
        return t ? e.length : Math.min(e.length, 34);
    }
    function r(e) {
        const t = a(e);
        return e.length <= 34 ? t : Math.max(1, t - 6);
    }
    function s(e) {
        const {labelGraphemes: t} = e;
        if (t.length <= 34) return e.ref.name;
        const a = n(Math.round(e.renderLabelChars), 1, t.length);
        return a >= t.length ? e.ref.name : `${t.slice(0, a - 1).join("")}…`;
    }
    function i(e, t, a) {
        const r = function(e) {
            const t = e.trim(), a = t.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
            if (a) {
                const e = a[1];
                return 3 === e.length ? {
                    r: parseInt(e[0] + e[0], 16),
                    g: parseInt(e[1] + e[1], 16),
                    b: parseInt(e[2] + e[2], 16)
                } : {
                    r: parseInt(e.slice(0, 2), 16),
                    g: parseInt(e.slice(2, 4), 16),
                    b: parseInt(e.slice(4, 6), 16)
                };
            }
            const r = t.match(/^rgba?\(([^)]+)\)$/i);
            if (!r) return null;
            const s = r[1].replace(/\//g, " ").split(/[\s,]+/).filter(Boolean).slice(0, 3);
            if (3 !== s.length) return null;
            const i = e => {
                if (e.endsWith("%")) {
                    const t = Number(e.slice(0, -1));
                    return Number.isFinite(t) ? n(Math.round(t / 100 * 255), 0, 255) : null;
                }
                const t = Number(e);
                return Number.isFinite(t) ? n(Math.round(t), 0, 255) : null;
            }, o = i(s[0]), c = i(s[1]), l = i(s[2]);
            return null === o || null === c || null === l ? null : {
                r: o,
                g: c,
                b: l
            };
        }(e);
        if (!r) return a;
        const s = n(t, 0, 1);
        return `rgb(${Math.round(r.r + (255 - r.r) * s)}, ${Math.round(r.g + (255 - r.g) * s)}, ${Math.round(r.b + (255 - r.b) * s)})`;
    }
    function o(e) {
        return getComputedStyle(document.documentElement).getPropertyValue(e).trim();
    }
    function c(e, t, n) {
        if (0 === t.length) return;
        if (e.moveTo(t[0].x, t[0].y), 1 === t.length) return;
        if (2 === t.length) return void e.lineTo(t[1].x, t[1].y);
        for (let r = 1; r < t.length - 1; r += 1) {
            const a = t[r - 1], s = t[r], i = t[r + 1], o = s.x - a.x, c = s.y - a.y, l = i.x - s.x, d = i.y - s.y, u = Math.hypot(o, c), p = Math.hypot(l, d);
            if (u < .001 || p < .001) {
                e.lineTo(s.x, s.y);
                continue;
            }
            const h = Math.min(n, .45 * u, .45 * p), g = s.x - o / u * h, m = s.y - c / u * h, v = s.x + l / p * h, f = s.y + d / p * h;
            e.lineTo(g, m), e.quadraticCurveTo(s.x, s.y, v, f);
        }
        const a = t[t.length - 1];
        e.lineTo(a.x, a.y);
    }
    function l(e, t, a, r) {
        const s = t.renderX, i = t.renderY, o = a.renderX, l = a.renderY, d = a.depth - t.depth, u = Math.abs(d);
        if (0 === u) {
            const a = Math.abs(s - o) < r.sameColumnXThreshold, d = Math.abs(i - l), u = t.depth < r.maxDepth;
            if (a && d > r.minDetourVerticalSpan && u) {
                const a = r.paddingX + t.depth * r.layerGap, u = r.paddingX + (t.depth + 1) * r.layerGap, p = .5 * (a + u);
                let h = p + r.detourInset;
                const g = Math.min(i, l) - 12, m = Math.max(i, l) + 12;
                (function(e, t, n, a, r) {
                    const s = e.depthNodeIndex.get(t);
                    if (!s || 0 === s.length) return !1;
                    const i = function(e, t) {
                        let n = 0, a = e.length;
                        for (;n < a; ) {
                            const r = n + (a - n >> 1);
                            e[r].renderY < t ? n = r + 1 : a = r;
                        }
                        return n;
                    }(s, n);
                    for (let o = i; o < s.length && s[o].renderY <= a; o += 1) if (Math.abs(s[o].renderX - r) < e.detourNodeClearance) return !0;
                    return !1;
                })(r, t.depth + 1, g, m, h) && (h += 12);
                h = n(h, p + 8, u - 24);
                const v = Math.max(1, h - s);
                return void c(e, [ {
                    x: s,
                    y: i
                }, {
                    x: h,
                    y: i
                }, {
                    x: h,
                    y: l
                }, {
                    x: o,
                    y: l
                } ], n(.42 * Math.min(v, d), 16, 52));
            }
            e.moveTo(s, i);
            const p = s + .5 * (o - s), h = i + (l - i) * r.edgeCurve;
            return void e.quadraticCurveTo(p, h, o, l);
        }
        if (1 === u) {
            const n = Math.min(t.depth, a.depth), c = r.paddingX + n * r.layerGap + .5 * r.layerGap;
            return e.moveTo(s, i), void e.bezierCurveTo(c, i, c, l, o, l);
        }
        const p = Math.sign(d), h = l - i, g = [ {
            x: s,
            y: i
        } ], m = r.paddingX + t.depth * r.layerGap + p * (.5 * r.layerGap);
        g.push({
            x: m,
            y: i
        });
        for (let n = 1; n < u; n += 1) {
            const e = t.depth + p * n, a = r.paddingX + e * r.layerGap + p * (.5 * r.layerGap), s = n / u;
            g.push({
                x: a,
                y: i + h * s
            });
        }
        const v = r.paddingX + a.depth * r.layerGap - p * (.5 * r.layerGap);
        g.push({
            x: v,
            y: l
        }), g.push({
            x: o,
            y: l
        }), c(e, g, 14);
    }
    function d(e, t, a, r) {
        r && t.highlighted ? function(e, t, a) {
            const r = t.renderX, s = t.renderY, i = a.renderX, o = a.renderY, c = i - r, l = o - s;
            if (e.moveTo(r, s), Math.abs(c) < 18) {
                const t = r + (s <= o ? 26 : -26);
                return void e.bezierCurveTo(t, s, t, o, i, o);
            }
            const d = n(.44 * Math.abs(c), 42, 150), u = Math.sign(c), p = n(.12 * Math.abs(l), 0, 24);
            e.bezierCurveTo(r + u * d, s + p * Math.sign(l), i - u * d, o - p * Math.sign(l), i, o);
        }(e, t.from, t.to) : l(e, t.from, t.to, a);
    }
    function u(e, t) {
        return `${e}@${t}`;
    }
    function p(e, t) {
        return `${e}->${t}`;
    }
    function h(e) {
        if (!e || "object" != typeof e) return !1;
        const t = e;
        if (!Array.isArray(t.workspaces)) return !1;
        if (!t.dependencies || "object" != typeof t.dependencies) return !1;
        const n = e => Array.isArray(e) && e.every(e => "string" == typeof e);
        if (!t.workspaces.every(e => (e => {
            if (!e || "object" != typeof e) return !1;
            const t = e;
            return "string" == typeof t.name && !!Array.isArray(t.directDependencies) && !!Array.isArray(t.directDevDependencies);
        })(e))) return !1;
        if (!t.workspaces.every(e => n(e.directDependencies) && n(e.directDevDependencies))) return !1;
        return !!Object.entries(t.dependencies).every(([, e]) => {
            if (!e || "object" != typeof e) return !1;
            const t = e;
            return !(void 0 !== t.dependencies && !Array.isArray(t.dependencies)) && !(void 0 !== t.workspaceOrigins && !Array.isArray(t.workspaceOrigins));
        });
    }
    function g(e) {
        const t = e.compliance.license.declared?.valid ? e.compliance.license.declared.spdxId : void 0;
        return t || (e.compliance.license.inferred?.spdxId || "Unknown");
    }
    function m(e) {
        const t = e.security?.summary;
        return t ? Number(t.critical || 0) + Number(t.high || 0) + Number(t.moderate || 0) + Number(t.low || 0) : 0;
    }
    function v(e) {
        const t = e.security?.summary?.highest;
        return "critical" === t || "high" === t ? "high" : "moderate" === t ? "moderate" : "none";
    }
    function f(e, t) {
        const n = new Set, a = [ t ];
        for (;a.length > 0; ) {
            const t = a.pop();
            if (!t) continue;
            const r = e.nodes.get(t);
            r && r.parents.forEach(e => {
                n.has(e) || (n.add(e), a.push(e));
            });
        }
        return n;
    }
    function y(e, t) {
        const n = new Set, a = [ t ];
        for (;a.length > 0; ) {
            const t = a.pop();
            if (!t) continue;
            const r = e.nodes.get(t);
            r && r.children.forEach(e => {
                n.has(e) || (n.add(e), a.push(e));
            });
        }
        return n;
    }
    function k(e, t, n) {
        const a = new Map, r = [ {
            slug: t,
            distance: 0
        } ];
        let s = 0;
        for (;s < r.length; ) {
            const t = r[s++], i = e.nodes.get(t.slug);
            i && i[n].forEach(e => {
                a.has(e) || (a.set(e, t.distance + 1), r.push({
                    slug: e,
                    distance: t.distance + 1
                }));
            });
        }
        return a;
    }
    function b(c) {
        const l = function(e, t, n) {
            const a = window.__DEPENDENCY_DATA__;
            if (h(a)) {
                const e = {};
                return Object.entries(a.dependencies).forEach(([t, n]) => {
                    const a = n, r = a.vulnerabilitySeverity || a.vulnerabilityHighest || a.highestSeverity || "none", s = String(r).trim().toLowerCase();
                    let i = "none";
                    "critical" === s || "high" === s ? i = "high" : "moderate" !== s && "medium" !== s || (i = "moderate"), 
                    e[t] = {
                        slug: String(a.slug || t),
                        name: String(a.name || t),
                        version: String(a.version || ""),
                        dependencies: Array.isArray(a.dependencies) ? a.dependencies.map(e => String(e)) : [],
                        license: String(a.license || "Unknown"),
                        vulnerabilityCount: Number(a.vulnerabilityCount || 0),
                        vulnerabilitySeverity: i,
                        isDevOnly: Boolean(a.isDevOnly),
                        workspaceOrigins: Array.isArray(a.workspaceOrigins) ? a.workspaceOrigins.map(e => String(e)) : []
                    };
                }), {
                    workspaces: a.workspaces,
                    dependencies: e
                };
            }
            const r = {}, s = Object.values(e.dependencies || {});
            s.forEach(e => {
                const t = u(e.package.name, e.package.version);
                r[t] = {
                    slug: t,
                    name: e.package.name,
                    version: e.package.version,
                    dependencies: [],
                    license: g(e),
                    vulnerabilityCount: m(e),
                    vulnerabilitySeverity: v(e),
                    isDevOnly: "dev" === e.usage.scope,
                    workspaceOrigins: e.usage.origins.workspaces || []
                };
            }), s.forEach(e => {
                const a = u(e.package.name, e.package.version), s = e.graph.subDeps;
                if (!s) return;
                const i = new Set;
                [ "dep", "dev", "opt", "peer" ].forEach(e => {
                    const o = s[e];
                    o && Object.values(o).forEach(e => {
                        const s = e[1];
                        if (!s) return;
                        const o = n(s);
                        o && t.has(o) && r[o] && o !== a && i.add(o);
                    });
                }), r[a].dependencies = [ ...i ];
            });
            const i = new Map, o = e => {
                const t = i.get(e);
                if (t) return t;
                const n = {
                    directDependencies: new Set,
                    directDevDependencies: new Set
                };
                return i.set(e, n), n;
            };
            return o("root"), (e.workspaces.workspacePackages || []).forEach(e => {
                o(e.name);
            }), s.forEach(e => {
                if (!e.usage.direct) return;
                const t = u(e.package.name, e.package.version);
                (e.usage.origins.workspaces?.length ? e.usage.origins.workspaces : [ "root" ]).forEach(n => {
                    const a = o(n);
                    "dev" === e.usage.scope ? a.directDevDependencies.add(t) : a.directDependencies.add(t);
                });
            }), {
                workspaces: [ ...i.entries() ].map(([e, t]) => ({
                    name: e,
                    directDependencies: [ ...t.directDependencies ],
                    directDevDependencies: [ ...t.directDevDependencies ]
                })).sort((e, t) => e.name.localeCompare(t.name)),
                dependencies: r
            };
        }(c.report, c.knownDepKeys, c.resolveDepKey), b = new Map(l.workspaces.map(e => [ e.name, e ])), w = new Map, E = new Map;
        Object.values(l.dependencies).forEach(e => {
            const t = (e.dependencies || []).filter(t => t !== e.slug && Boolean(l.dependencies[t]));
            E.set(e.slug, t), t.forEach(t => {
                const n = w.get(t) || [];
                n.push(e.slug), w.set(t, n);
            });
        });
        let C = null, x = "", L = null, S = null, I = new Set, M = new Set, Y = new Set, P = new Map, X = null, B = null, D = new Set, A = new Set, T = null, N = 1, j = 0, R = 0, V = 1, H = .1, O = 0, F = 0, W = null, G = null, $ = !1, U = !0, _ = 0, q = Math.max(1, Math.floor(window.devicePixelRatio || 1)), z = 1, K = 1;
        const J = {
            down: !1,
            moved: !1,
            startX: 0,
            startY: 0,
            startPanX: 0,
            startPanY: 0
        }, Z = {
            active: !1,
            startX1: 0,
            startY1: 0,
            startX2: 0,
            startY2: 0,
            startPanX: 0,
            startPanY: 0,
            startDist: 0,
            startZoom: 0,
            anchorX: null,
            anchorY: null
        }, Q = {
            active: !1,
            velocityX: 0,
            velocityY: 0,
            lastSampleX: 0,
            lastSampleY: 0,
            lastSampleTime: 0,
            lastFrameTime: 0
        }, ee = c.canvas.getContext("2d"), te = Boolean(ee);
        let ne = !1, ae = !1, re = !1, se = null, ie = null, oe = null, ce = !1;
        const le = "function" == typeof window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
        let de = {
            runtime: "#10b981",
            runtimeHighlight: "#34d399",
            dev: "#f59e0b",
            devHighlight: "#fcd34d",
            transitive: "#06b6d4",
            transitiveHighlight: "#67e8f9",
            edge: "#64748b",
            highlight: "#22d3ee",
            muted: "#64748b",
            ringHigh: "#ef4444",
            ringModerate: "#f59e0b",
            label: "#e8edf5",
            backgroundPrimary: "#0c1222"
        };
        function ue() {
            const e = o("--graph-direct-runtime") || "#10b981", t = o("--graph-direct-dev") || "#f59e0b", n = o("--graph-transitive") || "#06b6d4";
            de = {
                runtime: e,
                runtimeHighlight: i(e, .2, "#34d399"),
                dev: t,
                devHighlight: i(t, .28, "#fcd34d"),
                transitive: n,
                transitiveHighlight: i(n, .38, "#67e8f9"),
                edge: o("--graph-edge") || "#64748b",
                highlight: o("--graph-highlight") || "#22d3ee",
                muted: o("--graph-muted") || "#64748b",
                ringHigh: o("--graph-vuln-high") || "#ef4444",
                ringModerate: o("--graph-vuln-medium") || "#f59e0b",
                label: o("--text-primary") || "#e8edf5",
                backgroundPrimary: o("--bg-primary") || "#0c1222"
            };
        }
        function pe() {
            if (ce) return;
            ce = !0, console.warn("Dependency Radar: unable to initialize 2D canvas; graph rendering disabled."), 
            c.controlsRoot.classList.add("hidden"), c.workspaceWrap.classList.add("hidden"), 
            c.canvas.style.display = "none";
            const e = document.createElement("div");
            e.className = "empty-state";
            const t = document.createElement("div");
            t.className = "empty-state-text", t.textContent = "Graph view is unavailable in this browser context.", 
            e.appendChild(t), c.canvasHost.appendChild(e);
        }
        function he(e) {
            return (e - j) / N;
        }
        function ge(e) {
            return (e - R) / N;
        }
        function me(e, t) {
            if (!C) return {
                x: e,
                y: t
            };
            const a = C.bounds.minX - 120, r = C.bounds.maxX + 120, s = C.bounds.minY - 90, i = C.bounds.maxY + 90, o = Math.min(.22 * z, 220), c = Math.min(.22 * K, 180), l = o - r * N, d = z - o - a * N, u = c - i * N, p = K - c - s * N;
            return {
                x: l > d ? .5 * (l + d) : n(e, l, d),
                y: u > p ? .5 * (u + p) : n(t, u, p)
            };
        }
        function ve(e, t) {
            const n = me(e, t);
            j = n.x, R = n.y;
        }
        function fe() {
            W = null, G = null;
        }
        function ye(t, a, r) {
            we(), fe();
            const s = n(t, H, e), i = he(a), o = ge(r);
            N = s, ve(a - i * N, r - o * N), U = !0, _e();
        }
        function ke(e, t) {
            we(), fe(), ve(j + e, R + t), U = !0, _e();
        }
        function be() {
            return !le?.matches;
        }
        function we() {
            Q.active = !1, Q.velocityX = 0, Q.velocityY = 0, Q.lastFrameTime = 0;
        }
        function Ee(e, t, n) {
            Q.lastSampleX = e, Q.lastSampleY = t, Q.lastSampleTime = n;
        }
        function Ce(e, t, n) {
            const a = n - Q.lastSampleTime;
            if (a <= 0) return void Ee(e, t, n);
            const r = (e - Q.lastSampleX) / a, s = (t - Q.lastSampleY) / a;
            Q.velocityX += .22 * (r - Q.velocityX), Q.velocityY += .22 * (s - Q.velocityY), 
            Ee(e, t, n);
        }
        function xe() {
            if (!be()) return void we();
            Math.hypot(Q.velocityX, Q.velocityY) < .08 ? we() : (Q.active = !0, Q.lastFrameTime = performance.now(), 
            je(!1), _e());
        }
        function Le() {
            const e = c.canvasHost.getBoundingClientRect();
            z = Math.max(1, Math.floor(e.width)), K = Math.max(1, Math.floor(e.height)), q = Math.max(1, Math.floor(window.devicePixelRatio || 1)), 
            c.canvas.width = z * q, c.canvas.height = K * q, c.canvas.style.width = `${z}px`, 
            c.canvas.style.height = `${K}px`;
            const t = c.canvasHost.querySelector(".graph-overlay-top"), n = t ? Math.ceil(t.getBoundingClientRect().height) : 50;
            c.canvasHost.style.setProperty("--graph-toolbar-height", `${n}px`), U = !0, _e();
        }
        function Se() {
            if (!C) return;
            const a = C.bounds;
            let r = a.maxX;
            ee && (ee.save(), ee.font = t, C.nodes.forEach(e => {
                const t = s(e);
                if (!t) return;
                const n = ee.measureText(t).width;
                r = Math.max(r, e.baseX + e.radius + 6 + n);
            }), ee.restore());
            const i = Math.max(1, a.maxY - a.minY), o = z / Math.max(1, r - a.minX), c = K / i;
            V = n(Math.min(o, c), .05, e), H = n(.64 * V, .05, e), O = .5 * (z - Math.max(1, r - a.minX) * V) - a.minX * V, 
            F = .5 * (K - i * V) - a.minY * V;
        }
        function Ie(e, t) {
            if (!C) return null;
            const n = c.canvas.getBoundingClientRect();
            if (e < n.left || e > n.right || t < n.top || t > n.bottom) return null;
            const a = he(e - n.left), r = ge(t - n.top);
            let s = null, i = 1 / 0;
            return C.nodes.forEach(e => {
                const t = a - e.renderX, n = r - e.renderY, o = Math.sqrt(t * t + n * n);
                o <= e.renderRadius + 5 && o < i && (i = o, s = e);
            }), s;
        }
        function Me(e) {
            c.canvas.classList.toggle("is-clickable", e && !J.down && !Z.active);
        }
        function Ye(e = !1) {
            Me(!1), e && c.canvas.classList.remove("is-panning");
        }
        function Pe(e, t) {
            const n = Ie(e, t);
            return Ve(n ? n.slug : null), Me(Boolean(n)), n;
        }
        function Xe(e) {
            const t = b.get(e);
            if (!t) return null;
            const n = new Set(t.directDependencies.filter(e => Boolean(l.dependencies[e]))), s = new Set(t.directDevDependencies.filter(e => Boolean(l.dependencies[e]))), i = new Set([ ...n, ...s ]);
            0 === i.size && Object.keys(l.dependencies).filter(e => 0 === (w.get(e) || []).length).slice(0, 40).forEach(e => {
                i.add(e);
            });
            const o = new Set, c = [ ...i ];
            let d = 0;
            for (;d < c.length; ) {
                const e = c[d++];
                e && (o.has(e) || l.dependencies[e] && (o.add(e), (E.get(e) || []).forEach(e => {
                    o.has(e) || c.push(e);
                })));
            }
            if (0 === o.size) return null;
            const u = new Map;
            o.forEach(e => {
                const t = n.has(e) ? "direct-runtime" : s.has(e) ? "direct-dev" : "transitive", i = Array.from(l.dependencies[e].name);
                u.set(e, {
                    slug: e,
                    ref: l.dependencies[e],
                    labelGraphemes: i,
                    parents: new Set,
                    children: new Set,
                    depth: Number.POSITIVE_INFINITY,
                    order: 0,
                    amplification: 0,
                    kind: t,
                    baseX: 0,
                    baseY: 0,
                    targetX: 0,
                    targetY: 0,
                    renderX: 0,
                    renderY: 0,
                    radius: 8,
                    targetRadius: 8,
                    renderRadius: 8,
                    targetLabelChars: a(i),
                    renderLabelChars: r(i)
                });
            }), u.forEach(e => {
                (w.get(e.slug) || []).forEach(t => {
                    u.has(t) && e.parents.add(t);
                }), (E.get(e.slug) || []).forEach(t => {
                    u.has(t) && e.children.add(t);
                });
            });
            const p = [];
            for (i.forEach(e => {
                const t = u.get(e);
                t && (t.depth = 0, p.push(e));
            }); p.length > 0; ) {
                const e = p.shift();
                if (!e) continue;
                const t = u.get(e);
                t && t.children.forEach(e => {
                    const n = u.get(e);
                    if (!n) return;
                    const a = t.depth + 1;
                    a >= n.depth || (n.depth = a, p.push(e));
                });
            }
            u.forEach(e => {
                if (Number.isFinite(e.depth)) return;
                let t = Number.POSITIVE_INFINITY;
                e.parents.forEach(e => {
                    const n = u.get(e);
                    n && Number.isFinite(n.depth) && (t = Math.min(t, n.depth + 1));
                }), e.depth = Number.isFinite(t) ? t : 0;
            });
            const h = [ ...u.values() ].reduce((e, t) => Math.max(e, t.depth), 0), g = Array.from({
                length: h + 1
            }, () => []);
            u.forEach(e => {
                g[e.depth].push(e.slug);
            });
            const m = [];
            u.forEach(e => {
                e.children.forEach(t => {
                    m.push({
                        from: e.slug,
                        to: t,
                        direct: 0 === e.depth
                    });
                });
            });
            const v = {
                workspaceName: e,
                nodes: u,
                edges: m,
                layers: g,
                directRuntime: n,
                directDev: s,
                directAll: new Set([ ...n, ...s ]),
                bounds: {
                    minX: 0,
                    maxX: 1,
                    minY: 0,
                    maxY: 1
                }
            };
            return Be(v), De(v), v;
        }
        function Be(e) {
            e.nodes.forEach(e => {
                e.amplification = 0;
            }), e.nodes.forEach(t => {
                if (0 !== t.depth) return;
                if (!e.directAll.has(t.slug)) return;
                const n = new Set, a = [ ...t.children ];
                for (;a.length > 0; ) {
                    const r = a.pop();
                    if (!r) continue;
                    if (r === t.slug) continue;
                    if (n.has(r)) continue;
                    n.add(r);
                    const s = e.nodes.get(r);
                    s && s.children.forEach(e => {
                        n.has(e) || a.push(e);
                    });
                }
                t.amplification = n.size;
            });
        }
        function De(e) {
            const t = new Map;
            e.layers.forEach((n, a) => {
                0 === a ? n.sort((t, n) => {
                    const a = e.nodes.get(t), r = e.nodes.get(n);
                    if (!a && !r) return 0;
                    if (!a) return 1;
                    if (!r) return -1;
                    if (a.amplification !== r.amplification) return r.amplification - a.amplification;
                    if (a.kind !== r.kind) {
                        if ("direct-runtime" === a.kind) return -1;
                        if ("direct-runtime" === r.kind) return 1;
                    }
                    return a.ref.name.localeCompare(r.ref.name);
                }) : n.sort((n, a) => {
                    const r = e.nodes.get(n), s = e.nodes.get(a);
                    if (!r && !s) return 0;
                    if (!r) return 1;
                    if (!s) return -1;
                    const i = (() => {
                        let e = 0, n = 0;
                        return r.parents.forEach(a => {
                            const r = t.get(a);
                            "number" == typeof r && (e += 1, n += r);
                        }), e > 0 ? n / e : Number.MAX_SAFE_INTEGER;
                    })(), o = (() => {
                        let e = 0, n = 0;
                        return s.parents.forEach(a => {
                            const r = t.get(a);
                            "number" == typeof r && (e += 1, n += r);
                        }), e > 0 ? n / e : Number.MAX_SAFE_INTEGER;
                    })();
                    return i !== o ? i - o : r.ref.name.localeCompare(s.ref.name);
                }), n.forEach((e, n) => {
                    t.set(e, n);
                });
            });
            const n = e.layers.reduce((e, t) => Math.max(e, t.length), 1);
            e.bounds = {
                minX: Number.POSITIVE_INFINITY,
                maxX: Number.NEGATIVE_INFINITY,
                minY: Number.POSITIVE_INFINITY,
                maxY: Number.NEGATIVE_INFINITY
            }, e.layers.forEach((t, s) => {
                const i = Math.max(0, 43 * (t.length - 1)), o = 64 + .5 * (43 * n - i);
                t.forEach((t, n) => {
                    const i = e.nodes.get(t);
                    if (!i) return;
                    i.order = n, i.baseX = 96 + 240 * s, i.baseY = o + 43 * n, i.targetX = i.baseX, 
                    i.targetY = i.baseY, i.renderX = i.baseX, i.renderY = i.baseY;
                    const c = .55 * Math.log(i.children.size + i.parents.size + 1), l = 0 === i.depth && e.directAll.has(i.slug) ? 1.05 * Math.log(i.amplification + 1) : 0;
                    i.radius = 6.7 + c + l, i.targetRadius = i.radius, i.renderRadius = i.radius, i.targetLabelChars = a(i.labelGraphemes), 
                    i.renderLabelChars = r(i.labelGraphemes), e.bounds.minX = Math.min(e.bounds.minX, i.baseX), 
                    e.bounds.maxX = Math.max(e.bounds.maxX, i.baseX), e.bounds.minY = Math.min(e.bounds.minY, i.baseY), 
                    e.bounds.maxY = Math.max(e.bounds.maxY, i.baseY);
                });
            }), Number.isFinite(e.bounds.minX) || (e.bounds = {
                minX: 0,
                maxX: 1,
                minY: 0,
                maxY: 1
            });
        }
        function Ae(t, a) {
            if (!C) return;
            const r = n(Math.max(N, 1.35 * V), H, e);
            N += (r - N) * (le?.matches ? 1 : .35), function(e, t) {
                const n = me(e, t);
                W = n.x, G = n.y;
            }(.46 * z - t * N, .5 * K - a * N);
        }
        function Te(e) {
            if (!C || !C.nodes.has(e)) return;
            we(), L = e;
            const t = f(C, e), a = y(C, e);
            I = new Set([ e ]), t.forEach(e => {
                I.add(e);
            }), a.forEach(e => {
                I.add(e);
            }), M = new Set;
            const r = [ e ], s = new Set([ e ]);
            for (;r.length > 0; ) {
                const e = r.pop();
                if (!e) continue;
                const t = C.nodes.get(e);
                t && t.parents.forEach(t => {
                    M.add(p(t, e)), s.has(t) || (s.add(t), r.push(t));
                });
            }
            const i = [ e ], o = new Set([ e ]);
            for (;i.length > 0; ) {
                const e = i.pop();
                if (!e) continue;
                const t = C.nodes.get(e);
                t && t.children.forEach(t => {
                    M.add(p(e, t)), o.has(t) || (o.add(t), i.push(t));
                });
            }
            Y = new Set(I);
            const c = C.nodes.get(e);
            c.parents.forEach(e => {
                Y.add(e);
            }), c.children.forEach(e => {
                Y.add(e);
            });
            const l = null === X || null === B, d = !l && Boolean(T) && I.has(T);
            !l && d || (X = c.renderX, B = c.renderY), P = function(e, t, a, r) {
                const s = new Map, i = k(e, t, "parents"), o = k(e, t, "children"), c = new Map;
                return s.set(t, {
                    x: a,
                    y: r
                }), I.forEach(n => {
                    if (n === t) return;
                    const r = e.nodes.get(n);
                    if (!r) return;
                    const s = i.get(n), l = o.get(n);
                    let d = 0;
                    "number" == typeof s && ("number" != typeof l || s <= l) ? d = -s : "number" == typeof l && (d = l), 
                    0 === d && (d = r.baseX < a ? -1 : 1);
                    const u = c.get(d) || [];
                    u.push(r), c.set(d, u);
                }), c.forEach((e, t) => {
                    e.sort((e, n) => {
                        const a = t < 0 ? i.get(e.slug) || 0 : o.get(e.slug) || 0, r = t < 0 ? i.get(n.slug) || 0 : o.get(n.slug) || 0;
                        return a !== r ? a - r : e.baseY !== n.baseY ? e.baseY - n.baseY : e.ref.name.localeCompare(n.ref.name);
                    });
                    const c = n(660 / Math.max(1, e.length - 1), 24, 34), l = r - (e.length - 1) * c * .5;
                    e.forEach((e, n) => {
                        const r = Math.abs(t), i = 170 * (1 + .78 * Math.max(0, r - 1));
                        s.set(e.slug, {
                            x: a + Math.sign(t) * i,
                            y: l + n * c
                        });
                    });
                }), s;
            }(C, e, X ?? c.renderX, B ?? c.renderY), Ae(X ?? c.renderX, B ?? c.renderY), U = !0, 
            _e();
        }
        function Ne() {
            L = null, I = new Set, M = new Set, Y = new Set, P = new Map, X = null, B = null, 
            fe(), U = !0, _e();
        }
        function je(e = !0) {
            S = null, D = new Set, A = new Set, e && (U = !0, _e());
        }
        function Re() {
            if (!C) return;
            const e = L && C.nodes.get(L) || null;
            C.nodes.forEach(t => {
                t.targetRadius = function(e) {
                    const t = L === e.slug, n = I.has(e.slug);
                    let a = e.radius;
                    t ? a *= 1.85 : L && n ? a *= 1.22 : L && !n ? a *= .84 : S && D.has(e.slug) ? a *= 1.1 : S && (a *= .9);
                    return a;
                }(t), t.targetLabelChars = a(t.labelGraphemes, Boolean(L) && I.has(t.slug) || !L && Boolean(S) && D.has(t.slug));
                const n = P.get(t.slug);
                if (e && n) return t.targetX = n.x, void (t.targetY = n.y);
                if (!e || !Y.has(t.slug)) return t.targetX = t.baseX, void (t.targetY = t.baseY);
                const r = t.baseX - e.baseX, s = t.baseY - e.baseY, i = 1 + 120 / (Math.sqrt(r * r + s * s) + 1);
                t.targetX = e.baseX + r * i, t.targetY = e.baseY + s * i;
            });
        }
        function Ve(e) {
            if (L) return;
            if (S = e, D = new Set, A = new Set, !C || !e || !C.nodes.has(e)) return U = !0, 
            void _e();
            const t = f(C, e), n = y(C, e);
            D = new Set([ e ]), t.forEach(e => {
                D.add(e);
            }), n.forEach(e => {
                D.add(e);
            });
            const a = C.nodes.get(e);
            a && (a.parents.forEach(e => {
                D.add(e);
            }), a.children.forEach(e => {
                D.add(e);
            })), C.edges.forEach(e => {
                D.has(e.from) && D.has(e.to) && A.add(p(e.from, e.to));
            }), U = !0, _e();
        }
        function He(e) {
            if (!C) return;
            const t = C.nodes.get(e);
            if (!t) return;
            const n = 0 === t.depth && C.directAll.has(t.slug);
            T = e, c.popoverName.textContent = t.ref.name, c.popoverVersion.textContent = `Version: ${t.ref.version}`, 
            c.popoverLicense.textContent = `License: ${t.ref.license || "Unknown"}`, c.popoverVulns.textContent = `Vulnerabilities: ${t.ref.vulnerabilityCount || 0}`, 
            c.popoverAmplification.textContent = n ? `Amplification: ${t.amplification}` : `Dependencies: ${t.children.size} • Dependents: ${t.parents.size}`, 
            c.popover.hidden = !1, Fe();
        }
        function Oe() {
            T = null, c.popover.hidden = !0;
        }
        function Fe() {
            if (!C || !T || c.popover.hidden) return;
            const e = C.nodes.get(T);
            if (!e) return void Oe();
            const t = e.renderX * N + j, a = e.renderY * N + R, r = c.canvasHost.getBoundingClientRect(), s = c.popover.getBoundingClientRect(), i = Math.max(8, r.width - s.width - 8), o = Math.max(8, r.height - s.height - 8), l = n(t + 14, 8, i), d = n(a + 14, 8, o);
            c.popover.style.left = `${l}px`, c.popover.style.top = `${d}px`;
        }
        function We(e) {
            return L ? I.has(e) ? 1 : .14 : S ? D.has(e) ? 1 : .16 : .95;
        }
        function Ge() {
            if (!ee) return;
            if (ee.setTransform(q, 0, 0, q, 0, 0), ee.clearRect(0, 0, z, K), !C) return;
            const e = C, a = he(0) - 80, r = he(z) + 80, i = ge(0) - 80, o = ge(K) + 80;
            ee.setTransform(q * N, 0, 0, q * N, q * j, q * R);
            const c = de.runtime, l = de.dev, u = de.transitive, h = de.edge, g = de.highlight, m = de.muted, v = de.ringHigh, f = de.ringModerate, y = de.label, k = de.backgroundPrimary, b = new Set;
            e.nodes.forEach(e => {
                const t = Math.max(e.radius, e.renderRadius);
                e.renderX + t >= a && e.renderX - t <= r && e.renderY + t >= i && e.renderY - t <= o && b.add(e.slug);
            });
            const w = [];
            let E = 0;
            e.nodes.forEach(e => {
                if (!b.has(e.slug)) return;
                let t = 0;
                L === e.slug ? t = 2 : (I.has(e.slug) || D.has(e.slug)) && (t = 1), w.push({
                    node: e,
                    priority: t,
                    order: E++
                });
            }), w.sort((e, t) => e.priority - t.priority || e.order - t.order);
            const x = Math.max(0, e.layers.length - 1), Y = function(e) {
                const t = new Map;
                return e.nodes.forEach(e => {
                    const n = t.get(e.depth);
                    n ? n.push(e) : t.set(e.depth, [ e ]);
                }), t.forEach(e => {
                    e.sort((e, t) => e.renderY - t.renderY);
                }), t;
            }(e), P = {
                depthNodeIndex: Y,
                maxDepth: x,
                sameColumnXThreshold: 6,
                minDetourVerticalSpan: 80,
                detourInset: 14,
                detourNodeClearance: 26,
                paddingX: 96,
                layerGap: 240,
                edgeCurve: .2
            }, X = [];
            e.edges.forEach(t => {
                const n = e.nodes.get(t.from), a = e.nodes.get(t.to);
                if (!n || !a) return;
                if (!b.has(n.slug) && !b.has(a.slug)) return;
                const r = p(t.from, t.to);
                X.push({
                    from: n,
                    to: a,
                    highlighted: M.has(r) || !L && A.has(r),
                    span: Math.abs(a.depth - n.depth)
                });
            }), X.sort((e, t) => t.span - e.span), ee.globalCompositeOperation = "source-over", 
            ee.strokeStyle = L || S ? m : h, ee.lineWidth = 1.05, ee.globalAlpha = function() {
                if (L || S) return .04 * n((N - .35) / .9, .75, 1);
                return .25 * n((N - .35) / .9, .2, 1);
            }(), ee.beginPath(), X.forEach(e => {
                e.highlighted || d(ee, e, P, Boolean(L));
            }), ee.stroke(), ee.globalCompositeOperation = "lighter", ee.strokeStyle = g, ee.lineWidth = 1.2, 
            ee.globalAlpha = .36 * n((N - .35) / .9, .2, 1), ee.beginPath(), X.forEach(e => {
                e.highlighted && d(ee, e, P, Boolean(L));
            }), ee.stroke(), ee.globalCompositeOperation = "source-over";
            const B = e => {
                const t = L === e.slug, n = e.renderRadius;
                ee.globalAlpha = 1, ee.fillStyle = k, ee.beginPath(), ee.arc(e.renderX, e.renderY, n, 0, 2 * Math.PI), 
                ee.fill(), ee.globalAlpha = We(e.slug);
                const a = ee.createRadialGradient(e.renderX - .3 * n, e.renderY - .3 * n, 0, e.renderX, e.renderY, 1.2 * n);
                "direct-runtime" === e.kind ? (a.addColorStop(0, de.runtimeHighlight), a.addColorStop(1, c)) : "direct-dev" === e.kind ? (a.addColorStop(0, de.devHighlight), 
                a.addColorStop(1, l)) : (a.addColorStop(0, de.transitiveHighlight), a.addColorStop(1, u)), 
                ee.fillStyle = a, ee.beginPath(), ee.arc(e.renderX, e.renderY, n, 0, 2 * Math.PI), 
                ee.fill(), t && (ee.globalAlpha = .95, ee.strokeStyle = g, ee.lineWidth = 1.5, ee.beginPath(), 
                ee.arc(e.renderX, e.renderY, n + 4, 0, 2 * Math.PI), ee.stroke());
            }, T = e => {
                if (!e.ref.vulnerabilityCount || e.ref.vulnerabilityCount <= 0) return;
                if ("none" === e.ref.vulnerabilitySeverity) return;
                const t = e.renderRadius, n = "high" === e.ref.vulnerabilitySeverity ? v : f;
                var a;
                ee.save(), ee.translate(e.renderX, e.renderY), ee.globalAlpha = (a = e.slug, L ? I.has(a) ? .78 : .11 : S ? D.has(a) ? .76 : .12 : .8), 
                ee.strokeStyle = n;
                const r = t / e.radius, s = t / 3 * 1.2 / 12, i = 1.2 * s + 3 * (r - 1), o = Math.max(.5 * s, .15), c = Math.max(1 * s, .3), l = Math.max(3 * s, .8), d = Math.max(1 * s, .3), u = Math.max(.5 * s, .15), p = t + (2 + 6 * (r - 1)) + o / 2, h = p + o / 2 + i + c / 2, g = h + c / 2 + i + l / 2, m = g + l / 2 + i + d / 2, y = m + d / 2 + i + u / 2;
                ee.setLineDash([]), ee.lineWidth = u, ee.beginPath(), ee.arc(0, 0, y, 0, 2 * Math.PI), 
                ee.stroke(), ee.lineWidth = d, ee.beginPath(), ee.arc(0, 0, m, 0, 2 * Math.PI), 
                ee.stroke(), ee.lineWidth = l, ee.beginPath(), ee.arc(0, 0, g, 0, 2 * Math.PI), 
                ee.stroke(), ee.lineWidth = c, ee.beginPath(), ee.arc(0, 0, h, 0, 2 * Math.PI), 
                ee.stroke(), ee.lineWidth = o, ee.beginPath(), ee.arc(0, 0, p, 0, 2 * Math.PI), 
                ee.stroke(), ee.restore();
            };
            for (const t of [ 0, 1, 2 ]) w.forEach(({node: e, priority: n}) => {
                n === t && B(e);
            }), w.forEach(({node: e, priority: n}) => {
                n === t && T(e);
            });
            ee.textBaseline = "middle", ee.font = t, ee.fillStyle = y, w.forEach(({node: e}) => {
                (e => {
                    const t = s(e);
                    t && (ee.globalAlpha = We(e.slug), ee.fillText(t, e.renderX + e.renderRadius + 6, e.renderY));
                })(e);
            }), ee.globalAlpha = 1, Fe();
        }
        function $e() {
            if (!$) return void (_ = 0);
            Re();
            const e = function() {
                if (!C) return !1;
                let e = !1;
                const t = le?.matches;
                return C.nodes.forEach(n => {
                    if (t) return n.renderX = n.targetX, n.renderY = n.targetY, n.renderRadius = n.targetRadius, 
                    void (n.renderLabelChars = n.targetLabelChars);
                    const a = L ? .18 : .15;
                    n.renderX += (n.targetX - n.renderX) * a, n.renderY += (n.targetY - n.renderY) * a, 
                    n.renderRadius += .18 * (n.targetRadius - n.renderRadius), n.renderLabelChars += .32 * (n.targetLabelChars - n.renderLabelChars), 
                    Math.abs(n.targetX - n.renderX) < .06 && Math.abs(n.targetY - n.renderY) < .06 && Math.abs(n.targetRadius - n.renderRadius) < .04 && Math.abs(n.targetLabelChars - n.renderLabelChars) < .12 || (e = !0);
                }), e;
            }(), t = function(e) {
                if (!Q.active) return !1;
                if (!be()) return we(), !1;
                const t = n(e - Q.lastFrameTime || 16, 1, 32);
                Q.lastFrameTime = e, ve(j + Q.velocityX * t, R + Q.velocityY * t);
                const a = Math.exp(-.0042 * t);
                return Q.velocityX *= a, Q.velocityY *= a, U = !0, !(Math.hypot(Q.velocityX, Q.velocityY) < .02 && (we(), 
                1));
            }(performance.now()), a = null !== W && null !== G && (le?.matches ? (ve(W, G), 
            fe(), U = !0, !1) : (j += .12 * (W - j), R += .12 * (G - R), ve(j, R), Math.abs((W ?? j) - j) < .35 && Math.abs((G ?? R) - R) < .35 ? (ve(W, G), 
            fe(), U = !0, !1) : (U = !0, !0)));
            if (U || e || t || a) return Ge(), U = !1, void (_ = $ && (U || e || t || a) ? window.requestAnimationFrame($e) : 0);
            _ = 0;
        }
        function Ue() {
            $ && !_ && U && (_ = window.requestAnimationFrame($e));
        }
        function _e() {
            U = !0, $ && Ue();
        }
        function qe(e) {
            const t = Xe(e);
            t && (we(), x = e, C = t, Ne(), Oe(), S = null, D = new Set, A = new Set, Ye(!0), 
            C && (we(), fe(), Se(), N = V, ve(O, F)), U = !0, _e());
        }
        function ze(e) {
            0 === e.button && (we(), fe(), J.down = !0, J.moved = !1, J.startX = e.clientX, 
            J.startY = e.clientY, J.startPanX = j, J.startPanY = R, Ee(e.clientX, e.clientY, e.timeStamp), 
            Ye(), c.canvas.classList.add("is-panning"));
        }
        function Ke(e) {
            if (!J.down) return void Pe(e.clientX, e.clientY);
            const t = e.clientX - J.startX, n = e.clientY - J.startY;
            (Math.abs(t) > 2 || Math.abs(n) > 2) && (J.moved = !0), ve(J.startPanX + t, J.startPanY + n), 
            Ce(e.clientX, e.clientY, e.timeStamp), _e();
        }
        function Je(e) {
            if (!J.down) return;
            c.canvas.classList.remove("is-panning");
            const t = J.moved;
            if (J.down = !1, J.moved = !1, t) return xe(), Q.active ? void Me(!1) : void Pe(e.clientX, e.clientY);
            const n = Pe(e.clientX, e.clientY);
            if (!n) return je(!1), Ne(), void Oe();
            Te(n.slug), He(n.slug);
        }
        function Ze(e) {
            if (!c.canvasHost.contains(e.target)) return;
            e.preventDefault(), we();
            const t = c.canvas.getBoundingClientRect(), n = e.clientX - t.left, a = e.clientY - t.top, r = e.ctrlKey || e.metaKey ? .015 * e.deltaY : .002 * e.deltaY, s = Math.exp(-r);
            ye(N * s, n, a);
        }
        function Qe(e) {
            if (0 === e.touches.length) return;
            e.preventDefault(), we(), fe(), Ye();
            const t = c.canvas.getBoundingClientRect();
            if (1 === e.touches.length) Z.active = !0, J.moved = !1, Z.startX1 = e.touches[0].clientX, 
            Z.startY1 = e.touches[0].clientY, Z.startPanX = j, Z.startPanY = R, Ee(e.touches[0].clientX, e.touches[0].clientY, e.timeStamp), 
            c.canvas.classList.add("is-panning"); else if (2 === e.touches.length) {
                Z.active = !0, J.moved = !1, Z.startX1 = e.touches[0].clientX, Z.startY1 = e.touches[0].clientY, 
                Z.startX2 = e.touches[1].clientX, Z.startY2 = e.touches[1].clientY;
                const n = Z.startX2 - Z.startX1, a = Z.startY2 - Z.startY1;
                Z.startDist = Math.sqrt(n * n + a * a), Z.startZoom = N;
                const r = (Z.startX1 + Z.startX2) / 2, s = (Z.startY1 + Z.startY2) / 2, i = r - t.left, o = s - t.top;
                Z.anchorX = i, Z.anchorY = o;
            }
        }
        function et(e) {
            if (Z.active) if (e.preventDefault(), 1 === e.touches.length) {
                const t = e.touches[0].clientX - Z.startX1, n = e.touches[0].clientY - Z.startY1;
                (Math.abs(t) > 2 || Math.abs(n) > 2) && (J.moved = !0), ve(Z.startPanX + t, Z.startPanY + n), 
                Ce(e.touches[0].clientX, e.touches[0].clientY, e.timeStamp), _e();
            } else if (2 === e.touches.length) {
                we(), J.moved = !0;
                const t = e.touches[0].clientX, n = e.touches[0].clientY, a = e.touches[1].clientX - t, r = e.touches[1].clientY - n, s = Math.sqrt(a * a + r * r);
                if (Z.startDist > 0) {
                    const e = s / Z.startDist;
                    ye(Z.startZoom * e, Z.anchorX ?? z / 2, Z.anchorY ?? K / 2);
                }
            }
        }
        function tt(e) {
            if (!Z.active) return;
            e.preventDefault();
            if ("touchcancel" === e.type) return we(), Ye(!0), Z.active = !1, Z.anchorX = null, 
            Z.anchorY = null, void (J.moved = !1);
            if (0 === e.touches.length) {
                if (Ye(!0), Z.active = !1, Z.anchorX = null, Z.anchorY = null, J.moved || 1 !== e.changedTouches.length) J.moved && xe(); else {
                    const t = Ie(e.changedTouches[0].clientX, e.changedTouches[0].clientY);
                    t ? (Te(t.slug), He(t.slug)) : (je(!1), Ne(), Oe());
                }
                J.moved = !1;
            } else 1 === e.touches.length && (Z.startX1 = e.touches[0].clientX, Z.startY1 = e.touches[0].clientY, 
            Z.startPanX = j, Z.startPanY = R, Ee(e.touches[0].clientX, e.touches[0].clientY, e.timeStamp));
        }
        function nt() {
            Ve(null), Ye();
        }
        function at(e) {
            if (!$) return;
            const t = e.target;
            c.popover.hidden || c.popover.contains(t) || c.canvasHost.contains(t) || Oe();
        }
        function rt(e) {
            const t = e.target.closest("button[data-action]");
            if (!t) return;
            const n = t.dataset.action;
            n && ("zoom-in" !== n ? "zoom-out" !== n ? "pan-left" !== n ? "pan-right" !== n ? "pan-up" !== n ? "pan-down" !== n ? "reset" === n && (we(), 
            N = V, ve(O, F), Ne(), Oe(), _e()) : ke(0, 52) : ke(0, -52) : ke(52, 0) : ke(-52, 0) : ye(N / 1.18, .5 * z, .5 * K) : ye(1.18 * N, .5 * z, .5 * K));
        }
        function st() {
            T && c.onOpenList(T);
        }
        function it() {
            qe(c.workspaceSelect.value);
        }
        function ot() {
            $ && (Le(), z <= 1 || K <= 1 || (Se(), N = n(N, H, e), ve(j, R), _e()));
        }
        function ct() {
            re || (c.workspaceSelect.addEventListener("change", it), re = !0), ae || (c.controlsRoot.addEventListener("click", rt), 
            c.popoverOpenButton.addEventListener("click", st), ae = !0);
        }
        return {
            initGraphView: function() {
                const e = l.workspaces.length ? l.workspaces : [ {
                    name: "root",
                    directDependencies: [],
                    directDevDependencies: []
                } ], t = e.find(e => "root" === e.name), n = t ? [ t, ...e.filter(e => "root" !== e.name) ] : e;
                c.workspaceSelect.textContent = "", n.forEach((e, t) => {
                    const a = document.createElement("option");
                    if (a.value = e.name, a.textContent = "root" === e.name ? "Workspace root" : e.name, 
                    c.workspaceSelect.appendChild(a), "root" === e.name && n.length > 1 && 0 === t) {
                        const e = document.createElement("option");
                        e.disabled = !0, e.textContent = "──────────────", c.workspaceSelect.appendChild(e);
                    }
                }), c.workspaceWrap.classList.toggle("hidden", e.length <= 1), b.has("root") || 1 !== e.length || b.set("root", e[0]), 
                x = n[0].name, c.workspaceSelect.value = x, ue(), function() {
                    if (se && se.disconnect(), se = new MutationObserver(() => {
                        ue(), _e();
                    }), se.observe(document.documentElement, {
                        attributes: !0,
                        attributeFilter: [ "class", "data-theme" ]
                    }), ie && (ie.disconnect(), ie = null), oe && (window.removeEventListener("resize", oe), 
                    oe = null), "undefined" != typeof ResizeObserver) return ie = new ResizeObserver(ot), 
                    void ie.observe(c.canvasHost);
                    oe = ot, window.addEventListener("resize", oe);
                }(), ct(), te ? (Le(), qe(x)) : pe();
            },
            buildWorkspaceGraph: Xe,
            computeAmplification: Be,
            layoutGraph: De,
            renderLoop: Ue,
            applyFocus: Te,
            clearFocus: Ne,
            showPopover: He,
            hidePopover: Oe,
            switchWorkspace: qe,
            setActive: function(t) {
                if ($ = t, $) return te ? (!ne && te && (c.canvas.addEventListener("mousedown", ze), 
                window.addEventListener("mousemove", Ke), window.addEventListener("mouseup", Je), 
                c.canvas.addEventListener("wheel", Ze, {
                    passive: !1
                }), c.canvas.addEventListener("touchstart", Qe, {
                    passive: !1
                }), window.addEventListener("touchmove", et, {
                    passive: !1
                }), window.addEventListener("touchend", tt, {
                    passive: !1
                }), window.addEventListener("touchcancel", tt, {
                    passive: !1
                }), c.canvas.addEventListener("mouseleave", nt), document.addEventListener("mousedown", at), 
                ne = !0), Le(), z > 1 && K > 1 && (Se(), N = n(N, H, e), ve(j, R)), Ue(), void _e()) : void pe();
                ne && (c.canvas.removeEventListener("mousedown", ze), window.removeEventListener("mousemove", Ke), 
                window.removeEventListener("mouseup", Je), c.canvas.removeEventListener("wheel", Ze), 
                c.canvas.removeEventListener("touchstart", Qe), window.removeEventListener("touchmove", et), 
                window.removeEventListener("touchend", tt), window.removeEventListener("touchcancel", tt), 
                c.canvas.removeEventListener("mouseleave", nt), document.removeEventListener("mousedown", at), 
                Ye(!0), J.down = !1, J.moved = !1, Z.active = !1, Z.anchorX = null, Z.anchorY = null, 
                we(), ne = !1), we(), _ && (window.cancelAnimationFrame(_), _ = 0);
            },
            requestRender: _e
        };
    }
    const w = {
        permissive: [ "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "Unlicense", "0BSD", "CC0-1.0", "BSD", "Apache", "Apache 2.0", "Apache License 2.0", "MIT License", "ISC License" ],
        weakCopyleft: [ "LGPL-2.1", "LGPL-3.0", "LGPL-2.0", "LGPL", "MPL-2.0", "MPL-1.1", "MPL", "EPL-1.0", "EPL-2.0", "EPL" ],
        strongCopyleft: [ "GPL-2.0", "GPL-3.0", "GPL", "AGPL-3.0", "AGPL", "GPL-2.0-only", "GPL-3.0-only", "GPL-2.0-or-later", "GPL-3.0-or-later" ]
    }, E = {
        "network-access": "Accesses the network during install",
        "dynamic-exec": "Uses dynamic execution",
        "child-process": "Spawns child processes",
        encoding: "Uses encoding/decoding logic",
        obfuscated: "Contains obfuscated/minified install logic",
        "reads-env": "Reads environment variables",
        "reads-home": "Reads user home directory",
        "uses-ssh": "Uses SSH configuration/keys"
    };
    function C(e) {
        return e ? e.charAt(0).toUpperCase() + e.slice(1) : e;
    }
    function x(e) {
        const t = e.compliance.license, n = t.declared?.valid ? t.declared.spdxId : void 0, a = t.inferred?.spdxId;
        return n ? {
            value: n,
            isInferred: !1
        } : a ? {
            value: a,
            isInferred: !0
        } : {
            value: "Unknown",
            isInferred: !1
        };
    }
    function L(e) {
        const t = e.security;
        if (t?.summary) return {
            summary: t.summary,
            advisories: t.advisories
        };
        if (t?.vulnerabilities) {
            const e = t.vulnerabilities;
            return {
                summary: {
                    critical: Number(e.critical || 0),
                    high: Number(e.high || 0),
                    moderate: Number(e.moderate || 0),
                    low: Number(e.low || 0),
                    highest: e.highest || "none",
                    risk: t.vulnRisk || t.risk || "green"
                },
                advisories: t.advisories
            };
        }
        return {
            summary: {
                critical: 0,
                high: 0,
                moderate: 0,
                low: 0,
                highest: "none",
                risk: "green"
            },
            advisories: t?.advisories
        };
    }
    function S(e) {
        return e?.highest || "none";
    }
    function I(e) {
        return e && e.risk || "green";
    }
    const M = {
        permissive: "green",
        weakCopyleft: "amber",
        strongCopyleft: "red",
        unknown: "gray"
    }, Y = {
        none: 0,
        low: 1,
        moderate: 2,
        high: 3,
        critical: 4
    }, P = [ {
        id: "type",
        label: "Type",
        sortKey: "type",
        getValue: e => e.usage.direct ? "Dependency" : "Sub-Dependency",
        getTone: e => e.usage.direct ? "green" : "amber",
        sortFn: (e, t) => e.usage.direct === t.usage.direct ? 0 : e.usage.direct ? -1 : 1
    }, {
        id: "scope",
        label: "Scope",
        sortKey: "scope",
        getValue: e => {
            return "runtime" === (t = e.usage.scope) ? "Runtime" : "dev" === t ? "Dev" : "optional" === t ? "Optional" : "peer" === t ? "Peer" : t;
            var t;
        },
        getTone: e => "runtime" === e.usage.scope ? "green" : "dev" === e.usage.scope || "optional" === e.usage.scope ? "amber" : "gray",
        sortFn: (e, t) => e.usage.scope.localeCompare(t.usage.scope)
    }, {
        id: "license",
        label: "License",
        sortKey: "license",
        getValue: e => {
            const t = x(e), n = t.isInferred ? `${t.value} (inferred)` : t.value;
            return "mismatch" === e.compliance.license.status ? `${n} *` : n;
        },
        getTone: e => {
            const t = function(e) {
                if (!e) return "unknown";
                const t = e.toUpperCase();
                for (const [n, a] of Object.entries(w)) if (a.some(e => t.includes(e.toUpperCase()))) return n;
                return "unknown";
            }(x(e).value);
            return M[t];
        },
        sortFn: (e, t) => {
            const n = x(e).value, a = x(t).value;
            return n.localeCompare(a);
        }
    }, {
        id: "vulns",
        label: "Vulnerabilities",
        sortKey: "severity",
        getValue: e => C(S(L(e).summary)),
        getTone: e => L(e).summary.risk,
        sortFn: (e, t) => Y[S(L(t).summary)] - Y[S(L(e).summary)]
    }, {
        id: "install",
        label: "Install",
        sortKey: "install",
        getValue: e => {
            return (t = e.execution) ? C(t.risk || "low") : "Low";
            var t;
        },
        getTone: e => I(e.execution),
        sortFn: (e, t) => {
            const n = {
                green: 0,
                amber: 1,
                red: 2
            }, a = I(e.execution), r = I(t.execution);
            return n[a] - n[r];
        }
    } ], X = P.length;
    function B(e) {
        if (!e) return "unknown";
        const t = e.toUpperCase();
        for (const [n, a] of Object.entries(w)) if (a.some(e => t.includes(e.toUpperCase()))) return n;
        return "unknown";
    }
    function D(e) {
        const t = e.compliance.license, n = t.declared?.valid ? t.declared.spdxId : void 0, a = t.inferred?.spdxId;
        return n ? {
            value: n,
            isInferred: !1
        } : a ? {
            value: a,
            isInferred: !0
        } : {
            value: "Unknown",
            isInferred: !1
        };
    }
    function A(e) {
        switch (e) {
          case "declared-only":
            return "Declared";

          case "inferred-only":
            return "Inferred";

          case "match":
            return "Declared + Inferred (match)";

          case "mismatch":
            return "Declared + Inferred (mismatch)";

          case "invalid-spdx":
            return "Invalid SPDX";

          default:
            return "Unknown";
        }
    }
    const T = {
        none: 0,
        low: 1,
        moderate: 2,
        high: 3,
        critical: 4
    };
    function N(e) {
        const t = e.security;
        if (t?.summary) return {
            summary: t.summary,
            advisories: t.advisories
        };
        if (t?.vulnerabilities) {
            const e = t.vulnerabilities;
            return {
                summary: {
                    critical: Number(e.critical || 0),
                    high: Number(e.high || 0),
                    moderate: Number(e.moderate || 0),
                    low: Number(e.low || 0),
                    highest: e.highest || "none",
                    risk: t.vulnRisk || t.risk || "green"
                },
                advisories: t.advisories
            };
        }
        return {
            summary: {
                critical: 0,
                high: 0,
                moderate: 0,
                low: 0,
                highest: "none",
                risk: "green"
            },
            advisories: t?.advisories
        };
    }
    function j(e) {
        return e ? String(e).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;") : "";
    }
    function R(e) {
        return null != e && ("string" == typeof e ? e.trim().length > 0 : Array.isArray(e) ? e.length > 0 : "object" != typeof e || Object.keys(e).length > 0);
    }
    function V(e) {
        return Array.isArray(e) ? e.map(e => V(e)).join(", ") : "boolean" == typeof e ? e ? "Yes" : "No" : "object" == typeof e && null !== e ? Object.entries(e).filter(([, e]) => R(e)).map(([e, t]) => j(e) + ": " + V(t)).join("<br>") : j(String(e));
    }
    function H(e, t) {
        return R(t) ? '<div class="metadata-row"><div class="metadata-row-label">' + j(e) + '</div><div class="metadata-row-value">' + V(t) + "</div></div>" : "";
    }
    function O(e, t) {
        const n = t.filter(Boolean);
        return 0 === n.length ? "" : '<section class="metadata-section"><div class="metadata-section-title">' + j(e) + '</div><div class="metadata-grid">' + n.join("") + "</div></section>";
    }
    function F(e) {
        const t = e.workspaces;
        if (!t || !t.enabled) return O("Workspaces", [ H("Enabled", !1), H("Type", t?.type) ]);
        const n = t.workspacePackages || [], a = n.length ? '<div class="metadata-list">' + n.map(e => '<div class="metadata-list-item"><div class="metadata-row-value">' + j(e.name) + '</div><div class="metadata-muted">' + j(e.relativePath) + " · runtime " + j(String(e.directExternal.runtime)) + " · dev " + j(String(e.directExternal.dev)) + "</div></div>").join("") + "</div>" : "";
        return O("Workspaces", [ H("Enabled", t.enabled), H("Type", t.type), H("Package count", t.packageCount), a ? '<div class="metadata-row"><div class="metadata-row-label">Packages</div><div>' + a + "</div></div>" : "" ]);
    }
    function W(e) {
        const t = e.supplyChain;
        if (!t) return "";
        const n = t.signatureAudit;
        return O("Supply Chain", [ H("Signals", t.signals?.length), n ? H("Signature audit", {
            attempted: n.attempted,
            ok: n.ok,
            status: n.status,
            error: n.error
        }) : "" ]);
    }
    function G(e) {
        return e ? e.charAt(0).toUpperCase() + e.slice(1) : e;
    }
    function $(e) {
        return e.split(/[\s-_]+/).map(e => e ? G(e) : e).join(" ");
    }
    function U(e) {
        return P.map(t => {
            return n = t.label, a = t.getValue(e), '<div class="badge-card ' + t.getTone(e) + '"><span class="badge-label">' + j(n) + '</span><span class="badge-value">' + j(a) + "</span></div>";
            var n, a;
        }).join("");
    }
    function _(e, t) {
        const n = P.map(n => function(e, t, n, a) {
            const r = n === e, s = r ? a ? " ▲" : " ▼" : "", i = r ? a ? " sorted-asc" : " sorted-desc" : "";
            return '<button type="button" class="column-header' + (r ? " sorted" : "") + i + '" data-sort="' + j(e) + '"><span class="column-header-label">' + j(t) + '</span><span class="sort-indicator">' + s + "</span></button>";
        }(n.sortKey, n.label, e, t)).join("");
        return '<div class="column-headers" style="--column-count: ' + X + '">' + n + "</div>";
    }
    function q(e, t, n) {
        let a = '<div class="kv-item">';
        return a += '<span class="kv-label">' + j(e) + "</span>", a += '<span class="kv-value">' + j(String(t)) + "</span>", 
        n && (a += '<span class="kv-hint">' + j(n) + "</span>"), a += "</div>", a;
    }
    function z(e, t) {
        return '<span class="kv-value risk-value"><span class="risk-dot ' + t + '"></span>' + j(String(e)) + "</span>";
    }
    function K(e, t, n) {
        let a = '<div class="kv-item">';
        return a += '<span class="kv-label">' + j(e) + "</span>", a += t, a += "</div>", 
        a;
    }
    function J(e, t) {
        if (!e || 0 === e.length) return '<span class="kv-value">None</span>';
        const n = e.slice(0, t), a = e.length - t;
        let r = '<div class="package-list">';
        return n.forEach(e => {
            r += '<span class="package-tag">' + j(e) + "</span>";
        }), a > 0 && (r += '<span class="package-tag">+' + a + " more</span>"), r += "</div>", 
        r;
    }
    function Z(e, t, n, a) {
        if (!e || 0 === e.length) return '<span class="kv-value">None</span>';
        const r = e.slice(0, t), s = e.length - t;
        let i = '<div class="package-list">';
        return r.forEach(e => {
            const t = se(e, n, a);
            i += t ? '<a class="package-tag package-tag-link root-package-link" href="#' + j(ne(t)) + '" data-dep-key="' + j(t) + '" aria-label="Jump to dependency ' + j(t) + '">' + j(e) + "</a>" : '<span class="package-tag">' + j(e) + "</span>";
        }), s > 0 && (i += '<span class="package-tag">+' + s + " more</span>"), i += "</div>", 
        i;
    }
    function Q(e, t) {
        return e + "@" + t;
    }
    const ee = new WeakMap;
    function te(e) {
        const t = e.lastIndexOf("@npm:");
        if (t > 0) return {
            name: e.slice(0, t),
            version: e.slice(t + 1)
        };
        const n = e.lastIndexOf("@");
        return n <= 0 ? null : {
            name: e.slice(0, n),
            version: e.slice(n + 1)
        };
    }
    function ne(e) {
        return `dep-${e}`;
    }
    function ae(e) {
        const t = ee.get(e);
        if (t) return t;
        const n = new Map;
        return e.forEach(e => {
            const t = te(e);
            if (!t) return;
            const a = n.get(t.name) || [];
            a.push(e), n.set(t.name, a);
        }), ee.set(e, n), n;
    }
    function re(e, t, n) {
        const a = ((n || ae(t)).get(e) || []).filter(e => t.has(e));
        return 1 === a.length ? a[0] : null;
    }
    function se(e, t, n) {
        if (t.has(e)) return e;
        const a = te(e);
        if (!a) return re(e, t, n);
        if (a.version.startsWith("npm:")) {
            const e = a.version.slice(4), n = a.name + (e.startsWith("@") ? e : "@" + e);
            if (t.has(n)) return n;
        }
        return re(a.name, t, n);
    }
    function ie(e, t, n, a) {
        if (!e || 0 === e.length) return '<span class="kv-value">None</span>';
        const r = e.slice(0, t), s = e.length - t;
        let i = '<div class="package-list">';
        return r.forEach(e => {
            if ("string" == typeof e) {
                const t = se(e, n, a);
                return t ? void (i += '<a class="package-tag package-tag-link root-package-link" href="#' + j(ne(t)) + '" data-dep-key="' + j(t) + '" aria-label="Jump to dependency ' + j(t) + '">' + j(e) + "</a>") : void (i += '<span class="package-tag">' + j(e) + "</span>");
            }
            const t = Q(e.name, e.version), r = e.name + "@" + e.version, s = se(t, n, a);
            i += s ? '<a class="package-tag package-tag-link root-package-link" href="#' + j(ne(s)) + '" data-dep-key="' + j(s) + '" aria-label="Jump to dependency ' + j(s) + '">' + j(r) + "</a>" : '<span class="package-tag">' + j(r) + "</span>";
        }), s > 0 && (i += '<span class="package-tag">+' + s + " more</span>"), i += "</div>", 
        i;
    }
    function oe(e, t, n) {
        const a = e.graph.subDeps;
        if (!a) return "";
        const r = [ {
            title: "Dependencies",
            key: "dep"
        }, {
            title: "Optional",
            key: "opt"
        }, {
            title: "Peer",
            key: "peer"
        }, {
            title: "Dev Dependencies",
            key: "dev"
        } ];
        let s = 0, i = 0;
        for (const l of r) {
            const e = a[l.key];
            if (e) for (const t of Object.values(e)) s += 1, t[1] && (i += 1);
        }
        if (0 === s) return "";
        const o = '<div class="declared-summary">Total: ' + s + " • Installed: " + i + " • Not installed: " + (s - i) + "</div>", c = r.map(e => {
            const r = a[e.key];
            if (!r || 0 === Object.keys(r).length) return "";
            let s = 0, i = 0;
            const o = Object.entries(r).sort(([e], [t]) => e.localeCompare(t)).map(([e, [a, r]]) => {
                s += 1, r && (i += 1);
                const o = '<div class="declared-name">' + j(e) + "</div>", c = '<div class="declared-range">' + j(a) + "</div>", l = r ? function(e, t, n) {
                    const a = se(e, t, n);
                    return a ? '<a class="status-pill installed root-package-link" href="#' + j(ne(a)) + '" data-dep-key="' + j(a) + '" aria-label="Jump to dependency ' + j(a) + '">Installed</a>' : '<span class="status-pill installed">Installed</span>';
                }(r, t, n) : '<span class="status-pill missing">Not installed</span>';
                return '<div class="declared-row">' + o + c + l + "</div>";
            }), c = i + " of " + s + " installed";
            return [ '<details class="declared-group">', '<summary class="declared-group-summary"><span class="expand-icon" aria-hidden="true"></span><span class="declared-group-title">' + j(e.title) + ' <span class="declared-count">(' + c + ")</span></span></summary>", '<div class="declared-table">' + o.join("") + "</div>", "</details>" ].join("");
        }).filter(Boolean);
        return ce("Declared Dependencies", "Dependencies declared by this package", o + '<div class="declared-deps">' + c.join("") + "</div>");
    }
    function ce(e, t, n) {
        let a = '<div class="section">';
        return a += '<div class="section-header">', a += '<span class="section-title">' + j(e) + "</span>", 
        t && (a += '<span class="section-desc">' + j(t) + "</span>"), a += "</div>", a += n, 
        a += "</div>", a;
    }
    function le(e, t, n, a) {
        let r = '<div class="subsection' + (a ? " " + a : "") + '">';
        return r += '<div class="subsection-header">', r += '<span class="subsection-title">' + j(e) + "</span>", 
        n && (r += '<span class="subsection-desc">' + j(n) + "</span>"), r += "</div>", 
        r += t, r += "</div>", r;
    }
    function de(e) {
        if (!e) return;
        const t = e.trim();
        if (!t) return;
        const n = e => e.replace(/\.git$/i, "");
        if (/^https?:\/\//i.test(t)) return n(t);
        if (/^git\+https?:\/\//i.test(t)) return n(t.replace(/^git\+/, ""));
        if (/^git:\/\/github\.com\//i.test(t)) return n(t.replace(/^git:\/\//i, "https://"));
        if (/^github:/i.test(t)) {
            const e = t.slice(7).replace(/^\/+/, "");
            return e ? `https://github.com/${n(e)}` : void 0;
        }
        if (/^git@github\.com:/i.test(t)) {
            const e = t.slice(15);
            return e ? `https://github.com/${n(e)}` : void 0;
        }
        return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(t) ? `https://github.com/${n(t)}` : void 0;
    }
    function ue(e, t) {
        const n = de(e);
        if (!n) return;
        let a;
        try {
            a = new URL(n);
        } catch {
            return;
        }
        if ("github.com" !== a.hostname.toLowerCase()) return;
        const r = a.pathname.split("/").filter(Boolean);
        if (r.length < 2) return;
        const s = r[0], i = r[1].replace(/\.git$/i, "");
        return s && i ? `https://github.com/${s}/${i}/blob/HEAD/${t}` : void 0;
    }
    function pe(e, t) {
        return t ? j(e) + ' <a class="kv-inline-link" href="' + j(t) + '" target="_blank" rel="noopener noreferrer">GitHub<svg class="kv-inline-link-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M7 17 17 7"/><path d="M9 7h8v8"/></svg></a>' : j(e);
    }
    function he(e) {
        const t = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331zM10.665 10H12v2.667h-1.335V10z"/></svg>', n = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>', a = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>', r = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>';
        if (!(e.npm || e.repository || e.homepage || e.issues)) return "";
        let s = '<div class="package-links">';
        return e.npm && (s += '<a href="' + j(e.npm) + '" target="_blank" rel="noopener" class="package-link">' + t + "npm</a>"), 
        e.repository && (s += '<a href="' + j(e.repository) + '" target="_blank" rel="noopener" class="package-link">' + n + "Repository</a>"), 
        e.homepage && (s += '<a href="' + j(e.homepage) + '" target="_blank" rel="noopener" class="package-link">' + r + "Homepage</a>"), 
        e.issues && (s += '<a href="' + j(e.issues) + '" target="_blank" rel="noopener" class="package-link">' + a + "Issues</a>"), 
        s += "</div>", s;
    }
    function ge(e) {
        const t = function(e, t) {
            const n = [ e.risk, t ];
            return n.includes("red") ? "red" : n.includes("amber") ? "amber" : "green";
        }(N(e).summary, e.compliance.licenseRisk), n = Q(e.package.name, e.package.version), a = ne(n), r = U(e), s = [ '<summary class="dep-summary">', '<span class="expand-icon" aria-hidden="true"></span>', '<span class="dep-name">' + j(e.package.name) + '<span class="dep-version">@' + j(e.package.version) + "</span></span>", '<div class="dep-indicators" style="--column-count: ' + X + '">', r, "</div>", "</summary>" ].join("");
        return [ '<details class="dep-card" data-risk="' + t + '" data-dep-key="' + j(n) + '" id="' + j(a) + '">', s, '<div class="dep-details" data-rendered="false"></div>', "</details>" ].join("");
    }
    function me(e, t, n) {
        const a = N(e), r = a.summary, s = D(e), i = s.isInferred ? `${s.value} (inferred)` : s.value, o = function(e) {
            const t = e.package?.links || {}, n = e.links || {}, a = de(t.repository || n.repository || n.repo);
            return {
                npm: t.npm || n.npm,
                repository: a || t.repository || n.repository || n.repo,
                homepage: t.homepage || n.homepage,
                issues: t.bugs || t.issues || n.bugs || n.issues
            };
        }(e), c = JSON.stringify(e, null, 2), l = [ e.usage.direct ? "Direct dependency" : "Indirect dependency (transitive)", "Scope: " + (d = e.usage.scope, 
        "runtime" === d ? "Runtime" : "dev" === d ? "Dev" : "optional" === d ? "Optional" : "peer" === d ? "Peer" : d) ];
        var d;
        e.package.description && l.unshift("Description: " + e.package.description), e.usage.origins.workspaces?.length && l.push("Used in " + e.usage.origins.workspaces.length + " workspaces"), 
        e.usage.importUsage && l.push("Imported in " + e.usage.importUsage.fileCount + " project files"), 
        e.usage.introduction && l.push("Introduced by: " + $(e.usage.introduction)), l.length < 3 && l.push("Dependency depth: " + e.usage.depth);
        var u, p;
        const h = ce("Overview", "Summary and key context", '<div class="micro-summary">' + l.slice(0, 5).map(e => '<div class="micro-line">' + j(e) + "</div>").join("") + "</div>" + (e.usage.origins.workspaces?.length ? '<div class="micro-sublist"><div class="micro-subtitle">Workspaces</div>' + J(e.usage.origins.workspaces, 8) + "</div>" : "") + ('<div class="section-block"><div class="block-title">Key context</div><div class="kv-grid kv-grid-tight">' + [ e.usage.runtimeImpact ? q("Runtime impact", (p = e.usage.runtimeImpact, 
        p ? $(p) : "")) : "", q("Dependency depth", e.usage.depth), e.usage.direct ? "" : K("Introduced via root packages", ie(e.usage.origins.topRootPackages, 8, t, n)), e.usage.direct ? "" : q("Direct roots", e.usage.origins.rootPackageCount), e.usage.direct ? "" : K("Direct parents", Z(e.usage.origins.topParentPackages, 8, t, n)), e.usage.direct ? "" : q("Direct parents count", e.usage.origins.parentPackageCount ?? 0), q("TypeScript types", (u = e.usage.tsTypes, 
        "bundled" === u ? "Bundled" : "definitelyTyped" === u ? "DefinitelyTyped" : "none" === u ? "None" : "Unknown")) ].filter(Boolean).join("") + "</div></div>") + function(e, t, n, a) {
            if (!t || 0 === t.length) return "";
            const r = t.slice(0, n), s = t.length - n;
            let i = '<div class="detail-list">';
            return i += '<div class="detail-title">' + j(e) + "</div>", i += '<ul class="detail-items ' + a + '">', 
            r.forEach(e => {
                i += '<li class="detail-item">' + j(e) + "</li>";
            }), s > 0 && (i += '<li class="detail-item muted">+' + s + " more</li>"), i += "</ul></div>", 
            i;
        }("Top import locations", e.usage.importUsage?.topFiles, 5, "mono")), g = e.compliance.license, m = ue(o.repository, "package.json"), v = ue(o.repository, "LICENSE"), f = [ K("Primary license", z(i, e.compliance.licenseRisk)), q("Status", A(g.status)) ];
        if (g.declared) {
            const e = [ g.declared.valid ? "valid" : "invalid", g.declared.expression ? "expression" : void 0, g.declared.deprecated ? "deprecated" : void 0 ].filter(Boolean).join(", "), t = g.exception?.id ? ` WITH ${g.exception.id}` : "";
            f.push(K("Declared SPDX in package.json", '<span class="kv-value">' + pe(`${g.declared.spdxId}${t}${e ? ` (${e})` : ""}`, m) + "</span>"));
        }
        g.inferred && f.push(K("Inferred from LICENSE file", '<span class="kv-value">' + pe(`${g.inferred.spdxId} (${g.inferred.confidence})`, v) + "</span>")), 
        "mismatch" === g.status && f.push(q("Mismatch", "Declared SPDX and LICENSE text do not match")), 
        "invalid-spdx" === g.status && f.push(q("Invalid SPDX", "Package.json license is not a valid SPDX identifier or expression"));
        const y = le("License", '<div class="kv-grid">' + f.join("") + "</div>"), k = r.critical + r.high + r.moderate + r.low, b = [ K("Known vulnerabilities", z(0 === k ? "None" : String(k), r.risk)), q("Highest severity", "none" === r.highest ? "None" : $(r.highest)) ], w = k > 0 ? '<div class="kv-grid kv-grid-tight">' + [ q("Critical", r.critical), q("High", r.high), q("Moderate", r.moderate), q("Low", r.low) ].join("") + "</div>" : "", C = function(e) {
            if (!e || 0 === e.length) return "";
            let t = '<table class="vuln-table"><thead><tr>';
            return t += "<th>Title</th><th>Severity</th><th>Affected range</th><th>Fix available</th><th>Reference</th>", 
            t += "</tr></thead><tbody>", e.forEach(e => {
                const n = j(e.title), a = e.url ? '<a href="' + j(e.url) + '" target="_blank" rel="noopener">Link</a>' : "";
                t += '<tr data-severity="' + j(e.severity) + '">', t += '<td data-label="Title">' + n + "</td>", 
                t += '<td data-label="Severity">' + j(G(e.severity)) + "</td>", t += '<td data-label="Affected range">' + j(e.vulnerableRange) + "</td>", 
                t += '<td data-label="Fix available">' + j(e.fixAvailable ? "Yes" : "No") + "</td>", 
                t += '<td data-label="Reference">' + a + "</td>", t += "</tr>";
            }), t += "</tbody></table>", t;
        }(a.advisories), x = ce("Risk & Compliance", "License, vulnerabilities, and install-time execution signals", y + le("VULNERABILITIES", [ '<div class="section-note">Based on npm audit findings (known disclosed issues).</div>', '<div class="kv-grid">' + b.join("") + "</div>", w ? '<div class="subtle-divider"></div>' + w : "", C ? '<div class="subtle-divider"></div>' + C : "" ].join(""), "Known security issues from npm audit", "vuln-block") + (e.execution ? function(e) {
            const t = [ K("Execution risk", z((n = e.risk, "red" === n ? "High" : "amber" === n ? "Medium" : "Low"), e.risk)) ];
            var n;
            if (e.native && t.push(q("Native build tooling detected (native)", "Yes")), e.scripts?.hooks?.length && t.push(K("Lifecycle hooks", J(e.scripts.hooks, 6))), 
            "number" == typeof e.scripts?.complexity && t.push(q("Heuristic complexity", "Script complexity: " + e.scripts.complexity + " (complexity)")), 
            e.scripts?.signals?.length) {
                const n = e.scripts.signals.map(e => `${E[e]} (${e})`);
                t.push(K("Install-time signals", J(n, 6)));
            }
            return le("Install-time execution behaviour", '<div class="section-note">Install-time behaviour signals detected. These describe code that runs automatically during install and may warrant review in security-sensitive environments.</div><div class="kv-grid">' + t.join("") + "</div>");
        }(e.execution) : "")), L = [ q("Outdated status", (S = e.upgrade.outdatedStatus, 
        S ? "unknown" === S ? "Unknown" : $(S) : "Not reported")) ];
        var S;
        e.upgrade.latestVersion && L.push(q("Latest version", e.upgrade.latestVersion));
        const I = le("Version", '<div class="section-note">Based on npm outdated findings.</div><div class="kv-grid">' + L.join("") + "</div>"), M = e.package.deprecated ? le("Deprecated", '<div class="kv-grid">' + q("Deprecated", "Yes", "Declared by the package author.") + "</div>", void 0, "warning") : "", Y = [ q("Node engine constraint", e.upgrade.nodeEngine || "Any") ];
        void 0 !== e.upgrade.blocksNodeMajor && Y.push(q("Blocks Node major upgrade", e.upgrade.blocksNodeMajor ? "Yes" : "No"));
        const P = le("Constraints", '<div class="kv-grid">' + Y.join("") + "</div>"), X = le("Blast radius", '<div class="kv-grid">' + [ q("Used by other packages (fanIn)", e.graph.fanIn), q("Depends on packages (fanOut)", e.graph.fanOut) ].join("") + "</div>"), B = {
            nodeEngine: "Node engine constraint",
            peerDependency: "Peer dependency constraints",
            nativeBindings: "Native bindings/build tooling",
            installScripts: "Install lifecycle scripts",
            deprecated: "Deprecated by author"
        }, T = ce("Upgrade & Change Impact", "Currency, constraints, and blast radius", I + M + P + X + (e.upgrade.blockers?.length ? '<div class="subsection"><div class="subsection-header"><span class="subsection-title">Upgrade blockers</span></div><ul class="bullet-list">' + e.upgrade.blockers.map(e => "<li>" + j(B[e] || e) + "</li>").join("") + "</ul></div>" : "")), R = oe(e, t, n);
        return [ he(o), h, x, T, R, '<details class="raw-data-toggle"><summary><span class="expand-icon" aria-hidden="true"></span>View raw data</summary><div class="raw-data-pane"><pre>' + j(c) + '</pre><button type="button" class="copy-json-btn" aria-label="Copy raw JSON">Copy JSON</button></div></details>' ].join("");
    }
    async function ve() {
        const e = await async function() {
            const e = document.getElementById("radar-data");
            return e && e.textContent && "{}" !== e.textContent.trim() ? JSON.parse(e.textContent) : (await fetch("./sample-data.json")).json();
        }();
        void 0 === window.__DEPENDENCY_DATA__ && (window.__DEPENDENCY_DATA__ = e);
        const t = document.getElementById("dependency-list"), n = document.getElementById("results-summary"), a = function(e) {
            const t = "string" == typeof e && e.trim().length > 0 ? e.trim() : "unknown";
            return `https://dependency-radar.com/next-steps?source=standalone-report&cli=${encodeURIComponent(t)}`;
        }(e.dependencyRadarVersion), r = document.getElementById("project-path");
        r && (r.textContent = e.project.name || e.project.projectDir, r.title = e.project.projectDir);
        const s = document.getElementById("metadata-toggle"), i = document.getElementById("metadata-panel"), o = document.getElementById("cta-primary-link"), c = document.getElementById("cta-secondary-link");
        o && (o.href = a), c && (c.href = a);
        const l = document.getElementById("formatted-date");
        let d = e.generatedAt || "";
        if (l && e.generatedAt) try {
            const t = new Date(e.generatedAt);
            d = new Intl.DateTimeFormat(void 0, {
                day: "numeric",
                month: "short",
                year: "numeric",
                hour: "2-digit",
                minute: "2-digit"
            }).format(t), l.textContent = d;
        } catch {
            d = e.generatedAt, l.textContent = e.generatedAt;
        }
        i && (i.innerHTML = function(e, t) {
            const n = e.environment || {}, a = n.minRequiredMajor, r = a && a > 0 ? "Node requirement derived from dependency engine ranges." : "";
            return [ O("Report", [ H("Dependency Radar", e.dependencyRadarVersion), H("Schema", e.schemaVersion), H("Generated", t || e.generatedAt), H("Generated raw", e.generatedAt) ]), O("Project", [ H("Name", e.project.name), H("Version", e.project.version), H("Path", e.project.projectDir), H("Description", e.project.description), H("License", e.project.license), H("Homepage", e.project.homepage), H("Repository", e.project.repository), H("Constraints", e.project.constraints), H("Dependency policy", e.project.dependencyPolicySummary) ]), O("Git", [ H("Branch", e.git?.branch) ]), O("Environment", [ H("Node", n.nodeVersion), H("Runtime", n.runtimeVersion), H("Minimum required Node major", n.minRequiredMajor), H("Target Node major", n.targetNodeMajor), H("Platform", n.platform), H("Architecture", n.arch), H("CI", n.ci), H("packageManager field", n.packageManagerField), H("Package manager", n.packageManager), H("Package manager version", n.packageManagerVersion), H("Tool versions", n.toolVersions), H("Node note", r) ]), F(e), O("Summary", [ H("Dependencies", e.summary?.dependencyCount), H("Direct", e.summary?.directCount), H("Transitive", e.summary?.transitiveCount), H("Findings", e.summary?.findingCount) ]), W(e) ].filter(Boolean).join("");
        }(e, d), i.hidden = !1);
        const u = e => {
            s && i && (i.classList.toggle("open", e), s.classList.toggle("open", e), s.setAttribute("aria-expanded", String(e)));
        };
        s?.addEventListener("click", () => {
            const e = !i?.classList.contains("open");
            u(e);
        }), document.addEventListener("click", e => {
            if (!s || !i) return;
            if (!i.classList.contains("open")) return;
            const t = e.target;
            s.contains(t) || i.contains(t) || u(!1);
        }), document.addEventListener("keydown", e => {
            "Escape" === e.key && u(!1);
        });
        const p = {
            search: document.getElementById("search"),
            direct: document.getElementById("direct-filter"),
            runtime: document.getElementById("runtime-filter"),
            workspace: document.getElementById("workspace-filter"),
            workspaceWrap: document.getElementById("workspace-filter-wrap"),
            sort: document.getElementById("sort-by"),
            sortDirection: document.getElementById("sort-direction"),
            hasVulns: document.getElementById("has-vulns"),
            themeSwitch: document.getElementById("theme-switch"),
            licenseToggle: document.getElementById("license-toggle"),
            licensePanel: document.getElementById("license-panel"),
            licensePermissive: document.getElementById("license-permissive"),
            licenseWeakCopyleft: document.getElementById("license-weak-copyleft"),
            licenseStrongCopyleft: document.getElementById("license-strong-copyleft"),
            licenseUnknown: document.getElementById("license-unknown"),
            licenseAll: document.getElementById("license-all"),
            licenseFriendly: document.getElementById("license-friendly"),
            filtersToggle: document.getElementById("filters-toggle"),
            filterCountBadge: document.getElementById("filter-count-badge"),
            filterControls: document.getElementById("filter-controls"),
            activeFiltersRow: document.getElementById("active-filters-row"),
            activeFilterChips: document.getElementById("active-filter-chips"),
            activeFilterClear: document.getElementById("active-filter-clear"),
            clearAllFilters: document.getElementById("clear-all-filters"),
            licensePermissiveLabel: document.getElementById("license-permissive-label"),
            licenseWeakCopyleftLabel: document.getElementById("license-weak-copyleft-label"),
            licenseStrongCopyleftLabel: document.getElementById("license-strong-copyleft-label"),
            licenseUnknownLabel: document.getElementById("license-unknown-label"),
            hasVulnsLabel: document.getElementById("has-vulns-label"),
            columnHeadersContainer: document.getElementById("column-headers-container"),
            packageHeader: document.getElementById("package-header"),
            viewGraphButton: document.getElementById("view-graph-btn"),
            graphBackButton: document.getElementById("graph-back-btn"),
            listViewPanel: document.getElementById("list-view"),
            graphViewPanel: document.getElementById("graph-view"),
            graphWorkspaceSelect: document.getElementById("graph-workspace"),
            graphWorkspaceWrap: document.getElementById("graph-workspace-wrap"),
            graphControls: document.getElementById("graph-controls"),
            graphCanvas: document.getElementById("graph-canvas"),
            graphCanvasShell: document.getElementById("graph-canvas-shell"),
            graphPopover: document.getElementById("graph-popover"),
            graphPopoverName: document.getElementById("graph-popover-name"),
            graphPopoverVersion: document.getElementById("graph-popover-version"),
            graphPopoverLicense: document.getElementById("graph-popover-license"),
            graphPopoverVulns: document.getElementById("graph-popover-vulns"),
            graphPopoverAmplification: document.getElementById("graph-popover-amplification"),
            graphOpenList: document.getElementById("graph-open-list"),
            reportFooter: document.querySelector(".report-footer")
        };
        let h = "name", g = !0, m = null, v = !1;
        document.documentElement.setAttribute("data-theme", "dark");
        "light" === localStorage.getItem("dependency-radar-theme") ? (document.documentElement.classList.add("light"), 
        p.themeSwitch.classList.add("light"), document.documentElement.setAttribute("data-theme", "light")) : (document.documentElement.classList.remove("light"), 
        p.themeSwitch.classList.remove("light"), document.documentElement.setAttribute("data-theme", "dark")), 
        p.themeSwitch.addEventListener("click", () => {
            document.documentElement.classList.toggle("light"), p.themeSwitch.classList.toggle("light");
            const e = document.documentElement.classList.contains("light");
            document.documentElement.setAttribute("data-theme", e ? "light" : "dark"), localStorage.setItem("dependency-radar-theme", e ? "light" : "dark"), 
            m?.requestRender();
        });
        const f = window.matchMedia("(max-width: 768px)");
        let y = f.matches;
        const k = e => {
            p.filterControls && p.filtersToggle && (p.filterControls.classList.toggle("open", e), 
            p.filtersToggle.classList.toggle("open", e), p.filtersToggle.setAttribute("aria-expanded", String(e)), 
            e && u(!1));
        }, w = () => {
            if (f.matches) return k(!1), void (y = !0);
            y && k(!1), y = !1;
        };
        function E() {
            if (p.columnHeadersContainer && (p.columnHeadersContainer.innerHTML = _(h, g)), 
            p.packageHeader) {
                const e = p.packageHeader.querySelector(".sort-indicator");
                e && ("name" === h ? (e.textContent = g ? " ▲" : " ▼", p.packageHeader.classList.add("sorted")) : (e.textContent = "", 
                p.packageHeader.classList.remove("sorted")));
            }
        }
        function C(e) {
            const t = e.target.closest(".column-header");
            if (!t) return;
            const n = t.dataset.sort;
            n && (h === n ? g = !g : (h = n, g = !0), p.sort && (p.sort.value = h, p.sortDirection.textContent = g ? "↑" : "↓"), 
            E(), K());
        }
        p.filtersToggle && p.filterControls && p.filtersToggle.addEventListener("click", () => {
            const e = !p.filterControls.classList.contains("open");
            k(e);
        }), document.addEventListener("click", e => {
            if (!p.filterControls || !p.filtersToggle) return;
            const t = e.target;
            p.filterControls.contains(t) || p.filtersToggle.contains(t) || k(!1);
        }), document.addEventListener("keydown", e => {
            "Escape" === e.key && k(!1);
        }), window.addEventListener("resize", w), w(), p.sortDirection.addEventListener("click", () => {
            g = !g, p.sortDirection.textContent = g ? "↑" : "↓", E(), K();
        }), p.sort.addEventListener("change", () => {
            h = p.sort.value, E(), K();
        }), p.columnHeadersContainer && p.columnHeadersContainer.addEventListener("click", C), 
        p.packageHeader && p.packageHeader.addEventListener("click", C), E(), p.licenseAll.addEventListener("click", () => {
            p.licensePermissive.checked = !0, p.licenseWeakCopyleft.checked = !0, p.licenseStrongCopyleft.checked = !0, 
            p.licenseUnknown.checked = !0, V.clear(), K();
        }), p.licenseFriendly.addEventListener("click", () => {
            p.licensePermissive.checked = !0, p.licenseWeakCopyleft.checked = !1, p.licenseStrongCopyleft.checked = !1, 
            p.licenseUnknown.checked = !1, V.clear(), K();
        });
        const x = Object.values(e.dependencies || {}), L = function(e) {
            if (!e.workspaces.enabled) return [];
            const t = new Set;
            return (e.workspaces.workspacePackages || []).forEach(e => {
                e.name && t.add(e.name);
            }), Object.values(e.dependencies || {}).forEach(e => {
                (e.usage.origins.workspaces || []).forEach(e => {
                    e && t.add(e);
                });
            }), Array.from(t).sort((e, t) => "root" === e ? -1 : "root" === t ? 1 : e.localeCompare(t));
        }(e), S = (e, t) => e + " (" + t + ")", I = e => {
            return T[(t = N(e).summary, t?.highest || "none")] > 0;
            var t;
        }, M = e => x.reduce((t, n) => t + (e(n) ? 1 : 0), 0);
        if (p.workspace && p.workspaceWrap && L.length > 1) {
            p.workspace.textContent = "";
            const e = document.createElement("option");
            e.value = "all", e.textContent = S("All workspaces", x.length), p.workspace.appendChild(e), 
            L.forEach(e => {
                const t = document.createElement("option");
                t.value = e, t.textContent = S("root" === e ? "Workspace root" : e, M(t => (t.usage.origins.workspaces || []).includes(e))), 
                p.workspace.appendChild(t);
            }), p.workspaceWrap.classList.remove("hidden");
        }
        !function() {
            const e = x.length;
            p.direct.options[0].textContent = S("All", e), p.direct.options[1].textContent = S("Direct", M(e => e.usage.direct)), 
            p.direct.options[2].textContent = S("Transitive", M(e => !e.usage.direct));
            const t = {
                all: "All",
                runtime: "Production",
                dev: "Development",
                optional: "Optional",
                peer: "Peer"
            };
            Array.from(p.runtime.options).forEach(n => {
                n.textContent = S(t[n.value] || n.textContent || n.value, "all" === n.value ? e : M(e => e.usage.scope === n.value));
            });
            const n = {
                permissive: 0,
                weakCopyleft: 0,
                strongCopyleft: 0,
                unknown: 0
            };
            x.forEach(e => {
                n[B(D(e).value)] += 1;
            }), p.licensePermissiveLabel && (p.licensePermissiveLabel.textContent = S("Permissive", n.permissive)), 
            p.licenseWeakCopyleftLabel && (p.licenseWeakCopyleftLabel.textContent = S("Weak Copyleft", n.weakCopyleft)), 
            p.licenseStrongCopyleftLabel && (p.licenseStrongCopyleftLabel.textContent = S("Strong Copyleft", n.strongCopyleft)), 
            p.licenseUnknownLabel && (p.licenseUnknownLabel.textContent = S("Other / Unknown", n.unknown)), 
            p.hasVulnsLabel && (p.hasVulnsLabel.textContent = S("Has vulnerabilities", M(I)));
        }();
        const Y = new Map;
        x.forEach(e => {
            Y.set(Q(e.package.name, e.package.version), e);
        });
        const X = new Set(Y.keys()), A = ae(X), R = new Set, V = new Set, G = new Map, $ = (() => {
            const e = document.getElementById("copy-announcer");
            if (e) return e;
            const t = document.createElement("div");
            return t.id = "copy-announcer", t.className = "sr-only", t.setAttribute("aria-live", "polite"), 
            document.body.appendChild(t), t;
        })();
        function U(e) {
            const t = e.dataset.depKey;
            if (!t) return;
            const n = e.querySelector(".dep-details");
            if (!n || "true" === n.dataset.rendered) return;
            const a = Y.get(t);
            a && (n.setAttribute("aria-busy", "true"), n.innerHTML = [ '<div class="dep-loading" role="presentation">', '<div class="dep-loading-bar"></div>', "</div>" ].join(""), 
            requestAnimationFrame(() => {
                n.innerHTML = me(a, X, A), n.dataset.rendered = "true", n.removeAttribute("aria-busy");
            }));
        }
        function q(e) {
            const t = e.selectedOptions[0];
            return (t?.textContent || "").replace(/\s+\(\d+\)$/, "");
        }
        function z() {
            const e = [];
            "all" !== p.direct.value && e.push({
                id: "type",
                label: "Type: " + q(p.direct),
                remove: () => {
                    p.direct.value = "all";
                }
            }), "all" !== p.runtime.value && e.push({
                id: "scope",
                label: "Scope: " + q(p.runtime),
                remove: () => {
                    p.runtime.value = "all";
                }
            }), p.workspace && "all" !== p.workspace.value && e.push({
                id: "workspace",
                label: "Workspace: " + q(p.workspace),
                remove: () => {
                    p.workspace.value = "all";
                }
            });
            return [ {
                id: "license-permissive",
                checked: p.licensePermissive.checked,
                label: "License: Permissive",
                reset: () => {
                    p.licensePermissive.checked = !0;
                }
            }, {
                id: "license-weak-copyleft",
                checked: p.licenseWeakCopyleft.checked,
                label: "License: Weak Copyleft",
                reset: () => {
                    p.licenseWeakCopyleft.checked = !0;
                }
            }, {
                id: "license-strong-copyleft",
                checked: p.licenseStrongCopyleft.checked,
                label: "License: Strong Copyleft",
                reset: () => {
                    p.licenseStrongCopyleft.checked = !0;
                }
            }, {
                id: "license-unknown",
                checked: p.licenseUnknown.checked,
                label: "License: Other / Unknown",
                reset: () => {
                    p.licenseUnknown.checked = !0;
                }
            } ].forEach(t => {
                t.checked || e.push({
                    id: t.id,
                    label: t.label,
                    remove: t.reset
                });
            }), p.hasVulns.checked && e.push({
                id: "has-vulns",
                label: "Has vulnerabilities",
                remove: () => {
                    p.hasVulns.checked = !1;
                }
            }), e;
        }
        function K() {
            !function() {
                const e = z(), t = e.length;
                p.filtersToggle.classList.toggle("has-active-filters", t > 0), p.filterCountBadge && (p.filterCountBadge.hidden = 0 === t, 
                p.filterCountBadge.textContent = String(t)), p.activeFiltersRow && p.activeFilterChips && (p.activeFiltersRow.hidden = 0 === t, 
                p.activeFilterChips.innerHTML = e.map(e => '<span class="active-filter-chip">' + j(e.label) + '<button type="button" class="active-filter-remove" data-filter-chip="' + j(e.id) + '" aria-label="Remove ' + j(e.label) + '">×</button></span>').join(""));
            }();
            const a = function(e) {
                const t = [ ...e ];
                if ("name" === h) t.sort((e, t) => e.package.name.localeCompare(t.package.name)); else if ("depth" === h) t.sort((e, t) => e.usage.depth - t.usage.depth); else {
                    const e = P.find(e => e.sortKey === h || e.id === h);
                    e?.sortFn ? t.sort(e.sortFn) : e && t.sort((t, n) => e.getValue(t).localeCompare(e.getValue(n)));
                }
                return g || t.reverse(), t;
            }(function() {
                const e = (p.search.value || "").toLowerCase(), t = p.direct.value, n = p.runtime.value, a = p.workspace?.value || "all", r = p.hasVulns.checked, s = p.licensePermissive.checked, i = p.licenseWeakCopyleft.checked, o = p.licenseStrongCopyleft.checked, c = p.licenseUnknown.checked;
                return x.filter(l => {
                    const d = Q(l.package.name, l.package.version);
                    if (V.has(d)) return !0;
                    const u = D(l), p = [ u.value, l.compliance.license.declared?.spdxId, l.compliance.license.inferred?.spdxId ].filter(Boolean).join(" ").toLowerCase();
                    if (e && !l.package.name.toLowerCase().includes(e) && !p.includes(e)) return !1;
                    if ("direct" === t && !l.usage.direct) return !1;
                    if ("transitive" === t && l.usage.direct) return !1;
                    if ("all" !== n && l.usage.scope !== n) return !1;
                    if ("all" !== a && !(l.usage.origins.workspaces || []).includes(a)) return !1;
                    if (r && !I(l)) return !1;
                    const h = B(u.value);
                    return !("permissive" === h && !s || "weakCopyleft" === h && !i || "strongCopyleft" === h && !o || "unknown" === h && !c);
                });
            }()), r = e.summary?.dependencyCount || x.length;
            n.innerHTML = "Showing <strong>" + a.length + "</strong> of <strong>" + r + "</strong> dependencies", 
            "all" !== (p.workspace?.value || "all") && (n.innerHTML += " in <strong>" + j(p.workspace.value) + "</strong>"), 
            0 !== a.length ? (t.innerHTML = a.map(ge).join(""), G.clear(), t.querySelectorAll("details.dep-card").forEach(e => {
                const t = e.dataset.depKey;
                t && G.set(t, e);
            }), R.forEach(e => {
                const t = G.get(e);
                t && (t.open || (t.open = !0), U(t));
            })) : t.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📦</div><div class="empty-state-text">No dependencies match your filters</div></div>';
        }
        function J(e) {
            const t = A.get(e) || [];
            return 1 === t.length ? t[0] : null;
        }
        function Z(e) {
            if (Y.has(e)) return e;
            const t = te(e);
            if (!t) return J(e);
            if (t.version.startsWith("npm:")) {
                const e = t.version.slice(4), n = t.name + (e.startsWith("@") ? e : "@" + e);
                if (Y.has(n)) return n;
            }
            return J(t.name);
        }
        function ee(t) {
            if (!p.listViewPanel || !p.graphViewPanel) return void console.warn("Dependency Radar: view panels are missing from the report DOM.");
            const n = "list" === t;
            n || Boolean(p.graphWorkspaceSelect && p.graphWorkspaceWrap && p.graphControls && p.graphCanvas && p.graphCanvasShell && p.graphPopover && p.graphPopoverName && p.graphPopoverVersion && p.graphPopoverLicense && p.graphPopoverVulns && p.graphPopoverAmplification && p.graphOpenList) ? (p.listViewPanel.classList.toggle("active", n), 
            p.graphViewPanel.classList.toggle("active", !n), p.listViewPanel.setAttribute("aria-hidden", String(!n)), 
            p.graphViewPanel.setAttribute("aria-hidden", String(n)), p.viewGraphButton && (p.viewGraphButton.style.display = n ? "" : "none"), 
            p.graphBackButton && (p.graphBackButton.style.display = n ? "none" : ""), p.reportFooter?.classList.toggle("hidden", !n), 
            document.body.classList.toggle("graph-mode", !n), n ? m?.setActive(!1) : (v || (m = b({
                report: e,
                knownDepKeys: X,
                resolveDepKey: Z,
                workspaceSelect: p.graphWorkspaceSelect,
                workspaceWrap: p.graphWorkspaceWrap,
                controlsRoot: p.graphControls,
                canvas: p.graphCanvas,
                canvasHost: p.graphCanvasShell,
                popover: p.graphPopover,
                popoverName: p.graphPopoverName,
                popoverVersion: p.graphPopoverVersion,
                popoverLicense: p.graphPopoverLicense,
                popoverVulns: p.graphPopoverVulns,
                popoverAmplification: p.graphPopoverAmplification,
                popoverOpenButton: p.graphOpenList,
                onOpenList: e => {
                    !function(e) {
                        ee("list");
                        let t = document.getElementById(ne(e));
                        !t && Y.has(e) && (V.add(e), K(), t = document.getElementById(ne(e)));
                        if (!t) return;
                        if (t instanceof HTMLDetailsElement) {
                            const e = t.dataset.depKey;
                            e && R.add(e), t.open || (t.open = !0), U(t);
                        }
                        t.classList.add("dep-list-highlight"), re(t, !0), window.setTimeout(() => {
                            t?.classList.remove("dep-list-highlight");
                        }, 2e3);
                    }(e);
                }
            }), m.initGraphView(), v = !0), m?.setActive(!0), m?.requestRender())) : console.warn("Dependency Radar: graph view DOM nodes are missing; graph view disabled.");
        }
        function re(e, t = !1) {
            const n = () => {
                const n = window.scrollY + e.getBoundingClientRect().top - function() {
                    const e = document.querySelector(".filter-bar");
                    return !e || document.body.classList.contains("graph-mode") ? 0 : Math.ceil(e.getBoundingClientRect().height + 8);
                }();
                if (window.scrollTo({
                    top: Math.max(0, n),
                    behavior: "smooth"
                }), t) {
                    const t = e.querySelector("summary");
                    t && t.focus({
                        preventScroll: !0
                    });
                }
            };
            requestAnimationFrame(() => {
                n(), window.setTimeout(n, 60);
            });
        }
        const se = [ p.search, p.direct, p.runtime, p.sort, p.hasVulns, p.workspace, p.licensePermissive, p.licenseWeakCopyleft, p.licenseStrongCopyleft, p.licenseUnknown ], ie = () => {
            V.clear(), K();
        };
        se.forEach(e => {
            e && (e.addEventListener("input", ie), e.addEventListener("change", ie));
        }), p.activeFilterChips?.addEventListener("click", e => {
            const t = e.target.closest("[data-filter-chip]");
            if (!t) return;
            const n = z().find(e => e.id === t.dataset.filterChip);
            n && (n.remove(), ie());
        });
        const oe = () => {
            p.direct.value = "all", p.runtime.value = "all", p.workspace && (p.workspace.value = "all"), 
            p.hasVulns.checked = !1, p.licensePermissive.checked = !0, p.licenseWeakCopyleft.checked = !0, 
            p.licenseStrongCopyleft.checked = !0, p.licenseUnknown.checked = !0, ie();
        };
        function ce(e) {
            const t = e.getAttribute("data-dep-key");
            if (!t) return;
            const n = Z(t);
            if (!n) return;
            let a = G.get(n);
            a || (V.add(n), K(), a = G.get(n)), a && (R.add(n), a.open || (a.open = !0), U(a), 
            re(a, !0));
        }
        p.activeFilterClear?.addEventListener("click", oe), p.clearAllFilters?.addEventListener("click", oe), 
        p.viewGraphButton?.addEventListener("click", () => {
            ee("graph");
        }), p.graphBackButton?.addEventListener("click", () => {
            ee("list");
        }), t.addEventListener("toggle", e => {
            const t = e.target;
            if (!(t instanceof HTMLDetailsElement)) return;
            if (!t.classList.contains("dep-card")) return;
            const n = t.dataset.depKey;
            n && (t.open ? (R.add(n), U(t)) : R.delete(n));
        }, !0), t.addEventListener("click", e => {
            const t = e.target, n = t.closest(".root-package-link");
            if (n) return e.preventDefault(), void ce(n);
            const a = t.closest(".copy-json-btn");
            a && (e.preventDefault(), async function(e) {
                const t = e.closest(".raw-data-toggle"), n = t?.querySelector("pre"), a = n?.textContent ?? "";
                if (a) try {
                    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(a); else {
                        const e = document.createElement("textarea");
                        e.value = a, e.setAttribute("readonly", "true"), e.style.position = "absolute", 
                        e.style.left = "-9999px", document.body.appendChild(e), e.select(), document.execCommand("copy"), 
                        document.body.removeChild(e);
                    }
                    const t = e.dataset.label || e.textContent || "Copy JSON";
                    e.dataset.label = t, e.textContent = "Copied", e.classList.add("copied"), $.textContent = "Copied JSON to clipboard.", 
                    window.setTimeout(() => {
                        e.textContent = t, e.classList.remove("copied");
                    }, 1500);
                } catch {
                    $.textContent = "Copy failed.";
                }
            }(a));
        }), t.addEventListener("keydown", e => {
            const t = e.target.closest(".root-package-link");
            t && (" " !== e.key && "Spacebar" !== e.key || (e.preventDefault(), ce(t)));
        }), E(), K(), ee("list");
    }
    "loading" === document.readyState ? document.addEventListener("DOMContentLoaded", ve) : ve();
}();
