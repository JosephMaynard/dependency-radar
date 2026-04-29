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
    function d(e, t) {
        return `${e}@${t}`;
    }
    function u(e, t) {
        return `${e}->${t}`;
    }
    function p(e) {
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
    function h(e) {
        const t = e.compliance.license.declared?.valid ? e.compliance.license.declared.spdxId : void 0;
        return t || (e.compliance.license.inferred?.spdxId || "Unknown");
    }
    function g(e) {
        const t = e.security?.summary;
        return t ? Number(t.critical || 0) + Number(t.high || 0) + Number(t.moderate || 0) + Number(t.low || 0) : 0;
    }
    function m(e) {
        const t = e.security?.summary?.highest;
        return "critical" === t || "high" === t ? "high" : "moderate" === t ? "moderate" : "none";
    }
    function v(e, t) {
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
    function f(e, t) {
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
    function y(c) {
        const y = function(e, t, n) {
            const a = window.__DEPENDENCY_DATA__;
            if (p(a)) {
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
                const t = d(e.package.name, e.package.version);
                r[t] = {
                    slug: t,
                    name: e.package.name,
                    version: e.package.version,
                    dependencies: [],
                    license: h(e),
                    vulnerabilityCount: g(e),
                    vulnerabilitySeverity: m(e),
                    isDevOnly: "dev" === e.usage.scope,
                    workspaceOrigins: e.usage.origins.workspaces || []
                };
            }), s.forEach(e => {
                const a = d(e.package.name, e.package.version), s = e.graph.subDeps;
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
                const t = d(e.package.name, e.package.version);
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
        }(c.report, c.knownDepKeys, c.resolveDepKey), k = new Map(y.workspaces.map(e => [ e.name, e ])), b = new Map, w = new Map;
        Object.values(y.dependencies).forEach(e => {
            const t = (e.dependencies || []).filter(t => t !== e.slug && Boolean(y.dependencies[t]));
            w.set(e.slug, t), t.forEach(t => {
                const n = b.get(t) || [];
                n.push(e.slug), b.set(t, n);
            });
        });
        let E = null, C = "", x = null, L = null, S = new Set, I = new Set, M = new Set, X = new Set, Y = new Set, P = null, B = 1, D = 0, A = 0, N = 1, T = .1, R = 0, H = 0, V = !1, O = !0, j = 0, F = Math.max(1, Math.floor(window.devicePixelRatio || 1)), W = 1, $ = 1;
        const G = {
            down: !1,
            moved: !1,
            startX: 0,
            startY: 0,
            startPanX: 0,
            startPanY: 0
        }, U = {
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
        }, _ = {
            active: !1,
            velocityX: 0,
            velocityY: 0,
            lastSampleX: 0,
            lastSampleY: 0,
            lastSampleTime: 0,
            lastFrameTime: 0
        }, q = c.canvas.getContext("2d"), z = Boolean(q);
        let K = !1, J = !1, Z = !1, Q = null, ee = null, te = null, ne = !1;
        const ae = "function" == typeof window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
        let re = {
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
        function se() {
            const e = o("--graph-direct-runtime") || "#10b981", t = o("--graph-direct-dev") || "#f59e0b", n = o("--graph-transitive") || "#06b6d4";
            re = {
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
        function ie() {
            if (ne) return;
            ne = !0, console.warn("Dependency Radar: unable to initialize 2D canvas; graph rendering disabled."), 
            c.controlsRoot.classList.add("hidden"), c.workspaceWrap.classList.add("hidden"), 
            c.canvas.style.display = "none";
            const e = document.createElement("div");
            e.className = "empty-state";
            const t = document.createElement("div");
            t.className = "empty-state-text", t.textContent = "Graph view is unavailable in this browser context.", 
            e.appendChild(t), c.canvasHost.appendChild(e);
        }
        function oe(e) {
            return (e - D) / B;
        }
        function ce(e) {
            return (e - A) / B;
        }
        function le(e, t) {
            const a = function(e, t) {
                if (!E) return {
                    x: e,
                    y: t
                };
                const a = E.bounds.minX - 120, r = E.bounds.maxX + 120, s = E.bounds.minY - 90, i = E.bounds.maxY + 90, o = Math.min(.22 * W, 220), c = Math.min(.22 * $, 180), l = o - r * B, d = W - o - a * B, u = c - i * B, p = $ - c - s * B;
                return {
                    x: l > d ? .5 * (l + d) : n(e, l, d),
                    y: u > p ? .5 * (u + p) : n(t, u, p)
                };
            }(e, t);
            D = a.x, A = a.y;
        }
        function de(t, a, r) {
            he();
            const s = n(t, T, e), i = oe(a), o = ce(r);
            B = s, le(a - i * B, r - o * B), O = !0, He();
        }
        function ue(e, t) {
            he(), le(D + e, A + t), O = !0, He();
        }
        function pe() {
            return !ae?.matches;
        }
        function he() {
            _.active = !1, _.velocityX = 0, _.velocityY = 0, _.lastFrameTime = 0;
        }
        function ge(e, t, n) {
            _.lastSampleX = e, _.lastSampleY = t, _.lastSampleTime = n;
        }
        function me(e, t, n) {
            const a = n - _.lastSampleTime;
            if (a <= 0) return void ge(e, t, n);
            const r = (e - _.lastSampleX) / a, s = (t - _.lastSampleY) / a;
            _.velocityX += .22 * (r - _.velocityX), _.velocityY += .22 * (s - _.velocityY), 
            ge(e, t, n);
        }
        function ve() {
            if (!pe()) return void he();
            Math.hypot(_.velocityX, _.velocityY) < .08 ? he() : (_.active = !0, _.lastFrameTime = performance.now(), 
            Me(!1), He());
        }
        function fe() {
            const e = c.canvasHost.getBoundingClientRect();
            W = Math.max(1, Math.floor(e.width)), $ = Math.max(1, Math.floor(e.height)), F = Math.max(1, Math.floor(window.devicePixelRatio || 1)), 
            c.canvas.width = W * F, c.canvas.height = $ * F, c.canvas.style.width = `${W}px`, 
            c.canvas.style.height = `${$}px`;
            const t = c.canvasHost.querySelector(".graph-overlay-top"), n = t ? Math.ceil(t.getBoundingClientRect().height) : 50;
            c.canvasHost.style.setProperty("--graph-toolbar-height", `${n}px`), O = !0, He();
        }
        function ye() {
            if (!E) return;
            const a = E.bounds;
            let r = a.maxX;
            q && (q.save(), q.font = t, E.nodes.forEach(e => {
                const t = s(e);
                if (!t) return;
                const n = q.measureText(t).width;
                r = Math.max(r, e.baseX + e.radius + 6 + n);
            }), q.restore());
            const i = Math.max(1, a.maxY - a.minY), o = W / Math.max(1, r - a.minX), c = $ / i;
            N = n(Math.min(o, c), .05, e), T = n(.64 * N, .05, e), R = .5 * (W - Math.max(1, r - a.minX) * N) - a.minX * N, 
            H = .5 * ($ - i * N) - a.minY * N;
        }
        function ke(e, t) {
            if (!E) return null;
            const n = c.canvas.getBoundingClientRect();
            if (e < n.left || e > n.right || t < n.top || t > n.bottom) return null;
            const a = oe(e - n.left), r = ce(t - n.top);
            let s = null, i = 1 / 0;
            return E.nodes.forEach(e => {
                const t = a - e.renderX, n = r - e.renderY, o = Math.sqrt(t * t + n * n);
                o <= e.renderRadius + 5 && o < i && (i = o, s = e);
            }), s;
        }
        function be(e) {
            c.canvas.classList.toggle("is-clickable", e && !G.down && !U.active);
        }
        function we(e = !1) {
            be(!1), e && c.canvas.classList.remove("is-panning");
        }
        function Ee(e, t) {
            const n = ke(e, t);
            return Ye(n ? n.slug : null), be(Boolean(n)), n;
        }
        function Ce(e) {
            const t = k.get(e);
            if (!t) return null;
            const n = new Set(t.directDependencies.filter(e => Boolean(y.dependencies[e]))), s = new Set(t.directDevDependencies.filter(e => Boolean(y.dependencies[e]))), i = new Set([ ...n, ...s ]);
            0 === i.size && Object.keys(y.dependencies).filter(e => 0 === (b.get(e) || []).length).slice(0, 40).forEach(e => {
                i.add(e);
            });
            const o = new Set, c = [ ...i ];
            let l = 0;
            for (;l < c.length; ) {
                const e = c[l++];
                e && (o.has(e) || y.dependencies[e] && (o.add(e), (w.get(e) || []).forEach(e => {
                    o.has(e) || c.push(e);
                })));
            }
            if (0 === o.size) return null;
            const d = new Map;
            o.forEach(e => {
                const t = n.has(e) ? "direct-runtime" : s.has(e) ? "direct-dev" : "transitive", i = Array.from(y.dependencies[e].name);
                d.set(e, {
                    slug: e,
                    ref: y.dependencies[e],
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
            }), d.forEach(e => {
                (b.get(e.slug) || []).forEach(t => {
                    d.has(t) && e.parents.add(t);
                }), (w.get(e.slug) || []).forEach(t => {
                    d.has(t) && e.children.add(t);
                });
            });
            const u = [];
            for (i.forEach(e => {
                const t = d.get(e);
                t && (t.depth = 0, u.push(e));
            }); u.length > 0; ) {
                const e = u.shift();
                if (!e) continue;
                const t = d.get(e);
                t && t.children.forEach(e => {
                    const n = d.get(e);
                    if (!n) return;
                    const a = t.depth + 1;
                    a >= n.depth || (n.depth = a, u.push(e));
                });
            }
            d.forEach(e => {
                if (Number.isFinite(e.depth)) return;
                let t = Number.POSITIVE_INFINITY;
                e.parents.forEach(e => {
                    const n = d.get(e);
                    n && Number.isFinite(n.depth) && (t = Math.min(t, n.depth + 1));
                }), e.depth = Number.isFinite(t) ? t : 0;
            });
            const p = [ ...d.values() ].reduce((e, t) => Math.max(e, t.depth), 0), h = Array.from({
                length: p + 1
            }, () => []);
            d.forEach(e => {
                h[e.depth].push(e.slug);
            });
            const g = [];
            d.forEach(e => {
                e.children.forEach(t => {
                    g.push({
                        from: e.slug,
                        to: t,
                        direct: 0 === e.depth
                    });
                });
            });
            const m = {
                workspaceName: e,
                nodes: d,
                edges: g,
                layers: h,
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
            return xe(m), Le(m), m;
        }
        function xe(e) {
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
        function Le(e) {
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
        function Se(e) {
            if (!E || !E.nodes.has(e)) return;
            x = e;
            const t = v(E, e), n = f(E, e);
            S = new Set([ e ]), t.forEach(e => {
                S.add(e);
            }), n.forEach(e => {
                S.add(e);
            }), I = new Set;
            const a = [ e ], r = new Set([ e ]);
            for (;a.length > 0; ) {
                const e = a.pop();
                if (!e) continue;
                const t = E.nodes.get(e);
                t && t.parents.forEach(t => {
                    I.add(u(t, e)), r.has(t) || (r.add(t), a.push(t));
                });
            }
            const s = [ e ], i = new Set([ e ]);
            for (;s.length > 0; ) {
                const e = s.pop();
                if (!e) continue;
                const t = E.nodes.get(e);
                t && t.children.forEach(t => {
                    I.add(u(e, t)), i.has(t) || (i.add(t), s.push(t));
                });
            }
            M = new Set(S);
            const o = E.nodes.get(e);
            o.parents.forEach(e => {
                M.add(e);
            }), o.children.forEach(e => {
                M.add(e);
            }), O = !0, He();
        }
        function Ie() {
            x = null, S = new Set, I = new Set, M = new Set, O = !0, He();
        }
        function Me(e = !0) {
            L = null, X = new Set, Y = new Set, e && (O = !0, He());
        }
        function Xe() {
            if (!E) return;
            const e = x && E.nodes.get(x) || null;
            E.nodes.forEach(t => {
                if (t.targetRadius = function(e) {
                    const t = x === e.slug, n = S.has(e.slug);
                    let a = e.radius;
                    t ? a *= 1.85 : x && n ? a *= 1.22 : x && !n ? a *= .84 : L && X.has(e.slug) ? a *= 1.1 : L && (a *= .9);
                    return a;
                }(t), t.targetLabelChars = a(t.labelGraphemes, Boolean(x) && S.has(t.slug) || !x && Boolean(L) && X.has(t.slug)), 
                !e || !M.has(t.slug)) return t.targetX = t.baseX, void (t.targetY = t.baseY);
                const n = t.baseX - e.baseX, r = t.baseY - e.baseY, s = 1 + 120 / (Math.sqrt(n * n + r * r) + 1);
                t.targetX = e.baseX + n * s, t.targetY = e.baseY + r * s;
            });
        }
        function Ye(e) {
            if (x) return;
            if (L = e, X = new Set, Y = new Set, !E || !e || !E.nodes.has(e)) return O = !0, 
            void He();
            const t = v(E, e), n = f(E, e);
            X = new Set([ e ]), t.forEach(e => {
                X.add(e);
            }), n.forEach(e => {
                X.add(e);
            });
            const a = E.nodes.get(e);
            a && (a.parents.forEach(e => {
                X.add(e);
            }), a.children.forEach(e => {
                X.add(e);
            })), E.edges.forEach(e => {
                X.has(e.from) && X.has(e.to) && Y.add(u(e.from, e.to));
            }), O = !0, He();
        }
        function Pe(e) {
            if (!E) return;
            const t = E.nodes.get(e);
            if (!t) return;
            const n = 0 === t.depth && E.directAll.has(t.slug);
            P = e, c.popoverName.textContent = t.ref.name, c.popoverVersion.textContent = `Version: ${t.ref.version}`, 
            c.popoverLicense.textContent = `License: ${t.ref.license || "Unknown"}`, c.popoverVulns.textContent = `Vulnerabilities: ${t.ref.vulnerabilityCount || 0}`, 
            c.popoverAmplification.textContent = n ? `Amplification: ${t.amplification}` : `Dependencies: ${t.children.size} • Dependents: ${t.parents.size}`, 
            c.popover.hidden = !1, De();
        }
        function Be() {
            P = null, c.popover.hidden = !0;
        }
        function De() {
            if (!E || !P || c.popover.hidden) return;
            const e = E.nodes.get(P);
            if (!e) return void Be();
            const t = e.renderX * B + D, a = e.renderY * B + A, r = c.canvasHost.getBoundingClientRect(), s = c.popover.getBoundingClientRect(), i = Math.max(8, r.width - s.width - 8), o = Math.max(8, r.height - s.height - 8), l = n(t + 14, 8, i), d = n(a + 14, 8, o);
            c.popover.style.left = `${l}px`, c.popover.style.top = `${d}px`;
        }
        function Ae(e) {
            return x ? S.has(e) ? 1 : .14 : L ? X.has(e) ? 1 : .16 : .95;
        }
        function Ne() {
            if (!q) return;
            if (q.setTransform(F, 0, 0, F, 0, 0), q.clearRect(0, 0, W, $), !E) return;
            const e = E, a = oe(0) - 80, r = oe(W) + 80, i = ce(0) - 80, o = ce($) + 80;
            q.setTransform(F * B, 0, 0, F * B, F * D, F * A);
            const c = re.runtime, d = re.dev, p = re.transitive, h = re.edge, g = re.highlight, m = re.muted, v = re.ringHigh, f = re.ringModerate, y = re.label, k = re.backgroundPrimary, b = new Set;
            e.nodes.forEach(e => {
                const t = Math.max(e.radius, e.renderRadius);
                e.renderX + t >= a && e.renderX - t <= r && e.renderY + t >= i && e.renderY - t <= o && b.add(e.slug);
            });
            const w = [];
            let C = 0;
            e.nodes.forEach(e => {
                if (!b.has(e.slug)) return;
                let t = 0;
                x === e.slug ? t = 2 : (S.has(e.slug) || X.has(e.slug)) && (t = 1), w.push({
                    node: e,
                    priority: t,
                    order: C++
                });
            }), w.sort((e, t) => e.priority - t.priority || e.order - t.order);
            const M = Math.max(0, e.layers.length - 1), P = function(e) {
                const t = new Map;
                return e.nodes.forEach(e => {
                    const n = t.get(e.depth);
                    n ? n.push(e) : t.set(e.depth, [ e ]);
                }), t.forEach(e => {
                    e.sort((e, t) => e.renderY - t.renderY);
                }), t;
            }(e), N = {
                depthNodeIndex: P,
                maxDepth: M,
                sameColumnXThreshold: 6,
                minDetourVerticalSpan: 80,
                detourInset: 14,
                detourNodeClearance: 26,
                paddingX: 96,
                layerGap: 240,
                edgeCurve: .2
            }, T = [];
            e.edges.forEach(t => {
                const n = e.nodes.get(t.from), a = e.nodes.get(t.to);
                if (!n || !a) return;
                if (!b.has(n.slug) && !b.has(a.slug)) return;
                const r = u(t.from, t.to);
                T.push({
                    from: n,
                    to: a,
                    highlighted: I.has(r) || !x && Y.has(r),
                    span: Math.abs(a.depth - n.depth)
                });
            }), T.sort((e, t) => t.span - e.span), q.globalCompositeOperation = "source-over", 
            q.strokeStyle = x || L ? m : h, q.lineWidth = 1.05, q.globalAlpha = function() {
                if (x || L) return .04 * n((B - .35) / .9, .75, 1);
                return .25 * n((B - .35) / .9, .2, 1);
            }(), q.beginPath(), T.forEach(e => {
                e.highlighted || l(q, e.from, e.to, N);
            }), q.stroke(), q.globalCompositeOperation = "lighter", q.strokeStyle = g, q.lineWidth = 1.2, 
            q.globalAlpha = .36 * n((B - .35) / .9, .2, 1), q.beginPath(), T.forEach(e => {
                e.highlighted && l(q, e.from, e.to, N);
            }), q.stroke(), q.globalCompositeOperation = "source-over";
            const R = e => {
                const t = x === e.slug, n = e.renderRadius;
                q.globalAlpha = 1, q.fillStyle = k, q.beginPath(), q.arc(e.renderX, e.renderY, n, 0, 2 * Math.PI), 
                q.fill(), q.globalAlpha = Ae(e.slug);
                const a = q.createRadialGradient(e.renderX - .3 * n, e.renderY - .3 * n, 0, e.renderX, e.renderY, 1.2 * n);
                "direct-runtime" === e.kind ? (a.addColorStop(0, re.runtimeHighlight), a.addColorStop(1, c)) : "direct-dev" === e.kind ? (a.addColorStop(0, re.devHighlight), 
                a.addColorStop(1, d)) : (a.addColorStop(0, re.transitiveHighlight), a.addColorStop(1, p)), 
                q.fillStyle = a, q.beginPath(), q.arc(e.renderX, e.renderY, n, 0, 2 * Math.PI), 
                q.fill(), t && (q.globalAlpha = .95, q.strokeStyle = g, q.lineWidth = 1.5, q.beginPath(), 
                q.arc(e.renderX, e.renderY, n + 4, 0, 2 * Math.PI), q.stroke());
            }, H = e => {
                if (!e.ref.vulnerabilityCount || e.ref.vulnerabilityCount <= 0) return;
                if ("none" === e.ref.vulnerabilitySeverity) return;
                const t = e.renderRadius, n = "high" === e.ref.vulnerabilitySeverity ? v : f;
                var a;
                q.save(), q.translate(e.renderX, e.renderY), q.globalAlpha = (a = e.slug, x ? S.has(a) ? .78 : .11 : L ? X.has(a) ? .76 : .12 : .8), 
                q.strokeStyle = n;
                const r = t / e.radius, s = t / 3 * 1.2 / 12, i = 1.2 * s + 3 * (r - 1), o = Math.max(.5 * s, .15), c = Math.max(1 * s, .3), l = Math.max(3 * s, .8), d = Math.max(1 * s, .3), u = Math.max(.5 * s, .15), p = t + (2 + 6 * (r - 1)) + o / 2, h = p + o / 2 + i + c / 2, g = h + c / 2 + i + l / 2, m = g + l / 2 + i + d / 2, y = m + d / 2 + i + u / 2;
                q.setLineDash([]), q.lineWidth = u, q.beginPath(), q.arc(0, 0, y, 0, 2 * Math.PI), 
                q.stroke(), q.lineWidth = d, q.beginPath(), q.arc(0, 0, m, 0, 2 * Math.PI), q.stroke(), 
                q.lineWidth = l, q.beginPath(), q.arc(0, 0, g, 0, 2 * Math.PI), q.stroke(), q.lineWidth = c, 
                q.beginPath(), q.arc(0, 0, h, 0, 2 * Math.PI), q.stroke(), q.lineWidth = o, q.beginPath(), 
                q.arc(0, 0, p, 0, 2 * Math.PI), q.stroke(), q.restore();
            };
            for (const t of [ 0, 1, 2 ]) w.forEach(({node: e, priority: n}) => {
                n === t && R(e);
            }), w.forEach(({node: e, priority: n}) => {
                n === t && H(e);
            });
            q.textBaseline = "middle", q.font = t, q.fillStyle = y, w.forEach(({node: e}) => {
                (e => {
                    const t = s(e);
                    t && (q.globalAlpha = Ae(e.slug), q.fillText(t, e.renderX + e.renderRadius + 6, e.renderY));
                })(e);
            }), q.globalAlpha = 1, De();
        }
        function Te() {
            if (!V) return void (j = 0);
            Xe();
            const e = function() {
                if (!E) return !1;
                let e = !1;
                const t = ae?.matches;
                return E.nodes.forEach(n => {
                    if (t) return n.renderX = n.targetX, n.renderY = n.targetY, n.renderRadius = n.targetRadius, 
                    void (n.renderLabelChars = n.targetLabelChars);
                    n.renderX += .15 * (n.targetX - n.renderX), n.renderY += .15 * (n.targetY - n.renderY), 
                    n.renderRadius += .18 * (n.targetRadius - n.renderRadius), n.renderLabelChars += .32 * (n.targetLabelChars - n.renderLabelChars), 
                    Math.abs(n.targetX - n.renderX) < .06 && Math.abs(n.targetY - n.renderY) < .06 && Math.abs(n.targetRadius - n.renderRadius) < .04 && Math.abs(n.targetLabelChars - n.renderLabelChars) < .12 || (e = !0);
                }), e;
            }(), t = function(e) {
                if (!_.active) return !1;
                if (!pe()) return he(), !1;
                const t = n(e - _.lastFrameTime || 16, 1, 32);
                _.lastFrameTime = e, le(D + _.velocityX * t, A + _.velocityY * t);
                const a = Math.exp(-.0042 * t);
                return _.velocityX *= a, _.velocityY *= a, O = !0, !(Math.hypot(_.velocityX, _.velocityY) < .02 && (he(), 
                1));
            }(performance.now());
            if (O || e || t) return Ne(), O = !1, void (j = V && (O || e || t) ? window.requestAnimationFrame(Te) : 0);
            j = 0;
        }
        function Re() {
            V && !j && O && (j = window.requestAnimationFrame(Te));
        }
        function He() {
            O = !0, V && Re();
        }
        function Ve(e) {
            const t = Ce(e);
            t && (he(), C = e, E = t, Ie(), Be(), L = null, X = new Set, Y = new Set, we(!0), 
            E && (he(), ye(), B = N, le(R, H)), O = !0, He());
        }
        function Oe(e) {
            0 === e.button && (he(), G.down = !0, G.moved = !1, G.startX = e.clientX, G.startY = e.clientY, 
            G.startPanX = D, G.startPanY = A, ge(e.clientX, e.clientY, e.timeStamp), we(), c.canvas.classList.add("is-panning"));
        }
        function je(e) {
            if (!G.down) return void Ee(e.clientX, e.clientY);
            const t = e.clientX - G.startX, n = e.clientY - G.startY;
            (Math.abs(t) > 2 || Math.abs(n) > 2) && (G.moved = !0), le(G.startPanX + t, G.startPanY + n), 
            me(e.clientX, e.clientY, e.timeStamp), He();
        }
        function Fe(e) {
            if (!G.down) return;
            c.canvas.classList.remove("is-panning");
            const t = G.moved;
            if (G.down = !1, G.moved = !1, t) return ve(), _.active ? void be(!1) : void Ee(e.clientX, e.clientY);
            const n = Ee(e.clientX, e.clientY);
            if (!n) return Me(!1), Ie(), void Be();
            Se(n.slug), Pe(n.slug);
        }
        function We(e) {
            if (!c.canvasHost.contains(e.target)) return;
            e.preventDefault(), he();
            const t = c.canvas.getBoundingClientRect(), n = e.clientX - t.left, a = e.clientY - t.top, r = e.ctrlKey || e.metaKey ? .015 * e.deltaY : .002 * e.deltaY, s = Math.exp(-r);
            de(B * s, n, a);
        }
        function $e(e) {
            if (0 === e.touches.length) return;
            e.preventDefault(), he(), we();
            const t = c.canvas.getBoundingClientRect();
            if (1 === e.touches.length) U.active = !0, G.moved = !1, U.startX1 = e.touches[0].clientX, 
            U.startY1 = e.touches[0].clientY, U.startPanX = D, U.startPanY = A, ge(e.touches[0].clientX, e.touches[0].clientY, e.timeStamp), 
            c.canvas.classList.add("is-panning"); else if (2 === e.touches.length) {
                U.active = !0, G.moved = !1, U.startX1 = e.touches[0].clientX, U.startY1 = e.touches[0].clientY, 
                U.startX2 = e.touches[1].clientX, U.startY2 = e.touches[1].clientY;
                const n = U.startX2 - U.startX1, a = U.startY2 - U.startY1;
                U.startDist = Math.sqrt(n * n + a * a), U.startZoom = B;
                const r = (U.startX1 + U.startX2) / 2, s = (U.startY1 + U.startY2) / 2, i = r - t.left, o = s - t.top;
                U.anchorX = i, U.anchorY = o;
            }
        }
        function Ge(e) {
            if (U.active) if (e.preventDefault(), 1 === e.touches.length) {
                const t = e.touches[0].clientX - U.startX1, n = e.touches[0].clientY - U.startY1;
                (Math.abs(t) > 2 || Math.abs(n) > 2) && (G.moved = !0), le(U.startPanX + t, U.startPanY + n), 
                me(e.touches[0].clientX, e.touches[0].clientY, e.timeStamp), He();
            } else if (2 === e.touches.length) {
                he(), G.moved = !0;
                const t = e.touches[0].clientX, n = e.touches[0].clientY, a = e.touches[1].clientX - t, r = e.touches[1].clientY - n, s = Math.sqrt(a * a + r * r);
                if (U.startDist > 0) {
                    const e = s / U.startDist;
                    de(U.startZoom * e, U.anchorX ?? W / 2, U.anchorY ?? $ / 2);
                }
            }
        }
        function Ue(e) {
            if (!U.active) return;
            e.preventDefault();
            if ("touchcancel" === e.type) return he(), we(!0), U.active = !1, U.anchorX = null, 
            U.anchorY = null, void (G.moved = !1);
            if (0 === e.touches.length) {
                if (we(!0), U.active = !1, U.anchorX = null, U.anchorY = null, G.moved || 1 !== e.changedTouches.length) G.moved && ve(); else {
                    const t = ke(e.changedTouches[0].clientX, e.changedTouches[0].clientY);
                    t ? (Se(t.slug), Pe(t.slug)) : (Me(!1), Ie(), Be());
                }
                G.moved = !1;
            } else 1 === e.touches.length && (U.startX1 = e.touches[0].clientX, U.startY1 = e.touches[0].clientY, 
            U.startPanX = D, U.startPanY = A, ge(e.touches[0].clientX, e.touches[0].clientY, e.timeStamp));
        }
        function _e() {
            Ye(null), we();
        }
        function qe(e) {
            if (!V) return;
            const t = e.target;
            c.popover.hidden || c.popover.contains(t) || c.canvasHost.contains(t) || Be();
        }
        function ze(e) {
            const t = e.target.closest("button[data-action]");
            if (!t) return;
            const n = t.dataset.action;
            n && ("zoom-in" !== n ? "zoom-out" !== n ? "pan-left" !== n ? "pan-right" !== n ? "pan-up" !== n ? "pan-down" !== n ? "reset" === n && (he(), 
            B = N, le(R, H), Ie(), Be(), He()) : ue(0, 52) : ue(0, -52) : ue(52, 0) : ue(-52, 0) : de(B / 1.18, .5 * W, .5 * $) : de(1.18 * B, .5 * W, .5 * $));
        }
        function Ke() {
            P && c.onOpenList(P);
        }
        function Je() {
            Ve(c.workspaceSelect.value);
        }
        function Ze() {
            V && (fe(), W <= 1 || $ <= 1 || (ye(), B = n(B, T, e), le(D, A), He()));
        }
        function Qe() {
            Z || (c.workspaceSelect.addEventListener("change", Je), Z = !0), J || (c.controlsRoot.addEventListener("click", ze), 
            c.popoverOpenButton.addEventListener("click", Ke), J = !0);
        }
        return {
            initGraphView: function() {
                const e = y.workspaces.length ? y.workspaces : [ {
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
                }), c.workspaceWrap.classList.toggle("hidden", e.length <= 1), k.has("root") || 1 !== e.length || k.set("root", e[0]), 
                C = n[0].name, c.workspaceSelect.value = C, se(), function() {
                    if (Q && Q.disconnect(), Q = new MutationObserver(() => {
                        se(), He();
                    }), Q.observe(document.documentElement, {
                        attributes: !0,
                        attributeFilter: [ "class", "data-theme" ]
                    }), ee && (ee.disconnect(), ee = null), te && (window.removeEventListener("resize", te), 
                    te = null), "undefined" != typeof ResizeObserver) return ee = new ResizeObserver(Ze), 
                    void ee.observe(c.canvasHost);
                    te = Ze, window.addEventListener("resize", te);
                }(), Qe(), z ? (fe(), Ve(C)) : ie();
            },
            buildWorkspaceGraph: Ce,
            computeAmplification: xe,
            layoutGraph: Le,
            renderLoop: Re,
            applyFocus: Se,
            clearFocus: Ie,
            showPopover: Pe,
            hidePopover: Be,
            switchWorkspace: Ve,
            setActive: function(t) {
                if (V = t, V) return z ? (!K && z && (c.canvas.addEventListener("mousedown", Oe), 
                window.addEventListener("mousemove", je), window.addEventListener("mouseup", Fe), 
                c.canvas.addEventListener("wheel", We, {
                    passive: !1
                }), c.canvas.addEventListener("touchstart", $e, {
                    passive: !1
                }), window.addEventListener("touchmove", Ge, {
                    passive: !1
                }), window.addEventListener("touchend", Ue, {
                    passive: !1
                }), window.addEventListener("touchcancel", Ue, {
                    passive: !1
                }), c.canvas.addEventListener("mouseleave", _e), document.addEventListener("mousedown", qe), 
                K = !0), fe(), W > 1 && $ > 1 && (ye(), B = n(B, T, e), le(D, A)), Re(), void He()) : void ie();
                K && (c.canvas.removeEventListener("mousedown", Oe), window.removeEventListener("mousemove", je), 
                window.removeEventListener("mouseup", Fe), c.canvas.removeEventListener("wheel", We), 
                c.canvas.removeEventListener("touchstart", $e), window.removeEventListener("touchmove", Ge), 
                window.removeEventListener("touchend", Ue), window.removeEventListener("touchcancel", Ue), 
                c.canvas.removeEventListener("mouseleave", _e), document.removeEventListener("mousedown", qe), 
                we(!0), G.down = !1, G.moved = !1, U.active = !1, U.anchorX = null, U.anchorY = null, 
                he(), K = !1), he(), j && (window.cancelAnimationFrame(j), j = 0);
            },
            requestRender: He
        };
    }
    const k = {
        permissive: [ "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "Unlicense", "0BSD", "CC0-1.0", "BSD", "Apache", "Apache 2.0", "Apache License 2.0", "MIT License", "ISC License" ],
        weakCopyleft: [ "LGPL-2.1", "LGPL-3.0", "LGPL-2.0", "LGPL", "MPL-2.0", "MPL-1.1", "MPL", "EPL-1.0", "EPL-2.0", "EPL" ],
        strongCopyleft: [ "GPL-2.0", "GPL-3.0", "GPL", "AGPL-3.0", "AGPL", "GPL-2.0-only", "GPL-3.0-only", "GPL-2.0-or-later", "GPL-3.0-or-later" ]
    }, b = {
        "network-access": "Accesses the network during install",
        "dynamic-exec": "Uses dynamic execution",
        "child-process": "Spawns child processes",
        encoding: "Uses encoding/decoding logic",
        obfuscated: "Contains obfuscated/minified install logic",
        "reads-env": "Reads environment variables",
        "reads-home": "Reads user home directory",
        "uses-ssh": "Uses SSH configuration/keys"
    };
    function w(e) {
        return e ? e.charAt(0).toUpperCase() + e.slice(1) : e;
    }
    function E(e) {
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
    function C(e) {
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
    function x(e) {
        return e?.highest || "none";
    }
    function L(e) {
        return e && e.risk || "green";
    }
    const S = {
        permissive: "green",
        weakCopyleft: "amber",
        strongCopyleft: "red",
        unknown: "gray"
    }, I = {
        none: 0,
        low: 1,
        moderate: 2,
        high: 3,
        critical: 4
    }, M = [ {
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
            const t = E(e), n = t.isInferred ? `${t.value} (inferred)` : t.value;
            return "mismatch" === e.compliance.license.status ? `${n} *` : n;
        },
        getTone: e => {
            const t = function(e) {
                if (!e) return "unknown";
                const t = e.toUpperCase();
                for (const [n, a] of Object.entries(k)) if (a.some(e => t.includes(e.toUpperCase()))) return n;
                return "unknown";
            }(E(e).value);
            return S[t];
        },
        sortFn: (e, t) => {
            const n = E(e).value, a = E(t).value;
            return n.localeCompare(a);
        }
    }, {
        id: "vulns",
        label: "Vulnerabilities",
        sortKey: "severity",
        getValue: e => w(x(C(e).summary)),
        getTone: e => C(e).summary.risk,
        sortFn: (e, t) => I[x(C(t).summary)] - I[x(C(e).summary)]
    }, {
        id: "install",
        label: "Install",
        sortKey: "install",
        getValue: e => {
            return (t = e.execution) ? w(t.risk || "low") : "Low";
            var t;
        },
        getTone: e => L(e.execution),
        sortFn: (e, t) => {
            const n = {
                green: 0,
                amber: 1,
                red: 2
            }, a = L(e.execution), r = L(t.execution);
            return n[a] - n[r];
        }
    } ], X = M.length;
    function Y(e) {
        if (!e) return "unknown";
        const t = e.toUpperCase();
        for (const [n, a] of Object.entries(k)) if (a.some(e => t.includes(e.toUpperCase()))) return n;
        return "unknown";
    }
    function P(e) {
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
    function B(e) {
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
    const D = {
        none: 0,
        low: 1,
        moderate: 2,
        high: 3,
        critical: 4
    };
    function A(e) {
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
    function N(e) {
        return e ? String(e).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;") : "";
    }
    function T(e) {
        return e ? e.charAt(0).toUpperCase() + e.slice(1) : e;
    }
    function R(e) {
        return e.split(/[\s-_]+/).map(e => e ? T(e) : e).join(" ");
    }
    function H(e) {
        return M.map(t => {
            return n = t.label, a = t.getValue(e), '<div class="badge-card ' + t.getTone(e) + '"><span class="badge-label">' + N(n) + '</span><span class="badge-value">' + N(a) + "</span></div>";
            var n, a;
        }).join("");
    }
    function V(e, t) {
        const n = M.map(n => function(e, t, n, a) {
            const r = n === e, s = r ? a ? " ▲" : " ▼" : "", i = r ? a ? " sorted-asc" : " sorted-desc" : "";
            return '<button type="button" class="column-header' + (r ? " sorted" : "") + i + '" data-sort="' + N(e) + '"><span class="column-header-label">' + N(t) + '</span><span class="sort-indicator">' + s + "</span></button>";
        }(n.sortKey, n.label, e, t)).join("");
        return '<div class="column-headers" style="--column-count: ' + X + '">' + n + "</div>";
    }
    function O(e, t, n) {
        let a = '<div class="kv-item">';
        return a += '<span class="kv-label">' + N(e) + "</span>", a += '<span class="kv-value">' + N(String(t)) + "</span>", 
        n && (a += '<span class="kv-hint">' + N(n) + "</span>"), a += "</div>", a;
    }
    function j(e, t) {
        return '<span class="kv-value risk-value"><span class="risk-dot ' + t + '"></span>' + N(String(e)) + "</span>";
    }
    function F(e, t, n) {
        let a = '<div class="kv-item">';
        return a += '<span class="kv-label">' + N(e) + "</span>", a += t, a += "</div>", 
        a;
    }
    function W(e, t) {
        if (!e || 0 === e.length) return '<span class="kv-value">None</span>';
        const n = e.slice(0, t), a = e.length - t;
        let r = '<div class="package-list">';
        return n.forEach(e => {
            r += '<span class="package-tag">' + N(e) + "</span>";
        }), a > 0 && (r += '<span class="package-tag">+' + a + " more</span>"), r += "</div>", 
        r;
    }
    function $(e, t, n, a) {
        if (!e || 0 === e.length) return '<span class="kv-value">None</span>';
        const r = e.slice(0, t), s = e.length - t;
        let i = '<div class="package-list">';
        return r.forEach(e => {
            const t = J(e, n, a);
            i += t ? '<a class="package-tag package-tag-link root-package-link" href="#' + N(q(t)) + '" data-dep-key="' + N(t) + '" aria-label="Jump to dependency ' + N(t) + '">' + N(e) + "</a>" : '<span class="package-tag">' + N(e) + "</span>";
        }), s > 0 && (i += '<span class="package-tag">+' + s + " more</span>"), i += "</div>", 
        i;
    }
    function G(e, t) {
        return e + "@" + t;
    }
    const U = new WeakMap;
    function _(e) {
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
    function q(e) {
        return `dep-${e}`;
    }
    function z(e) {
        const t = U.get(e);
        if (t) return t;
        const n = new Map;
        return e.forEach(e => {
            const t = _(e);
            if (!t) return;
            const a = n.get(t.name) || [];
            a.push(e), n.set(t.name, a);
        }), U.set(e, n), n;
    }
    function K(e, t, n) {
        const a = ((n || z(t)).get(e) || []).filter(e => t.has(e));
        return 1 === a.length ? a[0] : null;
    }
    function J(e, t, n) {
        if (t.has(e)) return e;
        const a = _(e);
        if (!a) return K(e, t, n);
        if (a.version.startsWith("npm:")) {
            const e = a.version.slice(4), n = a.name + (e.startsWith("@") ? e : "@" + e);
            if (t.has(n)) return n;
        }
        return K(a.name, t, n);
    }
    function Z(e, t, n, a) {
        if (!e || 0 === e.length) return '<span class="kv-value">None</span>';
        const r = e.slice(0, t), s = e.length - t;
        let i = '<div class="package-list">';
        return r.forEach(e => {
            if ("string" == typeof e) {
                const t = J(e, n, a);
                return t ? void (i += '<a class="package-tag package-tag-link root-package-link" href="#' + N(q(t)) + '" data-dep-key="' + N(t) + '" aria-label="Jump to dependency ' + N(t) + '">' + N(e) + "</a>") : void (i += '<span class="package-tag">' + N(e) + "</span>");
            }
            const t = G(e.name, e.version), r = e.name + "@" + e.version, s = J(t, n, a);
            i += s ? '<a class="package-tag package-tag-link root-package-link" href="#' + N(q(s)) + '" data-dep-key="' + N(s) + '" aria-label="Jump to dependency ' + N(s) + '">' + N(r) + "</a>" : '<span class="package-tag">' + N(r) + "</span>";
        }), s > 0 && (i += '<span class="package-tag">+' + s + " more</span>"), i += "</div>", 
        i;
    }
    function Q(e, t, n) {
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
                const o = '<div class="declared-name">' + N(e) + "</div>", c = '<div class="declared-range">' + N(a) + "</div>", l = r ? function(e, t, n) {
                    const a = J(e, t, n);
                    return a ? '<a class="status-pill installed root-package-link" href="#' + N(q(a)) + '" data-dep-key="' + N(a) + '" aria-label="Jump to dependency ' + N(a) + '">Installed</a>' : '<span class="status-pill installed">Installed</span>';
                }(r, t, n) : '<span class="status-pill missing">Not installed</span>';
                return '<div class="declared-row">' + o + c + l + "</div>";
            }), c = i + " of " + s + " installed";
            return [ '<details class="declared-group">', '<summary class="declared-group-summary"><span class="expand-icon" aria-hidden="true"></span><span class="declared-group-title">' + N(e.title) + ' <span class="declared-count">(' + c + ")</span></span></summary>", '<div class="declared-table">' + o.join("") + "</div>", "</details>" ].join("");
        }).filter(Boolean);
        return ee("Declared Dependencies", "Dependencies declared by this package", o + '<div class="declared-deps">' + c.join("") + "</div>");
    }
    function ee(e, t, n) {
        let a = '<div class="section">';
        return a += '<div class="section-header">', a += '<span class="section-title">' + N(e) + "</span>", 
        t && (a += '<span class="section-desc">' + N(t) + "</span>"), a += "</div>", a += n, 
        a += "</div>", a;
    }
    function te(e, t, n, a) {
        let r = '<div class="subsection' + (a ? " " + a : "") + '">';
        return r += '<div class="subsection-header">', r += '<span class="subsection-title">' + N(e) + "</span>", 
        n && (r += '<span class="subsection-desc">' + N(n) + "</span>"), r += "</div>", 
        r += t, r += "</div>", r;
    }
    function ne(e) {
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
    function ae(e, t) {
        const n = ne(e);
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
    function re(e, t) {
        return t ? N(e) + ' <a class="kv-inline-link" href="' + N(t) + '" target="_blank" rel="noopener noreferrer">GitHub<svg class="kv-inline-link-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M7 17 17 7"/><path d="M9 7h8v8"/></svg></a>' : N(e);
    }
    function se(e) {
        const t = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331zM10.665 10H12v2.667h-1.335V10z"/></svg>', n = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>', a = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>', r = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>';
        if (!(e.npm || e.repository || e.homepage || e.issues)) return "";
        let s = '<div class="package-links">';
        return e.npm && (s += '<a href="' + N(e.npm) + '" target="_blank" rel="noopener" class="package-link">' + t + "npm</a>"), 
        e.repository && (s += '<a href="' + N(e.repository) + '" target="_blank" rel="noopener" class="package-link">' + n + "Repository</a>"), 
        e.homepage && (s += '<a href="' + N(e.homepage) + '" target="_blank" rel="noopener" class="package-link">' + r + "Homepage</a>"), 
        e.issues && (s += '<a href="' + N(e.issues) + '" target="_blank" rel="noopener" class="package-link">' + a + "Issues</a>"), 
        s += "</div>", s;
    }
    function ie(e) {
        const t = function(e, t) {
            const n = [ e.risk, t ];
            return n.includes("red") ? "red" : n.includes("amber") ? "amber" : "green";
        }(A(e).summary, e.compliance.licenseRisk), n = G(e.package.name, e.package.version), a = q(n), r = H(e), s = [ '<summary class="dep-summary">', '<span class="expand-icon" aria-hidden="true"></span>', '<span class="dep-name">' + N(e.package.name) + '<span class="dep-version">@' + N(e.package.version) + "</span></span>", '<div class="dep-indicators" style="--column-count: ' + X + '">', r, "</div>", "</summary>" ].join("");
        return [ '<details class="dep-card" data-risk="' + t + '" data-dep-key="' + N(n) + '" id="' + N(a) + '">', s, '<div class="dep-details" data-rendered="false"></div>', "</details>" ].join("");
    }
    function oe(e, t, n) {
        const a = A(e), r = a.summary, s = P(e), i = s.isInferred ? `${s.value} (inferred)` : s.value, o = function(e) {
            const t = e.package?.links || {}, n = e.links || {}, a = ne(t.repository || n.repository || n.repo);
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
        e.usage.introduction && l.push("Introduced by: " + R(e.usage.introduction)), l.length < 3 && l.push("Dependency depth: " + e.usage.depth);
        var u, p;
        const h = ee("Overview", "Summary and key context", '<div class="micro-summary">' + l.slice(0, 5).map(e => '<div class="micro-line">' + N(e) + "</div>").join("") + "</div>" + (e.usage.origins.workspaces?.length ? '<div class="micro-sublist"><div class="micro-subtitle">Workspaces</div>' + W(e.usage.origins.workspaces, 8) + "</div>" : "") + ('<div class="section-block"><div class="block-title">Key context</div><div class="kv-grid kv-grid-tight">' + [ e.usage.runtimeImpact ? O("Runtime impact", (p = e.usage.runtimeImpact, 
        p ? R(p) : "")) : "", O("Dependency depth", e.usage.depth), e.usage.direct ? "" : F("Introduced via root packages", Z(e.usage.origins.topRootPackages, 8, t, n)), e.usage.direct ? "" : O("Direct roots", e.usage.origins.rootPackageCount), e.usage.direct ? "" : F("Direct parents", $(e.usage.origins.topParentPackages, 8, t, n)), e.usage.direct ? "" : O("Direct parents count", e.usage.origins.parentPackageCount ?? 0), O("TypeScript types", (u = e.usage.tsTypes, 
        "bundled" === u ? "Bundled" : "definitelyTyped" === u ? "DefinitelyTyped" : "none" === u ? "None" : "Unknown")) ].filter(Boolean).join("") + "</div></div>") + function(e, t, n, a) {
            if (!t || 0 === t.length) return "";
            const r = t.slice(0, n), s = t.length - n;
            let i = '<div class="detail-list">';
            return i += '<div class="detail-title">' + N(e) + "</div>", i += '<ul class="detail-items ' + a + '">', 
            r.forEach(e => {
                i += '<li class="detail-item">' + N(e) + "</li>";
            }), s > 0 && (i += '<li class="detail-item muted">+' + s + " more</li>"), i += "</ul></div>", 
            i;
        }("Top import locations", e.usage.importUsage?.topFiles, 5, "mono")), g = e.compliance.license, m = ae(o.repository, "package.json"), v = ae(o.repository, "LICENSE"), f = [ F("Primary license", j(i, e.compliance.licenseRisk)), O("Status", B(g.status)) ];
        if (g.declared) {
            const e = [ g.declared.valid ? "valid" : "invalid", g.declared.expression ? "expression" : void 0, g.declared.deprecated ? "deprecated" : void 0 ].filter(Boolean).join(", "), t = g.exception?.id ? ` WITH ${g.exception.id}` : "";
            f.push(F("Declared SPDX in package.json", '<span class="kv-value">' + re(`${g.declared.spdxId}${t}${e ? ` (${e})` : ""}`, m) + "</span>"));
        }
        g.inferred && f.push(F("Inferred from LICENSE file", '<span class="kv-value">' + re(`${g.inferred.spdxId} (${g.inferred.confidence})`, v) + "</span>")), 
        "mismatch" === g.status && f.push(O("Mismatch", "Declared SPDX and LICENSE text do not match")), 
        "invalid-spdx" === g.status && f.push(O("Invalid SPDX", "Package.json license is not a valid SPDX identifier or expression"));
        const y = te("License", '<div class="kv-grid">' + f.join("") + "</div>"), k = r.critical + r.high + r.moderate + r.low, w = [ F("Known vulnerabilities", j(0 === k ? "None" : String(k), r.risk)), O("Highest severity", "none" === r.highest ? "None" : R(r.highest)) ], E = k > 0 ? '<div class="kv-grid kv-grid-tight">' + [ O("Critical", r.critical), O("High", r.high), O("Moderate", r.moderate), O("Low", r.low) ].join("") + "</div>" : "", C = function(e) {
            if (!e || 0 === e.length) return "";
            let t = '<table class="vuln-table"><thead><tr>';
            return t += "<th>Title</th><th>Severity</th><th>Affected range</th><th>Fix available</th><th>Reference</th>", 
            t += "</tr></thead><tbody>", e.forEach(e => {
                const n = N(e.title), a = e.url ? '<a href="' + N(e.url) + '" target="_blank" rel="noopener">Link</a>' : "";
                t += '<tr data-severity="' + N(e.severity) + '">', t += '<td data-label="Title">' + n + "</td>", 
                t += '<td data-label="Severity">' + N(T(e.severity)) + "</td>", t += '<td data-label="Affected range">' + N(e.vulnerableRange) + "</td>", 
                t += '<td data-label="Fix available">' + N(e.fixAvailable ? "Yes" : "No") + "</td>", 
                t += '<td data-label="Reference">' + a + "</td>", t += "</tr>";
            }), t += "</tbody></table>", t;
        }(a.advisories), x = ee("Risk & Compliance", "License, vulnerabilities, and install-time execution signals", y + te("VULNERABILITIES", [ '<div class="section-note">Based on npm audit findings (known disclosed issues).</div>', '<div class="kv-grid">' + w.join("") + "</div>", E ? '<div class="subtle-divider"></div>' + E : "", C ? '<div class="subtle-divider"></div>' + C : "" ].join(""), "Known security issues from npm audit", "vuln-block") + (e.execution ? function(e) {
            const t = [ F("Execution risk", j((n = e.risk, "red" === n ? "High" : "amber" === n ? "Medium" : "Low"), e.risk)) ];
            var n;
            if (e.native && t.push(O("Native build tooling detected (native)", "Yes")), e.scripts?.hooks?.length && t.push(F("Lifecycle hooks", W(e.scripts.hooks, 6))), 
            "number" == typeof e.scripts?.complexity && t.push(O("Heuristic complexity", "Script complexity: " + e.scripts.complexity + " (complexity)")), 
            e.scripts?.signals?.length) {
                const n = e.scripts.signals.map(e => `${b[e]} (${e})`);
                t.push(F("Install-time signals", W(n, 6)));
            }
            return te("Install-time execution behaviour", '<div class="section-note">Install-time behaviour signals detected. These describe code that runs automatically during install and may warrant review in security-sensitive environments.</div><div class="kv-grid">' + t.join("") + "</div>");
        }(e.execution) : "")), L = [ O("Outdated status", (S = e.upgrade.outdatedStatus, 
        S ? "unknown" === S ? "Unknown" : R(S) : "Not reported")) ];
        var S;
        e.upgrade.latestVersion && L.push(O("Latest version", e.upgrade.latestVersion));
        const I = te("Version", '<div class="section-note">Based on npm outdated findings.</div><div class="kv-grid">' + L.join("") + "</div>"), M = e.package.deprecated ? te("Deprecated", '<div class="kv-grid">' + O("Deprecated", "Yes", "Declared by the package author.") + "</div>", void 0, "warning") : "", X = [ O("Node engine constraint", e.upgrade.nodeEngine || "Any") ];
        void 0 !== e.upgrade.blocksNodeMajor && X.push(O("Blocks Node major upgrade", e.upgrade.blocksNodeMajor ? "Yes" : "No"));
        const Y = te("Constraints", '<div class="kv-grid">' + X.join("") + "</div>"), D = te("Blast radius", '<div class="kv-grid">' + [ O("Used by other packages (fanIn)", e.graph.fanIn), O("Depends on packages (fanOut)", e.graph.fanOut) ].join("") + "</div>"), H = {
            nodeEngine: "Node engine constraint",
            peerDependency: "Peer dependency constraints",
            nativeBindings: "Native bindings/build tooling",
            installScripts: "Install lifecycle scripts",
            deprecated: "Deprecated by author"
        }, V = ee("Upgrade & Change Impact", "Currency, constraints, and blast radius", I + M + Y + D + (e.upgrade.blockers?.length ? '<div class="subsection"><div class="subsection-header"><span class="subsection-title">Upgrade blockers</span></div><ul class="bullet-list">' + e.upgrade.blockers.map(e => "<li>" + N(H[e] || e) + "</li>").join("") + "</ul></div>" : "")), G = Q(e, t, n);
        return [ se(o), h, x, V, G, '<details class="raw-data-toggle"><summary><span class="expand-icon" aria-hidden="true"></span>View raw data</summary><div class="raw-data-pane"><pre>' + N(c) + '</pre><button type="button" class="copy-json-btn" aria-label="Copy raw JSON">Copy JSON</button></div></details>' ].join("");
    }
    async function ce() {
        const e = await async function() {
            const e = document.getElementById("radar-data");
            return e && e.textContent && "{}" !== e.textContent.trim() ? JSON.parse(e.textContent) : (await fetch("./sample-data.json")).json();
        }();
        void 0 === window.__DEPENDENCY_DATA__ && (window.__DEPENDENCY_DATA__ = e);
        const t = document.getElementById("dependency-list"), n = document.getElementById("results-summary"), a = function(e) {
            const t = "string" == typeof e && e.trim().length > 0 ? e.trim() : "unknown";
            return `https://dependency-radar.com/next-steps?source=standalone-report&cli=${encodeURIComponent(t)}`;
        }(e.dependencyRadarVersion), r = document.getElementById("project-path");
        r && (r.textContent = e.project.projectDir);
        const s = document.getElementById("cta-primary-link"), i = document.getElementById("cta-secondary-link");
        s && (s.href = a), i && (i.href = a);
        const o = document.getElementById("git-branch-item"), c = document.getElementById("git-branch");
        e.git?.branch && e.git.branch && o && c && (c.textContent = e.git.branch, o.style.display = "");
        const l = document.getElementById("node-item"), d = document.getElementById("node-version"), u = document.getElementById("node-disclaimer");
        if (e.environment && l && d) {
            const t = e.environment.runtimeVersion?.replace(/^v/, "") || "unknown", n = e.environment.minRequiredMajor;
            d.textContent = t + (n && n > 0 ? ` (requires ≥${n})` : ""), l.style.display = "", 
            n && n > 0 && u && (u.textContent = "Node requirement derived from dependency engine ranges.", 
            u.style.display = "");
        }
        const p = document.getElementById("formatted-date");
        if (p && e.generatedAt) try {
            const t = new Date(e.generatedAt), n = new Intl.DateTimeFormat(void 0, {
                day: "numeric",
                month: "short",
                year: "numeric",
                hour: "2-digit",
                minute: "2-digit"
            }).format(t);
            p.textContent = n;
        } catch {
            p.textContent = e.generatedAt;
        }
        const h = {
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
        let g = "name", m = !0, v = null, f = !1;
        document.documentElement.setAttribute("data-theme", "dark");
        "light" === localStorage.getItem("dependency-radar-theme") ? (document.documentElement.classList.add("light"), 
        h.themeSwitch.classList.add("light"), document.documentElement.setAttribute("data-theme", "light")) : (document.documentElement.classList.remove("light"), 
        h.themeSwitch.classList.remove("light"), document.documentElement.setAttribute("data-theme", "dark")), 
        h.themeSwitch.addEventListener("click", () => {
            document.documentElement.classList.toggle("light"), h.themeSwitch.classList.toggle("light");
            const e = document.documentElement.classList.contains("light");
            document.documentElement.setAttribute("data-theme", e ? "light" : "dark"), localStorage.setItem("dependency-radar-theme", e ? "light" : "dark"), 
            v?.requestRender();
        });
        const k = window.matchMedia("(max-width: 768px)");
        let b = k.matches;
        const w = e => {
            h.filterControls && h.filtersToggle && (h.filterControls.classList.toggle("open", e), 
            h.filtersToggle.classList.toggle("open", e), h.filtersToggle.setAttribute("aria-expanded", String(e)));
        }, E = () => {
            if (k.matches) return w(!1), void (b = !0);
            b && w(!1), b = !1;
        };
        function C() {
            if (h.columnHeadersContainer && (h.columnHeadersContainer.innerHTML = V(g, m)), 
            h.packageHeader) {
                const e = h.packageHeader.querySelector(".sort-indicator");
                e && ("name" === g ? (e.textContent = m ? " ▲" : " ▼", h.packageHeader.classList.add("sorted")) : (e.textContent = "", 
                h.packageHeader.classList.remove("sorted")));
            }
        }
        function x(e) {
            const t = e.target.closest(".column-header");
            if (!t) return;
            const n = t.dataset.sort;
            n && (g === n ? m = !m : (g = n, m = !0), h.sort && (h.sort.value = g, h.sortDirection.textContent = m ? "↑" : "↓"), 
            C(), J());
        }
        h.filtersToggle && h.filterControls && h.filtersToggle.addEventListener("click", () => {
            const e = !h.filterControls.classList.contains("open");
            w(e);
        }), document.addEventListener("click", e => {
            if (!h.filterControls || !h.filtersToggle) return;
            const t = e.target;
            h.filterControls.contains(t) || h.filtersToggle.contains(t) || w(!1);
        }), document.addEventListener("keydown", e => {
            "Escape" === e.key && w(!1);
        }), window.addEventListener("resize", E), E(), h.sortDirection.addEventListener("click", () => {
            m = !m, h.sortDirection.textContent = m ? "↑" : "↓", C(), J();
        }), h.sort.addEventListener("change", () => {
            g = h.sort.value, C(), J();
        }), h.columnHeadersContainer && h.columnHeadersContainer.addEventListener("click", x), 
        h.packageHeader && h.packageHeader.addEventListener("click", x), C(), h.licenseAll.addEventListener("click", () => {
            h.licensePermissive.checked = !0, h.licenseWeakCopyleft.checked = !0, h.licenseStrongCopyleft.checked = !0, 
            h.licenseUnknown.checked = !0, j.clear(), J();
        }), h.licenseFriendly.addEventListener("click", () => {
            h.licensePermissive.checked = !0, h.licenseWeakCopyleft.checked = !1, h.licenseStrongCopyleft.checked = !1, 
            h.licenseUnknown.checked = !1, j.clear(), J();
        });
        const L = Object.values(e.dependencies || {}), S = function(e) {
            if (!e.workspaces.enabled) return [];
            const t = new Set;
            return (e.workspaces.workspacePackages || []).forEach(e => {
                e.name && t.add(e.name);
            }), Object.values(e.dependencies || {}).forEach(e => {
                (e.usage.origins.workspaces || []).forEach(e => {
                    e && t.add(e);
                });
            }), Array.from(t).sort((e, t) => "root" === e ? -1 : "root" === t ? 1 : e.localeCompare(t));
        }(e), I = (e, t) => e + " (" + t + ")", X = e => {
            return D[(t = A(e).summary, t?.highest || "none")] > 0;
            var t;
        }, B = e => L.reduce((t, n) => t + (e(n) ? 1 : 0), 0);
        if (h.workspace && h.workspaceWrap && S.length > 1) {
            h.workspace.textContent = "";
            const e = document.createElement("option");
            e.value = "all", e.textContent = I("All workspaces", L.length), h.workspace.appendChild(e), 
            S.forEach(e => {
                const t = document.createElement("option");
                t.value = e, t.textContent = I("root" === e ? "Workspace root" : e, B(t => (t.usage.origins.workspaces || []).includes(e))), 
                h.workspace.appendChild(t);
            }), h.workspaceWrap.classList.remove("hidden");
        }
        !function() {
            const e = L.length;
            h.direct.options[0].textContent = I("All", e), h.direct.options[1].textContent = I("Direct", B(e => e.usage.direct)), 
            h.direct.options[2].textContent = I("Transitive", B(e => !e.usage.direct));
            const t = {
                all: "All",
                runtime: "Production",
                dev: "Development",
                optional: "Optional",
                peer: "Peer"
            };
            Array.from(h.runtime.options).forEach(n => {
                n.textContent = I(t[n.value] || n.textContent || n.value, "all" === n.value ? e : B(e => e.usage.scope === n.value));
            });
            const n = {
                permissive: 0,
                weakCopyleft: 0,
                strongCopyleft: 0,
                unknown: 0
            };
            L.forEach(e => {
                n[Y(P(e).value)] += 1;
            }), h.licensePermissiveLabel && (h.licensePermissiveLabel.textContent = I("Permissive", n.permissive)), 
            h.licenseWeakCopyleftLabel && (h.licenseWeakCopyleftLabel.textContent = I("Weak Copyleft", n.weakCopyleft)), 
            h.licenseStrongCopyleftLabel && (h.licenseStrongCopyleftLabel.textContent = I("Strong Copyleft", n.strongCopyleft)), 
            h.licenseUnknownLabel && (h.licenseUnknownLabel.textContent = I("Other / Unknown", n.unknown)), 
            h.hasVulnsLabel && (h.hasVulnsLabel.textContent = I("Has vulnerabilities", B(X)));
        }();
        const T = new Map;
        L.forEach(e => {
            T.set(G(e.package.name, e.package.version), e);
        });
        const R = new Set(T.keys()), H = z(R), O = new Set, j = new Set, F = new Map, W = (() => {
            const e = document.getElementById("copy-announcer");
            if (e) return e;
            const t = document.createElement("div");
            return t.id = "copy-announcer", t.className = "sr-only", t.setAttribute("aria-live", "polite"), 
            document.body.appendChild(t), t;
        })();
        function $(e) {
            const t = e.dataset.depKey;
            if (!t) return;
            const n = e.querySelector(".dep-details");
            if (!n || "true" === n.dataset.rendered) return;
            const a = T.get(t);
            a && (n.setAttribute("aria-busy", "true"), n.innerHTML = [ '<div class="dep-loading" role="presentation">', '<div class="dep-loading-bar"></div>', "</div>" ].join(""), 
            requestAnimationFrame(() => {
                n.innerHTML = oe(a, R, H), n.dataset.rendered = "true", n.removeAttribute("aria-busy");
            }));
        }
        function U(e) {
            const t = e.selectedOptions[0];
            return (t?.textContent || "").replace(/\s+\(\d+\)$/, "");
        }
        function K() {
            const e = [];
            "all" !== h.direct.value && e.push({
                id: "type",
                label: "Type: " + U(h.direct),
                remove: () => {
                    h.direct.value = "all";
                }
            }), "all" !== h.runtime.value && e.push({
                id: "scope",
                label: "Scope: " + U(h.runtime),
                remove: () => {
                    h.runtime.value = "all";
                }
            }), h.workspace && "all" !== h.workspace.value && e.push({
                id: "workspace",
                label: "Workspace: " + U(h.workspace),
                remove: () => {
                    h.workspace.value = "all";
                }
            });
            return [ {
                id: "license-permissive",
                checked: h.licensePermissive.checked,
                label: "License: Permissive",
                reset: () => {
                    h.licensePermissive.checked = !0;
                }
            }, {
                id: "license-weak-copyleft",
                checked: h.licenseWeakCopyleft.checked,
                label: "License: Weak Copyleft",
                reset: () => {
                    h.licenseWeakCopyleft.checked = !0;
                }
            }, {
                id: "license-strong-copyleft",
                checked: h.licenseStrongCopyleft.checked,
                label: "License: Strong Copyleft",
                reset: () => {
                    h.licenseStrongCopyleft.checked = !0;
                }
            }, {
                id: "license-unknown",
                checked: h.licenseUnknown.checked,
                label: "License: Other / Unknown",
                reset: () => {
                    h.licenseUnknown.checked = !0;
                }
            } ].forEach(t => {
                t.checked || e.push({
                    id: t.id,
                    label: t.label,
                    remove: t.reset
                });
            }), h.hasVulns.checked && e.push({
                id: "has-vulns",
                label: "Has vulnerabilities",
                remove: () => {
                    h.hasVulns.checked = !1;
                }
            }), e;
        }
        function J() {
            !function() {
                const e = K(), t = e.length;
                h.filtersToggle.classList.toggle("has-active-filters", t > 0), h.filterCountBadge && (h.filterCountBadge.hidden = 0 === t, 
                h.filterCountBadge.textContent = String(t)), h.activeFiltersRow && h.activeFilterChips && (h.activeFiltersRow.hidden = 0 === t, 
                h.activeFilterChips.innerHTML = e.map(e => '<span class="active-filter-chip">' + N(e.label) + '<button type="button" class="active-filter-remove" data-filter-chip="' + N(e.id) + '" aria-label="Remove ' + N(e.label) + '">×</button></span>').join(""));
            }();
            const a = function(e) {
                const t = [ ...e ];
                if ("name" === g) t.sort((e, t) => e.package.name.localeCompare(t.package.name)); else if ("depth" === g) t.sort((e, t) => e.usage.depth - t.usage.depth); else {
                    const e = M.find(e => e.sortKey === g || e.id === g);
                    e?.sortFn ? t.sort(e.sortFn) : e && t.sort((t, n) => e.getValue(t).localeCompare(e.getValue(n)));
                }
                return m || t.reverse(), t;
            }(function() {
                const e = (h.search.value || "").toLowerCase(), t = h.direct.value, n = h.runtime.value, a = h.workspace?.value || "all", r = h.hasVulns.checked, s = h.licensePermissive.checked, i = h.licenseWeakCopyleft.checked, o = h.licenseStrongCopyleft.checked, c = h.licenseUnknown.checked;
                return L.filter(l => {
                    const d = G(l.package.name, l.package.version);
                    if (j.has(d)) return !0;
                    const u = P(l), p = [ u.value, l.compliance.license.declared?.spdxId, l.compliance.license.inferred?.spdxId ].filter(Boolean).join(" ").toLowerCase();
                    if (e && !l.package.name.toLowerCase().includes(e) && !p.includes(e)) return !1;
                    if ("direct" === t && !l.usage.direct) return !1;
                    if ("transitive" === t && l.usage.direct) return !1;
                    if ("all" !== n && l.usage.scope !== n) return !1;
                    if ("all" !== a && !(l.usage.origins.workspaces || []).includes(a)) return !1;
                    if (r && !X(l)) return !1;
                    const h = Y(u.value);
                    return !("permissive" === h && !s || "weakCopyleft" === h && !i || "strongCopyleft" === h && !o || "unknown" === h && !c);
                });
            }()), r = e.summary?.dependencyCount || L.length;
            n.innerHTML = "Showing <strong>" + a.length + "</strong> of <strong>" + r + "</strong> dependencies", 
            "all" !== (h.workspace?.value || "all") && (n.innerHTML += " in <strong>" + N(h.workspace.value) + "</strong>"), 
            0 !== a.length ? (t.innerHTML = a.map(ie).join(""), F.clear(), t.querySelectorAll("details.dep-card").forEach(e => {
                const t = e.dataset.depKey;
                t && F.set(t, e);
            }), O.forEach(e => {
                const t = F.get(e);
                t && (t.open || (t.open = !0), $(t));
            })) : t.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📦</div><div class="empty-state-text">No dependencies match your filters</div></div>';
        }
        function Z(e) {
            const t = H.get(e) || [];
            return 1 === t.length ? t[0] : null;
        }
        function Q(e) {
            if (T.has(e)) return e;
            const t = _(e);
            if (!t) return Z(e);
            if (t.version.startsWith("npm:")) {
                const e = t.version.slice(4), n = t.name + (e.startsWith("@") ? e : "@" + e);
                if (T.has(n)) return n;
            }
            return Z(t.name);
        }
        function ee(t) {
            if (!h.listViewPanel || !h.graphViewPanel) return void console.warn("Dependency Radar: view panels are missing from the report DOM.");
            const n = "list" === t;
            n || Boolean(h.graphWorkspaceSelect && h.graphWorkspaceWrap && h.graphControls && h.graphCanvas && h.graphCanvasShell && h.graphPopover && h.graphPopoverName && h.graphPopoverVersion && h.graphPopoverLicense && h.graphPopoverVulns && h.graphPopoverAmplification && h.graphOpenList) ? (h.listViewPanel.classList.toggle("active", n), 
            h.graphViewPanel.classList.toggle("active", !n), h.listViewPanel.setAttribute("aria-hidden", String(!n)), 
            h.graphViewPanel.setAttribute("aria-hidden", String(n)), h.viewGraphButton && (h.viewGraphButton.style.display = n ? "" : "none"), 
            h.graphBackButton && (h.graphBackButton.style.display = n ? "none" : ""), h.reportFooter?.classList.toggle("hidden", !n), 
            document.body.classList.toggle("graph-mode", !n), n ? v?.setActive(!1) : (f || (v = y({
                report: e,
                knownDepKeys: R,
                resolveDepKey: Q,
                workspaceSelect: h.graphWorkspaceSelect,
                workspaceWrap: h.graphWorkspaceWrap,
                controlsRoot: h.graphControls,
                canvas: h.graphCanvas,
                canvasHost: h.graphCanvasShell,
                popover: h.graphPopover,
                popoverName: h.graphPopoverName,
                popoverVersion: h.graphPopoverVersion,
                popoverLicense: h.graphPopoverLicense,
                popoverVulns: h.graphPopoverVulns,
                popoverAmplification: h.graphPopoverAmplification,
                popoverOpenButton: h.graphOpenList,
                onOpenList: e => {
                    !function(e) {
                        ee("list");
                        let t = document.getElementById(q(e));
                        !t && T.has(e) && (j.add(e), J(), t = document.getElementById(q(e)));
                        if (!t) return;
                        if (t instanceof HTMLDetailsElement) {
                            const e = t.dataset.depKey;
                            e && O.add(e), t.open || (t.open = !0), $(t);
                        }
                        t.classList.add("dep-list-highlight"), te(t, !0), window.setTimeout(() => {
                            t?.classList.remove("dep-list-highlight");
                        }, 2e3);
                    }(e);
                }
            }), v.initGraphView(), f = !0), v?.setActive(!0), v?.requestRender())) : console.warn("Dependency Radar: graph view DOM nodes are missing; graph view disabled.");
        }
        function te(e, t = !1) {
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
        const ne = [ h.search, h.direct, h.runtime, h.sort, h.hasVulns, h.workspace, h.licensePermissive, h.licenseWeakCopyleft, h.licenseStrongCopyleft, h.licenseUnknown ], ae = () => {
            j.clear(), J();
        };
        ne.forEach(e => {
            e && (e.addEventListener("input", ae), e.addEventListener("change", ae));
        }), h.activeFilterChips?.addEventListener("click", e => {
            const t = e.target.closest("[data-filter-chip]");
            if (!t) return;
            const n = K().find(e => e.id === t.dataset.filterChip);
            n && (n.remove(), ae());
        });
        const re = () => {
            h.direct.value = "all", h.runtime.value = "all", h.workspace && (h.workspace.value = "all"), 
            h.hasVulns.checked = !1, h.licensePermissive.checked = !0, h.licenseWeakCopyleft.checked = !0, 
            h.licenseStrongCopyleft.checked = !0, h.licenseUnknown.checked = !0, ae();
        };
        function se(e) {
            const t = e.getAttribute("data-dep-key");
            if (!t) return;
            const n = Q(t);
            if (!n) return;
            let a = F.get(n);
            a || (j.add(n), J(), a = F.get(n)), a && (O.add(n), a.open || (a.open = !0), $(a), 
            te(a, !0));
        }
        h.activeFilterClear?.addEventListener("click", re), h.clearAllFilters?.addEventListener("click", re), 
        h.viewGraphButton?.addEventListener("click", () => {
            ee("graph");
        }), h.graphBackButton?.addEventListener("click", () => {
            ee("list");
        }), t.addEventListener("toggle", e => {
            const t = e.target;
            if (!(t instanceof HTMLDetailsElement)) return;
            if (!t.classList.contains("dep-card")) return;
            const n = t.dataset.depKey;
            n && (t.open ? (O.add(n), $(t)) : O.delete(n));
        }, !0), t.addEventListener("click", e => {
            const t = e.target, n = t.closest(".root-package-link");
            if (n) return e.preventDefault(), void se(n);
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
                    e.dataset.label = t, e.textContent = "Copied", e.classList.add("copied"), W.textContent = "Copied JSON to clipboard.", 
                    window.setTimeout(() => {
                        e.textContent = t, e.classList.remove("copied");
                    }, 1500);
                } catch {
                    W.textContent = "Copy failed.";
                }
            }(a));
        }), t.addEventListener("keydown", e => {
            const t = e.target.closest(".root-package-link");
            t && (" " !== e.key && "Spacebar" !== e.key || (e.preventDefault(), se(t)));
        }), C(), J(), ee("list");
    }
    "loading" === document.readyState ? document.addEventListener("DOMContentLoaded", ce) : ce();
}();
