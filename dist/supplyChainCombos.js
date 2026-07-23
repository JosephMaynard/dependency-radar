"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.supplyChainSignalTypesByPackageName = supplyChainSignalTypesByPackageName;
exports.detectSupplyChainCombos = detectSupplyChainCombos;
const COMBO_RULES = [
    {
        signalType: 'git-dependency',
        type: 'install-scripts-git-source',
        severity: 'error',
        title: 'Install scripts from a git-sourced package',
        detail: 'This package runs code at install time AND is installed from a git source, so its content can change without a version bump or registry publish.'
    },
    {
        signalType: 'non-registry-tarball',
        type: 'install-scripts-non-registry-tarball',
        severity: 'error',
        title: 'Install scripts from a non-registry tarball',
        detail: 'This package runs code at install time AND is fetched from a tarball outside the configured registry, bypassing registry review surfaces.'
    },
    {
        signalType: 'unexpected-registry-host',
        type: 'install-scripts-unexpected-registry-host',
        severity: 'error',
        title: 'Install scripts from an unexpected registry host',
        detail: 'This package runs code at install time AND resolves from a registry host that does not match the expected hosts for this project.'
    },
    {
        signalType: 'missing-integrity',
        type: 'install-scripts-missing-integrity',
        severity: 'warning',
        title: 'Install scripts without lockfile integrity',
        detail: 'This package runs code at install time AND has no lockfile integrity hash, so a substituted artifact would not be detected at install.'
    }
];
/**
 * Index project-level supply-chain signal types by package name.
 *
 * @param signals - The report's lockfile supply-chain signals, if any
 * @returns Map from package name to the set of signal types observed for it
 */
function supplyChainSignalTypesByPackageName(signals) {
    const byName = new Map();
    for (const signal of signals || []) {
        let name = signal.packageName;
        if (!name && signal.packageId) {
            const at = signal.packageId.lastIndexOf('@');
            if (at > 0)
                name = signal.packageId.slice(0, at);
        }
        if (!name)
            continue;
        const types = byName.get(name) || new Set();
        types.add(signal.type);
        byName.set(name, types);
    }
    return byName;
}
/**
 * Detect install-script × source-signal combinations for one dependency.
 *
 * @param dep - The dependency record to inspect for install lifecycle hooks
 * @param signalTypes - Supply-chain signal types observed for this package name
 * @returns Combos ordered most severe first; empty when the package has no
 *   install hooks or no qualifying source signal
 */
function detectSupplyChainCombos(dep, signalTypes) {
    var _a, _b;
    const hooks = ((_b = (_a = dep.execution) === null || _a === void 0 ? void 0 : _a.scripts) === null || _b === void 0 ? void 0 : _b.hooks) || [];
    if (hooks.length === 0 || !signalTypes || signalTypes.size === 0)
        return [];
    const combos = [];
    for (const rule of COMBO_RULES) {
        if (!signalTypes.has(rule.signalType))
            continue;
        combos.push({
            type: rule.type,
            severity: rule.severity,
            signalType: rule.signalType,
            hooks: [...hooks].sort(),
            title: rule.title,
            detail: rule.detail
        });
    }
    return combos;
}
