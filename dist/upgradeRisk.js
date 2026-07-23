"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveUpgradeRisk = deriveUpgradeRisk;
exports.applyUpgradeRisk = applyUpgradeRisk;
/**
 * Derive a coarse upgrade-risk band from outdated status and known blockers.
 *
 * @param dep - The dependency record to classify
 * @returns 'high' for major-version lag, Node-major blockage, or 2+ blockers;
 *   'medium' for one blocker or minor lag; 'unknown' when outdated data could
 *   not classify the package; 'low' otherwise
 */
function deriveUpgradeRisk(dep) {
    const blockers = dep.upgrade.blockers || [];
    const outdatedStatus = dep.upgrade.outdatedStatus;
    if (dep.upgrade.blocksNodeMajor === true || blockers.length >= 2 || outdatedStatus === 'major') {
        return 'high';
    }
    if (outdatedStatus === 'unknown') {
        return 'unknown';
    }
    if (blockers.length >= 1 || outdatedStatus === 'minor') {
        return 'medium';
    }
    return 'low';
}
/**
 * Stamp `upgrade.risk` onto every dependency record in place.
 *
 * Safe to call more than once; the scan re-applies it after registry
 * enrichment because a registry-discovered deprecation adds a blocker.
 */
function applyUpgradeRisk(aggregated) {
    for (const dep of Object.values(aggregated.dependencies || {})) {
        dep.upgrade.risk = deriveUpgradeRisk(dep);
    }
}
