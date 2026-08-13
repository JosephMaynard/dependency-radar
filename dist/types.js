"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isProductionScope = isProductionScope;
/**
 * Scopes that install and execute in production. Optional dependencies are
 * skipped only when they fail to build — when present they run exactly like
 * runtime dependencies, so production policies must include them.
 */
function isProductionScope(scope) {
    return scope === 'runtime' || scope === 'optional';
}
