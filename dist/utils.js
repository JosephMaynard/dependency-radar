"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runCommand = runCommand;
exports.ensureDir = ensureDir;
exports.writeJsonFile = writeJsonFile;
exports.pathExists = pathExists;
exports.removeDir = removeDir;
exports.readJsonFile = readJsonFile;
exports.readPackageJson = readPackageJson;
exports.findBin = findBin;
exports.licenseRiskLevel = licenseRiskLevel;
exports.vulnRiskLevel = vulnRiskLevel;
exports.maintenanceRisk = maintenanceRisk;
exports.readLicenseFromPackageJson = readLicenseFromPackageJson;
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
function runCommand(command, args, options = {}) {
    return new Promise((resolve, reject) => {
        const child = (0, child_process_1.spawn)(command, args, {
            cwd: options.cwd,
            shell: false
        });
        const stdoutChunks = [];
        const stderrChunks = [];
        child.stdout.on('data', (d) => stdoutChunks.push(Buffer.from(d)));
        child.stderr.on('data', (d) => stderrChunks.push(Buffer.from(d)));
        child.on('error', (err) => reject(err));
        child.on('close', (code) => {
            resolve({
                stdout: Buffer.concat(stdoutChunks).toString('utf8'),
                stderr: Buffer.concat(stderrChunks).toString('utf8'),
                code
            });
        });
    });
}
async function ensureDir(dir) {
    await promises_1.default.mkdir(dir, { recursive: true });
}
async function writeJsonFile(filePath, data) {
    await ensureDir(path_1.default.dirname(filePath));
    const content = JSON.stringify(data, null, 2);
    await promises_1.default.writeFile(filePath, content, 'utf8');
}
async function pathExists(target) {
    try {
        await promises_1.default.access(target);
        return true;
    }
    catch (err) {
        return false;
    }
}
async function removeDir(target) {
    await promises_1.default.rm(target, { recursive: true, force: true });
}
async function readJsonFile(filePath) {
    const raw = await promises_1.default.readFile(filePath, 'utf8');
    return JSON.parse(raw);
}
async function readPackageJson(projectPath) {
    const pkgPath = path_1.default.join(projectPath, 'package.json');
    const pkgRaw = await promises_1.default.readFile(pkgPath, 'utf8');
    return JSON.parse(pkgRaw);
}
function findBin(projectPath, binName) {
    const ext = process.platform === 'win32' ? '.cmd' : '';
    const candidates = [
        path_1.default.join(projectPath, 'node_modules', '.bin', `${binName}${ext}`),
        path_1.default.join(process.cwd(), 'node_modules', '.bin', `${binName}${ext}`),
        path_1.default.join(__dirname, '..', 'node_modules', '.bin', `${binName}${ext}`),
        `${binName}${ext}`
    ];
    for (const candidate of candidates) {
        if (fs_1.default.existsSync(candidate))
            return candidate;
    }
    return candidates[candidates.length - 1];
}
function licenseRiskLevel(license) {
    if (!license)
        return 'red';
    const normalized = license.toUpperCase();
    const green = ['MIT', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE', 'APACHE-2.0', 'ISC'];
    const amber = ['LGPL', 'LGPL-2.1', 'LGPL-3.0', 'MPL', 'MPL-2.0'];
    if (green.includes(normalized))
        return 'green';
    if (amber.includes(normalized))
        return 'amber';
    return 'red';
}
function vulnRiskLevel(counts) {
    const { low = 0, moderate = 0, high = 0, critical = 0 } = counts;
    if (high > 0 || critical > 0)
        return 'red';
    if (low > 0 || moderate > 0)
        return 'amber';
    return 'green';
}
function maintenanceRisk(lastPublished) {
    if (!lastPublished)
        return 'unknown';
    const last = new Date(lastPublished).getTime();
    if (Number.isNaN(last))
        return 'unknown';
    const now = Date.now();
    const months = (now - last) / (1000 * 60 * 60 * 24 * 30);
    if (months <= 12)
        return 'green';
    if (months <= 36)
        return 'amber';
    return 'red';
}
async function readLicenseFromPackageJson(pkgName, projectPath) {
    try {
        const pkgJsonPath = require.resolve(path_1.default.join(pkgName, 'package.json'), { paths: [projectPath] });
        const pkgRaw = await promises_1.default.readFile(pkgJsonPath, 'utf8');
        const pkg = JSON.parse(pkgRaw);
        const license = pkg.license || (Array.isArray(pkg.licenses) ? pkg.licenses.map((l) => (typeof l === 'string' ? l : l === null || l === void 0 ? void 0 : l.type)).filter(Boolean).join(' OR ') : undefined);
        if (!license)
            return undefined;
        return { license, licenseFile: pkgJsonPath };
    }
    catch (err) {
        return undefined;
    }
}
