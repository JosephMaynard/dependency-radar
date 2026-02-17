const cp = require('child_process');
const path = require('path');

const installScriptPath = path.join(__dirname, 'install.js');
const maxAttempts = 2;

let attempt = 0;
let lastError;

while (attempt < maxAttempts) {
  attempt += 1;
  try {
    cp.execFileSync(process.execPath, [installScriptPath], { stdio: 'inherit' });
    process.exit(0);
  } catch (error) {
    lastError = error;
    if (attempt < maxAttempts) {
      console.warn(`[fixture] install attempt ${attempt} failed, retrying...`);
    }
  }
}

if (lastError) {
  throw lastError;
}
