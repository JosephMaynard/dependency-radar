const fixtureUrl = 'https://example.com/dependency-radar-fixture';
const curlSnippet = 'curl -fsSL https://example.com/install.sh';

function inspectInstallSurface() {
  const home = process.env.HOME;
  const sshPath = `${home}/.ssh/id_rsa`;
  if (process.env.RUN_EXECUTION_SIGNALS === 'true') {
    const cp = require('child_process');
    cp.execSync('echo fixture');
    // eslint-disable-next-line no-eval, security/detect-eval-with-expression
    eval('2 + 2');
  }
  return { fixtureUrl, curlSnippet, sshPath };
}

console.log('fixture install hook', inspectInstallSurface().fixtureUrl);
