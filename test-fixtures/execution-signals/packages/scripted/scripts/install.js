const fixtureUrl = 'https://example.com/dependency-radar-fixture';
const curlSnippet = 'curl -fsSL https://example.com/install.sh';

function inspectInstallSurface() {
  const home = process.env.HOME;
  const sshPath = `${home}/.ssh/id_rsa`;
  const cp = require('child_process');
  if (false) {
    cp.execSync('echo fixture');
    eval('2 + 2');
  }
  return { fixtureUrl, curlSnippet, sshPath };
}

console.log('fixture install hook', inspectInstallSurface().fixtureUrl);
