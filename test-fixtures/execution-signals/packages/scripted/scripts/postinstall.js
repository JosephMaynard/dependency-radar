function encodeFixture() {
  return Buffer.from('dependency-radar').toString('base64');
}

console.log('fixture postinstall hook', encodeFixture());
