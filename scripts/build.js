'use strict';
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'public');
const assets = ['index.html', 'app.js', 'style.css'];

fs.rmSync(output, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
for (const file of assets) {
  const source = path.join(root, file);
  if (!fs.existsSync(source) || !fs.statSync(source).isFile()) {
    throw new Error(`Required static app asset is missing: ${file}`);
  }
  fs.copyFileSync(source, path.join(output, file));
}
console.log(`Built CASTONE static site into ${path.relative(root, output)}/ (${assets.join(', ')})`);
