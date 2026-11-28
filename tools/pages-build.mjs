// Builds the GitHub Pages copy of the docs into _site/. The FastFlare server serves docs/ as is;
// the Pages copy has no GitHub button or links to the source on GitHub.
import fs from 'node:fs';
import path from 'node:path';

const src = path.resolve('docs');
const out = path.resolve('_site');
const REPO = 'https://github.com/ArthWarrior3201/FastFlare';
const SITE = 'https://arthwarrior3201.github.io/FastFlare/';

fs.rmSync(out, { recursive: true, force: true });
fs.cpSync(src, out, { recursive: true });

function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) walk(f);
    else if (/\.(html|js)$/.test(e.name)) {
      let s = fs.readFileSync(f, 'utf8');
      s = s.replace(/^[ \t]*<a href="https:\/\/github\.com\/ArthWarrior3201\/FastFlare">GitHub<\/a>\r?\n/gm, ''); // nav button
      s = s.replaceAll(`${REPO}/blob/main/`, 'https://raw.githubusercontent.com/ArthWarrior3201/FastFlare/main/'); // direct downloads
      s = s.replaceAll(`href="${REPO}"`, `href="${SITE}"`); // widget badge
      s = s.replace(/[ \t]*<p>Prefer to run it by hand\?[\s\S]*?<\/code><\/pre>\r?\n/, ''); // git clone block
      fs.writeFileSync(f, s);
    }
  }
}
walk(out);

const left = [];
(function check(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) check(f);
    else if (/\.(html|js)$/.test(e.name) && /https:\/\/github\.com\//.test(fs.readFileSync(f, 'utf8'))) left.push(f);
  }
})(out);
if (left.length) {
  console.error('GitHub links left in: ' + left.join(', '));
  process.exit(1);
}
console.log('Pages site built in _site/');
