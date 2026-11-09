// node-check.mjs - preloaded by the npm scripts (node --import) so an old Node fails with a clear
// message instead of a TypeScript syntax / ERR_UNKNOWN_FILE_EXTENSION error. Plain JS on purpose:
// it must parse on any Node that has --import (>= 18.19 / 20.6).
const MIN = 24;
const major = Number(process.versions.node.split('.')[0]);
if (!(major >= MIN)) {
  console.error(`spendfuse needs Node.js >= ${MIN} (package.json "engines"); this is Node ${process.version}.`);
  console.error(`Install Node ${MIN}+ (e.g. nvm install ${MIN} && nvm use ${MIN}) and run the command again.`);
  process.exit(1);
}
