// Exit non-zero if two files differ; always delete the second (a temporary regenerated copy).
import { readFileSync, rmSync } from "node:fs";

const [expectedPath, regeneratedPath] = process.argv.slice(2);
if (!expectedPath || !regeneratedPath) {
  console.error("usage: compare-files.mjs <committed> <regenerated>");
  process.exit(2);
}
const same = readFileSync(expectedPath, "utf8") === readFileSync(regeneratedPath, "utf8");
rmSync(regeneratedPath);
if (!same) {
  console.error(`${expectedPath} is stale. Run: npm run contracts:generate`);
  process.exit(1);
}
console.log(`${expectedPath} is up to date`);
