// The pinned signify-ts source tree, for the generators that read the reference's own TypeScript.
//
// The npm package ships only `dist/`, and these generators parse `src/` and `test/` with the
// reference's own compiler and scan every `.ts` file in the tree. So the commit pinned in
// package-lock.json is checked out once, shallowly, into a cache directory next to this file.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { referenceSha } from "./reference.mjs";

const upstream = "https://github.com/WebOfTrust/signify-ts.git";
const checkout = new URL(`.signify-ts/${referenceSha}/`, import.meta.url);

function git(args, cwd) {
  const result = spawnSync("git", args, { cwd, stdio: ["ignore", "ignore", "inherit"] });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed with status ${result.status}`);
  }
}

if (!existsSync(new URL("package.json", checkout))) {
  const directory = fileURLToPath(checkout);
  mkdirSync(directory, { recursive: true });
  git(["init", "--quiet"], directory);
  git(["fetch", "--quiet", "--depth", "1", upstream, referenceSha], directory);
  git(["checkout", "--quiet", "--detach", "FETCH_HEAD"], directory);
}

/** Resolves a path inside the pinned source tree. */
export function sourceUrl(relativePath) {
  return new URL(relativePath, checkout);
}

/** Reads one file of the pinned source tree as text. */
export function sourceText(relativePath) {
  return readFileSync(sourceUrl(relativePath), "utf8");
}

/** Every `.ts` file under the given roots of the pinned tree, sorted, so an absence can be scanned. */
export function sourceFiles(roots) {
  const files = [];
  const walk = (relative) => {
    let entries;
    try {
      entries = readdirSync(sourceUrl(`${relative}/`), { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const child = `${relative}/${entry.name}`;
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules") {
          walk(child);
        }
      } else if (entry.name.endsWith(".ts")) {
        files.push(child);
      }
    }
  };
  for (const root of roots) {
    walk(root);
  }
  return files.sort();
}
