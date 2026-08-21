import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

const [outputDirectory] = process.argv.slice(2);
const repositoryBasePath = "/lockbox-swift";

if (!outputDirectory) {
  console.error("Usage: node Scripts/check-site-links.mjs <published-directory>");
  process.exit(1);
}

async function htmlFiles(directory) {
  const entries = await readdir(directory);
  const files = await Promise.all(entries.map(async (entry) => {
    const entryPath = path.join(directory, entry);
    const entryStats = await stat(entryPath);

    if (entryStats.isDirectory()) {
      return htmlFiles(entryPath);
    }

    return entryPath.endsWith(".html") ? [entryPath] : [];
  }));

  return files.flat();
}

async function publishedTarget(candidate) {
  try {
    const candidateStats = await stat(candidate);
    if (candidateStats.isDirectory()) {
      const indexPath = path.join(candidate, "index.html");
      await stat(indexPath);
      return indexPath;
    }
    return candidate;
  } catch {
    try {
      const htmlPath = `${candidate}.html`;
      await stat(htmlPath);
      return htmlPath;
    } catch {
      return null;
    }
  }
}

function isExternal(value) {
  return value.startsWith("mailto:") ||
    value.startsWith("tel:") ||
    value.startsWith("data:") ||
    value.startsWith("javascript:") ||
    /^[a-z][a-z\d+.-]*:/i.test(value) ||
    value.startsWith("//");
}

const files = await htmlFiles(outputDirectory);
const brokenLinks = [];
const documentIDs = new Map();

async function IDsFor(file) {
  if (!documentIDs.has(file)) {
    const html = await readFile(file, "utf8");
    const ids = new Set([...html.matchAll(/\bid\s*=\s*(["'])(.*?)\1/gi)].map((match) => match[2]));
    documentIDs.set(file, ids);
  }
  return documentIDs.get(file);
}

for (const file of files) {
  const html = await readFile(file, "utf8");
  const attributes = [...html.matchAll(/\b(?:href|src)\s*=\s*(["'])(.*?)\1/gi)].map((match) => match[2]);
  const sourceSets = [...html.matchAll(/\bsrcset\s*=\s*(["'])(.*?)\1/gi)]
    .flatMap((match) => match[2].split(",").map((candidate) => candidate.trim().split(/\s+/, 1)[0]));

  for (const rawValue of [...attributes, ...sourceSets]) {
    const value = rawValue.trim();
    if (!value || isExternal(value)) continue;

    const [pathAndQuery, rawFragment] = value.split("#", 2);
    const pathname = pathAndQuery.split("?", 1)[0];

    let target;
    if (!pathname) {
      target = file;
    } else if (pathname.startsWith("/")) {
      if (pathname !== repositoryBasePath && !pathname.startsWith(`${repositoryBasePath}/`)) {
        brokenLinks.push(`${path.relative(outputDirectory, file)} -> ${value} (missing repository base path)`);
        continue;
      }
      target = path.join(outputDirectory, pathname.slice(repositoryBasePath.length));
    } else {
      target = path.resolve(path.dirname(file), pathname);
    }

    const resolvedTarget = await publishedTarget(target);
    if (!resolvedTarget) {
      brokenLinks.push(`${path.relative(outputDirectory, file)} -> ${value}`);
      continue;
    }

    if (rawFragment && resolvedTarget.endsWith(".html")) {
      let fragment;
      try {
        fragment = decodeURIComponent(rawFragment);
      } catch {
        brokenLinks.push(`${path.relative(outputDirectory, file)} -> ${value} (invalid fragment encoding)`);
        continue;
      }
      const ids = await IDsFor(resolvedTarget);
      if (!ids.has(fragment)) {
        brokenLinks.push(`${path.relative(outputDirectory, file)} -> ${value} (missing fragment)`);
      }
    }
  }
}

if (brokenLinks.length > 0) {
  console.error("Broken internal links:");
  for (const brokenLink of brokenLinks) console.error(`- ${brokenLink}`);
  process.exit(1);
}

console.log(`Checked internal links in ${files.length} HTML files.`);
