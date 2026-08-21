export interface Release {
  version: string;
  publishedAt: Date;
  notesURL: string;
}

interface GitHubRelease {
  tag_name?: unknown;
  html_url?: unknown;
  published_at?: unknown;
  draft?: unknown;
  prerelease?: unknown;
}

const endpoint = "https://api.github.com/repos/modern-swift-dev/lockbox-swift/releases/latest";
const semanticVersion = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

async function fetchLatestRelease(): Promise<Release> {
  let response: Response;
  try {
    response = await fetch(endpoint, { headers: { Accept: "application/vnd.github+json" } });
  } catch (error) {
    throw new Error(`Could not fetch the latest Lockbox release: ${error instanceof Error ? error.message : String(error)}`);
  }

  if (!response.ok) {
    throw new Error(`Could not fetch the latest Lockbox release: GitHub returned ${response.status} ${response.statusText}.`);
  }

  let data: GitHubRelease;
  try {
    data = await response.json() as GitHubRelease;
  } catch (error) {
    throw new Error(`Could not read the latest Lockbox release from ${endpoint}: ${error instanceof Error ? error.message : String(error)}`);
  }

  const date = typeof data.published_at === "string" ? new Date(data.published_at) : null;
  const notesURL = typeof data.html_url === "string" && URL.canParse(data.html_url) ? new URL(data.html_url) : null;
  if (
    typeof data.tag_name !== "string" || !semanticVersion.test(data.tag_name) ||
    !notesURL || notesURL.protocol !== "https:" || notesURL.hostname !== "github.com" ||
    !notesURL.pathname.startsWith("/modern-swift-dev/lockbox-swift/releases/") ||
    !date || Number.isNaN(date.valueOf()) || data.draft !== false || data.prerelease !== false
  ) {
    throw new Error(`GitHub returned invalid release data from ${endpoint}. A stable semantic version, UTC publication date, and canonical release-notes URL are required.`);
  }

  return { version: data.tag_name.replace(/^v/, ""), publishedAt: date, notesURL: notesURL.href };
}

let cachedRelease: Promise<Release> | undefined;

export function latestRelease(): Promise<Release> {
  cachedRelease ??= fetchLatestRelease();
  return cachedRelease;
}
