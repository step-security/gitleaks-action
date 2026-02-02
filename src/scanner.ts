import * as exec from "@actions/exec";
import * as cache from "@actions/cache";
import * as core from "@actions/core";
import * as tc from "@actions/tool-cache";
import { readFileSync, existsSync } from "fs";
import * as os from "os";
import * as path from "path";
import { DefaultArtifactClient } from "@actions/artifact";
import { Octokit } from "@octokit/rest";

// Types and Interfaces
interface ExitCodes {
  SUCCESS: number;
  ERROR: number;
  LEAKS_DETECTED: number;
}

interface GitleaksConfig {
  releaseBaseUrl: string;
  owner: string;
  repo: string;
  sarifOutputFile: string;
  artifactName: string;
}

interface ScanOptions {
  command: string;
  flags: {
    redact: boolean;
    verbose: boolean;
    exitCode: number;
    reportFormat: string;
    logLevel: string;
  };
}

interface ScanInfo {
  baseRef?: string;
  headRef?: string;
  gitleaksPath?: string;
}

interface RepoInfo {
  owner: string;
  repo: string;
}

interface PRComment {
  owner: string;
  repo: string;
  pull_number: number;
  body: string;
  commit_id: string;
  path: string;
  side: string;
  line: number;
}

interface ExistingComment {
  body: string;
  path: string;
  original_line?: number;
}

interface SarifResult {
  ruleId: string;
  partialFingerprints: {
    commitSha: string;
  };
  locations: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
      };
      region: {
        startLine: number;
      };
    };
  }>;
}

interface EventJSON {
  repository: {
    full_name: string;
  };
  number: number;
  pull_request?: {
    base: {
      sha: string;
    };
    head: {
      sha: string;
    };
  };
}

// Constants
const EXIT_CODES: ExitCodes = {
  SUCCESS: 0,
  ERROR: 1,
  LEAKS_DETECTED: 2,
};

const GITLEAKS_CONFIG: GitleaksConfig = {
  releaseBaseUrl: "https://github.com/zricethezav/gitleaks/releases/download",
  owner: "zricethezav",
  repo: "gitleaks",
  sarifOutputFile: "results.sarif",
  artifactName: "gitleaks-results.sarif",
};

const SCAN_OPTIONS: ScanOptions = {
  command: "detect",
  flags: {
    redact: true,
    verbose: true,
    exitCode: 2,
    reportFormat: "sarif",
    logLevel: "debug",
  },
};

// Platform helpers
function normalizePlatform(platform: string): string {
  return platform === "win32" ? "windows" : platform;
}

function buildReleaseUrl(version: string, platform: string, arch: string): string {
  const normalizedPlatform = normalizePlatform(platform);
  const filename = `gitleaks_${version}_${normalizedPlatform}_${arch}.tar.gz`;
  return `${GITLEAKS_CONFIG.releaseBaseUrl}/v${version}/${filename}`;
}

function buildCacheKey(version: string, platform: string, arch: string): string {
  return `gitleaks-cache-${version}-${platform}-${arch}`;
}

function getInstallPath(version: string): string {
  return path.join(os.tmpdir(), `gitleaks-${version}`);
}

// Cache management
async function tryRestoreFromCache(installPath: string, cacheKey: string): Promise<boolean> {
  try {
    const restoredKey = await cache.restoreCache([installPath], cacheKey);
    return restoredKey !== undefined;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    core.warning(`Cache restore failed: ${errorMessage}`);
    return false;
  }
}

async function trySaveToCache(installPath: string, cacheKey: string): Promise<void> {
  try {
    await cache.saveCache([installPath], cacheKey);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    core.warning(`Cache save failed: ${errorMessage}`);
  }
}

// Download and extraction
async function downloadBinary(url: string, destination: string): Promise<string> {
  try {
    return await tc.downloadTool(url, destination);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    core.error(`Failed to download from ${url}: ${errorMessage}`);
    throw error;
  }
}

async function extractArchive(archivePath: string, destination: string, url: string): Promise<void> {
  if (url.endsWith(".zip")) {
    await tc.extractZip(archivePath, destination);
  } else if (url.endsWith(".tar.gz")) {
    await tc.extractTar(archivePath, destination);
  } else {
    throw new Error(`Unsupported archive format: ${url}`);
  }
}

// Main install function
export async function Install(version: string): Promise<string> {
  const installPath = getInstallPath(version);
  const cacheKey = buildCacheKey(version, process.platform, process.arch);

  core.info(`Installing Gitleaks ${version} to ${installPath}`);

  const cacheHit = await tryRestoreFromCache(installPath, cacheKey);

  if (cacheHit) {
    core.info("Gitleaks restored from cache");
  } else {
    await downloadAndInstallBinary(version, installPath, cacheKey);
  }

  core.addPath(installPath);
  return installPath;
}

async function downloadAndInstallBinary(version: string, installPath: string, cacheKey: string): Promise<void> {
  const releaseUrl = buildReleaseUrl(version, process.platform, process.arch);
  const downloadPath = path.join(os.tmpdir(), "gitleaks.tmp");

  core.info(`Downloading Gitleaks from ${releaseUrl}`);

  const archive = await downloadBinary(releaseUrl, downloadPath);
  await extractArchive(archive, installPath, releaseUrl);
  await trySaveToCache(installPath, cacheKey);
}

// Version management
export async function Latest(octokit: Octokit): Promise<string> {
  const response = await octokit.rest.repos.getLatestRelease({
    owner: GITLEAKS_CONFIG.owner,
    repo: GITLEAKS_CONFIG.repo,
  });

  return response.data.tag_name.replace(/^v/, "");
}

// Command building
function buildScanCommand(scanInfo: ScanInfo, eventType: string): string[] {
  const args = [
    SCAN_OPTIONS.command,
    "--redact",
    "-v",
    `--exit-code=${SCAN_OPTIONS.flags.exitCode}`,
    `--report-format=${SCAN_OPTIONS.flags.reportFormat}`,
    `--report-path=${GITLEAKS_CONFIG.sarifOutputFile}`,
    `--log-level=${SCAN_OPTIONS.flags.logLevel}`,
  ];

  const logOpts = buildGitLogOptions(scanInfo, eventType);
  if (logOpts) {
    args.push(`--log-opts=${logOpts}`);
  }

  return args;
}

function buildGitLogOptions(scanInfo: ScanInfo, eventType: string): string | null {
  if (eventType === "push" || eventType === "pull_request") {
    const { baseRef, headRef } = scanInfo;

    if (baseRef === headRef) {
      return "-1";
    }

    return `--no-merges --first-parent ${baseRef}^..${headRef}`;
  }

  return null;
}

// Artifact upload
async function uploadScanArtifact(): Promise<void> {
  const artifactClient = new DefaultArtifactClient();

  await artifactClient.uploadArtifact(
    GITLEAKS_CONFIG.artifactName,
    [GITLEAKS_CONFIG.sarifOutputFile],
    process.cwd()
  );
}

// Main scan function
export async function Scan(shouldUploadArtifact: boolean, scanInfo: ScanInfo, eventType: string): Promise<number> {
  const args = buildScanCommand(scanInfo, eventType);

  core.info(`Executing: gitleaks ${args.join(" ")}`);

  const exitCode = await exec.exec("gitleaks", args, {
    ignoreReturnCode: true,
    delay: 60 * 1000,
  });

  core.setOutput("exit-code", exitCode);

  if (shouldUploadArtifact) {
    await uploadScanArtifact();
  }

  return exitCode;
}

// Pull request helpers
async function fetchPullRequestCommits(octokit: Octokit, owner: string, repo: string, pullNumber: number): Promise<any[]> {
  const response = await octokit.request(
    "GET /repos/{owner}/{repo}/pulls/{pull_number}/commits",
    { owner, repo, pull_number: pullNumber }
  );

  return response.data;
}

function extractRepoInfo(fullRepoName: string): RepoInfo {
  const [owner, repo] = fullRepoName.split("/");
  return { owner, repo };
}

function buildScanInfoFromCommits(commits: any[], baseRefOverride?: string): ScanInfo {
  const baseRef = baseRefOverride || commits[0].sha;
  const headRef = commits[commits.length - 1].sha;

  if (baseRefOverride) {
    core.info(`Using base ref override: ${baseRefOverride}`);
  }

  return { baseRef, headRef };
}

// Comment management
async function fetchExistingComments(octokit: Octokit, owner: string, repo: string, pullNumber: number): Promise<ExistingComment[]> {
  const response = await octokit.request(
    "GET /repos/{owner}/{repo}/pulls/{pull_number}/comments",
    { owner, repo, pull_number: pullNumber }
  );

  return response.data as ExistingComment[];
}

function isCommentDuplicate(existingComment: ExistingComment, proposedComment: PRComment): boolean {
  return (
    existingComment.body === proposedComment.body &&
    existingComment.path === proposedComment.path &&
    existingComment.original_line === proposedComment.line
  );
}

function commentAlreadyExists(existingComments: ExistingComment[], proposedComment: PRComment): boolean {
  return existingComments.some((comment) =>
    isCommentDuplicate(comment, proposedComment)
  );
}

// Secret detection helpers
function buildSecretFingerprint(result: SarifResult): string {
  const commitSha = result.partialFingerprints.commitSha;
  const location = result.locations[0].physicalLocation;
  const filePath = location.artifactLocation.uri;
  const line = location.region.startLine;
  const ruleId = result.ruleId;

  return `${commitSha}:${filePath}:${ruleId}:${line}`;
}

function buildCommentBody(result: SarifResult, fingerprint: string, userList?: string): string {
  const { ruleId } = result;
  const commitSha = result.partialFingerprints.commitSha;

  let body = `🛑 **Gitleaks** has detected a secret with rule-id \`${ruleId}\` in commit ${commitSha}.
If this secret is a _true_ positive, please rotate the secret ASAP.

If this secret is a _false_ positive, you can add the fingerprint below to your \`.gitleaksignore\` file and commit the change to this branch.

\`\`\`
echo ${fingerprint} >> .gitleaksignore
\`\`\`
`;

  if (userList) {
    body += `\n\ncc ${userList}`;
  }

  return body;
}

function buildReviewComment(result: SarifResult, owner: string, repo: string, pullNumber: number): PRComment {
  const location = result.locations[0].physicalLocation;
  const commitSha = result.partialFingerprints.commitSha;
  const fingerprint = buildSecretFingerprint(result);
  const userList = process.env.GITLEAKS_NOTIFY_USER_LIST;

  return {
    owner,
    repo,
    pull_number: pullNumber,
    body: buildCommentBody(result, fingerprint, userList),
    commit_id: commitSha,
    path: location.artifactLocation.uri,
    side: "RIGHT",
    line: location.region.startLine,
  };
}

async function postReviewComment(octokit: Octokit, comment: PRComment): Promise<void> {
  try {
    await octokit.rest.pulls.createReviewComment(comment as any);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    core.warning(
      `Failed to post comment on PR #${comment.pull_number}: ${errorMessage}
Likely caused by a large diff. All secrets will be reported in the summary and artifacts.`
    );
  }
}

// SARIF parsing
function parseSarifFile(): SarifResult[] | null {
  if (!existsSync(GITLEAKS_CONFIG.sarifOutputFile)) {
    return null;
  }

  try {
    const content = readFileSync(GITLEAKS_CONFIG.sarifOutputFile, "utf8");
    const sarif = JSON.parse(content);
    return sarif.runs[0].results;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    core.warning(`Failed to parse SARIF file: ${errorMessage}`);
    return null;
  }
}

// Main PR scan function
export async function ScanPullRequest(shouldUploadArtifact: boolean, octokit: Octokit, eventJSON: EventJSON, eventType: string): Promise<number> {
  validateGitHubToken();

  const { owner, repo } = extractRepoInfo(eventJSON.repository.full_name);
  const pullNumber = eventJSON.number;

  // Use PR base/head from event data for accurate diff comparison
  let scanInfo: ScanInfo;
  if (process.env.BASE_REF) {
    // If BASE_REF is explicitly set, fetch commits to get head SHA
    const commits = await fetchPullRequestCommits(octokit, owner, repo, pullNumber);
    scanInfo = buildScanInfoFromCommits(commits, process.env.BASE_REF);
  } else if (eventJSON.pull_request) {
    // Use PR base and head SHA from event data
    const baseSha = eventJSON.pull_request.base.sha;
    const headSha = eventJSON.pull_request.head.sha;
    scanInfo = {
      baseRef: baseSha,
      headRef: headSha,
    };
    core.info(`Scanning PR from ${baseSha.substring(0, 7)} to ${headSha.substring(0, 7)}`);
  } else {
    // Fallback to fetching commits
    const commits = await fetchPullRequestCommits(octokit, owner, repo, pullNumber);
    scanInfo = buildScanInfoFromCommits(commits);
  }

  const exitCode = await Scan(shouldUploadArtifact, scanInfo, eventType);

  if (shouldPostComments()) {
    await postPullRequestComments(octokit, owner, repo, pullNumber, exitCode);
  }

  return exitCode;
}

function validateGitHubToken(): void {
  if (!process.env.GITHUB_TOKEN) {
    core.error(
      "🛑 GITHUB_TOKEN is required for pull request scanning. " +
      "Use the automatically created token as shown in the README."
    );
    process.exit(1);
  }
}

function shouldPostComments(): boolean {
  return process.env.GITLEAKS_ENABLE_COMMENTS !== "false";
}

async function postPullRequestComments(octokit: Octokit, owner: string, repo: string, pullNumber: number, exitCode: number): Promise<void> {
  if (exitCode !== EXIT_CODES.LEAKS_DETECTED) {
    return;
  }

  const secrets = parseSarifFile();
  if (!secrets || secrets.length === 0) {
    return;
  }

  const existingComments = await fetchExistingComments(octokit, owner, repo, pullNumber);

  for (const secret of secrets) {
    const comment = buildReviewComment(secret, owner, repo, pullNumber);

    if (!commentAlreadyExists(existingComments, comment)) {
      await postReviewComment(octokit, comment);
    }
  }
}

// Exports
export const EXIT_CODE_LEAKS_DETECTED = EXIT_CODES.LEAKS_DETECTED;
