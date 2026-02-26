import { Octokit } from "@octokit/rest";
import { readFileSync, existsSync } from "fs";
import * as core from "@actions/core";
import * as scanner from "./scanner";
import * as github from "@actions/github";
import axios, {isAxiosError} from 'axios'

async function validateSubscription() {
  const repoPrivate = github.context?.payload?.repository?.private;
  const action = process.env.GITHUB_ACTION_REPOSITORY;
  const docsUrl = 'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions';

  core.info(`\n\u001b[1;33mStepSecurity Maintained Action\u001b[0m`);
  core.info(`\u001b[37mSecure, reviewed, drop-in replacement for ${action}\u001b[0m`);
  if (repoPrivate === false) core.info('\u001b[32m\u2713 Free for public repositories\u001b[0m');
  core.info(`\u001b[36m${docsUrl}\u001b[0m\n`);

  if (repoPrivate === false) return;

  const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';
  const body: Record<string, string> = { action: action || '' };
  if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl;
  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
      body, { timeout: 3000 }
    );
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 403) {
      core.error(`\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m`);
      core.error(`\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`);
      process.exit(1);
    }
    core.info('Timeout or API not reachable. Continuing to next step.');
  }
}
// ============================================================================
// REPORT MODULE - Generates GitHub Actions job report
// ============================================================================

// Types and Interfaces
interface ExitCodes {
  SUCCESS: number;
  ERROR: number;
  LEAKS_FOUND: number;
}

interface TableCell {
  data: string;
  header?: boolean;
}

interface SarifResult {
  ruleId: string;
  partialFingerprints: {
    commitSha: string;
    author: string;
    date: string;
    email: string;
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

interface EventData {
  repository: {
    html_url: string;
    owner: {
      login: string;
    };
    full_name: string;
    name: string;
  };
  commits?: Array<{
    id: string;
  }>;
  number: number;
}

interface Config {
  enableSummary: boolean;
  enableUploadArtifact: boolean;
  version: string;
  baseRef?: string;
}

interface ScanConfig extends Config {
  apiClient: Octokit;
  eventData: EventData;
  gitleaksPath: string;
}

interface EventInfo {
  type: string;
  path: string;
}

const EXIT_CODES: ExitCodes = {
  SUCCESS: 0,
  ERROR: 1,
  LEAKS_FOUND: 2,
};

const SARIF_FILE_PATH = "results.sarif";

const TABLE_HEADERS: TableCell[] = [
  { data: "Rule ID", header: true },
  { data: "Commit", header: true },
  { data: "Secret URL", header: true },
  { data: "Start Line", header: true },
  { data: "Author", header: true },
  { data: "Date", header: true },
  { data: "Email", header: true },
  { data: "File", header: true },
];

function buildCommitUrl(repoUrl: string, commitSha: string): string {
  return `${repoUrl}/commit/${commitSha}`;
}

function buildSecretUrl(repoUrl: string, commitSha: string, filePath: string, lineNumber: number): string {
  return `${repoUrl}/blob/${commitSha}/${filePath}#L${lineNumber}`;
}

function buildFileUrl(repoUrl: string, commitSha: string, filePath: string): string {
  return `${repoUrl}/blob/${commitSha}/${filePath}`;
}

function formatSecretRow(secret: SarifResult, repoUrl: string): (string | TableCell)[] {
  const commitSha = secret.partialFingerprints.commitSha;
  const location = secret.locations[0].physicalLocation;
  const filePath = location.artifactLocation.uri;
  const lineNumber = location.region.startLine;

  const commitUrl = buildCommitUrl(repoUrl, commitSha);
  const secretUrl = buildSecretUrl(repoUrl, commitSha, filePath, lineNumber);
  const fileUrl = buildFileUrl(repoUrl, commitSha, filePath);

  return [
    secret.ruleId,
    `<a href="${commitUrl}">${commitSha.substring(0, 7)}</a>`,
    `<a href="${secretUrl}">View Secret</a>`,
    lineNumber.toString(),
    secret.partialFingerprints.author,
    secret.partialFingerprints.date,
    secret.partialFingerprints.email,
    `<a href="${fileUrl}">${filePath}</a>`,
  ];
}

function parseSarifResults(sarifPath: string): SarifResult[] | null {
  try {
    if (!existsSync(sarifPath)) {
      core.warning(`SARIF file not found at ${sarifPath}`);
      return null;
    }

    const sarifContent = readFileSync(sarifPath, "utf8");
    const sarif = JSON.parse(sarifContent);

    if (!sarif.runs || !sarif.runs[0] || !sarif.runs[0].results) {
      core.warning("Invalid SARIF structure");
      return null;
    }

    return sarif.runs[0].results;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    core.warning(`Error parsing SARIF file: ${errorMessage}`);
    return null;
  }
}

function buildSecretsTable(secrets: SarifResult[], repoUrl: string): Array<Array<string | TableCell>> {
  const rows = secrets.map((secret) => formatSecretRow(secret, repoUrl));
  return [TABLE_HEADERS as any, ...rows as any];
}

async function writeLeaksDetectedSummary(repoUrl: string): Promise<void> {
  const secrets = parseSarifResults(SARIF_FILE_PATH);

  if (!secrets || secrets.length === 0) {
    await core.summary
      .addHeading("⚠️ Gitleaks reported leaks but no details found")
      .write();
    return;
  }

  const tableData = buildSecretsTable(secrets, repoUrl);

  await core.summary
    .addHeading("🛑 Gitleaks detected secrets 🛑")
    .addTable(tableData)
    .write();
}

async function writeSuccessSummary(): Promise<void> {
  await core.summary.addHeading("No leaks detected ✅").write();
}

async function writeErrorSummary(exitCode: number): Promise<void> {
  const message =
    exitCode === EXIT_CODES.ERROR
      ? `❌ Gitleaks exited with error. Exit code [${exitCode}]`
      : `❌ Gitleaks exited with unexpected exit code [${exitCode}]`;

  await core.summary.addHeading(message).write();
}

async function writeSummary(exitCode: number, eventJSON: EventData): Promise<void> {
  const repoUrl = eventJSON.repository.html_url;

  switch (exitCode) {
    case EXIT_CODES.SUCCESS:
      await writeSuccessSummary();
      break;
    case EXIT_CODES.LEAKS_FOUND:
      await writeLeaksDetectedSummary(repoUrl);
      break;
    default:
      await writeErrorSummary(exitCode);
      break;
  }
}

// ============================================================================
// MAIN MODULE - Orchestrates the GitHub Action execution
// ============================================================================

const DEFAULT_GITLEAKS_VERSION = "8.24.3";

const EVENT_TYPES = {
  PUSH: "push",
  PULL_REQUEST: "pull_request",
  WORKFLOW_DISPATCH: "workflow_dispatch",
  SCHEDULE: "schedule",
};

const SUPPORTED_EVENTS = [
  EVENT_TYPES.PUSH,
  EVENT_TYPES.PULL_REQUEST,
  EVENT_TYPES.WORKFLOW_DISPATCH,
  EVENT_TYPES.SCHEDULE,
];

const EXIT_STATUS = {
  SUCCESS: 0,
  LEAKS_DETECTED: 1,
};

// Configuration helpers
function parseEnvironmentConfig(): Config {
  return {
    enableSummary: parseBooleanEnv("GITLEAKS_ENABLE_SUMMARY", true),
    enableUploadArtifact: parseBooleanEnv("GITLEAKS_ENABLE_UPLOAD_ARTIFACT", true),
    version: process.env.GITLEAKS_VERSION || DEFAULT_GITLEAKS_VERSION,
    baseRef: process.env.BASE_REF,
  };
}

function parseBooleanEnv(key: string, defaultValue: boolean): boolean {
  const value = process.env[key];
  if (value === "false" || value === "0") {
    return false;
  }
  return defaultValue;
}

function getEventInfo(): EventInfo {
  return {
    type: process.env.GITHUB_EVENT_NAME || "",
    path: process.env.GITHUB_EVENT_PATH || "",
  };
}

// Event data loading
function loadEventData(eventPath: string): EventData {
  try {
    const content = readFileSync(eventPath, "utf8");
    return JSON.parse(content);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    core.error(`Failed to load event data from ${eventPath}: ${errorMessage}`);
    process.exit(1);
  }
}

function validateEventType(eventType: string): void {
  if (!SUPPORTED_EVENTS.includes(eventType)) {
    core.error(`ERROR: The [${eventType}] event is not yet supported`);
    process.exit(1);
  }
}

// Schedule event handling
function normalizeScheduleEvent(eventData: EventData, eventType: string): EventData {
  if (eventType !== EVENT_TYPES.SCHEDULE) {
    return eventData;
  }

  const owner = process.env.GITHUB_REPOSITORY_OWNER || "";
  const fullRepo = process.env.GITHUB_REPOSITORY || "";
  const repoName = fullRepo.replace(`${owner}/`, "");

  return {
    ...eventData,
    repository: {
      owner: { login: owner },
      full_name: fullRepo,
      name: repoName,
      html_url: `https://github.com/${fullRepo}`,
    },
  };
}

// API client initialization
function createApiClient(): Octokit {
  return new Octokit({
    auth: process.env.GITHUB_TOKEN,
    baseUrl: process.env.GITHUB_API_URL,
  });
}

// Version resolution
async function resolveGitleaksVersion(version: string, apiClient: Octokit): Promise<string> {
  if (version === "latest") {
    core.info("Resolving latest Gitleaks version...");
    return await scanner.Latest(apiClient);
  }
  return version;
}

// Scan info builders
function buildPushScanInfo(eventData: EventData, baseRefOverride?: string): { baseRef: string; headRef: string } {
  const commits = eventData.commits;

  if (!commits || commits.length === 0) {
    core.info("No commits to scan");
    process.exit(EXIT_STATUS.SUCCESS);
  }

  const baseRef = baseRefOverride || commits[0].id;
  const headRef = commits[commits.length - 1].id;

  if (baseRefOverride) {
    core.info(`Overriding baseRef for scan with ${baseRefOverride}.`);
  }

  return { baseRef, headRef };
}

// Scan orchestration
type ScannerFunction = () => Promise<number>;

async function executeScan(scanType: string, scanParams: any, config: ScanConfig): Promise<number> {
  const scanners: Record<string, ScannerFunction> = {
    [EVENT_TYPES.PUSH]: () =>
      scanner.Scan(config.enableUploadArtifact, scanParams, scanType),
    [EVENT_TYPES.WORKFLOW_DISPATCH]: () =>
      scanner.Scan(config.enableUploadArtifact, scanParams, scanType),
    [EVENT_TYPES.SCHEDULE]: () =>
      scanner.Scan(config.enableUploadArtifact, scanParams, scanType),
    [EVENT_TYPES.PULL_REQUEST]: () =>
      scanner.ScanPullRequest(
        config.enableUploadArtifact,
        config.apiClient,
        config.eventData,
        scanType
      ),
  };

  const scannerFunc = scanners[scanType];
  if (!scannerFunc) {
    core.error(`No scanner configured for event type: ${scanType}`);
    process.exit(1);
  }

  return await scannerFunc();
}

async function performScan(eventType: string, eventData: EventData, config: ScanConfig): Promise<number> {
  core.info(`Event type: ${eventType}`);

  const scanParams = { gitleaksPath: config.gitleaksPath };

  if (eventType === EVENT_TYPES.PUSH) {
    const scanInfo = buildPushScanInfo(eventData, config.baseRef);
    return await executeScan(eventType, scanInfo, {
      ...config,
      eventData,
    });
  }

  if (eventType === EVENT_TYPES.PULL_REQUEST) {
    return await executeScan(eventType, scanParams, {
      ...config,
      eventData,
    });
  }

  if (
    eventType === EVENT_TYPES.WORKFLOW_DISPATCH ||
    eventType === EVENT_TYPES.SCHEDULE
  ) {
    return await executeScan(eventType, scanParams, {
      ...config,
      eventData,
    });
  }

  core.error(`Unhandled event type: ${eventType}`);
  process.exit(1);
}

// Summary generation
async function generateSummary(exitCode: number, eventData: EventData, shouldGenerate: boolean): Promise<void> {
  if (!shouldGenerate) {
    core.debug("Summary generation disabled");
    return;
  }

  await writeSummary(exitCode, eventData);
}

// Exit handling
function handleScanResult(exitCode: number): void {
  if (exitCode === EXIT_STATUS.SUCCESS) {
    core.info("✅ No leaks detected");
    return;
  }

  if (exitCode === scanner.EXIT_CODE_LEAKS_DETECTED) {
    core.warning("🛑 Leaks detected, see job summary for details");
    process.exit(EXIT_STATUS.LEAKS_DETECTED);
  }

  core.error(`ERROR: Unexpected exit code [${exitCode}]`);
  process.exit(exitCode);
}

// Main execution flow
async function run(): Promise<void> {
  await validateSubscription();
  const config = parseEnvironmentConfig();
  const eventInfo = getEventInfo();

  core.debug(
    config.enableSummary
      ? "GitHub Actions Summary enabled"
      : "Disabling GitHub Actions Summary."
  );

  core.debug(
    config.enableUploadArtifact
      ? "Artifact upload enabled"
      : "Disabling uploading of results.sarif artifact."
  );

  validateEventType(eventInfo.type);

  let eventData = loadEventData(eventInfo.path);
  eventData = normalizeScheduleEvent(eventData, eventInfo.type);

  const apiClient = createApiClient();

  const version = await resolveGitleaksVersion(config.version, apiClient);
  core.info(`Gitleaks version: ${version}`);

  const gitleaksPath = await scanner.Install(version);

  const scanConfig: ScanConfig = {
    ...config,
    apiClient,
    eventData,
    gitleaksPath,
  };

  const exitCode = await performScan(eventInfo.type, eventData, scanConfig);

  await generateSummary(exitCode, eventData, config.enableSummary);

  handleScanResult(exitCode);
}

// Entry point
run().catch((error) => {
  const errorMessage = error instanceof Error ? error.message : String(error);
  const errorStack = error instanceof Error ? error.stack : undefined;
  core.error(`Unexpected error: ${errorMessage}`);
  if (errorStack) {
    core.debug(errorStack);
  }
  process.exit(1);
});
