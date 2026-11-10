/** src/index.ts: the public surface of the package. */

export * from './types.js';
export * from './errors.js';
export * from './interfaces.js';
export { HttpPhylaxApi, type CallOptions, type HttpPhylaxApiOptions, type PhylaxApi } from './api.js';
export {
  SecurityReview, type ApplyOutcome, type ApplyStatus, type NotCorrected, type ProposalResult, type ProposedCorrection, type ReviewFinding,
  type ReviewOptions, type ReviewResult, type ScanSummary, type UnscannedFile, type VerificationResult,
} from './review.js';
export { DiskFileChanger, sha256Text, type DiskFileChangerOptions } from './adapters/disk.js';
export { OqeliraFileChanger, OQELIRA_MAX_CONTENT_CHARS, type OqeliraChangesModule, type OqeliraFileChangerOptions } from './adapters/oqelira.js';
export { SOURCE_EXTENSIONS, SKIP_FOLDERS, isBlockedPath, isSourceFile, resolveInside, selectFiles, sortPaths, walkProject } from './project-files.js';
export { formatSummary, formatProposal, formatOutcomes, formatVerification } from './format.js';
export { createSecurityTools, type Consent, type SecurityTool, type SecurityTools, type SecurityToolsOptions, type ToolResult, type ToolRunContext } from './tools.js';
