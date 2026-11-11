/**
 * src/project-files.ts
 *
 * Which files of a project are worth scanning, and how to name them safely. Shared by every adapter that reads a folder, so a project is
 * walked the same way whichever agent it is attached to. It follows the same skip rules as the Python tool (`python -m security_service.scan`).
 */

import { lstat, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';

import { ChangeRefusedError } from './errors.js';

/** The code languages Phylax can scan today. */
export const SOURCE_EXTENSIONS = ['.py', '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'] as const;

/**
 * Configuration and text files. Phylax checks them for hardcoded secrets ONLY, and every report says so (coverage.limited_scope). They are scanned, never corrected: a
 * secret is not fixed by editing code, so no correction is ever proposed for one.
 */
export const CONFIG_EXTENSIONS = ['.json', '.yaml', '.yml', '.toml', '.ini', '.properties', '.config', '.txt'] as const;

/** Lock files and generated files: large, written by a tool, never hold a secret worth finding. Matched by file name. */
const GENERATED_NAMES = new Set([
  'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'composer.lock', 'pipfile.lock', 'poetry.lock', 'yarn.lock', 'bun.lock', 'cargo.lock',
]);
const GENERATED_ENDINGS = ['.min.json'];

/** Folders that hold other people's code or build output. Hidden folders (starting with a dot) are skipped as well. */
export const SKIP_FOLDERS = new Set([
  '.git', 'node_modules', 'venv', '.venv', 'env', '__pycache__', 'site-packages', '.tox', '.nox', 'build', 'dist', '.eggs',
  'vendor', 'vendors', 'third_party', 'bower_components', '.next', '.nuxt', 'coverage', '.turbo', '.cache', '.parcel-cache', '.svelte-kit',
]);

const NOT_SOURCE_ENDINGS = ['.min.js', '.min.mjs', '.min.cjs', '.bundle.js', '.d.ts', '.d.mts', '.d.cts'];

/** Files and folders no tool may read or change on a person's behalf: version control, cloud credentials, keys and environment files. */
const BLOCKED = /(^|\/)(\.git|\.oqelira|\.phylax|\.ssh|\.azure|\.aws|\.env(?!\.example(?:\/|$))(?:\.[^/]*)?)(\/|$)|\.(pem|key|pfx|p12)$/i;

export function isSourceFile(relativePath: string): boolean {
  const name = relativePath.toLowerCase();
  return SOURCE_EXTENSIONS.some((ext) => name.endsWith(ext)) && !NOT_SOURCE_ENDINGS.some((ending) => name.endsWith(ending));
}

/** A configuration or text file worth checking for secrets (not a lock file, not generated). */
export function isConfigFile(relativePath: string): boolean {
  const name = relativePath.toLowerCase();
  const base = name.slice(name.lastIndexOf('/') + 1);
  return CONFIG_EXTENSIONS.some((ext) => name.endsWith(ext)) && !GENERATED_NAMES.has(base) && !GENERATED_ENDINGS.some((ending) => name.endsWith(ending));
}

/** Everything a project scan sends: source code and configuration files. */
export function isScannableFile(relativePath: string): boolean {
  return isSourceFile(relativePath) || isConfigFile(relativePath);
}

export function isBlockedPath(relativePath: string): boolean {
  return BLOCKED.test(relativePath);
}

/**
 * A project-relative path (forward slashes) turned into an absolute path that is guaranteed to be inside `root`, or a ChangeRefusedError. Rejects
 * absolute paths, `..`, NUL, Windows drive letters and backslash tricks, blocked names, and anything that reaches outside the root through a symlink.
 */
export async function resolveInside(root: string, relativePath: string): Promise<{ absolute: string; relative: string }> {
  if (typeof relativePath !== 'string' || relativePath.length === 0 || relativePath.includes('\0')) {
    throw new ChangeRefusedError('The path is empty or invalid.');
  }
  const unified = relativePath.replace(/\\/g, '/');
  if (unified.startsWith('/') || /^[a-zA-Z]:/.test(unified)) {
    throw new ChangeRefusedError('Paths must be relative to the project folder.');
  }
  const normalized = path.posix.normalize(unified);
  if (normalized === '..' || normalized.startsWith('../') || normalized === '.' || normalized.split('/').includes('..')) {
    throw new ChangeRefusedError('The path leaves the project folder.');
  }
  if (isBlockedPath(normalized)) {
    throw new ChangeRefusedError('That path is protected (credentials, keys, environment files or version control) and is never read or changed.');
  }
  const absolute = path.resolve(root, ...normalized.split('/'));
  const realRoot = await realpath(root);
  let probe = absolute;
  for (;;) {                                           // the deepest part that exists must really be inside the root (no symlink escape)
    try {
      const real = await realpath(probe);
      if (real !== realRoot && !real.startsWith(realRoot + path.sep)) {
        throw new ChangeRefusedError('The path leaves the project folder.');
      }
      break;
    } catch (error) {
      if (error instanceof ChangeRefusedError) throw error;
      const parent = path.dirname(probe);
      if (parent === probe) throw new ChangeRefusedError('The path cannot be resolved.');
      probe = parent;
    }
  }
  return { absolute, relative: normalized };
}

/** Plain string order: the same on every operating system (readdir order is not: Windows is case-insensitive, Linux is not). */
export function sortPaths(paths: string[]): string[] {
  return [...paths].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** The scannable files of a folder, as sorted project-relative paths. Symlinks are never followed. */
export async function walkProject(root: string): Promise<string[]> {
  const found: string[] = [];
  async function visit(directory: string, prefix: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (SKIP_FOLDERS.has(entry.name) || entry.name.startsWith('.')) continue;
        await visit(path.join(directory, entry.name), relative);
      } else if (entry.isFile() && isScannableFile(relative) && !isBlockedPath(relative)) {
        found.push(relative);
      }
    }
  }
  await visit(root, '');
  return sortPaths(found);
}

/** The selection as validated, de-duplicated, sorted project-relative paths. A named file is used whatever its extension; a missing one is refused. */
export async function selectFiles(root: string, selection: { kind: 'project' } | { kind: 'files'; paths: string[] }): Promise<string[]> {
  if (selection.kind === 'project') return walkProject(root);
  const unique = new Set<string>();
  for (const given of selection.paths) {
    const { absolute, relative } = await resolveInside(root, given);
    let stat;
    try {
      stat = await lstat(absolute);
    } catch {
      throw new ChangeRefusedError(`${given} does not exist.`);
    }
    if (!stat.isFile()) throw new ChangeRefusedError(`${given} is not a file. Select files, or the whole project.`);
    unique.add(relative);
  }
  return sortPaths([...unique]);
}
