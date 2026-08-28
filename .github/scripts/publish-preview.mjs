// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const MARKER = "<!-- rs-key-flasher-preview -->";
export const SAFE_VARIANTS = [
  "default",
  "pqc",
  "fips",
  "fips-pqc",
  "strong-pin",
  "strong-pin-pqc",
  "always-uv",
  "always-uv-pqc",
  "strict-up",
  "strict-up-pqc",
  "display",
  "2mb",
  "16mb",
  "board-waveshare-one",
  "board-tenstar-usb",
  "board-seeed-xiao",
  "board-waveshare-touch-lcd",
  "board-abrobot-4m",
  "board-abrobot-16m",
  "strict-config",
];

const githubApi = "https://api.github.com";

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not configured.`);
  return value;
}

function githubHeaders() {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${requiredEnvironment("GITHUB_TOKEN")}`,
    "User-Agent": "rs-key-preview-publisher",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

async function github(path, init = {}) {
  const response = await fetch(`${githubApi}${path}`, {
    ...init,
    headers: { ...githubHeaders(), ...init.headers },
  });
  if (!response.ok) throw new Error(`GitHub ${path} returned ${response.status}: ${await response.text()}`);
  if (response.status === 204) return null;
  return response.json();
}

async function pagedGithub(path) {
  const values = [];
  for (let page = 1; ; page += 1) {
    const separator = path.includes("?") ? "&" : "?";
    const result = await github(`${path}${separator}per_page=100&page=${page}`);
    if (!Array.isArray(result)) throw new Error(`GitHub ${path} did not return a list.`);
    values.push(...result);
    if (result.length < 100) return values;
  }
}

async function runArtifacts(repository, runId) {
  const artifacts = [];
  for (let page = 1; ; page += 1) {
    const result = await github(`/repos/${repository}/actions/runs/${runId}/artifacts?per_page=100&page=${page}`);
    artifacts.push(...result.artifacts);
    if (artifacts.length >= result.total_count || result.artifacts.length === 0) return artifacts;
  }
}

export async function relatedPullRequests(repository, workflowRun) {
  const associated = await pagedGithub(`/repos/${repository}/commits/${workflowRun.head_sha}/pulls`);
  if (associated.length === 0) {
    for (const reference of workflowRun.pull_requests || []) {
      associated.push(await github(`/repos/${repository}/pulls/${reference.number}`));
    }
  }
  return associated
    .filter((pullRequest) => pullRequest.head?.sha === workflowRun.head_sha)
    .map((pullRequest) => ({
      number: pullRequest.number,
      title: pullRequest.title || `Pull request #${pullRequest.number}`,
      url: pullRequest.html_url,
      baseBranch: pullRequest.base?.ref || "main",
    }));
}

export function selectArtifacts(artifacts) {
  const selected = new Map();
  for (const variant of SAFE_VARIANTS) {
    const prefix = `firmware-${variant}-`;
    const matches = artifacts.filter((artifact) =>
      !artifact.expired && artifact.name.startsWith(prefix) && /^[0-9a-f]{40}$/.test(artifact.name.slice(prefix.length)),
    );
    if (matches.length > 1) throw new Error(`More than one artifact matches ${variant}.`);
    if (matches[0]) selected.set(variant, matches[0]);
  }
  if (selected.size === 0) return null;
  if (selected.size !== SAFE_VARIANTS.length) {
    const missing = SAFE_VARIANTS.filter((variant) => !selected.has(variant));
    throw new Error(`The firmware run has an incomplete preview set: ${missing.join(", ")}.`);
  }
  return selected;
}

async function downloadArtifact(repository, artifact, variant, directory) {
  const response = await fetch(`${githubApi}/repos/${repository}/actions/artifacts/${artifact.id}/zip`, {
    headers: githubHeaders(),
    redirect: "follow",
  });
  if (!response.ok) throw new Error(`Artifact ${artifact.name} returned ${response.status}.`);
  const archive = new Uint8Array(await response.arrayBuffer());
  if (archive.byteLength > 40 * 1024 * 1024) throw new Error(`Artifact ${artifact.name} is too large.`);
  const zipPath = join(directory, `${variant}.zip`);
  writeFileSync(zipPath, archive);
  const entries = execFileSync("unzip", ["-Z1", zipPath], { encoding: "utf8", maxBuffer: 1024 * 1024 })
    .split("\n").filter(Boolean);
  const filename = `firmware-${variant}.uf2`;
  if (entries.length !== 1 || entries[0] !== filename) throw new Error(`Artifact ${artifact.name} has an unexpected archive layout.`);
  const bytes = execFileSync("unzip", ["-p", zipPath, filename], { maxBuffer: 40 * 1024 * 1024 });
  if (bytes.byteLength < 512 || bytes.byteLength > 32 * 1024 * 1024) throw new Error(`${filename} has an invalid size.`);
  return {
    variant,
    filename,
    size: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes,
  };
}

async function publish(metadata, assets) {
  const form = new FormData();
  form.set("metadata", JSON.stringify(metadata));
  for (const asset of assets) {
    form.set(`asset:${asset.variant}`, new Blob([asset.bytes]), asset.filename);
  }
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const response = await fetch(requiredEnvironment("PREVIEW_API_URL"), {
        method: "POST",
        headers: { Authorization: `Bearer ${requiredEnvironment("RS_KEY_FLASHER_UPLOAD_TOKEN")}` },
        body: form,
      });
      if (!response.ok) throw new Error(`Preview API returned ${response.status}: ${await response.text()}`);
      return await response.json();
    } catch (error) {
      lastError = error;
      if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, attempt * 1000));
    }
  }
  throw lastError;
}

export async function addCommentOnce(repository, pullRequest) {
  const comments = await pagedGithub(`/repos/${repository}/issues/${pullRequest.number}/comments`);
  if (comments.some((comment) => comment.user?.login === "github-actions[bot]" && comment.body?.includes(MARKER))) return;
  const pageUrl = requiredEnvironment("PREVIEW_PAGE_URL");
  await github(`/repos/${repository}/issues/${pullRequest.number}/comments`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      body: `${MARKER}\nDevelopment firmware for this pull request: ${pageUrl}?pr=${pullRequest.number}\n\nThe link always opens the latest successful preview build.`,
    }),
  });
}

export function buildMetadata(event, workflowRun, pullRequests, assets) {
  return {
    schemaVersion: 1,
    repository: event.repository.full_name,
    repositoryId: event.repository.id,
    event: workflowRun.event,
    runId: workflowRun.id,
    runAttempt: workflowRun.run_attempt,
    runUrl: workflowRun.html_url,
    commitSha: workflowRun.head_sha,
    branch: workflowRun.head_branch,
    actor: workflowRun.actor.login,
    sourceRepository: workflowRun.head_repository?.full_name || event.repository.full_name,
    createdAt: workflowRun.created_at,
    pullRequests,
    assets: assets.map(({ bytes: _bytes, ...asset }) => asset),
  };
}

async function main() {
  const event = JSON.parse(await (await import("node:fs/promises")).readFile(requiredEnvironment("GITHUB_EVENT_PATH"), "utf8"));
  const workflowRun = event.workflow_run;
  const repository = event.repository.full_name;
  if (workflowRun.conclusion !== "success") return;
  if (workflowRun.event !== "pull_request" && !(workflowRun.event === "push" && workflowRun.head_branch === "main")) return;

  const artifacts = selectArtifacts(await runArtifacts(repository, workflowRun.id));
  if (!artifacts) {
    console.log("No firmware artifacts were produced; preview publication is a no-op.");
    return;
  }
  const pullRequests = workflowRun.event === "pull_request" ? await relatedPullRequests(repository, workflowRun) : [];
  if (workflowRun.event === "pull_request" && pullRequests.length === 0) {
    throw new Error(`No pull request is associated with commit ${workflowRun.head_sha}.`);
  }

  const directory = mkdtempSync(join(tmpdir(), "rs-key-preview-"));
  try {
    const assets = [];
    for (const variant of SAFE_VARIANTS) {
      assets.push(await downloadArtifact(repository, artifacts.get(variant), variant, directory));
    }
    const metadata = buildMetadata(event, workflowRun, pullRequests, assets);
    const build = await publish(metadata, assets);
    console.log(`Published preview build ${build.id} from GitHub run ${workflowRun.id}.`);
    for (const pullRequest of pullRequests) await addCommentOnce(repository, pullRequest);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
