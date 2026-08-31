// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { afterEach, test } from "node:test";
import {
  addCommentOnce,
  buildMetadata,
  relatedPullRequests,
  requestGitHubOidcToken,
  SAFE_VARIANTS,
  selectArtifacts,
} from "./publish-preview.mjs";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  delete process.env.GITHUB_TOKEN;
  delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  delete process.env.PREVIEW_API_URL;
  delete process.env.PREVIEW_PAGE_URL;
});

function artifact(name, id) {
  return { id, name, expired: false };
}

test("the publisher selects all safe variants and never selects no-touch", () => {
  const sha = "a".repeat(40);
  const artifacts = SAFE_VARIANTS.map((variant, index) => artifact(`firmware-${variant}-${sha}`, index + 1));
  artifacts.push(artifact(`firmware-no-touch-${sha}`, 100));
  artifacts.push(artifact(`firmware-no-touch-pqc-${sha}`, 101));

  const selected = selectArtifacts(artifacts);
  assert.equal(selected.size, 20);
  assert.equal([...selected.keys()].some((variant) => variant.startsWith("no-touch")), false);
});

test("a skipped firmware scope is a no-op and a partial set fails", () => {
  assert.equal(selectArtifacts([]), null);
  assert.throws(
    () => selectArtifacts([artifact(`firmware-default-${"a".repeat(40)}`, 1)]),
    /incomplete preview set/,
  );
});

test("a fork pull request is resolved from the run head commit", async () => {
  process.env.GITHUB_TOKEN = "test-token";
  const sha = "b".repeat(40);
  globalThis.fetch = async (url) => {
    assert.match(String(url), new RegExp(`/commits/${sha}/pulls`));
    return Response.json([{
      number: 94,
      title: "Fork firmware change",
      html_url: "https://github.com/TheMaxMur/RS-Key/pull/94",
      head: { sha },
      base: { ref: "main" },
    }]);
  };

  const pullRequests = await relatedPullRequests("TheMaxMur/RS-Key", { head_sha: sha, pull_requests: [] });
  assert.deepEqual(pullRequests, [{
    number: 94,
    title: "Fork firmware change",
    url: "https://github.com/TheMaxMur/RS-Key/pull/94",
    baseBranch: "main",
  }]);
});

test("a fork pull request is resolved from its head when the commit lookup is empty", async () => {
  process.env.GITHUB_TOKEN = "test-token";
  const sha = "c".repeat(40);
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    if (String(url).includes(`/commits/${sha}/pulls`)) return Response.json([]);
    assert.match(String(url), /pulls\?state=all&head=contributor%3Afeature%2Fpreview/);
    return Response.json([{
      number: 99,
      title: "Fork firmware change",
      html_url: "https://github.com/TheMaxMur/RS-Key/pull/99",
      head: { sha },
      base: { ref: "main" },
    }]);
  };

  const pullRequests = await relatedPullRequests("TheMaxMur/RS-Key", {
    head_sha: sha,
    head_branch: "feature/preview",
    head_repository: { full_name: "contributor/RS-Key" },
    pull_requests: [],
  });
  assert.deepEqual(pullRequests, [{
    number: 99,
    title: "Fork firmware change",
    url: "https://github.com/TheMaxMur/RS-Key/pull/99",
    baseBranch: "main",
  }]);
  assert.equal(calls.length, 2);
});

test("an existing marker makes the PR comment idempotent", async () => {
  process.env.GITHUB_TOKEN = "test-token";
  process.env.PREVIEW_PAGE_URL = "https://rskey.fob.wtf/preview";
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: init?.method || "GET" });
    return Response.json([{
      user: { login: "github-actions[bot]" },
      body: "<!-- rs-key-flasher-preview -->\nalready posted",
    }]);
  };

  await addCommentOnce("TheMaxMur/RS-Key", { number: 16 });
  assert.deepEqual(calls.map((call) => call.method), ["GET"]);
});

test("metadata contains the GitHub run ID, attempt, and link", () => {
  const workflowRun = {
    event: "pull_request",
    id: 7788,
    run_attempt: 3,
    html_url: "https://github.com/TheMaxMur/RS-Key/actions/runs/7788",
    head_sha: "c".repeat(40),
    head_branch: "preview-test",
    actor: { login: "contributor" },
    head_repository: { full_name: "contributor/RS-Key" },
    created_at: "2026-08-28T12:00:00Z",
  };
  const metadata = buildMetadata(
    { repository: { full_name: "TheMaxMur/RS-Key", id: 1266469959 } },
    workflowRun,
    [],
    [{ variant: "default", filename: "firmware-default.uf2", size: 512, sha256: "d".repeat(64), bytes: new Uint8Array() }],
  );
  assert.equal(metadata.runId, 7788);
  assert.equal(metadata.runAttempt, 3);
  assert.equal(metadata.runUrl, workflowRun.html_url);
  assert.equal(metadata.sourceRepository, "contributor/RS-Key");
  assert.equal("bytes" in metadata.assets[0], false);
});

test("the publisher requests an audience-scoped GitHub OIDC token", async () => {
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "runner-credential";
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = "https://token.actions.test/oidc?api-version=2.0";
  globalThis.fetch = async (url, init) => {
    assert.equal(String(url), "https://token.actions.test/oidc?api-version=2.0&audience=https%3A%2F%2Frskey.fob.wtf%2Fapi%2Fpreviews");
    assert.equal(init.headers.Authorization, "Bearer runner-credential");
    return Response.json({ value: "signed-github-jwt" });
  };

  assert.equal(
    await requestGitHubOidcToken("https://rskey.fob.wtf/api/previews"),
    "signed-github-jwt",
  );
});

test("the preview workflow grants OIDC and PR comment access with no upload secret", async () => {
  const workflow = await readFile(new URL("../workflows/preview-publish.yml", import.meta.url), "utf8");
  const publisher = await readFile(new URL("publish-preview.mjs", import.meta.url), "utf8");
  assert.match(workflow, /id-token:\s*write/);
  assert.match(workflow, /pull-requests:\s*write/);
  assert.doesNotMatch(workflow, /issues:\s*write/);
  assert.doesNotMatch(workflow, /RS_KEY_FLASHER_UPLOAD_TOKEN/);
  assert.doesNotMatch(publisher, /RS_KEY_FLASHER_UPLOAD_TOKEN/);
});

test("CI adds the partition table before UF2 conversion", async () => {
  const workflow = await readFile(new URL("../workflows/ci.yml", import.meta.url), "utf8");
  const packageStep = workflow.slice(workflow.indexOf("- name: package firmware-"), workflow.indexOf("- uses: actions/upload-artifact", workflow.indexOf("- name: package firmware-")));
  assert.ok(packageStep.indexOf("./scripts/pt.sh") >= 0);
  assert.ok(packageStep.indexOf("./scripts/pt.sh") < packageStep.indexOf("picotool uf2 convert"));
  assert.match(packageStep, /firmware-\$\{\{ matrix\.name \}\}\.elf -t elf/);
});
