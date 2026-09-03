import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const fail = (message) => {
  console.error(`HARNESS FAIL: ${message}`);
  process.exitCode = 1;
};
const exists = (p) => fs.existsSync(path.join(root, p));
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(root, p), "utf8"));
const required = [
  "AGENTS.md",
  ".harness/project.json",
  ".harness/active-task.json",
  ".harness/HANDOFF.md",
  ".harness/receipts/README.md"
];

for (const p of required) {
  if (!exists(p)) fail(`missing required file ${p}`);
}

let project;
let task;
try { project = readJson(".harness/project.json"); } catch (error) { fail(`invalid .harness/project.json: ${error.message}`); }
try { task = readJson(".harness/active-task.json"); } catch (error) { fail(`invalid .harness/active-task.json: ${error.message}`); }

if (project) {
  if (project.schema !== "mikel-harness-project-v0.1") fail("unsupported project schema");
  if (!project.project?.name || !project.project?.repository) fail("project identity is incomplete");
  if (!Array.isArray(project.sources_of_truth) || project.sources_of_truth.length < 3) fail("sources_of_truth must map at least three areas");
  if (!project.action_policy || !project.retry_policy) fail("action and retry policies are required");
  if (project.retry_policy.max_retries < 1 || project.retry_policy.max_retries > 5) fail("project max_retries must be between 1 and 5");
}

if (task && project) {
  const statuses = new Set(["queued", "in_progress", "blocked", "ready_for_review", "completed", "abandoned"]);
  if (task.schema !== "mikel-harness-task-v0.1") fail("unsupported task schema");
  if (!task.task_id || !task.goal) fail("task_id and goal are required");
  if (!statuses.has(task.status)) fail(`invalid task status ${task.status}`);
  for (const key of ["sources", "outputs", "constraints", "done_when", "forbidden"]) {
    if (!Array.isArray(task[key]) || task[key].length === 0) fail(`${key} must be a non-empty array`);
  }
  if (!project.action_policy?.[task.risk_class]) fail(`unknown risk_class ${task.risk_class}`);
  if (typeof task.approval_required !== "boolean") fail("approval_required must be boolean");
  if (["A3", "A4"].includes(task.risk_class) && task.approval_required !== true) fail(`${task.risk_class} tasks require human approval`);
  if (!Number.isInteger(task.max_retries) || task.max_retries < 0 || task.max_retries > project.retry_policy.max_retries) fail(`task max_retries must be between 0 and ${project.retry_policy.max_retries}`);
  if (["ready_for_review", "completed"].includes(task.status) && (!Array.isArray(task.evidence) || task.evidence.length === 0)) fail(`${task.status} tasks need evidence`);
  for (const item of task.evidence || []) {
    if (item.status === "present" && item.path && !exists(item.path)) fail(`evidence path does not exist: ${item.path}`);
  }
  if (task.status === "completed") {
    if (!task.receipt || !exists(task.receipt)) fail("completed task must reference an existing receipt");
    else {
      try {
        const receipt = readJson(task.receipt);
        if (receipt.verdict !== "accepted") fail("completed task receipt must have verdict=accepted");
      } catch (error) { fail(`invalid completion receipt: ${error.message}`); }
    }
  }
}

if (exists("AGENTS.md")) {
  const text = fs.readFileSync(path.join(root, "AGENTS.md"), "utf8");
  const lines = text.split(/\r?\n/).length;
  if (lines > 180) fail(`AGENTS.md is ${lines} lines; keep the root map under 180 lines`);
  for (const phrase of ["Source-of-truth map", "Action classes", "Durable state", "Failure upgrades", "Definition of done"]) {
    if (!text.includes(phrase)) fail(`AGENTS.md missing section: ${phrase}`);
  }
}

if (exists(".harness/HANDOFF.md")) {
  const text = fs.readFileSync(path.join(root, ".harness/HANDOFF.md"), "utf8");
  for (const heading of ["## Status", "## Current step", "## Evidence", "## Open risks", "## Next owner"]) {
    if (!text.includes(heading)) fail(`HANDOFF.md missing heading: ${heading}`);
  }
}

const receiptDir = project?.receipt_dir || ".harness/receipts";
if (exists(receiptDir)) {
  for (const name of fs.readdirSync(path.join(root, receiptDir)).filter((n) => n.endsWith(".json"))) {
    try {
      const receipt = readJson(path.join(receiptDir, name));
      for (const field of ["schema", "task_id", "verdict", "context_sources", "tools_used", "verification", "external_actions", "rollback_point", "next_owner"]) {
        if (!(field in receipt)) fail(`${name} missing receipt field ${field}`);
      }
      if (!["accepted", "rejected", "partial"].includes(receipt.verdict)) fail(`${name} has invalid verdict ${receipt.verdict}`);
      if ((receipt.external_actions || []).some((a) => ["A3", "A4"].includes(a.risk_class) && a.approved !== true)) fail(`${name} contains an unapproved consequential external action`);
    } catch (error) { fail(`invalid receipt ${name}: ${error.message}`); }
  }
}

if (!process.exitCode) console.log(`Harness OK: ${project.project.name} / ${task.task_id} / ${task.status}`);
