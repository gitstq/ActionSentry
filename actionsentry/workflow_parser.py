"""
Workflow parser - converts raw YAML data into structured Workflow objects.
"""

import os
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    Workflow, WorkflowJob, WorkflowStep, Finding, Rule, Severity, Category,
)
from .parser import parse_yaml, LineTracker, parse_yaml_file
from .utils import read_file, get_line_at


def parse_workflow_file(file_path: str) -> Tuple[Optional[Workflow], Optional[str]]:
    """Parse a workflow YAML file into a Workflow object.

    Returns (workflow, error). error is None on success.
    """
    content, err = read_file(file_path)
    if err:
        return None, err

    data, tracker, parse_err = parse_yaml_file(file_path)
    if parse_err:
        return None, parse_err

    if not isinstance(data, dict):
        return None, "Invalid workflow: root element is not a mapping"

    workflow = Workflow(file_path=file_path, raw_content=content)
    workflow.lines = content.split("\n")
    workflow.raw = data

    # Parse name
    workflow.name = str(data.get("name", ""))

    # Parse 'on' / triggers
    on_data = data.get("on", data.get(True, {}))
    if on_data is None:
        on_data = {}
    workflow.on = on_data
    workflow.triggers = _parse_triggers(on_data)

    # Parse permissions
    perm = data.get("permissions")
    if perm is not None:
        if isinstance(perm, dict):
            workflow.permissions = perm
        elif isinstance(perm, str):
            workflow.permissions = {"_raw": perm}
        elif isinstance(perm, bool):
            workflow.permissions = {"_raw": str(perm).lower()}

    # Parse env (top-level)
    top_env = data.get("env")
    if isinstance(top_env, dict):
        workflow.env = top_env

    # Parse concurrency
    conc = data.get("concurrency")
    if isinstance(conc, (dict, str)):
        workflow.concurrency = conc if isinstance(conc, dict) else {"group": conc}

    # Parse jobs
    jobs_data = data.get("jobs", {})
    if isinstance(jobs_data, dict):
        for job_id, job_data in jobs_data.items():
            if not isinstance(job_data, dict):
                continue
            job = _parse_job(job_id, job_data, content, tracker)
            workflow.jobs.append(job)

    return workflow, None


def _parse_triggers(on_data: Any) -> Dict[str, Any]:
    """Parse the 'on' key into a normalized triggers dict."""
    triggers: Dict[str, Any] = {}
    if isinstance(on_data, str):
        triggers[on_data] = {}
    elif isinstance(on_data, list):
        for item in on_data:
            if isinstance(item, str):
                triggers[item] = {}
            elif isinstance(item, dict):
                for k, v in item.items():
                    triggers[k] = v
    elif isinstance(on_data, dict):
        for key, val in on_data.items():
            triggers[str(key)] = val
    return triggers


def _parse_job(job_id: str, job_data: Dict, content: str,
               tracker: LineTracker) -> WorkflowJob:
    """Parse a single job from workflow data."""
    job = WorkflowJob(job_id=job_id)

    job.name = str(job_data.get("name", job_id))

    # runs-on
    runs_on = job_data.get("runs-on", job_data.get("runs_on"))
    if isinstance(runs_on, str):
        job.runs_on = [runs_on]
    elif isinstance(runs_on, list):
        job.runs_on = [str(x) for x in runs_on]
    elif isinstance(runs_on, dict):
        # Self-hosted with labels: {self-hosted: [label1, label2]}
        labels = runs_on.get("self-hosted", [])
        if isinstance(labels, list):
            job.runs_on = ["self-hosted"] + [str(x) for x in labels]
        elif isinstance(labels, str):
            job.runs_on = ["self-hosted", labels]
        else:
            job.runs_on = ["self-hosted"]

    # permissions (job-level)
    perm = job_data.get("permissions")
    if isinstance(perm, dict):
        job.permissions = perm
    elif isinstance(perm, str):
        job.permissions = {"_raw": perm}
    elif isinstance(perm, bool):
        job.permissions = {"_raw": str(perm).lower()}

    # env (job-level)
    env = job_data.get("env")
    if isinstance(env, dict):
        job.env = env

    # needs
    needs = job_data.get("needs")
    if isinstance(needs, str):
        job.needs = [needs]
    elif isinstance(needs, list):
        job.needs = [str(x) for x in needs]

    # if condition
    if_cond = job_data.get("if")
    if if_cond is not None:
        job.if_condition = str(if_cond)

    # steps
    steps_data = job_data.get("steps", [])
    if isinstance(steps_data, list):
        for idx, step_data in enumerate(steps_data):
            if isinstance(step_data, dict):
                step = _parse_step(step_data, content, tracker)
                job.steps.append(step)
            elif isinstance(step_data, str):
                # "uses: action@ref" shorthand
                step = WorkflowStep(uses=step_data)
                job.steps.append(step)

    # Find the line number of this job in the content
    job.line = _find_key_line(content, job_id)

    return job


def _parse_step(step_data: Dict, content: str,
                tracker: LineTracker) -> WorkflowStep:
    """Parse a single step from workflow data."""
    step = WorkflowStep()

    step.name = str(step_data.get("name", ""))
    step.uses = str(step_data.get("uses", ""))
    step.run = str(step_data.get("run", ""))
    step.shell = str(step_data.get("shell", ""))
    step.working_directory = str(step_data.get("working-directory", ""))
    step.continue_on_error = bool(step_data.get("continue-on-error", False))
    step.timeout_minutes = int(step_data.get("timeout-minutes", 0))

    # with -> with_
    with_data = step_data.get("with")
    if isinstance(with_data, dict):
        step.with_ = with_data

    # env
    env = step_data.get("env")
    if isinstance(env, dict):
        step.env = env

    # Find line number
    # Try to find by step name or uses
    if step.name:
        step.line = _find_key_line(content, step.name)
    if step.line == 0 and step.uses:
        step.line = _find_key_line(content, step.uses)
    if step.line == 0 and step.run:
        step.line = _find_line_containing(content, step.run[:50])

    return step


def _find_key_line(content: str, key: str) -> int:
    """Find the line number (1-indexed) where a key first appears."""
    lines = content.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(key) or key in stripped:
            return i + 1
    return 0


def _find_line_containing(content: str, text: str) -> int:
    """Find the line number (1-indexed) containing the given text."""
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if text in line:
            return i + 1
    return 0


def get_all_workflow_files(base_path: str) -> List[str]:
    """Find all workflow files in .github/workflows/ under base_path."""
    workflows_dir = os.path.join(base_path, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return []

    files = []
    for fname in os.listdir(workflows_dir):
        if fname.endswith(".yml") or fname.endswith(".yaml"):
            files.append(os.path.join(workflows_dir, fname))
    return sorted(files)
