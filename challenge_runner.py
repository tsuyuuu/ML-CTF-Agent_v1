# This code was created using ChatGPT-6 on November 10, 2026. The code was reviewed and debugged by team members to fit desired results.
# Runs the CTF-solving agent on a single challenge from the NYU CTF Bench dataset inside a sandboxed Docker container, then prints a summary of the run.

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path

from nyuctf.dataset import CTFDataset
from nyuctf.challenge import CTFChallenge

from agent_core import run_agent
from solver_runtime import DockerSolver
from controller import ToolDispatcher
from ctf_runtime_config import limits_from_env


BASE_DIR = Path(__file__).resolve().parent

DEV_DATASET = (
    BASE_DIR / "external"
    / "NYU_CTF_Bench"
    / "development_dataset.json"
)

TOOLS_FILE = BASE_DIR / "tools.json"

# Look up a challenge by ID in the chosen dataset and return it as a CTFChallenge object.
# This function was implemented with ChatGPT 6.0 Thinking.
# We designed the overall architecture, security constraints, and execution
# workflow, while using AI to assist with implementation, debugging, and
# code documentation. We reviewed and tested the resulting code to ensure
# it aligned with our project requirements.
def load_challenge(challenge_id, dataset="development"):
    if dataset == "development":
        dataset_path = (
            BASE_DIR
            / "external/NYU_CTF_Bench/development_dataset.json"
        )
    elif dataset == "ctftiny":
        dataset_path = (
            BASE_DIR
            / "external/CTFTiny/ctftiny.json"
        )
    else:
        raise ValueError(f"Unsupported dataset: {dataset}")

    ds = CTFDataset(dataset_json=str(dataset_path))

    # Reject IDs that are not in the selected dataset.
    challenge_data = ds.get(challenge_id)

    if challenge_data is None:
        raise ValueError(
            f"Challenge '{challenge_id}' not found in {dataset}"
        )

    return CTFChallenge(challenge_data, ds.basedir)

# Copy only the files a real contestant would get into the workspace, read-only.
# This function was implemented with ChatGPT 6.0 Thinking.
# We designed the overall architecture, security constraints, and execution
# workflow, while using AI to assist with implementation, debugging, and
# code documentation. We reviewed and tested the resulting code to ensure
# it aligned with our project requirements.
def prepare_contestant_files(challenge, workspace):
    """
    Export only authorized contestant files.

    Do not copy challenge.json, hidden source,
    build files, or verifier metadata.
    """
    exported = []

    for filename in challenge.files:
        source = Path(challenge.challenge_dir) / filename

        if not source.is_file():
            raise FileNotFoundError(
                f"Missing contestant file: {filename}"
            )

        destination = workspace / filename
        destination.parent.mkdir(
            parents=True, exist_ok=True
        )

        shutil.copy2(source, destination)

        # Make exported contestant files readable by ctfuser.
        # Do not grant write access.
        destination.chmod(0o644)

        exported.append(filename)

    # The solver runs as an unprivileged uid (10001) that differs from the
    # staging user, and reaches these files only through the read-only
    # /challenge mount, i.e. via the "other" permission bits. A contestant
    # file nested in a subdirectory (e.g. attachment/maze.pt) is unreachable
    # unless every parent directory is traversable (o+x). Normalize the whole
    # staged tree: directories -> 0o755 (read + traverse), files -> 0o644
    # (read only). The read-only mount still prevents any writes.
    for root, dirs, filenames in os.walk(workspace):
        try:
            os.chmod(root, 0o755)
        except OSError:
            pass
        for fname in filenames:
            try:
                os.chmod(os.path.join(root, fname), 0o644)
            except OSError:
                pass

    return exported

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--challenge-id",
        required=True
    )

    args = parser.parse_args()

    api_key = os.environ.get("OLLAMA_API_KEY")

    if not api_key:
        raise RuntimeError(
            "OLLAMA_API_KEY not configured"
        )

    challenge = load_challenge(args.challenge_id)

    tools = json.loads(TOOLS_FILE.read_text())
    dev_steps, dev_seconds = limits_from_env()

    # Exclude flag verification until approved
    # private evaluator is integrated.
    tools = [
        tool for tool in tools
        if tool["function"]["name"]
        != "submit_flag"
    ]

    # Fresh workspace for each development attempt
    with tempfile.TemporaryDirectory(
        prefix="ctf_contestant_"
    ) as temporary_dir:

        workspace = Path(temporary_dir)

        # TemporaryDirectory defaults to mode 700.
        # Allow the unprivileged solver to traverse the mounted directory.
        workspace.chmod(0o755)

        exported = prepare_contestant_files(
            challenge, workspace
        )

        solver = DockerSolver()

        try:
            solver.start(
                challenge_dir=workspace
            )

            dispatcher = ToolDispatcher(solver)

            result = run_agent(
                challenge_id=args.challenge_id,
                description=(
                    f"Challenge: {challenge.name}\n"
                    f"Category: {challenge.category}\n"
                    f"Description: {challenge.description}\n"
                    "The permitted files are mounted "
                    "read-only under /challenge.\n"
                    "Flag verification is unavailable "
                    "for this development test."
                ),
                files=[
                    f"/challenge/{filename}"
                    for filename in exported
                ],
                execute_tool=dispatcher,
                api_key=api_key,
                tools=tools,
                max_steps=dev_steps,
                max_seconds=dev_seconds
            )

            print("\n=== RUN SUMMARY ===")
            print(json.dumps(result, indent=2))

        finally:
            solver.stop()


if __name__ == "__main__":
    main()
