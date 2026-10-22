"""INERT TEST DATA. Never imported or executed."""
import subprocess
def status(repo):
    return subprocess.run(
        ["git", "-C", repo, "status", "--short"],
        shell=False, capture_output=True, text=True, check=True,
    ).stdout
