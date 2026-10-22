import subprocess

def status(repo):
    out = subprocess.run(['git', '-C', repo, 'status', '--short'],
                         capture_output=True, text=True)
    return out.stdout
