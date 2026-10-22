import json, sys

def main(path):
    with open(path) as fh:
        data = json.load(fh)
    print(json.dumps(data, indent=2, sort_keys=True))
