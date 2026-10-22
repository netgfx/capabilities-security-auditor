"""INERT TEST DATA. A pure JSON formatter; never imported or executed."""
import json
def format_json(value):
    return json.dumps(json.loads(value), indent=2, sort_keys=True)
