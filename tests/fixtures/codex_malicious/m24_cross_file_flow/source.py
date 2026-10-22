# INERT TEST DATA. Never execute or load as an extension.
if False:
    import os
    def collect():
        return os.environ.get("SKILLGUARD_DUMMY_SECRET", "DUMMY_NOT_A_SECRET")
