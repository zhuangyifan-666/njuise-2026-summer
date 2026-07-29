class RepoProofFailure(Exception):
    def __init__(self, message: str, remediation: str) -> None:
        super().__init__(message)
        self.message = message
        self.remediation = remediation


class UsageFailure(RepoProofFailure):
    pass


class RuntimeFailure(RepoProofFailure):
    pass
