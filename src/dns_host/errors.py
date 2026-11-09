"""API errors returned to upload clients."""


class ApiError(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status = status
        self.error = error
        self.message = message

    def as_dict(self) -> dict:
        return {"error": self.error, "message": self.message}
