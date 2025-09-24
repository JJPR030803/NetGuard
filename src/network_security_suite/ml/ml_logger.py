from src.network_security_suite.utils.logger import Logger


class MLLogger(Logger):
    def save_logs(self, path: str):
        pass

    def log(self, message: str):
        pass


Logger = MLLogger("")
