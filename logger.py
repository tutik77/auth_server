from loguru import logger
import sys

logger.remove()

logger.add(sys.stdout, format="{time} {level} {message}", level="DEBUG")
logger.add("logs/app.log", rotation="10 MB", retention="7 days", compression="zip", level="INFO")

def log_exceptions(exc_type, exc_value, exc_traceback):
    logger.exception("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = log_exceptions

__all__ = ["logger"]