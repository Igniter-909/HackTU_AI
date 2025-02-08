import os
import sys
import logging

# Corrected logging format string
logging_str = "[%(asctime)s] [%(levelname)s] [%(module)s] - %(message)s"
log_dir = "logs"
log_filepath = os.path.join(log_dir, "running_logs.log")

# Create logs directory if it doesn't exist
os.makedirs(log_dir, exist_ok=True)

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format=logging_str,
    handlers=[
        logging.FileHandler(log_filepath),
        logging.StreamHandler(sys.stdout)
    ]
)

# Create a logger
logger = logging.getLogger("textSummarizerLogger_unique")

# Example usage of the logger
logger.info("Logging setup is working correctly.")

for handler in logger.handlers:
    if isinstance(handler, logging.FileHandler):
        handler.flush()