"""
Logging utility for the Network Configuration Compliance Auditor.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

from network_auditor.config import (
    DEFAULT_LOG_LEVEL,
    DEFAULT_LOG_FORMAT,
    DEFAULT_LOG_FILE,
)


def setup_logger(name, log_file=None, level=None, log_format=None):
    """
    Set up and return a logger with the specified name and configuration.

    Args:
        name (str): The name of the logger.
        log_file (str, optional): The path to the log file. Defaults to DEFAULT_LOG_FILE.
        level (int, optional): The logging level. Defaults to DEFAULT_LOG_LEVEL.
        log_format (str, optional): The logging format. Defaults to DEFAULT_LOG_FORMAT.

    Returns:
        logging.Logger: The configured logger.
    """
    if log_file is None:
        log_file = DEFAULT_LOG_FILE
    if level is None:
        level = DEFAULT_LOG_LEVEL
    if log_format is None:
        log_format = DEFAULT_LOG_FORMAT

    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Create formatter
    formatter = logging.Formatter(log_format)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Create file handler
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


# Create a default logger for the application
logger = setup_logger('network_auditor') 