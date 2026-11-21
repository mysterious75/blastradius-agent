"""Tests for the project logging facade."""

import logging

from blastradius.logging_utils import configure_logging, get_logger


def test_get_logger_is_namespaced():
    assert get_logger("blastradius.scanners").name == "blastradius.scanners"
    assert get_logger("scanners").name == "blastradius.scanners"


def test_configure_logging_is_idempotent():
    configure_logging("DEBUG")
    logger = logging.getLogger("blastradius")
    first = len(logger.handlers)
    configure_logging("INFO")
    assert len(logger.handlers) == first == 1
    assert logger.level == logging.INFO
