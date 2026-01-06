"""
Logging utilities
"""
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def get_logger(name):
    """Get logger instance"""
    return logging.getLogger(name)

def log_scan(scan_type, content, result):
    """Log scan activity"""
    logger = get_logger('scan')
    logger.info(f"Scan Type: {scan_type} | Threat Score: {result.get('threat_score')} | Risk: {result.get('risk_level')}")
