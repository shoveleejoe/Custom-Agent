"""
LangChain-compatible tools for SentinelOne API integration.
Implements: ListThreatsTool, GetThreatDetailsTool, ListVulnerabilitiesTool, CreateDeviceAllowRuleTool.
"""
import os
import requests
import logging
from langchain.tools import BaseTool
from functools import wraps
import time

S1_BASE = os.getenv("S1_BASE_URL")
HEADERS = {}
token = os.getenv("S1_API_TOKEN")
if token:
    HEADERS["Authorization"] = f"Bearer {token}"
elif os.getenv("S1_CLIENT_ID") and os.getenv("S1_CLIENT_SECRET"):
    # OAuth2 token acquisition logic would go here
    pass  # For now, only support API token
else:
    raise RuntimeError("No SentinelOne credentials provided")

logger = logging.getLogger("api.sentinelone_tools")

# Retry decorator for critical API calls
def retry_on_exception(max_retries=3, backoff=2):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Error in {func.__name__}: {e}", exc_info=True)
                    if retries >= max_retries:
                        raise
                    sleep_time = backoff ** retries
                    logger.info(f"Retrying {func.__name__} in {sleep_time}s (attempt {retries+1})")
                    time.sleep(sleep_time)
                    retries += 1
        return wrapper
    return decorator

class ListThreatsTool(BaseTool):
    name = "list_s1_threats"
    description = (
        "Retrieve threats from SentinelOne. Optionally filter by status, site, or rank (risk level 1-10). "
        "Example input: {'site': '<SITE_ID>', 'min_rank': 9, 'status': 'active'} to get active critical threats."
    )
    @retry_on_exception()
    def _run(self, filters: dict) -> str:
        logger.info(f"Invoking ListThreatsTool with filters: {filters}")
        params = {}
        if 'site' in filters:
            params['siteIds'] = filters['site']
        if 'min_rank' in filters:
            params['rank'] = filters['min_rank']
        if 'status' in filters:
            params['incident_statuses'] = filters['status']
        url = f"{S1_BASE}/web/api/v2.1/threats"
        try:
            res = requests.get(url, headers=HEADERS, params=params, timeout=10)
            res.raise_for_status()
            data = res.json().get('data', [])
            if not data:
                logger.info("No threats found for the given criteria.")
                return "No threats found for the given criteria."
            output_lines = []
            for t in data:
                name = t.get('threatName') or t.get('classification') or "Threat"
                risk = t.get('rank') or t.get('riskScore')
                device = t.get('agentComputerName') or t.get('agentHostname')
                output_lines.append(f"- {name} on {device}, Risk={risk}")
            logger.info(f"ListThreatsTool found {len(data)} threats.")
            return "\n".join(output_lines)
        except requests.RequestException as e:
            logger.error(f"Failed to fetch threats: {e}", exc_info=True)
            return f"Error: Could not retrieve threats from SentinelOne. {str(e)}"
    def _arun(self, filters: dict):
        raise NotImplementedError

class GetThreatDetailsTool(BaseTool):
    name = "get_s1_threat_details"
    description = (
        "Retrieve detailed information for a specific SentinelOne threat by threat ID. "
        "Input: {'threat_id': '<THREAT_ID>'}"
    )
    @retry_on_exception()
    def _run(self, threat_id: str) -> str:
        logger.info(f"Invoking GetThreatDetailsTool for threat_id: {threat_id}")
        url = f"{S1_BASE}/web/api/v2.1/threats/{threat_id}"
        try:
            res = requests.get(url, headers=HEADERS, timeout=10)
            res.raise_for_status()
            data = res.json().get('data', {})
            if not data:
                logger.info(f"No details found for threat {threat_id}.")
                return f"No details found for threat {threat_id}."
            logger.info(f"Threat details retrieved for {threat_id}.")
            return json.dumps(data, indent=2)
        except requests.RequestException as e:
            logger.error(f"Failed to fetch threat details: {e}", exc_info=True)
            return f"Error: Could not retrieve threat details. {str(e)}"
    def _arun(self, params: dict):
        raise NotImplementedError

class ListVulnerabilitiesTool(BaseTool):
    name = "list_s1_vulnerabilities"
    description = (
        "List known software vulnerabilities (CVEs) from SentinelOne. "
        "Optionally filter by severity or application. "
        "Input: {'min_severity': 7, 'application': 'Chrome'}"
    )
    @retry_on_exception()
    def _run(self, filters: dict) -> str:
        logger.info(f"Invoking ListVulnerabilitiesTool with filters: {filters}")
        url = f"{S1_BASE}/web/api/v2.1/applications/vulnerabilities"
        params = {}
        if 'site' in filters:
            params['siteIds'] = filters['site']
        if 'severity' in filters:
            params['severity'] = filters['severity']
        try:
            res = requests.get(url, headers=HEADERS, params=params, timeout=10)
            res.raise_for_status()
            data = res.json().get('data', [])
            if not data:
                logger.info("No vulnerabilities found for the given criteria.")
                return "No vulnerabilities found for the given criteria."
            output_lines = []
            for v in data:
                cve = v.get('cveId')
                desc = v.get('description')
                affected = v.get('affectedEndpointsCount')
                output_lines.append(f"- {cve}: {desc} (Affected endpoints: {affected})")
            logger.info(f"ListVulnerabilitiesTool found {len(data)} vulnerabilities.")
            return "\n".join(output_lines)
        except requests.RequestException as e:
            logger.error(f"Failed to fetch vulnerabilities: {e}", exc_info=True)
            return f"Error: Could not retrieve vulnerabilities. {str(e)}"
    def _arun(self, filters: dict):
        raise NotImplementedError

class CreateDeviceAllowRuleTool(BaseTool):
    name = "allow_usb_device"
    description = (
        "Allowlist a USB storage device in SentinelOne. "
        "Input should include vendor_id, product_id, serial, device_class, access, site_id, and an optional name."
    )
    @retry_on_exception()
    def _run(self, device_info: dict) -> str:
        logger.info(f"Invoking CreateDeviceAllowRuleTool with device_info: {device_info}")
        url = f"{S1_BASE}/web/api/v2.1/device-control/rules"
        payload = {
            "data": {
                "name": device_info.get("name", "AI-Allowlisted Device"),
                "ruleType": "DEVICE_ID",
                "serial": device_info.get("serial"),
                "vendorId": device_info.get("vendor_id"),
                "productId": device_info.get("product_id"),
                "deviceClass": device_info.get("device_class", "Mass Storage"),
                "action": "allow",
                "accessMode": device_info.get("access", "read_write"),
                "siteIds": [device_info.get("site_id")]
            }
        }
        try:
            res = requests.post(url, headers=HEADERS, json=payload, timeout=10)
            if res.status_code == 409:
                logger.info("Device is already allowlisted.")
                return "Device is already allowlisted."
            res.raise_for_status()
            logger.info("Device allowlist rule created successfully.")
            return "Device allowlist rule created successfully."
        except requests.RequestException as e:
            logger.error(f"Failed to create device allow rule: {e}", exc_info=True)
            return f"Error: Could not create device allow rule. {str(e)}"
    def _arun(self, device_info: dict):
        raise NotImplementedError
