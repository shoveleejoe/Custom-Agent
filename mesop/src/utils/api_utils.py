import requests
import logging

# local imports
from . import config

logger = logging.getLogger("mesop.api_utils")

def call_jira_agent(request):
    try:
        data = {"request": request}
        logger.info(f"Calling Jira agent with request: {request}")
        if (response := requests.post(f"{config.DJANGO_URL}api/jira-agent/", data=data)) and \
        (response.status_code == 200) and \
        (output := response.json().get("output")):
            return f"Request: {request}<br>Output: {output}<br><br>"
    except Exception as e:
        logger.error(f"Error in call_jira_agent: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    pass
