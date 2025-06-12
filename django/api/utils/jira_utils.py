import requests
import os 
import re 
import json 
from typing import Union
import logging

JIRA_INSTANCE_URL = os.environ.get("JIRA_INSTANCE_URL")
PROJECT_KEY = os.environ.get("PROJECT_KEY")
JIRA_USERNAME = os.environ.get("JIRA_USERNAME")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN")

logger = logging.getLogger("api.jira_utils")

def link_jira_issue(inward_issue_key: str, outward_issue_key: str, link_type: str='Relates') -> None:
    """Links two Jira tickets.

    Args:
        primary_issue_key: Jira key of the inward issue.
        outward_issue_key: Jira key of the outward issue.
        link_type: Jira link type.
    Returns:
    """
    try:
        logger.info(f"Invoking link_jira_issue: {inward_issue_key} -> {outward_issue_key} with link type {link_type}")
        data = json.dumps({
            "inwardIssue": {
              "key": inward_issue_key
            },
            "outwardIssue": {
              "key": outward_issue_key
            },
            "type": {
              "name": link_type
            }
        }) 
        headers = {
          "Accept": "application/json",
          "Content-Type": "application/json"
        }
        if (result := requests.post(f'{JIRA_INSTANCE_URL}/rest/api/2/issueLink', data=data, headers=headers, auth=(JIRA_USERNAME, JIRA_API_TOKEN))) and \
        (result.status_code == 201):
            logger.info(f'Linked successfully {inward_issue_key}->{outward_issue_key}')
    except Exception as e:
        logger.error(f'Error in link_jira_issue: {e}', exc_info=True)
        raise

def extract_tag_helper(text: str, tag: str='related') -> Union[str, None]:
    """Extract the text between two tags.

    Args:
        text: Text to search.
        tag: Tag name to be. 
    Returns:
        The text between two tags. 
    """
    try:
        if regex := re.compile(f'<{tag}>(.*?)<{tag}>', flags=re.DOTALL).search(text):
            return regex.group(1)
    except Exception as e:
        logger.error(f'Error in extract_tag_helper: {e}', exc_info=True)
        raise

def parse_jira_issue_fields(data: dict) -> tuple:
    """Extract the key, summary and description fields from Jira.

    Args:
        data: Jira response JSON object.
    Returns:
        The Jira key, also concatenates the summary and description fields.
    """
    key = data.get('key')
    summary_description = f"{data.get('fields',{}).get('summary')} {data.get('fields',{}).get('description')}" 
    return (key, summary_description)

def get_all_tickets() -> Union[dict, None]:
    """Get all unresolved Jira tickets for a Jira project (maximum 1000). 

    Args:
        
    Returns:
        A dictionary of Jira key, description and summary data.
    """
    try:
        logger.info(f"Fetching all unresolved tickets for project {PROJECT_KEY}")
        if (result := requests.get(f'{JIRA_INSTANCE_URL}/rest/api/2/search?jql=project={PROJECT_KEY}+AND+resolution=unresolved&maxResults=1000', auth=(JIRA_USERNAME, JIRA_API_TOKEN))) \
        and (issues := result.json().get('issues')):
            return {parse_jira_issue_fields(issue)[0]: parse_jira_issue_fields(issue)[1] for issue in issues}
    except Exception as e:
        logger.error(f'Error in get_all_tickets: {e}', exc_info=True)
        raise

def get_ticket_data(key: str) -> Union[dict, None]:
    """Get Jira issue data. 

    Args:
        key: Jira issue key to be looked up.
    Returns:
        Jira ticket data.
    """
    try:
        logger.info(f"Fetching data for ticket {key}")
        if (result := requests.get(f'{JIRA_INSTANCE_URL}/rest/agile/1.0/issue/{key}', auth=(JIRA_USERNAME, JIRA_API_TOKEN))):
            return parse_jira_issue_fields(result.json())
    except Exception as e:
        logger.error(f'Error in get_ticket_data: {e}', exc_info=True)
        raise

def add_jira_comment(key: str, comment: str)-> None:
    """Add comment to Jira issue. 

    Args:
        key: Jira issue key to be commented on.
        comment: Comment to be applied to the ticket. 
    Returns:
    """
    try:
        logger.info(f"Adding comment to ticket {key}")
        data = json.dumps({
            "body": comment
        }) 
        headers = {
          "Accept": "application/json",
          "Content-Type": "application/json"
        }
        if (result := requests.post(f'{JIRA_INSTANCE_URL}/rest/api/2/issue/{key}/comment', data=data, headers=headers, auth=(JIRA_USERNAME, JIRA_API_TOKEN))) and \
        (result.status_code == 201):
            logger.info('Comment added successfully')
    except Exception as e:
        logger.error(f'Error in add_jira_comment: {e}', exc_info=True)
        raise

if __name__ == '__main__':
    pass