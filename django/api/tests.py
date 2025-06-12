from django.test import TestCase
import unittest
from unittest.mock import patch
from api.utils import model_utils, sentinelone_tools, jira_utils

class AgentWorkflowTests(unittest.TestCase):
    @patch('api.utils.sentinelone_tools.requests.get')
    def test_list_threats_success(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'data': [
                {'threatName': 'Malware', 'agentComputerName': 'host1', 'rank': 9},
                {'threatName': 'Ransomware', 'agentComputerName': 'host2', 'rank': 10}
            ]
        }
        tool = sentinelone_tools.ListThreatsTool()
        result = tool._run({'min_rank': 9})
        self.assertIn('Malware', result)
        self.assertIn('Ransomware', result)

    @patch('api.utils.sentinelone_tools.requests.get')
    def test_list_vulnerabilities_empty(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {'data': []}
        tool = sentinelone_tools.ListVulnerabilitiesTool()
        result = tool._run({'severity': 9})
        self.assertIn('No vulnerabilities found', result)

    @patch('api.utils.sentinelone_tools.requests.post')
    def test_allow_usb_device_already_allowlisted(self, mock_post):
        mock_post.return_value.status_code = 409
        tool = sentinelone_tools.CreateDeviceAllowRuleTool()
        result = tool._run({'vendor_id': '1234', 'product_id': '5678', 'serial': 'abc', 'site_id': 'site1'})
        self.assertIn('already allowlisted', result)

    @patch('api.utils.jira_utils.requests.get')
    def test_get_all_tickets_success(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'issues': [
                {'key': 'JIRA-1', 'fields': {'summary': 'Test', 'description': 'Desc'}},
                {'key': 'JIRA-2', 'fields': {'summary': 'Test2', 'description': 'Desc2'}}
            ]
        }
        tickets = jira_utils.get_all_tickets()
        self.assertIsNotNone(tickets)
        if tickets is not None:
            self.assertIn('JIRA-1', tickets)
            self.assertIn('JIRA-2', tickets)

    @patch('api.utils.jira_utils.requests.get')
    def test_get_ticket_data_not_found(self, mock_get):
        mock_get.return_value.status_code = 404
        mock_get.return_value.json.return_value = {}
        result = jira_utils.get_ticket_data('NONEXISTENT')
        self.assertIsNone(result)

    @patch('api.utils.model_utils.llm_check_ticket_match')
    @patch('api.utils.jira_utils.get_all_tickets')
    @patch('api.utils.jira_utils.get_ticket_data')
    def test_triage_missing_ticket(self, mock_get_ticket_data, mock_get_all_tickets, mock_llm_check):
        mock_get_ticket_data.return_value = None
        result = model_utils.triage('BAD-KEY')
        self.assertIn('Error: No data found for ticket', result)

if __name__ == '__main__':
    unittest.main()
