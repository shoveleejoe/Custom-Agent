# Solution Architecture: Custom AI Jira Agent with SentinelOne Integration

## Introduction

This document describes a comprehensive extension of the **Custom-AI-Jira-Agent** project to integrate **SentinelOne’s API** for enhanced cybersecurity operations. The goal is to enable a LangChain-based AI agent to interact with both **Jira** and **SentinelOne** through natural language. Users will be able to query SentinelOne for threat and vulnerability information and automatically create or update Jira tickets based on those findings. Key workflows include identifying critical threats and opening Jira issues, summarizing threats with mitigation suggestions, listing vulnerabilities with remediation tickets, and allowlisting USB devices after approval via Jira.

We prioritize a clear, modular design so a junior engineer can easily understand, implement, and extend the system. The solution covers system architecture, functional and non-functional requirements, tool development (using SentinelOne’s Swagger API spec), UI enhancements for confirmation vs. autonomous modes, containerization with Docker Compose, and thorough testing guidelines.

## Architecture Overview

The extended system follows a **multi-component architecture** that integrates the new SentinelOne functionality into the existing Jira AI agent framework. The major components are:

* **User Interface (UI)**: A web-based chat interface (built with Django and Google Mesop in the base project) where users input natural language requests and view agent responses. A toggle in the UI allows switching between **“Require Confirmation”** and **“Autonomous”** modes for actions.
* **LangChain AI Agent**: The core intelligent agent powered by an LLM (e.g. GPT-4 or similar), orchestrated via LangChain. It uses **Tools** to perform actions on external systems (Jira and SentinelOne) based on user queries. The agent is configured with a custom system prompt (CO-STAR format) and few-shot Chain-of-Thought examples for reasoning.
* **Jira API Integration**: Existing LangChain tools that allow the agent to search issues, create tickets, comment, or update Jira via Jira’s REST API. (This was provided in the base project; we will maintain it and ensure compatibility with the new features.)
* **SentinelOne API Integration**: New LangChain tools that interface with SentinelOne’s RESTful API (which offers hundreds of endpoints for threat, device, and vulnerability management). These tools are auto-generated or manually crafted from SentinelOne’s Swagger spec for key operations. The agent uses them to retrieve threat data, list vulnerabilities, and execute protective actions (like allowlisting a device).
* **Database**: A PostgreSQL database (with pgvector extension in the base project) for persisting data – e.g. chat history, user profiles/settings (including the confirmation toggle state), Jira ticket triage info, and possibly a vector store for semantic memory. This ensures stateful interactions and context retention.
* **LLM and Vector Store**: The LLM (possibly via external API like OpenAI) processes user input and agent reasoning. A vector store (pgvector or similar) may store prior tickets or threat descriptions for context, enabling the agent to retrieve relevant background info when formulating responses.

&#x20;*Figure 1: High-level Architecture.* The user interacts via a web chat UI. The LangChain agent, running in the Django backend, uses Jira and SentinelOne tools to fulfill requests. Data flows to Jira and SentinelOne APIs securely. The database stores chat and config data.

**Workflow Example:** For a request like *“Check for critical threats and open Jira tickets for each”*, the user message goes to the agent; the agent calls SentinelOne’s threat-list API tool to find threats marked *critical* (severity high), then calls the Jira tool to create an issue for each threat, and finally confirms to the user that tickets were created (optionally asking for confirmation first, based on mode).

## Functional Requirements

The extended system will support the following **functionalities and workflows**:

1. **Natural Language Querying for Jira and SentinelOne**: Users can ask questions or give instructions involving Jira issues or SentinelOne security data in a single conversational interface. The agent understands intents like *“list unresolved threats”*, *“open a Jira bug for this vulnerability”*, etc., and invokes the correct tools.

2. **Threat Identification & Ticketing**: The agent can retrieve threat detections from SentinelOne and create Jira tickets for critical issues. For example, *“Identify all malware threats above severity 8 and open a Jira incident for each”*. The agent will call the SentinelOne API to get threats filtered by severity or risk rank (e.g. rank 9-10 for critical), then for each threat it will compose a Jira issue (with details like threat name, impacted device, recommended action) via the Jira API.

3. **Threat Summary & Mitigation Advice**: The agent can summarize a set of SentinelOne threats and suggest mitigation steps. For example, *“Summarize the latest threats and how to mitigate them”*. The agent may fetch recent threat data from SentinelOne (e.g. unresolved threats from the last 24 hours), then use the LLM to generate a concise summary and best-practice mitigations (drawn from threat descriptions or known playbooks). The summary and recommendations can be delivered as a chat answer or even logged to a Jira task if requested.

4. **Vulnerability Listing & Remediation Tickets**: The agent can list all known software vulnerabilities (as identified by SentinelOne’s endpoint vulnerability management) and create Jira tickets to track their remediation. For instance, *“List all vulnerabilities found on our endpoints and open patch tasks”*. The agent will call SentinelOne’s API for application inventory and CVE data to retrieve vulnerabilities (SentinelOne can provide *“apps with known CVEs and outdated software”* via its vulnerability management feature). It will then create Jira tickets for each distinct critical vulnerability or group them logically, including information like CVE ID, affected hosts, and recommended fix versions.

5. **Device Allowlisting Workflow**: When a user requests a USB storage device to be allowed (after an approval in Jira), the agent will facilitate this by verifying the Jira approval and adding the device to SentinelOne’s allowlist. **Example**: A manager files a Jira ticket to allow a specific USB drive (providing device identifiers), and once it’s approved, the agent, upon prompt, will confirm the approval status via Jira API, then call SentinelOne’s device control API to create an allow rule. The allowlist (exclusion) rule will be scoped to that user’s machine or site as appropriate. SentinelOne’s API supports creating device control rules that specify USB device criteria – e.g. vendor ID, product ID, serial number (unique device ID), device class (mass storage), access permission (Read/Write), and rule action (allow). The agent will supply these parameters based on the information from the Jira ticket and enable the rule. Finally, it will update the Jira ticket (or comment) that the device has been allowlisted.

6. **User Confirmation Mode**: The system provides a **confirmation toggle** in the UI that, if enabled, forces the agent to get explicit user approval before executing any action that changes data (e.g. creating a Jira issue, modifying SentinelOne settings). In **“Always require confirmation”** mode, the agent will present the intended actions (like “I found 2 critical threats. Should I create Jira tickets for them?”) and only proceed when the user confirms. In **“Autonomous action”** mode, the agent will carry out the actions immediately and then inform the user (e.g. “Opened tickets SEC-101 and SEC-102 for the critical threats”). This toggle applies to **all workflows** to prevent unintended changes if desired.

7. **Logging and Traceability**: All agent actions and decisions should be logged. Every API call to Jira or SentinelOne and its result will be recorded (in the database or logs) for audit. This helps in debugging and verifying that the agent’s behavior is correct and safe, which is especially important when autonomous mode is enabled.

8. **Error Handling and User Guidance**: The agent will handle API errors gracefully. If a SentinelOne API call fails (e.g. due to authentication issues or network error) or returns no results, the agent should inform the user (e.g. “No threats found” or “Failed to connect to SentinelOne API”) and possibly suggest remedies (check credentials, etc.). It should not crash or leave the user without feedback. Similarly, any Jira operation failure will be reported.

## Non-Functional Requirements

In addition to the above capabilities, the solution must meet various **non-functional criteria**:

* **Security**: Protecting credentials and limiting actions is paramount. SentinelOne API credentials (URL, Client ID/Secret, API token) and Jira credentials must be stored securely (e.g. as environment variables or in a secure config store, not in code). All communication with Jira and SentinelOne should use HTTPS. The LangChain agent will be constrained to call only the allowed APIs (as Tools) – we will use LangChain’s tool mechanism and OpenAPI specs to **safelist specific endpoints**. We also ensure that in confirmation mode, no destructive action happens without human oversight. Role-based access control could be applied for the UI (e.g. only certain users can toggle autonomous mode or initiate allowlisting actions).

* **Modularity**: The design should remain modular. The SentinelOne integration will be encapsulated in its own set of tools or modules, separate from Jira tools. This modularity allows independent development and testing of the SentinelOne functionalities. In code terms, we might have a `sentinelone_toolkit.py` for all SentinelOne tools, analogous to an existing `jira_toolkit.py`. The LangChain agent can then load both tool sets. This separation also means the Jira part can be modified or upgraded independently of SentinelOne part, and vice versa.

* **Reproducibility & Deployment**: Using Docker Compose ensures that a new developer or tester can bring up the entire system reliably. The Docker environment will provision all required services (web app, database, etc.) with consistent versions. We will pin dependency versions in `requirements.txt` and use a specific Python version base image to avoid “works on my machine” issues. The Docker setup will also make it easy to deploy the agent in different environments (local, staging, production) with minimal configuration changes.

* **Scalability & Performance**: Although initial usage may be small-scale (a single agent for a team), the architecture should allow scaling if needed. For instance, the Django app could be scaled horizontally behind a load balancer if many concurrent users/chat sessions are expected. The agent’s design (being stateless between messages except for DB-stored context) allows scaling out. The database (PostgreSQL) can handle the moderate load of chat history and vector queries. We will also consider rate limits of the SentinelOne API – if it’s large (300+ functions available), ensuring our calls (especially in autonomous loops) do not hammer the API. Caching of recent results (short-term caching in memory or DB) for repeated queries could be implemented to reduce duplicate calls, especially for summaries.

* **Reliability**: The system should be robust against failures. Docker containers will restart on failure. The agent should validate assumptions (e.g. check that SentinelOne returned valid data before trying to use it). We will include health checks: for example, a small endpoint in Django to test DB connectivity and perhaps a quick SentinelOne API check (like fetch current user info) to verify integration health. Logging and monitoring (possibly using the built-in Django logging or additional tools like Sentry) will be enabled to quickly catch and fix issues.

* **Usability**: For the junior engineer and end-users, clarity is key. The code will be well-documented and the UI will provide guidance (tooltips or documentation panel describing how to phrase queries, and what operations are possible). The output format of the agent’s answers should be easy to read – e.g. using Markdown formatting for lists of threats or vulnerabilities, and including Jira issue links if possible. We will maintain short paragraphs in responses and use lists when enumerating items, to align with readability expectations (this is also reflected in how the agent responds to the user).

## LangChain Agent Design

**Agent Type**: We will use a LangChain **Multi-Tool React Agent** (ReAct framework) with tools for Jira and SentinelOne. The agent’s prompt will be extended from the base project’s CO-STAR prompt to also include instructions on the SentinelOne tools. Essentially, the system prompt will now describe both domains:

* Jira domain: how to format queries about tickets, what Jira tool actions can do (create, search, update issues, etc.).
* SentinelOne domain: what kind of data is available (threats, devices, vulnerabilities) and what actions can be taken (get info, allowlist device, etc.).

We will include few-shot examples in the prompt for the new workflows so the agent sees how a question about SentinelOne should be handled. For instance, an example conversation for *“list all high severity threats and summarize them”* and its step-by-step reasoning and tool usage will be added to the few-shots. This helps the agent understand when to invoke SentinelOne tools vs Jira tools.

**Tools and Swagger Spec**: The SentinelOne integration relies on its Swagger (OpenAPI) specification, which defines all endpoints and their parameters. We have two approaches to incorporate this:

* *Manual Tool Definition*: For clarity and control, we will **manually define LangChain Tools** for the specific SentinelOne operations needed. Each tool will be a small wrapper around an HTTPS request to a SentinelOne API endpoint, with proper authentication headers and parameter handling. For example, a `ListThreatsTool` that calls `GET /web/api/v2.1/threats` with query params, or a `CreateDeviceRuleTool` that calls `POST /web/api/v2.1/device-control/rules` with the allowlist payload. We will restrict the tool inputs to what a user might naturally specify (e.g. severity level, or device identifiers) and map those to API parameters. This approach ensures we implement exactly what’s needed for the four workflows, and we can thoroughly test each call.

* *Dynamic OpenAPI Agent*: For broader coverage (full integration of all SentinelOne API functions), we can leverage LangChain’s **OpenAPI Toolkit**. LangChain can read a Swagger spec and generate an agent that can decide which API operation to use given a query. In a hierarchical planning approach, a **planner** LLM first selects relevant endpoints, and a **controller** LLM executes them. This would enable the agent to handle even unforeseen SentinelOne requests by referring to the API documentation. However, this method is more complex and may require trimming the spec (SentinelOne has a *massive API surface*) for performance. We can consider this as a future enhancement. For now, we will focus on a curated set of tools (manual approach) to ensure reliability for our known use cases.

In either case, the **SentinelOne Swagger JSON** (from the provided URL) will be used as a reference to ensure our tool implementation is correct. We may even auto-generate a Python API client from the spec (using tools like `openapi-generator` or `bravado`) to speed up development and then wrap those calls in LangChain tools.

**Authentication Handling**: SentinelOne’s API allows authentication via different methods, so our agent must accommodate:

* **API Token (Personal Access Token)**: A static token (bearer token) generated from SentinelOne console (often via creating a *Service User* with an API token). This token is included in an HTTP header for all requests: `Authorization: Bearer <token>`. We will use this as the primary method for simplicity (the token corresponds to a specific role and scope in SentinelOne – e.g. site or account level – which should be configured to have permissions to retrieve threats, manage device control, etc.).
* **Client ID & Secret**: If SentinelOne provides an OAuth2 authentication flow, the client ID/secret can be used to obtain a time-limited token (e.g. via a token endpoint). Some deployments might prefer this method. We will support it by having the backend detect if `S1_CLIENT_ID` and `S1_CLIENT_SECRET` are provided (and no static token is given). In that case, the backend will perform the OAuth handshake at startup or before the first API call: typically by POSTing to `oauth2/token` endpoint on the SentinelOne server (URL also provided in config) to get an access token, then caching it for use in Authorization header. Token refresh logic will be added if needed (based on token expiry, which we’ll parse from the response).
* **URL / Console**: SentinelOne is offered as a cloud service (with regional domains like `https://usea1.sentinelone.net`) or on-prem. The **base URL** of the API (e.g. `https://<company>.sentinelone.net`) is required and configurable. In Docker Compose, we’ll let the user supply `S1_BASE_URL`. The agent then constructs API endpoints by appending the known paths (e.g. `/web/api/v2.1/threats`). We’ll ensure no hard-coding of URLs beyond the path.

The Docker Compose and Django settings will be updated to include these config options. For example, in `docker-compose.yml` we’ll add:

```yaml
services:
  ai_agent:
    build: .
    environment:
      - JIRA_SERVER_URL=https://yourdomain.atlassian.net
      - JIRA_API_TOKEN=${JIRA_API_TOKEN}
      - JIRA_USER_EMAIL=${JIRA_USER_EMAIL}
      - S1_BASE_URL=${S1_BASE_URL}         # e.g. https://usea1.sentinelone.net
      - S1_API_TOKEN=${S1_API_TOKEN}       # if using token auth
      - S1_CLIENT_ID=${S1_CLIENT_ID}       # if using OAuth client credentials
      - S1_CLIENT_SECRET=${S1_CLIENT_SECRET}
      - S1_API_VERSION=2.1                # API version (2.1 in our case)
      ...
```

In the agent backend code, we will initialize a **SentinelOne API client** with these credentials. For example (pseudo-code in Django startup or LangChain tool initialization):

```python
import os, requests

S1_BASE = os.getenv("S1_BASE_URL")
S1_TOKEN = os.getenv("S1_API_TOKEN")
S1_ID = os.getenv("S1_CLIENT_ID")
S1_SECRET = os.getenv("S1_CLIENT_SECRET")

if S1_TOKEN:
    auth_header = {"Authorization": f"Bearer {S1_TOKEN}"}
elif S1_ID and S1_SECRET:
    # obtain OAuth token
    resp = requests.post(f"{S1_BASE}/web/api/v2.1/oauth/token", 
                         data={"client_id": S1_ID, "client_secret": S1_SECRET})
    resp.raise_for_status()
    token = resp.json().get("access_token")
    auth_header = {"Authorization": f"Bearer {token}"}
else:
    raise RuntimeError("No SentinelOne credentials provided")
```

This `auth_header` will then be used by all SentinelOne tool functions when making requests. The **Jira credentials** (server URL, user email, API token) similarly are loaded from environment (likely already set up in the base project’s Docker).

**Defining SentinelOne Tools**: We will create a set of tools corresponding to the needed SentinelOne operations:

* **Tool: ListThreats** – *Input:* filters like site ID (if multi-site), severity or rank threshold, status (active/mitigated). *Action:* Makes a GET request to `/<base>/web/api/v2.1/threats` with query params. *Output:* A summary of threats found (e.g. list of threat names, IDs, affected machine, risk score). The tool will internally format the JSON response into a concise text or Python object that the agent can parse. For example, we might return a list of dictionaries or a markdown table of threats. The agent can then decide how to use that (present to user or feed into next tool). According to SentinelOne’s API, we can filter threats by parameters like `rank` (risk level 1-10), `status` (e.g. unresolved), and more. For critical threats, the agent might call `ListThreats` with `rank>=9` or similar.

* **Tool: GetThreatDetails** – *Input:* a specific threat ID. *Action:* GET `/web/api/v2.1/threats/{id}` to retrieve detailed information on that threat (e.g. the file hash, kill chain, mitigation status, etc.). *Output:* Detailed info which can be used for summarization. This tool might not always be necessary if `ListThreats` already returns enough info, but it’s available if the agent needs more details to include in a Jira ticket or summary.

* **Tool: ListVulnerabilities** – *Input:* filters such as severity or application name (optional). *Action:* likely GET `/web/api/v2.1/applications/vulnerabilities` or a similar endpoint (from the spec). SentinelOne’s API can provide a list of vulnerabilities (CVE records) found in the environment. This might involve first listing all applications or endpoints and their known CVEs. In practice, the agent might call an endpoint to get **all CVEs known** (the Swagger spec likely defines an operation for this, and the Postman collection suggests an operation “Get known CVEs for applications installed on endpoints”). We will implement this tool to retrieve, for example, all CVEs with a severity score or tag them by risk. *Output:* A list of vulnerabilities (CVE IDs, descriptions, number of affected devices). The agent will use this output to formulate an answer or to iterate and create Jira tickets. Possibly, we will have the agent group vulnerabilities by priority and then call Jira.

* **Tool: CreateDeviceAllowRule** – *Input:* device identifiers (vendor ID, product ID, serial number or UID), plus scope info (site or agent ID) and an optional descriptive name. *Action:* POST to `/web/api/v2.1/device-control/rules` (based on Swagger) with a JSON payload to allow the device. SentinelOne’s device control API requires specifying the rule parameters such as:

  * **Rule Name** (string, e.g. "Allow Marketing USB Drive"),
  * **Rule Type** (the identifier type; to allow a specific device, we’d use *Serial* number or *Vendor+Product* combination),
  * **Serial ID (UID)** if Rule Type is serial,
  * **Vendor ID** and **Product ID** (typically hex strings or integers identifying the USB device model) if those are used,
  * **Device Class** (e.g. `MassStorage` or the USB class code to restrict to storage devices),
  * **Access Permission** (what level is allowed – likely “Read & Write” for full allow),
  * **Action** (allow or block – here it would be an allow rule, which in some systems might be indicated by a boolean or just by virtue of being an “allow” rule type),
  * **Site ID** (to scope the rule to a specific site if needed; this can often be retrieved from SentinelOne if the organization is multi-tenant),
  * **Status** (enabled).

  The tool will construct this JSON and call the API. On success, SentinelOne will enforce that going forward the specified device is permitted. The tool output can simply confirm success or throw an error if failed. The agent will likely not present the raw API result to the user, but instead a friendly confirmation like “USB device XYZ has been allowlisted for user John’s machine.”

* **Tool: JiraCreateIssue** – (Already exists in the Jira toolkit) used by agent to create tickets. We ensure that when the agent passes information from SentinelOne to Jira, it includes relevant details. For example, for a threat, the Jira ticket description might include the threat name, ID, affected endpoint, severity, and perhaps a link to SentinelOne console (if available) for further investigation. We might enhance the Jira tool to accept richer input or handle attachments (like if we want to attach a JSON of threat details to Jira).

The LangChain agent will choose these tools as needed. For example, a user query *“Find all threats with ransomware and file tickets”* might trigger a plan like: use `ListThreats` (with filter classification contains "Ransomware"), then loop over results and for each call `JiraCreateIssue`. The agent’s chain-of-thought and memory (the CO-STAR prompt encourages reasoning steps) will ensure it explains each step internally before executing. The final answer to the user will be a confirmation, e.g., *“Found 2 ransomware threats. Created Jira tickets: SEC-123, SEC-124.”* (Or a question for confirmation if in that mode.)

**Using the OpenAPI Spec for Tools**: Given we have the Swagger JSON, we can semi-automate tool creation. For instance, using LangChain’s OpenAPI agent utilities, one could load the spec and have it generate an **OpenAPISpec** object. From there, specific **APIOperation** objects can be derived. For example (in code):

```python
from langchain.tools.openapi import OpenAPISpec, APIOperation

spec = OpenAPISpec.from_url("sentinelone-swagger.json")
# Suppose the spec has an operation ID "listThreats"
list_threats_op = APIOperation.from_openapi_spec(spec, "listThreats")
```

However, the SentinelOne spec might not directly give nice operation IDs; we might instead search by path:

```python
ops = [op for op in spec if "/threats" in op.path and op.method == "get"]
```

We can then create a LangChain tool dynamically from that, or simply use the `Requests` tool in LangChain to call the API endpoint directly. **Important**: We must set `allow_dangerous_request=True` for the OpenAPI agent to actually call external URLs (LangChain prevents arbitrary web requests by default). Since we trust the curated spec and we’re controlling what endpoints can be called, this is acceptable. We will enforce that only SentinelOne’s base URL is allowed in those tools to avoid any misuse.

## Implementation Steps

This section breaks down the engineering steps for each part of the system, from development through deployment and testing:

### 1. Project Setup and Dependencies

* **Update Codebase**: Start by pulling the latest Custom-AI-Jira-Agent project code. Create a new branch for the SentinelOne integration feature.
* **Install SentinelOne SDK or HTTP Client**: If SentinelOne provides an SDK or if we plan to use OpenAPI tools, install necessary packages. For example, we might add `openapi-python-client` or just use Python’s `requests` (which is likely already in use for Jira integration). Also ensure LangChain is up-to-date for OpenAPI agent support. Update `requirements.txt` accordingly (e.g., ensure `langchain>=0.xx`, `requests`, etc.).
* **Environment Variables**: Document the new env vars needed:

  * `S1_BASE_URL` – e.g. `"https://usea1.sentinelone.net"`.
  * `S1_API_TOKEN` – SentinelOne API token (if using token auth).
  * `S1_CLIENT_ID` and `S1_CLIENT_SECRET` – if using OAuth2.
  * (Optional) `S1_SITE_ID` – if the organization requires specifying a site in API calls (some endpoints may need site context; we can also fetch site ID via API if needed).
    These can be added to the project’s `.env.example` file and README for clarity. Ensure the Docker Compose file passes them through (as shown earlier).

### 2. SentinelOne Tools Development

* **Create SentinelOne Tools Module**: The file `django/api/utils/sentinelone_tools.py` has been created. It defines a LangChain-compatible `ListThreatsTool` for SentinelOne. Additional tools (GetThreatDetailsTool, ListVulnerabilitiesTool, CreateDeviceAllowRuleTool) should be added following the same pattern.

  ```python
  from langchain.tools import BaseTool
  import requests, os, json

  S1_BASE = os.getenv("S1_BASE_URL")
  HEADERS = {}  # we'll populate the auth header at module import
  token = os.getenv("S1_API_TOKEN")
  if token:
      HEADERS["Authorization"] = f"Bearer {token}"
  elif os.getenv("S1_CLIENT_ID") and os.getenv("S1_CLIENT_SECRET"):
      # Acquire token as shown earlier
      # ...
      HEADERS["Authorization"] = f"Bearer {fetched_token}"

  class ListThreatsTool(BaseTool):
      name = "list_s1_threats"
      description = ("Retrieve threats from SentinelOne. Optionally filter by status, site, or rank (risk level 1-10). "
                     "Example input: {'site': '<SITE_ID>', 'min_rank': 9, 'status': 'active'} to get active critical threats.")
      def _run(self, filters: dict) -> str:
          params = {}
          if 'site' in filters:
              params['siteIds'] = filters['site']
          if 'min_rank' in filters:
              params['rank'] = filters['min_rank']  # assuming API 2.0 uses rank; for 2.1, risk_level maybe
          if 'status' in filters:
              params['incident_statuses'] = filters['status']
          url = f"{S1_BASE}/web/api/v2.1/threats"
          res = requests.get(url, headers=HEADERS, params=params)
          res.raise_for_status()
          data = res.json().get('data', [])
          # Format output
          if not data:
              return "No threats found for the given criteria."
          output_lines = []
          for t in data:
              name = t.get('threatName') or t.get('classification') or "Threat"
              risk = t.get('rank') or t.get('riskScore')
              device = t.get('agentComputerName') or t.get('agentHostname')
              output_lines.append(f"- {name} on {device}, Risk={risk}")
          return "\n".join(output_lines)
      def _arun(self, filters: dict):
          # async version if needed; otherwise not used
          raise NotImplementedError
  ```

  The above is illustrative: it shows how we might implement listing threats. We utilize the `rank` or `incident_statuses` as per SentinelOne’s API spec (for example, `incident_statuses=UNRESOLVED` or similar to get active threats). We ensure to handle if no data or error.

  We then implement similar classes for `GetThreatDetailsTool`, `ListVulnerabilitiesTool`, `CreateDeviceAllowRuleTool`. Each will construct the appropriate endpoint and request. For the device allow tool, for instance:

  ```python
  class CreateDeviceAllowRuleTool(BaseTool):
      name = "allow_usb_device"
      description = ("Allowlist a USB storage device in SentinelOne. Input should include vendor_id, product_id, serial, and an optional note.")
      def _run(self, device_info: dict) -> str:
          url = f"{S1_BASE}/web/api/v2.1/device-control/rules"
          payload = {
             "data": {
               "name": device_info.get("name", "AI-Allowlisted Device"),
               "ruleType": "DEVICE_ID",  # or "VENDOR_PRODUCT" or "SERIAL" depending on what API expects
               "serial": device_info.get("serial"),
               "vendorId": device_info.get("vendor_id"),
               "productId": device_info.get("product_id"),
               "deviceClass": device_info.get("device_class", "Mass Storage"),
               "action": "allow",  # if required; some APIs might implicitly allow if creating allow rule
               "accessMode": device_info.get("access", "read_write"),  # e.g. read_write or read_only
               "siteIds": [ device_info.get("site_id") ]  # ensure the rule is scoped appropriately
             }
          }
          res = requests.post(url, headers=HEADERS, json=payload)
          if res.status_code == 409:
              return "Device is already allowlisted."
          res.raise_for_status()
          return "Device allowlist rule created successfully."
  ```

  (The exact payload keys depend on the API spec; we’d verify them against the Swagger or docs. The BlinkOps doc shows parameters like Access Permission, Device Class, Vendor ID, etc. which guided this structure.)

* **Incorporate Tools into Agent**: Once tools are defined, we integrate them into the LangChain agent setup. In the Django view or wherever the agent is initialized, we will do something like:

  ```python
  from langchain.agents import initialize_agent
  from langchain.chat_models import ChatOpenAI
  from jira_tools import JiraSearchTool, JiraCreateIssueTool, ...  # existing tools
  from sentinelone_tools import ListThreatsTool, GetThreatDetailsTool, ListVulnerabilitiesTool, CreateDeviceAllowRuleTool

  llm = ChatOpenAI(model_name="gpt-4", temperature=0)  # or another LLM
  tools = [
      JiraSearchTool(), JiraCreateIssueTool(), ...,
      ListThreatsTool(), GetThreatDetailsTool(), ListVulnerabilitiesTool(), CreateDeviceAllowRuleTool()
  ]
  agent = initialize_agent(tools, llm, agent="chat-zero-shot-react-description", verbose=True)
  ```

  Here we choose an agent type appropriate for multiple tools. `chat-zero-shot-react-description` is a common choice where the agent uses the tool `description` to decide usage. We will ensure our tool `description` fields are very clear so the agent knows when to use each. For example, the description for ListThreatsTool clearly states it’s for retrieving SentinelOne threats.

  Also, we prepend a **tool description prefix** in the prompt that might group tools by domain (so the agent can distinguish Jira vs SentinelOne). For example:

  * “Jira Tools: Use these for Jira issue queries and updates (e.g. `search_jira`, `create_jira_issue` …).”
  * “SentinelOne Tools: Use these for endpoint security data (e.g. `list_s1_threats` to find threats, `allow_usb_device` to allowlist a device, etc.).”

  This can be part of the system message or as additional context injected into LangChain’s agent initialization (LangChain allows an optional `agent_kwargs={"prefix": ..., "format_instructions": ...}` when initializing agents). We’ll leverage that to ensure the agent fully understands its toolkit.

* **Testing Tools in Isolation**: Before full integration, we will test each tool function individually:

  * Write unit tests (or use Django management commands) that call the tool’s `_run` with sample inputs and assert the output. For example, simulate a known threat scenario by hitting a test SentinelOne server (if available) or by mocking `requests.get` to return a sample JSON (possibly from SentinelOne API documentation). Ensure that parsing works (e.g. our ListThreatsTool correctly formats output lines).
  * For the allow device tool, since it’s hard to test without an actual SentinelOne instance, we might mock a response or at least ensure that our payload structure matches what the API expects as per the Swagger. The BlinkOps example informs the required fields, so we’ll double-check with the Swagger spec (look at the `device-control/rules` definition in the JSON). If needed, adjust the payload keys/names.
  * If an actual SentinelOne environment is available for testing, we can perform an end-to-end test: create a dummy USB rule via the tool and verify in the SentinelOne console that it appears (and then remove it). For threats and vulnerabilities, we can possibly use real data if any exist (or simulate by lowering thresholds to catch benign items).

### 3. UI Enhancements (Chat and Confirmation Toggle)

* **Chat Interface**: The Django frontend (likely using Google Mesop components or standard Django templates with JavaScript) already provides a chat box for user messages and displays agent responses. We will maintain that, but extend the UI to support the new functionality:

  * Possibly add **suggested prompt buttons** for the new workflows (for user convenience). E.g., a button that says “List critical threats” or “Scan for vulnerabilities” which sends a pre-defined query to the agent. This is optional but improves usability.
  * Ensure the output formatting is user-friendly. We might tweak the CSS or Markdown rendering so that lists (like the bullet list of threats the agent might return) are nicely presented. If the agent returns Markdown tables (for vulnerabilities list with columns like CVE, Affected Applications, Risk), make sure the frontend supports that (maybe using a library or writing custom render logic).

* **Confirmation Toggle Implementation**: This toggle can be a simple checkbox or switch in the UI labeled e.g. “Autonomous Actions” (on/off). The default could be off (require confirmation). When toggled, it should send this preference to the backend – likely via an API call or WebSocket message to set a flag in the user’s session or profile.

  Backend logic:

  * We create a field in the user model or session (if we have user login) to store `require_confirmation` (True/False). If using session, when the user toggles, an AJAX call can set `request.session['require_confirmation'] = False` (for autonomous, false means do *not* require confirmation).
  * The agent handling code (where we call `agent.run(user_input)`) will check this flag. One approach:

    * If confirmation is required, we **modify the agent’s behavior**: We might wrap certain tools or outputs in a conditional. For example, we can subclass the Jira create issue tool and SentinelOne allow tool to *ask for confirmation* instead of executing if the flag is set.
    * Simpler: run the agent in two passes. First pass, we instruct the agent (via an extra system message) *“The user has confirmation mode ON. Before executing any irreversible action (creating tickets, changing SentinelOne), you must ask the user for approval.”* The agent might then, upon deciding to create a ticket, output something like: *“I found X, would you like me to create a Jira ticket? (yes/no)”*. We then need to capture the user’s “yes” as a follow-up that triggers the actual creation.
    * Alternatively, we intercept tool calls on the backend: We can modify the LangChain Tool classes to check a global flag. For instance, in `JiraCreateIssueTool._run`, before actually calling Jira, check `if require_confirmation: return "CONFIRM_PROMPT: Create issue with title ... ?"`. The agent will output that string to the user. We recognize the `CONFIRM_PROMPT` prefix in the output and instead of showing that directly, the UI can render a styled confirmation prompt (with Yes/No buttons). If user clicks Yes, the UI calls an endpoint that actually executes the pending action (perhaps calling the tool with `require_confirmation` off or directly using Jira API).
    * This requires more engineering but provides a clear separation: the agent in confirm mode basically tells the UI what it *wants* to do, and the UI/API will actually do it when confirmed.

  Given complexity, an iterative approach:

  * Initially, implement a **simple confirmation**: the agent itself asks the user for permission in plain language (because we added that instruction in the prompt). The user must then type "yes" to continue. This is less ideal UX (two-turn conversation for each action) but is straightforward. We can refine it to button-click flow later.
  * In autonomous mode, of course, the agent just does it.

  We'll document clearly in the README and code comments how this is implemented so the junior engineer can adjust if needed. The UI indicator (like switching color or showing “Autonomous mode ON” text) will remind users that the agent may take actions immediately.

### 4. Docker Compose and Containerization

* **Dockerfile Update**: Ensure the Dockerfile for the Django app has all new dependencies (if we added any library for SentinelOne integration). For example, if using `openapi-client`, that needs to be pip installed. Rebuild the image to verify.

* **Docker Compose Configuration**: As noted, add the SentinelOne-related environment variables to the `docker-compose.yml`. Also, if the base project had separate containers for worker vs web, update those too. For instance, if using Celery for background tasks (just a possibility), ensure the worker has the same env vars if it might call SentinelOne. In our simple architecture, probably the Django web process is handling everything synchronously.

* **Bringing up the Stack**: The instructions for a junior engineer should be explicit. E.g.:

  1. Copy the SentinelOne Swagger JSON into the project directory (if we use it at runtime) or ensure the code has access (we could bake it into the image or fetch it on startup).
  2. Set the environment variables in a `.env` file (based on template).
  3. Run `docker-compose up --build`. This will start the database, run migrations (if any), and start the web server.
  4. The web UI should then be accessible (e.g. [http://localhost:8000/](http://localhost:8000/)). Provide credentials if the app uses login, or mention if not needed.

* **Verifying Services**: After startup, check logs of each container:

  * The database should initialize without errors.
  * The web app should log that it connected to DB and is listening. It might also log a successful test connection to SentinelOne (we could implement a small check on startup, like calling a lightweight API e.g. GET `/web/api/v2.1/users/me` to verify auth).
  * If any issues (like misconfigured URL or auth), the logs should surface them; the junior engineer should know to look there.

* **Container Networking**: In Compose, ensure that the web container can reach the internet (for SentinelOne’s API). Usually, by default it can, as long as no network restrictions. If using an on-prem SentinelOne server reachable via VPN or special network, that complicates things beyond scope; we assume internet reachability or host networking if needed for on-prem testing.

* **Persistence**: If the agent’s chat history or vectors are stored in Postgres, consider using a Docker volume for the DB to persist data between restarts (so context isn’t lost each time). Add a volume in compose for the `db` service mapping to a local folder.

### 5. Testing & Validation

Once the system is up, we need to test the end-to-end flows:

**Functional Tests:**

* *Threat to Jira Workflow*: Simulate a scenario. If you don’t actually have threats in SentinelOne, you can temporarily mock the ListThreatsTool to return a fabricated threat. For a real test, if SentinelOne has an EICAR test malware or some benign threat in its console, use that. Ask the agent in the UI: *“Are there any critical threats? If so, create Jira tickets for them.”*

  * In confirmation mode: The agent should reply with something like *“I found X threat(s) with high severity. Would you like me to create tickets?”*. Then you respond *“yes”* (or click yes if UI supports). The agent then creates the ticket(s). Check Jira (or Jira test project) to see if tickets were created with correct details. Verify the agent’s final message lists the new Jira IDs.
  * In autonomous mode: The agent should perhaps directly say *“Found X threats and created tickets ABC-123, ABC-124.”* and the tickets should exist in Jira.

* *Threat Summary Workflow*: Ask *“Summarize the malware threats detected this week and suggest how to mitigate them.”* The agent should call ListThreats (with a date filter if implemented, or get all and filter by date in code/LLM). Then it should use the LLM to produce a summary. Verify the summary is coherent, mentions the threats and mitigations (the mitigations might come from SentinelOne threat data if available, or general knowledge – ensure the LLM has enough info either via the threat details or its own training). This tests the LLM’s capability to synthesize the API data into a useful answer. Also ensure it doesn’t hallucinate – ideally, if the agent isn’t confident, it should say something like *“According to SentinelOne, Threat X was detected on Host Y. A typical mitigation is to isolate the host and remove the file...”* Use domain knowledge from SentinelOne outputs if available.

* *Vulnerability Listing Workflow*: Ask *“What vulnerabilities were found in our environment?”*. If using a test environment, perhaps install a purposely outdated software on one endpoint to have a known CVE. The agent (via ListVulnerabilitiesTool) should retrieve something like *“CVE-2021-1234 in Application Z (present on 5 machines)”*. It should list them. Then you can follow up: *“Create Jira tickets to track fixing these.”* The agent should then create one Jira issue per vulnerability (or one encompassing issue listing all, depending on how it’s designed to behave – clarify this in prompt or as a design decision). Check Jira for those issues and content.

* *USB Allowlisting Workflow*: This one is harder to test end-to-end without actual hardware. We can simulate by taking a known device’s identifiers. Alternatively, test the pieces:

  1. Create a dummy Jira ticket (in a test Jira project) with the description containing something like “User Alice requests to allow USB device with Vendor ID 0xXXXX, Product ID 0xYYYY, Serial 1234567” and mark that ticket as “Approved” (perhaps by setting a custom field or status to Approved).
  2. Then ask the agent: *“Allowlist the USB device from ticket JT-100”* (where JT-100 is that Jira ticket). The agent should:

     * Use Jira tool to fetch ticket JT-100 (we might need to implement a JiraGetIssue tool if not present).
     * Parse the device info from the ticket description (we might need to rely on the LLM’s ability to read the text; possibly we supply a regex or use a prompt asking it to extract vendor/product/serial).
     * Call the CreateDeviceAllowRuleTool with extracted info.
     * In confirmation mode, it would ask for confirmation before the final allow (since that’s a significant action).
     * Upon proceeding, check the SentinelOne console’s Device Control rules to see if the rule appeared. If we cannot easily check a real console, at least ensure our tool returned “success” and perhaps log the payload sent.
     * The agent should respond to user that the device was successfully allowlisted. Also it could update the Jira ticket (comment or transition it to “Completed”).

* *Edge Cases*: Test queries that mix contexts or are ambiguous:

  * *“Open a ticket for the latest threat.”* (Agent should identify the latest SentinelOne threat and create a Jira – tests that it picks the right threat if multiple.)
  * *“Allow the device now”* without context (if asked right after a conversation on a specific request, does the agent keep track? Likely it would if chat history is in memory. Otherwise, it should ask “which device?”).
  * *“Show me all Jira issues related to SentinelOne”* (if we tag created issues or mention SentinelOne in them, the agent could search Jira by keyword – ensure that’s possible).
  * If the user asks something outside scope (like “What is SentinelOne?”), the agent should ideally give a helpful answer (the LLM can answer from general knowledge: \*“SentinelOne is an endpoint protection platform...”). For now, that’s fine.

**Performance & Load Testing:**

* While not a heavy-load application, we might simulate multiple queries in quick succession to see if any part is a bottleneck. The database and external API calls are the main potential slow points. If using OpenAI API for LLM, ensure rate limits are not hit when the agent makes many calls (maybe throttle if needed).
* The junior engineer should also test what happens if SentinelOne API returns a lot of data (say 1000 threats). We should implement some limits or summarization: perhaps default the ListThreatsTool to a `limit=20` unless specified. The Swagger likely has a `limit` parameter (often default 20, max 1000). We can expose that in the tool input if needed.

**Validation Criteria:**

* **Accuracy**: Does the agent correctly use SentinelOne data? (No hallucination of threats that don’t exist; Jira tickets have correct details.)
* **Safety**: In confirmation mode, ensure the agent *never* executes an action without yes. Try saying “no” or “cancel” to a confirmation prompt – agent should acknowledge and not do it.
* **Idempotency**: If asked twice to allow the same device, the second time the agent might either notice it’s already allowed (the API might return 409 conflict, which in our tool we handle by returning “already allowlisted”). The agent could convey that to user. Similarly for creating tickets – ensure it doesn’t duplicate unless explicitly asked. Perhaps tag Jira issues or search if one already exists for a threat (in advanced version).
* **Integration**: Both Jira and SentinelOne parts work in tandem. We don’t break existing Jira-only functionality by adding SentinelOne. All Jira-related tests from the base project (like creating issues from user prompt) should still pass.
