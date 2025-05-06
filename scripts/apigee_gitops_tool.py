#!/usr/bin/env python3

import argparse
import base64
import json
import logging
import os
import sys
import time
from pathlib import Path
import binascii
import re

# Third-party libraries
import requests
from deepdiff import DeepDiff
import google.auth
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import DefaultCredentialsError
from tabulate import tabulate

# --- Configuration ---
APIGEE_API_BASE = "https://apigee.googleapis.com/v1"
API_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
JSON_SUFFIX = ".json"

# Global cache for app context: Maps local app ID (filename w/o .json) -> context
# Context: {"developerApiId": dev_uuid, "developerPathId": dev_email_or_id_for_path,
#           "appApiId": app_uuid_from_api, "appName": app_name_from_api_or_local}
# This cache is populated when listing developer_apps.
_DEVELOPER_APP_CONTEXT_CACHE = {}


RESOURCE_CONFIG = {
    "developers": {
        "scope": "org",
        "id_field_in_list": "email", # Local filename for developer is <dev_email>.json
        "list_wrapper_key": "developer",
        "sub_resource_type": "developer_apps", # Indicates developers have apps as sub-resources
        "sub_resource_id_for_path_key": "email" # Local path to apps: .../developers/<dev_email>/apps/
    },
    "apiproducts": {
        "scope": "org",
        "id_field_in_list": None, # API list is a simple array of product names
        "list_wrapper_key": None
    },
    "developer_apps": { # This type is processed as a sub-resource of 'developers'
        "scope": "org_nested_developer", # Special scope for apps under a developer
        "id_field_in_git": "appId",      # Local app filename is <appId_uuid>.json (IMPORTANT CHANGE)
        "id_field_in_api_list": "appId", # ID from GET .../developers/{devId}/apps (this API returns only appId)
        "api_list_wrapper_key": "app",   # Wrapper key in the per-developer app list response
    },
    "resourcefiles": {"scope": "env"},
    "flowhooks": {"scope": "env"},
    "references": {"scope": "env"},
    "targetservers": {"scope": "env"},
}

TOP_LEVEL_RESOURCE_TYPES = ["developers", "apiproducts", "resourcefiles", "flowhooks", "references", "targetservers"]
ALL_CONFIGURED_RESOURCE_TYPES = list(RESOURCE_CONFIG.keys())

RESOURCEFILE_TYPE_MAP = {
    "jsc": "jsc", "js": "jsc", "java": "java", "jar": "java", "wsdl": "wsdl",
    "xsd": "xsd", "xsl": "xsl", "py": "py", "node": "node", "zip": "node",
    "properties": "properties", "png": "png", "jpg": "jpg", "jpeg": "jpg",
    "gif": "gif", "json": "json", "xml": "xml",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)-8s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# --- Authentication ---
def get_access_token(key_file_path=None):
    credentials = None
    auth_method = "key file" if key_file_path else "ADC"
    try:
        if key_file_path:
            logging.info(f"Attempting auth via Service Account key: {key_file_path}")
            credentials = service_account.Credentials.from_service_account_file(key_file_path, scopes=API_SCOPES)
        else:
            logging.info("Attempting auth via Application Default Credentials (ADC)...")
            credentials, project_id = google.auth.default(scopes=API_SCOPES)
            logging.debug(f"ADC obtained for project: {project_id or 'N/A'}")
        logging.info(f"Authenticated successfully using {auth_method}.")
    except Exception as e:
        logging.error(f"Failed to obtain credentials via {auth_method}: {e}")
        sys.exit(1)
    try:
        if not credentials.valid:
            logging.debug("Refreshing credentials...")
            credentials.refresh(Request())
            logging.debug("Credentials refreshed.")
        return credentials.token
    except Exception as e:
        logging.error(f"Failed to refresh credentials or get token: {e}")
        sys.exit(1)

# --- API Interaction ---
def make_apigee_request(
    method, url, token, params=None, json_data=None, raw_data=None,
    content_type=None, expected_status=(200,)
):
    headers = {"Authorization": f"Bearer {token}"}
    data_payload = None
    if json_data is not None and raw_data is not None:
        raise ValueError("Cannot provide both json_data and raw_data for API request.")

    if json_data is not None:
        headers["Content-Type"] = "application/json"
        data_payload = json.dumps(json_data)
    elif raw_data is not None:
        headers["Content-Type"] = content_type or "application/octet-stream"
        data_payload = raw_data

    try:
        response = requests.request(method, url, headers=headers, params=params, data=data_payload)
        if response.status_code not in expected_status:
            logging.error(
                f"API Error: {method} {url} (Params: {params}) - Status: {response.status_code}\n"
                f"Response Body (first 500 chars): {response.text[:500]}"
            )
            if response.status_code == 404: logging.warning(f" -> Resource not found at URL: {url}")
            return None
        if response.status_code == 204 or not response.content: return {}

        url_parts = url.split('/')
        is_get_specific_resourcefile = (
            method == 'GET' and len(url_parts) > 7 and
            url_parts[-3] == 'resourcefiles' and url_parts[-1] != 'resourcefiles'
        )
        if is_get_specific_resourcefile: return response.content
        try: return response.json()
        except json.JSONDecodeError: return response.text
    except Exception as e:
        logging.error(f"Error during API call to {url}: {e}")
        return None

# --- Helper to build base API URL ---
def get_resource_base_url(org_id, resource_type, env_id=None, developer_api_id=None):
    scope_config = RESOURCE_CONFIG.get(resource_type)
    if not scope_config: raise ValueError(f"Config not found for: {resource_type}")
    scope = scope_config["scope"]

    if scope == "org":
        return f"{APIGEE_API_BASE}/organizations/{org_id}/{resource_type}"
    elif scope == "env":
        if not env_id: raise ValueError(f"env_id required for: {resource_type}")
        return f"{APIGEE_API_BASE}/organizations/{org_id}/environments/{env_id}/{resource_type}"
    elif scope == "org_nested_developer" and resource_type == "developer_apps":
        if not developer_api_id: raise ValueError("developer_api_id (UUID) required for developer_apps")
        return f"{APIGEE_API_BASE}/organizations/{org_id}/developers/{developer_api_id}/apps"
    else:
        raise ValueError(f"Unknown or unsupported scope '{scope}' for: {resource_type}")

# --- Resource Specific API Actions ---
def create_resource_in_apigee(org_id, resource_type, resource_id, local_data, token, env_id=None, developer_api_id=None):
    log_context = f"(Env: {env_id or 'N/A'}, Dev API ID: {developer_api_id or 'N/A'})"
    logging.info(f"Attempting CREATE for {resource_type}/{resource_id} {log_context}...")
    success = False

    if resource_type == "developer_apps":
        # resource_id is the appId (from local filename).
        # local_data is app config from <appId>.json, MUST contain 'name'.
        # developer_api_id is parent dev's UUID.
        if not developer_api_id:
            logging.error(f"[apps/{resource_id}] Developer API ID missing for app creation.")
            return False
        if "name" not in local_data:
            logging.error(f"[apps/{resource_id}] App 'name' missing in local JSON data for creation.")
            return False

        create_url = get_resource_base_url(org_id, resource_type, developer_api_id=developer_api_id)
        app_payload_for_api = local_data.copy() # Use the content of <appId>.json as payload

        response = make_apigee_request("POST", create_url, token, json_data=app_payload_for_api, expected_status=(200, 201))
        if response and response.get("appId"):
            returned_app_id = response.get("appId")
            app_name_created = response.get("name", local_data["name"]) # Prefer name from response
            logging.info(f" -> SUCCESS: Created app '{app_name_created}' with actual appId '{returned_app_id}' under developer UUID '{developer_api_id}'.")
            if resource_id != returned_app_id:
                 logging.warning(f"Local filename/ID '{resource_id}' differs from API returned appId '{returned_app_id}'. Ensure local filename is the server-generated appId for future syncs.")
            # Update cache with the actual returned appId and its context
            # Keyed by local filename ID (resource_id), storing actual API IDs and name.
            _DEVELOPER_APP_CONTEXT_CACHE[resource_id] = {
                "developerApiId": developer_api_id,
                "developerPathId": _DEVELOPER_APP_CONTEXT_CACHE.get(resource_id, {}).get("developerPathId", "unknown_dev_path"),
                "appApiId": returned_app_id,
                "appName": app_name_created
            }
            success = True
        else:
            success = False # make_apigee_request would have logged error
    elif resource_type == "resourcefiles":
        base_url = get_resource_base_url(org_id, resource_type, env_id)
        # ... (resourcefile creation logic - unchanged from previous correct version) ...
        if not isinstance(local_data, dict) or "content" not in local_data: logging.error(f"[{resource_type}/{resource_id}] Local JSON missing 'content'."); return False
        try: raw_content = base64.b64decode(local_data["content"])
        except Exception as e: logging.error(f"[{resource_type}/{resource_id}] Base64 decode error: {e}"); return False
        match = re.match(r".*\.([^.]+)", resource_id); file_ext = match.group(1).lower() if match else None
        api_type = RESOURCEFILE_TYPE_MAP.get(file_ext)
        if not api_type: logging.error(f"[{resource_type}/{resource_id}] Cannot map extension '{file_ext}'."); return False
        params = {"name": resource_id, "type": api_type}
        ct_map = {"jsc": "application/javascript","zip": "application/zip", "png": "image/png"}; inferred_ct = ct_map.get(file_ext, "application/octet-stream")
        response = make_apigee_request("POST", base_url, token, params=params, raw_data=raw_content, content_type=inferred_ct, expected_status=(200, 201))
        success = response is not None

    else: # Developers, API Products, other env-scoped JSON
        base_url = get_resource_base_url(org_id, resource_type, env_id)
        if not isinstance(local_data, dict):
            logging.error(f"[{resource_type}/{resource_id}] Local data for creation must be a JSON object."); return False
        payload_to_send = local_data.copy()
        if resource_type == "apiproducts" and payload_to_send.get("name") != resource_id:
            payload_to_send["name"] = resource_id
        elif resource_type == "developers" and payload_to_send.get("email") != resource_id:
            payload_to_send["email"] = resource_id
        response = make_apigee_request("POST", base_url, token, json_data=payload_to_send, expected_status=(200, 201))
        success = response is not None

    if success and resource_type != "developer_apps": logging.info(f" -> SUCCESS: Created {resource_type}/{resource_id}")
    elif not success and resource_type != "developer_apps": logging.error(f" -> FAILED: Could not create {resource_type}/{resource_id}")
    return success

def delete_resource_from_apigee(org_id, resource_type, resource_id, token, env_id=None, developer_api_id=None, app_api_id_for_delete=None):
    # For 'developer_apps', resource_id is local filename (<appId>.json), developer_api_id is Dev UUID,
    # app_api_id_for_delete is the app's own UUID.
    log_context = f"(Env: {env_id or 'N/A'}, Dev API ID: {developer_api_id or 'N/A'})"
    logging.info(f"Attempting DELETE for {resource_type}/{resource_id} {log_context}...")
    logging.debug(f"DEBUG: delete_resource_from_apigee received resource_id: '{resource_id}' for type '{resource_type}'")
    success = False; url_for_delete = None

    if resource_type == "resourcefiles":
        # ... (unchanged from previous correct version) ...
        env_base_url = get_resource_base_url(org_id, resource_type, env_id)
        match = re.match(r".*\.([^.]+)", resource_id); file_ext = match.group(1).lower() if match else None
        api_type = RESOURCEFILE_TYPE_MAP.get(file_ext)
        if not api_type: logging.error(f"[{resource_type}/{resource_id}] Cannot map extension for delete."); return False
        url_for_delete = f"{env_base_url}/{api_type}/{resource_id}"

    elif resource_type == "developer_apps":
        if not developer_api_id: logging.error(f"[apps/{resource_id}] Developer API ID missing for app deletion."); return False
        if not app_api_id_for_delete: logging.error(f"[apps/{resource_id}] App API ID for delete path missing."); return False
        base_apps_url = get_resource_base_url(org_id, resource_type, developer_api_id=developer_api_id)
        url_for_delete = f"{base_apps_url}/{app_api_id_for_delete}" # Use the app's true API ID (UUID)
        logging.info(f"  Constructed app delete URL: {url_for_delete}")
    elif resource_type == "developers":
        org_base_url = get_resource_base_url(org_id, resource_type)
        url_for_delete = f"{org_base_url}/{resource_id}" # resource_id is developer's email
    else:
        base_url = get_resource_base_url(org_id, resource_type, env_id)
        url_for_delete = f"{base_url}/{resource_id}"

    response = make_apigee_request("DELETE", url_for_delete, token, expected_status=(200, 204))
    success = response is not None
    if success: logging.info(f" -> SUCCESS: Deleted {resource_type}/{resource_id} (using API path ID for apps if different)")
    else: logging.error(f" -> FAILED: Could not delete {resource_type}/{resource_id} (URL: {url_for_delete})")
    return success

# --- Get Apigee/Local Lists & Details ---
def get_apigee_resource_list(org_id, resource_type, token, env_id=None, developer_api_id=None):
    """Fetches resource list. For 'developer_apps', returns set of appIds (UUIDs)."""
    base_url = get_resource_base_url(org_id, resource_type, env_id, developer_api_id)
    logging.debug(f"API List Fetch: {base_url}")
    response_data = make_apigee_request("GET", base_url, token)
    if response_data is None: return set()

    resource_ids = set() # This will store primary IDs (appId for apps, email for devs, etc.)
    config = RESOURCE_CONFIG[resource_type]
    # For developer_apps, id_field is "appId". For developers, it's "email".
    id_field_from_api = config.get("id_field_in_api_list") or config.get("id_field_in_list")
    wrapper_key = config.get("api_list_wrapper_key") or config.get("list_wrapper_key")

    try:
        if resource_type == "resourcefiles":
            for item in response_data.get("resourceFile", []):
                if item.get("name"): resource_ids.add(item.get("name"))
        elif resource_type == "references" and env_id:
            if isinstance(response_data, list): resource_ids.update(response_data)
            elif isinstance(response_data, dict) and "environmentReferences" in response_data:
                resource_ids.update(response_data.get("environmentReferences", []))
        elif id_field_from_api and wrapper_key: # developers, developer_apps
            item_list = response_data.get(wrapper_key, [])
            for item in item_list:
                if item.get(id_field_from_api): resource_ids.add(item.get(id_field_from_api))
        elif isinstance(response_data, list): # apiproducts, flowhooks, targetservers
            resource_ids.update(name for name in response_data if isinstance(name, str))
        else:
            logging.warning(f"[{resource_type}] Could not parse list. Unexpected structure: {str(response_data)[:200]}")

        log_context = f"(Env: {env_id or 'N/A'}, Dev API ID: {developer_api_id or 'N/A'})"
        logging.debug(f"Apigee Found ({resource_type}) {log_context}: {len(resource_ids)}")
        return resource_ids
    except Exception as e:
        logging.error(f"Error parsing Apigee {resource_type} list {log_context}: {e}\nData: {response_data}")
        return set()

def get_apigee_resource_detail(org_id, resource_type, resource_id, token, env_id=None, developer_api_id=None, app_api_id_for_detail=None):
    """
    Fetches and cleans resource detail.
    For 'developer_apps', resource_id is local filename (<appId>.json),
    developer_api_id is Dev UUID, app_api_id_for_detail is App UUID (same as resource_id if filenames are appIds).
    """
    url_for_get = None
    if resource_type == "developer_apps":
        if not developer_api_id: logging.error(f"[apps/{resource_id}] Dev API ID missing for app detail."); return None
        # If local filename IS the appId, then app_api_id_for_detail is same as resource_id.
        # This ensures we use the true API ID (UUID) for the GET path.
        actual_app_api_id = app_api_id_for_detail or resource_id
        base_apps_url = get_resource_base_url(org_id, resource_type, developer_api_id=developer_api_id)
        url_for_get = f"{base_apps_url}/{actual_app_api_id}"
    else:
        base_url = get_resource_base_url(org_id, resource_type, env_id) # Dev API ID not used for non-nested
        url_for_get = f"{base_url}/{resource_id}" # resource_id is dev_email, product_name etc.

    logging.debug(f"API Detail Fetch: {url_for_get} (for {resource_type})")
    response_data = make_apigee_request("GET", url_for_get, token)
    if response_data is None: return None

    if isinstance(response_data, bytes): return response_data
    elif isinstance(response_data, dict):
        for key in ["lastModifiedBy", "createdBy", "lastModifiedAt", "createdAt", "lastModified", "created"]:
            response_data.pop(key, None)
        if resource_type == "developer_apps":
            response_data.pop("status", None); response_data.pop("appFamily", None)
            # Do NOT pop 'developerId' or 'appId' from app detail, they are useful context.
            # 'name' is also important.
        elif resource_type == "developers":
            response_data.pop("apps", None); response_data.pop("companies", None)
        elif resource_type == "targetservers":
            if 'port' in response_data and isinstance(response_data['port'], int):
                response_data['port'] = str(response_data['port'])
        return response_data
    else:
        return response_data

def get_local_resource_list(base_path, org_id, resource_type, env_id=None, developer_path_id=None):
    scope_config = RESOURCE_CONFIG.get(resource_type);
    if not scope_config: raise ValueError(f"Config missing for {resource_type}")
    scope = scope_config["scope"]; resource_type_path = None; path_desc = resource_type

    if scope == "org":
        resource_type_path = Path(base_path) / org_id / resource_type
    elif scope == "env":
        if not env_id: raise ValueError(f"env_id required for {resource_type}")
        resource_type_path = Path(base_path) / org_id / "environments" / env_id / resource_type
        path_desc = f"environments/{env_id}/{resource_type}"
    elif scope == "org_nested_developer" and resource_type == "developer_apps":
        if not developer_path_id: raise ValueError("developer_path_id required for developer_apps")
        resource_type_path = Path(base_path) / org_id / "developers" / developer_path_id / "apps"
        path_desc = f"developers/{developer_path_id}/apps"
    else: raise ValueError(f"Unsupported scope/type for local list: {scope}/{resource_type}")

    logging.debug(f"Scanning local directory: {resource_type_path}")
    local_ids = set()
    if not resource_type_path.is_dir(): logging.debug(f"Local directory not found: {resource_type_path}"); return local_ids
    try:
        for item in resource_type_path.iterdir():
            if item.is_file() and item.name.endswith(JSON_SUFFIX):
                resource_id = item.name[: -len(JSON_SUFFIX)] # This is appId for apps, email for devs
                if resource_id: local_ids.add(resource_id)
        logging.debug(f"Local Found ({path_desc}): {len(local_ids)}")
        return local_ids
    except OSError as e: logging.error(f"Error scanning local {resource_type_path}: {e}"); return set()

def get_local_resource_detail(base_path, org_id, resource_type, resource_id, env_id=None, developer_path_id=None):
    scope_config = RESOURCE_CONFIG.get(resource_type); # ... (similar path construction as get_local_resource_list)
    scope = scope_config["scope"]; expected_file = None
    if scope == "org": expected_file = Path(base_path)/org_id/resource_type/f"{resource_id}{JSON_SUFFIX}"
    elif scope == "env": expected_file = Path(base_path)/org_id/"environments"/env_id/resource_type/f"{resource_id}{JSON_SUFFIX}"
    elif scope == "org_nested_developer" and resource_type == "developer_apps":
        expected_file = Path(base_path)/org_id/"developers"/developer_path_id/"apps"/f"{resource_id}{JSON_SUFFIX}"
    else: raise ValueError(f"Unsupported scope/type for local detail: {scope}/{resource_type}")

    logging.debug(f"Reading local detail from: {expected_file}")
    if not expected_file or not expected_file.is_file(): logging.warning(f"Local file not found: {expected_file}"); return None
    try: content = expected_file.read_text(encoding="utf-8"); return json.loads(content)
    except Exception as e: logging.error(f"Error reading/parsing {expected_file}: {e}"); return None


# --- App Context Cache Population (used by developer_apps processing) ---
def _populate_developer_app_context_cache(org_id, developer_api_id, developer_path_id, token):
    global _DEVELOPER_APP_CONTEXT_CACHE
    apps_config = RESOURCE_CONFIG["developer_apps"]
    # URL to list apps for a specific developer
    apps_url = get_resource_base_url(org_id, "developer_apps", developer_api_id=developer_api_id)
    logging.debug(f"Fetching apps for developer API ID '{developer_api_id}' (Path ID: {developer_path_id}) from {apps_url}")
    response_data = make_apigee_request("GET", apps_url, token)

    if logging.getLogger().isEnabledFor(logging.DEBUG):
        try: response_str = json.dumps(response_data, indent=2) if response_data is not None else "None"
        except TypeError: response_str = str(response_data)
        logging.debug(f"DEBUG: Raw response for developer apps list (Dev API ID: {developer_api_id}):\n{response_str}")

    # This will store appIds (UUIDs) for this developer
    app_ids_for_this_developer = set()
    if response_data and isinstance(response_data.get(apps_config["api_list_wrapper_key"]), list):
        for app_data_item in response_data.get(apps_config["api_list_wrapper_key"], []):
            # The per-dev app list API returns only 'appId'
            app_api_id_from_list = app_data_item.get(apps_config["id_field_in_api_list"]) # This should be 'appId'
            app_name_from_api = app_data_item.get("name") # API GET .../devs/.../apps doesn't return name!

            if app_api_id_from_list:
                app_ids_for_this_developer.add(app_api_id_from_list)
                # Cache entry: key is appId (UUID). Value contains context.
                # We don't have appName from this list API. It would be fetched during Get Detail if needed.
                _DEVELOPER_APP_CONTEXT_CACHE[app_api_id_from_list] = {
                    "developerApiId": developer_api_id,
                    "developerPathId": developer_path_id,
                    "appApiId": app_api_id_from_list,
                    "appName": app_name_from_api or "Unknown (Name not in list API)" # Placeholder
                }
            else:
                logging.warning(f"[apps] App data entry missing '{apps_config['id_field_in_api_list']}' (expected appId) for dev API ID {developer_api_id}. Data: {app_data_item}")

    logging.debug(f"DEBUG: App IDs extracted for Dev API ID {developer_api_id}: {app_ids_for_this_developer}")
    return app_ids_for_this_developer


# --- Compare and Apply for a Single Developer's Apps ---
def compare_and_apply_single_developer_apps(
    base_path, org_id, token, developer_path_id, developer_api_id, apply_changes
):
    res_type = "developer_apps" # Use the conceptual type from RESOURCE_CONFIG
    logging.info(f"--- Comparing Apps for Developer Path: '{developer_path_id}' (API ID: '{developer_api_id}') ---")
    type_differences_found = False; type_apply_errors = False
    table_data = []; table_headers = ["App ID (Filename)", "App Name (from Detail)", "Exists in Git", "Exists in Apigee", "Status"]

    # Get Apigee app list (set of appIds) for this developer & populate cache
    apigee_app_ids = _populate_developer_app_context_cache(org_id, developer_api_id, developer_path_id, token)
    # Get local app list (set of appIds from filenames like <appId>.json)
    local_app_ids = get_local_resource_list(base_path, org_id, res_type, developer_path_id=developer_path_id)

    all_app_ids_for_dev = sorted(list(local_app_ids.union(apigee_app_ids)))
    if not all_app_ids_for_dev:
        logging.info(f"[apps for {developer_path_id}] No apps found locally or in Apigee for this developer.")
        return False, False, "No apps found for this developer."

    apps_only_in_local = local_app_ids - apigee_app_ids
    apps_only_in_apigee = apigee_app_ids - local_app_ids
    if apps_only_in_local or apps_only_in_apigee: type_differences_found = True

    # Deletes
    deleted_apps_ok, deleted_apps_fail = set(), set()
    if apply_changes and apps_only_in_apigee:
        logging.info(f"[apps for {developer_path_id}] Applying DELETES for {len(apps_only_in_apigee)} apps...")
        for app_id_to_delete in sorted(list(apps_only_in_apigee)): # app_id_to_delete is an appId (UUID)
            # For delete_resource_from_apigee: resource_id is the local key (appId),
            # developer_api_id is dev UUID, app_api_id_for_delete is app UUID.
            if delete_resource_from_apigee(org_id, res_type, app_id_to_delete, token,
                                           developer_api_id=developer_api_id,
                                           app_api_id_for_delete=app_id_to_delete): # Pass appId for both
                deleted_apps_ok.add(app_id_to_delete)
            else: deleted_apps_fail.add(app_id_to_delete); type_apply_errors = True
        logging.info(f"[apps for {developer_path_id}] Delete Results: {len(deleted_apps_ok)} OK, {len(deleted_apps_fail)} FAIL.")
    elif apps_only_in_apigee:
        logging.warning(f"[apps for {developer_path_id}] Found {len(apps_only_in_apigee)} apps only in Apigee (Potential Deletes).")

    # Creates
    created_apps_ok, created_apps_fail = set(), set()
    if apply_changes and apps_only_in_local:
        logging.info(f"[apps for {developer_path_id}] Applying CREATES for {len(apps_only_in_local)} apps...")
        for app_id_from_filename in sorted(list(apps_only_in_local)): # This is the appId (UUID) from local filename
            local_app_data = get_local_resource_detail(base_path, org_id, res_type, app_id_from_filename, developer_path_id=developer_path_id)
            if local_app_data is None:
                logging.error(f"[apps/{app_id_from_filename}] Cannot read local data for create. Skipping."); created_apps_fail.add(app_id_from_filename); type_apply_errors = True; continue
            if "name" not in local_app_data: # App POST payload requires a 'name'
                logging.error(f"[apps/{app_id_from_filename}] Local JSON data missing 'name' field for app creation. Skipping."); created_apps_fail.add(app_id_from_filename); type_apply_errors = True; continue

            # For create_resource_in_apigee: resource_id is local key (appId), local_data is app config,
            # developer_api_id is dev UUID.
            if create_resource_in_apigee(org_id, res_type, app_id_from_filename, local_app_data, token, developer_api_id=developer_api_id):
                created_apps_ok.add(app_id_from_filename)
            else: created_apps_fail.add(app_id_from_filename); type_apply_errors = True
        logging.info(f"[apps for {developer_path_id}] Create Results: {len(created_apps_ok)} OK, {len(created_apps_fail)} FAIL.")
    elif apps_only_in_local:
        logging.warning(f"[apps for {developer_path_id}] Found {len(apps_only_in_local)} apps only in Git (Potential Creates).")

    # Content Comparison
    current_apigee_app_ids = apigee_app_ids
    if apply_changes and (deleted_apps_ok or created_apps_ok or deleted_apps_fail or created_apps_fail):
        logging.info(f"[apps for {developer_path_id}] Re-fetching app list after apply actions...")
        time.sleep(0.5)
        current_apigee_app_ids = _populate_developer_app_context_cache(org_id, developer_api_id, developer_path_id, token)

    common_app_ids = local_app_ids.intersection(current_apigee_app_ids)
    mismatched_content, comparison_errors = set(), set()
    logging.info(f"[apps for {developer_path_id}] Comparing content for {len(common_app_ids)} common apps...")

    for app_id in sorted(list(common_app_ids)): # app_id is UUID
        if app_id in created_apps_fail: continue
        local_detail = get_local_resource_detail(base_path, org_id, res_type, app_id, developer_path_id=developer_path_id)
        # For get_apigee_resource_detail: resource_id is local key (appId), developer_api_id is dev UUID,
        # app_api_id_for_detail is app UUID (same as app_id here).
        apigee_detail = get_apigee_resource_detail(org_id, res_type, app_id, token,
                                                  developer_api_id=developer_api_id,
                                                  app_api_id_for_detail=app_id)
        if local_detail is None or apigee_detail is None:
            logging.error(f"[apps/{app_id}] Cannot compare content due to fetch/read errors."); comparison_errors.add(app_id); type_differences_found = True; continue

        # Update appName in cache from detail if it was "Unknown"
        if isinstance(apigee_detail, dict) and apigee_detail.get("name"):
             if app_id in _DEVELOPER_APP_CONTEXT_CACHE:
                 _DEVELOPER_APP_CONTEXT_CACHE[app_id]["appName"] = apigee_detail.get("name")


        cleaned_apigee_detail = apigee_detail.copy() if isinstance(apigee_detail, dict) else {}
        if isinstance(cleaned_apigee_detail, dict):
            # App specific cleanup for diff against local POST payload:
            # Local JSON for an app (<appId>.json) is what we'd POST.
            # API GET response for an app contains more fields (appId, developerId, status etc.)
            # We should compare local_detail against what the relevant parts of API GET are.
            cleaned_apigee_detail.pop('appId', None) # Not in POST payload
            cleaned_apigee_detail.pop('developerId', None) # Not in POST payload
            # If local_detail (POST payload) doesn't manage credentials, but API returns some, exclude.
            if 'credentials' not in local_detail and 'credentials' in cleaned_apigee_detail:
                logging.debug(f"[apps/{app_id}] Ignoring 'credentials' from Apigee detail for diff as not in local.")
                cleaned_apigee_detail.pop('credentials')

        detailed_diff = DeepDiff(local_detail, cleaned_apigee_detail, ignore_order=True, report_repetition=True, verbose_level=0)
        if detailed_diff:
            app_name_for_log = _DEVELOPER_APP_CONTEXT_CACHE.get(app_id,{}).get("appName", app_id)
            logging.warning(f"[apps/{app_name_for_log} (ID: {app_id})] Mismatch found.")
            if logging.getLogger().isEnabledFor(logging.DEBUG): logging.debug(f"Differences for app {app_name_for_log}:\n{detailed_diff}")
            mismatched_content.add(app_id); type_differences_found = True

    # Populate table_data for this developer's apps
    for app_id in all_app_ids_for_dev: # app_id is the UUID (filename)
        app_name_display = _DEVELOPER_APP_CONTEXT_CACHE.get(app_id, {}).get("appName", app_id)
        exists_git = app_id in local_app_ids
        exists_api = app_id in current_apigee_app_ids
        status = "Unknown"
        # ... (status logic - largely unchanged, use app_id for set lookups) ...
        if exists_git and exists_api:
            if app_id in mismatched_content: status = "Mismatch (Content)"
            elif app_id in comparison_errors: status = "Error Comparing"
            elif app_id in created_apps_ok : status = "CREATED (Now In Sync)"
            else: status = "In Sync"
        elif exists_git and not exists_api: # Only in Git
            if app_id in created_apps_fail: status = "Only in Git (Create FAILED)"
            else: status = "Only in Git (Potential Create)"
        elif not exists_git and exists_api: # Only in Apigee
            if app_id in deleted_apps_fail: status = "Only in Apigee (Delete FAILED)"
            else: status = "Only in Apigee (Potential Delete)"
        elif not exists_git and not exists_api: # Not in either (final state)
            if app_id in deleted_apps_ok: status = "DELETED (Sync OK)"
            else: status = "Not Present (Sync OK)"

        table_data.append([app_id, app_name_display, "Yes" if exists_git else "No", "Yes" if exists_api else "No", status])

    return type_differences_found, type_apply_errors, tabulate(table_data, headers=table_headers, tablefmt="grid")


# --- Main Comparison and Apply Orchestrator ---
def compare_and_apply_resources(
    base_path, org_id, token, types_to_process, apply_changes=False, target_env_id=None
):
    # ... (initial logging and apply_changes warning - unchanged) ...
    logging.info(f"Starting Main Comparison for Org: {org_id} (Target Env for env-scoped: {target_env_id or 'N/A'})")
    if apply_changes:
        logging.warning("=" * 30 + " APPLY MODE ENABLED " + "=" * 30); time.sleep(4) # ... (full warning)
    global _DEVELOPER_APP_CONTEXT_CACHE; _DEVELOPER_APP_CONTEXT_CACHE.clear()
    overall_summary_tables = {}; overall_differences_found = False; overall_apply_errors = False

    for res_type in types_to_process: # types_to_process contains TOP_LEVEL_RESOURCE_TYPES
        config = RESOURCE_CONFIG[res_type]
        scope = config["scope"]
        current_env_id = target_env_id if scope == "env" else None

        if scope == "env" and not target_env_id:
             logging.info(f"--- Skipping Env-Scoped Type: {res_type} (No --env specified) ---")
             overall_summary_tables[res_type] = "Skipped (Env-scoped, but no --env specified)"
             continue

        logging.info(f"--- Processing Top-Level Resource Type: {res_type} (Scope: {scope}, Env: {current_env_id or 'N/A'}) ---")
        # Placeholder for actual top-level resource processing (developers.json, apiproduct.json etc.)
        # For this example, we focus on the developer -> apps nesting.
        # Assume parent_diffs_found, parent_apply_errors are results of processing the top-level items.
        parent_diffs_found, parent_apply_errors = False, False # Simulate results
        parent_table_data, parent_table_headers = [], ["Resource Name", "Exists in Git", "Exists in Apigee", "Status"]

        apigee_parent_ids = get_apigee_resource_list(org_id, res_type, token, current_env_id)
        local_parent_ids = get_local_resource_list(base_path, org_id, res_type, current_env_id)
        all_parent_ids_to_process = sorted(list(local_parent_ids.union(apigee_parent_ids)))

        if not all_parent_ids_to_process:
            logging.info(f"[{res_type}] No resources found locally or in Apigee.")
            overall_summary_tables[res_type] = f"No {res_type} found."
            if config.get("sub_resource_type"):
                 overall_summary_tables[f"{config['sub_resource_type']} (under {res_type})"] = f"No parent {res_type} found."
            continue

        for parent_id in all_parent_ids_to_process: # e.g., developer_email for developers
            # --- Simulate processing the parent resource (e.g., developer.json) ---
            # Actual create/delete/compare of parent_id (developer.json) would happen here.
            # This example focuses on the sub-resource (apps) logic.
            # For simplicity, we just add a row to the parent table.
            parent_exists_git = parent_id in local_parent_ids
            parent_exists_api = parent_id in apigee_parent_ids
            parent_status = "Processed (Parent Diff Omitted)" # Placeholder
            # (Logic to determine actual parent_status based on its C/D/Compare would be here)
            parent_table_data.append([parent_id, "Yes" if parent_exists_git else "No", "Yes" if parent_exists_api else "No", parent_status])
            # --- End of simulated parent processing ---

            # If this top-level resource type has sub-resources (developers -> developer_apps)
            if config.get("sub_resource_type") == "developer_apps" and res_type == "developers":
                developer_path_id = parent_id # This is dev_email, used for local path
                developer_api_id_for_apps = None # This is dev_UUID, for API calls

                # Get the developer's API UUID if they exist in Apigee or were just created
                if parent_exists_api: # Developer exists in Apigee
                    dev_detail = get_apigee_resource_detail(org_id, "developers", developer_path_id, token)
                    if dev_detail and dev_detail.get("developerId"):
                        developer_api_id_for_apps = dev_detail["developerId"]
                elif parent_exists_git and apply_changes: # Developer was local-only and might have been created
                    # Attempt to re-fetch to get API ID if just created
                    logging.info(f"Dev '{developer_path_id}' might be newly created. Fetching detail for API ID...")
                    time.sleep(0.5)
                    dev_detail_after_create = get_apigee_resource_detail(org_id, "developers", developer_path_id, token)
                    if dev_detail_after_create and dev_detail_after_create.get("developerId"):
                        developer_api_id_for_apps = dev_detail_after_create["developerId"]

                if not developer_api_id_for_apps:
                    logging.warning(f"Could not determine API ID for developer '{developer_path_id}'. Skipping their apps.")
                    overall_summary_tables[f"Apps for Dev: {developer_path_id}"] = f"Skipped (Dev API ID not found for '{developer_path_id}')"
                    continue # Skip to next developer

                # Process apps for this developer
                app_diffs, app_errors, app_table_str = compare_and_apply_single_developer_apps(
                    base_path, org_id, token,
                    developer_path_id=developer_path_id,
                    developer_api_id=developer_api_id_for_apps,
                    apply_changes=apply_changes
                )
                overall_summary_tables[f"Apps for Dev: {developer_path_id}"] = app_table_str
                if app_diffs: overall_differences_found = True
                if app_errors: overall_apply_errors = True

        overall_summary_tables[res_type] = tabulate(parent_table_data, headers=parent_table_headers, tablefmt="grid")
        # Update overall flags based on parent_diffs_found, parent_apply_errors
        if parent_diffs_found: overall_differences_found = True
        if parent_apply_errors: overall_apply_errors = True
        logging.info(f"--- Finished Processing Top-Level Type: {res_type} ---")
        print("\n")

    # Final Summary Output and Exit Code Logic
    # ... (unchanged from previous correct version) ...
    print("\n" + "=" * 80 + "\n" + " " * 25 + "Final Comparison & Apply Summary" + "\n" + "=" * 80)
    for res_type_key, table_str in overall_summary_tables.items():
        print(f"\n=== Summary for: {res_type_key} ===\n{table_str}\n")
    final_exit_code = 0
    if apply_changes:
        if overall_apply_errors: logging.error("Overall Status: Apply actions completed WITH ERRORS."); final_exit_code = 1
        elif overall_differences_found: logging.warning("Overall Status: Apply (Creates/Deletes) OK, but CONTENT MISMATCHES or other diffs remain."); final_exit_code = 1
        else: logging.info("Overall Status: Apply actions completed successfully.")
    else:
        if overall_differences_found: logging.warning("Overall Status: Differences DETECTED (Apply mode OFF)."); final_exit_code = 1
        else: logging.info("Overall Status: No differences found.")
    return final_exit_code


# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Manages Apigee configurations using a GitOps approach.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-o", "--org", required=True, help="Apigee Organization ID.")
    parser.add_argument("-e", "--env", required=False, help="Apigee Environment ID for env-scoped resources.")
    parser.add_argument("-k", "--keyfile", required=False, help="Path to Service Account JSON key file.")
    parser.add_argument("-p", "--path", required=True, help="Path to root of local GitOps repository.")
    parser.add_argument("-t", "--resource-type", required=False, choices=TOP_LEVEL_RESOURCE_TYPES,
                        help=f"Specific top-level resource type. Choices: {', '.join(TOP_LEVEL_RESOURCE_TYPES)}")
    parser.add_argument("--ensure-git-state", action="store_true", help="Enable Apply Mode (Creates/Deletes). USE WITH CAUTION.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG level logging.")

    args = parser.parse_args()
    # ... (logging setup, path validation, token - unchanged) ...
    if args.verbose: logging.getLogger().setLevel(logging.DEBUG)
    else: logging.getLogger().setLevel(logging.INFO)
    logging.debug("Verbose logging enabled.")
    if not os.path.isdir(args.path): logging.error(f"Repo path invalid: {args.path}"); sys.exit(2)
    access_token = get_access_token(args.keyfile)

    process_these_top_level_types = []
    # ... (Logic to determine process_these_top_level_types based on args.resource_type and args.env - unchanged) ...
    if args.resource_type:
        specified_type_scope = RESOURCE_CONFIG[args.resource_type]["scope"]
        if args.env and specified_type_scope != "env":
             logging.error(f"Error: Type '{args.resource_type}' is not env-scoped but --env ('{args.env}') was given."); sys.exit(2)
        if not args.env and specified_type_scope == "env":
             logging.error(f"Error: Type '{args.resource_type}' is env-scoped but --env was not given."); sys.exit(2)
        process_these_top_level_types = [args.resource_type]
        logging.info(f"Targeting specific top-level resource type: {args.resource_type}")
    elif args.env:
        process_these_top_level_types = [rt for rt in TOP_LEVEL_RESOURCE_TYPES if RESOURCE_CONFIG[rt]["scope"] == "env"]
        logging.info(f"Targeting environment-scoped resources for env '{args.env}': {process_these_top_level_types}")
    else:
        process_these_top_level_types = [rt for rt in TOP_LEVEL_RESOURCE_TYPES if RESOURCE_CONFIG[rt]["scope"] == "org"]
        logging.info(f"Targeting organization-scoped resources: {process_these_top_level_types}")

    if not process_these_top_level_types:
        logging.info("No top-level resource types selected for processing. Exiting."); sys.exit(0)


    exit_code = compare_and_apply_resources(
        base_path=args.path, org_id=args.org, token=access_token,
        types_to_process=process_these_top_level_types,
        apply_changes=args.ensure_git_state, target_env_id=args.env
    )
    sys.exit(exit_code)