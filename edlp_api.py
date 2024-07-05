#!/usr/bin/python

"""
Author: Adam Nye
Email: adam@spoontech.biz
Date: 26/06/2024
Description: Script to fetch incidents and assignee information from Palo Alto Networks eDLP API and save the details to a CSV file.
"""

import requests
import json
import re
import csv
from requests.auth import HTTPBasicAuth

# Update with required creds
csv_file_path = 'output.csv'
client_id = 'client@creds'
client_secret = 'super_secret'
token_endpoint = 'https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token'
api_endpoint = 'https://api.dlp.paloaltonetworks.com'
tsig = '1234567890'

# Define the proxy dictionary
proxies = {
    'http': 'http://127.0.0.1:8888',
    'https': 'http://127.0.0.1:8888',
}

def match_field_regex(data, field_pattern):
    matches = []
    pattern = re.compile(field_pattern.replace('*', '[^.]*'))  # Convert wildcard pattern to regex pattern

    def traverse(obj, parent_key=''):
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{parent_key}.{key}" if parent_key else key
                if pattern.fullmatch(full_key):
                    matches.append(value)
                traverse(value, full_key)
        elif isinstance(obj, list):
            for index, item in enumerate(obj):
                full_key = f"{parent_key}[{index}]"
                traverse(item, full_key)

    traverse(data)
    return matches

def get_access_token(token_endpoint, client_id, client_secret, tsig):
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'tsg_id:' + tsig
    }

    token_response = requests.post(token_endpoint, data=token_data)

    try:
        token_response = requests.post(token_endpoint, data=token_data, proxies=proxies)
        token_response.raise_for_status()
        access_token = token_response.json().get('access_token')
        if access_token:
            print('Token successfully retrieved')
            return access_token
        else:
            print('Failed to obtain access token.')
            return None
    except requests.RequestException as e:
        print(f'Error fetching access token: {e}')
        return None

def get_assignees(api_endpoint, access_token):
    url = api_endpoint + '/v1/api/incidents/assignee'
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }

    response = requests.get(url, headers=headers, proxies=proxies)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve assignees. Status code: {response.status_code}")
        return None

def get_incidents(api_endpoint, access_token):
    url = api_endpoint + "/v2/api/incidents?page_size=10&region=au"
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }

    response = requests.get(url, headers=headers, proxies=proxies)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve incidents. Status code: {response.status_code}")
        return None

def read_existing_lines(csv_file_path):
    existing_lines = set()
    try:
        with open(csv_file_path, 'r', newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                existing_lines.add(tuple(row))
    except FileNotFoundError:
        # If the file doesn't exist, we assume there are no existing lines
        pass
    return existing_lines

def process_incidents(api_endpoint, access_token, csv_file_path):
    incidents = get_incidents(api_endpoint, access_token)

    if not incidents:
        print("No incidents retrieved.")
        return

    existing_lines = read_existing_lines(csv_file_path)

    with open(csv_file_path, 'a', newline='') as file:
        writer = csv.writer(file)

        if not existing_lines:
            writer.writerow(["Incident ID", "Report ID", "Data Profile Name", "File Name", "User", "Source", "Action", "Date_Time", "Direction", "Application Name", "URL", "Assignee", "Data Patterns"])

        for incident in incidents.get('resources', []):
            incident_id = incident['incident_id']
            incident_url = f"{api_endpoint}/v2/api/incidents/{incident_id}?region=au"
            headers = {
                'Accept': 'application/json',
                'Authorization': 'Bearer ' + access_token
            }

            incident_detail_response = requests.get(incident_url, headers=headers, proxies=proxies)

            if incident_detail_response.status_code == 200:
                json_output = incident_detail_response.json()

                field_pattern = 'match_info.*.name'
                field_matches = match_field_regex(json_output, field_pattern)

                assignee_id = json_output.get('assignee_id', 'None')

                line = [
                    incident_id,
                    json_output.get('report_id', 'N/A'),
                    json_output.get('data_profile_name', 'N/A'),
                    json_output.get('file_name', 'N/A'),
                    json_output.get('user', 'N/A'),
                    json_output.get('source', 'N/A'),
                    json_output.get('action', 'N/A'),
                    json_output.get('incident_creation_time', 'N/A'),
                    json_output.get('direction', 'N/A'),
                    json_output.get('app_name', 'N/A'),
                    json_output.get('url', 'N/A'),
                    assignee_id,
                    ','.join(field_matches)
                ]

                if tuple(line) not in existing_lines:
                    writer.writerow(line)
                    print("Incident added to CSV...")
                else:
                    print("Incident already existed in CSV...")
            else:
                print(f"Failed to retrieve details for incident {incident_id}. Status code: {incident_detail_response.status_code}")

if __name__ == '__main__':
    access_token = get_access_token(token_endpoint, client_id, client_secret, tsig)
    if access_token:
        process_incidents(api_endpoint, access_token, csv_file_path)
