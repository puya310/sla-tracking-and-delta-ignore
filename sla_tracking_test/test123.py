import argparse
import requests
import json
import os
from datetime import datetime

api_key = os.environ.get("SNYK_TOKEN")
org_id = "0ebb9084-0c7b-4362-9a45-880e038d6284"
endpoint_url = f"https://api.snyk.io/rest/orgs/{org_id}/audit_logs/search?version=2023-12-14%7Ebeta&size=100&event=org.project.ignore.create"


# Function to fetch user details
def get_user_details(user_id, api_key):
    user_endpoint = f"https://api.snyk.io/rest/orgs/{org_id}/users/{user_id}?version=2023-12-14%7Ebeta"
    user_headers = {
        'Authorization': f"token {api_key}",
        'Accept': 'application/vnd.api+json; charset=utf-8'
    }
    user_response = requests.get(user_endpoint, headers=user_headers)

    if user_response.status_code == 200:
        user_data = user_response.json()
        attributes = user_data['data']['attributes']
        user_name = attributes.get('name')
        user_email = attributes.get('email')
        return {'name': user_name, 'email': user_email}
    else:
        print(f"Error fetching user details. Status code: {user_response.status_code}")
        return {'name': None, 'email': None}

# Function to format creation time
def format_creation_time(creation_time_iso):
    creation_time_utc = datetime.fromisoformat(creation_time_iso[:-1]).strftime('%B %d, %Y at %H:%M')
    return f"{creation_time_utc} ({creation_time_iso})"

# Function to load JSON from file
def load_json(file_path):
    try:
        with open(file_path, 'r') as json_file:
            return json.load(json_file)
    except FileNotFoundError:
        return []

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Process Snyk API data.')
parser.add_argument('--baseline', action='store_true', help='Generate baseline JSON file')
parser.add_argument('--delta', metavar='DELTA_JSON_PATH', help='Compare with specified delta JSON file')
args = parser.parse_args()

# API endpoint

def get_projects_page(base_url, next_url):

    # Add "next url" on to the BASE URL
    url = base_url + next_url

    headers = {
        'Accept': 'application/vnd.api+json',
        'Authorization': f'token {api_key}'
    }

    return requests.request("GET", url, headers=headers)

def get_ignores(org_id):
    base_url="https://api.snyk.io"
    next_url="/rest/orgs/{org_id}/audit_logs/search?version=2023-12-14%7Ebeta&size=100&event=org.project.ignore.create"
    all_projects = []
    while next_url is not None:
        response = get_projects_page(base_url, next_url).json()

        if 'next' in res['links']:
            next_url = res['links']['next']
        else:
            next_url = None

        # add to list
        all_projects.extend(res['data'])                    
    
    repo_dict = {}

    for project in all_projects:
        user_id = project['data']['items']['user_id']
        project_id = project['data']['project_id']

        repo_dict[repo] = {
            'user_id': user_id,
            'project_id': project_id,
        }

   

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
    # Parse the JSON response
        data = response.json()

    # List to store the results
        results_list = []

    # Extract information for each item in the response
        for item in data['data']['items']:
            user_id = item['user_id']
            issue_id = item['content']['issueId']
            project_id = item['project_id']
            creation_time_iso = item['created']
            reason_for_ignore = item['content']['reasonType']

        # Fetch user details
            user_details = get_user_details(user_id, api_key)

        # Format the CreationTime
            creation_time = format_creation_time(creation_time_iso)

        # Create a dictionary with the extracted information
            result = {
                'UserID': user_id,
                'Name': user_details['name'],
                'Email': user_details['email'],
                'IssueID': issue_id,
                'ProjectID': project_id,
                'CreationTime': creation_time,
                'ReasonForIgnore': reason_for_ignore
            }

        # Append the result to the list
            results_list.append(result)


# If --baseline flag is provided, write results to a baseline JSON file
    
    
    if args.baseline:
        baseline_file_name = 'test1.json'
        with open('test1.json', 'w') as json_file:
            json.dump(results_list, json_file, indent=2)
            print(f'Baseline JSON file created and saved as {baseline_file_name} - to compare for new ignores, run script with "--delta [filename]"')

    # If --delta flag is provided, compare with the specified delta JSON file
    elif args.delta:
        delta_json = load_json(args.delta)
        new_entries = [entry for entry in results_list if entry not in delta_json]
        if new_entries:
            print('New entries:')
            print(json.dumps(new_entries, indent=2))
        else:
            print('No new entries found.')

    # If no arguments provided, print the result in JSON format
    else:
        for result in results_list:
            print(json.dumps(result, indent=2))

else:
    # Print an error message if the request was not successful
    print(f"Error: Unable to fetch data. Status code: {response.status_code}")






def get_all_repos(org_id):
    base_url = "https://api.snyk.io/rest"

    next_url = f"/orgs/{org_id}/projects?version=2023-06-23&limit=100&origins=azure-repos"

    all_projects = []

    while next_url is not None:
        res = get_projects_page(base_url, next_url).json()

        if 'next' in res['links']:
            next_url = res['links']['next']
        else:
            next_url = None

        # add to list
        all_projects.extend(res['data'])

    repo_dict = {}

    for project in all_projects:
        repo = project['attributes']['name'].split(':')[0]
        # print(project['attributes']['name'])
        owner = repo.split('/')[0]

        name = repo.split('/')[1]
        if name.find('(') != -1:
            name = name[:name.find('(')]

        branch = project['attributes']['target_reference']
        repo_dict[repo] = {
            'owner': owner,
            'name': name,
            'branch': branch
        }
    
    return list(repo_dict.values())