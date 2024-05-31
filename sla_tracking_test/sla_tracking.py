import requests
from datetime import datetime, timedelta
import os

# Replace {org_id} with your actual organization ID
org_id = "put-org-id-here"
url = f"https://api.snyk.io/rest/orgs/{org_id}/issues?version=2023-12-14%7Ebeta&type=package_vulnerability&limit=100"
api_key=os.environ.get("SNYK_TOKEN")

# Make the API request

headers = {
    'Authorization': f"token {api_key}",
    'Accept': 'application/vnd.api+json'
}
response = requests.get(url, headers=headers)

# Check if the request was successful (status code 200)
if response.status_code == 200:
    try:
        # Parse the JSON response
        data = response.json().get('data', [])

        # Input severity level (low, medium, high, critical)
        selected_severity = input("Enter severity level (low, medium, high, critical): ").lower()

        # Iterate through each entry in the 'data' array
        for entry in data:
            try:
                issue_id = entry.get('id', 'N/A')
                title = entry['attributes']['title']
                created_at_str = entry['attributes']['created_at']
                severity_level = entry['attributes']['effective_severity_level'].lower()
                cwe = entry['attributes'].get('classes', [{}])[0].get('id', 'N/A')

                # Convert the 'created_at' string to a datetime object
                created_at = datetime.strptime(created_at_str, '%Y-%m-%dT%H:%M:%S.%fZ')

                # Calculate the current date and time
                current_datetime = datetime.now()

                # Check if the issue is more than 2 weeks old and matches the selected severity level
                if current_datetime - created_at > timedelta(weeks=2) and severity_level in ('low', 'medium', 'high', 'critical'):
                    if (selected_severity == 'low' and severity_level in ('low', 'medium', 'high', 'critical')) or \
                       (selected_severity == 'medium' and severity_level in ('medium', 'high', 'critical')) or \
                       (selected_severity == 'high' and severity_level in ('high', 'critical')) or \
                       (selected_severity == 'critical' and severity_level == 'critical'):
                        # Print the information in JSON format
                        print(f"{{\"issueID\": \"{issue_id}\", \"title\": \"{title}\", \"CWE\": \"{cwe}\", \"Severity\": \"{severity_level}\", \"createdAt\": \"{created_at_str}\"}}")
                else:
                    print(f"Issue does not match criteria: {title}")

            except KeyError as key_error:
                print(f"KeyError: {key_error}. Unable to extract data from the response.")

    except Exception as e:
        # Print an error message if the request was not successful
        print(f"Failed to fetch data. Error: {e}")
else:
    print(f"Failed to fetch data. Status code: {response.status_code}")

