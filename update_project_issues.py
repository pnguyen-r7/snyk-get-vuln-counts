import argparse
import requests
import pprint
import logging
import shutil
import csv
import os

from tempfile import NamedTemporaryFile

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

# Snyk API base URL
API_BASE_URL = "https://api.snyk.io/v1"

# Organization ID
ORG_ID = "ce8dc694-7bb9-4388-ba7e-5636cc5d97cb"


def get_issue_severity_count_for_project(project_id, api_token):
    """
    Gets issue severity counts for a project ID.  Only looks for issues with issueType 'vuln'.  Ignores 'license' and
    'configuration' issue types.
    @param project_id: int, project id
    @param api_token: str, API token
    @return: dict, issue severity counts
    """
    logging.info(f"Getting severity counts for project_id \"{project_id}\"")
    # Endpoint URL for getting vulnerabilities for a project
    endpoint_url = f"{API_BASE_URL}/org/{ORG_ID}/project/{project_id}/aggregated-issues"

    logging.debug(f"ENDPOINT {endpoint_url}")

    # Headers for API requests
    headers = {
        "Authorization": f"token {api_token}",
        "Content-Type": "application/json"
    }

    body = {
        "includeDescription": "false",
        "includeIntroducedThrough": "false"
    }

    try:
        # Make GET request to Snyk API
        response = requests.post(endpoint_url, headers=headers, json=body)
        response.raise_for_status()  # Raise an exception for non-200 status codes

        # Parse response JSON
        response_body = response.json()

        severity = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Critical/High': 0
        }

        for issue in response_body['issues']:
            if issue['issueType'] == 'vuln':
                match issue['issueData']['severity']:
                    case 'critical':
                        severity['Critical'] += 1
                    case 'high':
                        severity['High'] += 1
                    case 'medium':
                        severity['Medium'] += 1
                    case 'low':
                        severity['Low'] += 1

        # Sum up critical & high issues
        severity['Critical/High'] = severity['Critical'] + severity['High']

        logging.info(f"Severity counts for project_id {project_id}: {pprint.pformat(severity)}")
        return severity

    except requests.exceptions.RequestException as e:
        logging.error(f"Error: {e}")
        raise


def main(csv_path, token):
    logging.info(f"CSV file: {os.path.abspath(csv_path)}")
    temp_file = NamedTemporaryFile(mode='w', delete=False)

    fields = ['name', 'id', 'team', 'domain', 'critical', 'high', 'medium', 'low', 'critical/high', 'ticket']

    with (open(csv_path, 'r') as csvfile, temp_file):
        reader = csv.DictReader(csvfile, fieldnames=fields)
        writer = csv.DictWriter(temp_file, fieldnames=fields)
        for row in reader:
            # Write headers to first row
            if row['name'] == 'name':
                writer.writeheader()
                continue
            logging.info(f"Updating csv for project {row['name']}")
            sevs = get_issue_severity_count_for_project(row['id'], token)
            row['critical'], row['high'], row['medium'], row['low'], row['critical/high'] = sevs['Critical'], sevs['High'], sevs['Medium'], sevs['Low'], sevs['Critical/High']
            writer.writerow(row)

    shutil.move(temp_file.name, csv_path)

    logging.info('Done')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', help='Path to CSV', required=True)
    parser.add_argument('-t', '--token', help='Snyk API Token.  Can be passed via argument or env variable')

    args = parser.parse_args()

    if os.environ.get('SnykToken'):
        args.token = os.environ['SnykToken']

    if not args.token:
        logging.fatal('Missing Snyk token!')
        exit(-1)

    main(args.path, args.token)
