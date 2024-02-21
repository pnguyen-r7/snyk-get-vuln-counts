# Get Snyk Vuln Counts

Python script to get issue counts by severity.  Script reads a csv file with project Ids and updates the csv file with 
updated severity counts.  Script gets all issues with issueType "Vuln".  IssueTypes with "license" or "configuration" 
are ignored.

## Requirements

- Python 3.11+
- Snyk API Token
- CSV file with list of project IDs (see ea_projects.csv as an example)

```bash
pip install -r requirements.txt
```

## Usage

```bash
python update_project_issues.py -h
usage: update_project_issues.py [-h] -p PATH [-t TOKEN]

options:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to CSV
  -t TOKEN, --token TOKEN
                        Snyk API Token. Can be passed via argument or env variable

```
#### Example 1

```bash
python update_project_issues.py -p ./csvs/mindseekers_projects.csv -t <TOKEN>
```

#### Example 2: Snyk API Token can be declared as an environmental variable "SnykToken".
```bash
export SnykToken=<MyToken>
python update_project_issues.py -p ./csvs/mindseekers_projects.csv
```
