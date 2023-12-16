# sla-tracking-and-delta-ignore

There are 2 scripts that are a work in progress:

1) SLA_tracking.py

This will output all issues matching your specified criticality threshold that are OLDER THAN 2 WEEKS - this can be changed in the code. Currently this only outputs 100 until pagination is implemented.

- Fork/clone the script locally, and add your own Github Org on line 6.
- Add your Snyk API Token to your systems environment variables, or, hardcode it (not recommended) on line line 8
- Run the script 'python SLA_tracking.py' 

2) ignore_test.py

This will output all ignores within an Org that were created in the UI. It will output all info including who created the ignore, time, issueID, etc. 

- Per above instructions, make sure you have SNYK_TOKEN in your env variables, or hardcode it on line 7
- Run the script 'python ignore_test.py' to print the results to console
- Add --baseline flag to the above command to set a baseline .json file which will save in current directory
- Run 'ptyon ignore_test.py --delta [filename.json] that was generated above to return only DELTA NEW IGNORES from the baseline specified above. 
