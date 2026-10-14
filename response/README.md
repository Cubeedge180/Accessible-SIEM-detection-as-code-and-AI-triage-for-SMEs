# response/

SOAR-lite actions (block IP, disable account, isolate host, kill process).
The LLM can only propose an action that a playbook step allows; nothing runs
until a person approves it in the dashboard. Every approval and rejection is
logged with the alert id and time, which is what MTTR (alert to approved
response) is measured from.

Not implemented yet.
