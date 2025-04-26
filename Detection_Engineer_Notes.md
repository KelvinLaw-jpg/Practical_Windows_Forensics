# TCM Detection Engineer Notes

### Detection Enginnering Workflow

Information Gathering -> Unit Testing -> Alert Development -> Documentation Creation -> Peer Review / Handover

- Unit Testing: Confirms Alert Logic -> Repeatability -> Gap Identification -> Tool Validation
- Alert Development: Initial rule craft (broad: look at anything contain 'badURL.com') -> Final rule (Specific: look at incoming emails which contain any URL in the Malicious URL list containing 'badURL.com'
- Detection Documentation: Sigma, YAML - Splunk, TOML - Elastic (Tools: [uncoder.io](uncoder.io), [https://socprime.com/](https://socprime.com/))
- Handover: Peer review -> Incident Response team Handover -> Doc uploaded -> Alert Enable -> Ticket Close


Testing Tools: Splunk Attack Range, Atomic Red Team, AttackIQ, BloodHound, Caldera
