# Fix Verification Retester

A Burp Suite extension for saving and re-testing security fix verification cases against the same target endpoint. It helps security testers confirm whether a fix is effective by replaying captured requests and asserting the expected secure-state behavior.

This project targets the legacy Jython Extender API used by Burp Suite and is designed for workflows such as:

- Re-testing a single request after a patch
- Validating a privilege-escalation fix across multiple steps
- Checking OTP rate limiting with bounded attempts
- Verifying response-manipulation or chained security cases

## What this tool does

The extension adds a tab named `Fix Retester` in Burp and exposes context menu actions in the Repeater tool.

From a selected request in Repeater, you can:

- Save a request as a fix-verification test case
- Define a secure-state assertion for that request
- Retest all saved cases
- Chain multiple requests for sequential security checks
- Export a text report of the results

Saved cases are stored locally in your user profile at:

- `~/.burp_fix_verification_cases.json`

## Features

### Single request retesting

Save a request and specify an expected secure-state condition, such as:

- `status == 403`
- `body not_contains "UNIQUE_MARKER"`
- `response contains "token"`
- `header["X-Header"] not_contains "debug"`

The extension will replay the request and evaluate whether the assertion still holds.

### Chained security checks

The extension supports three chain types:

1. Privilege escalation (sequential requests)
2. OTP brute force (bounded attempts)
3. OTP bypass / response-manipulation follow-up

These can be built from a series of requests captured in Repeater and re-run to confirm that a bug remains fixed across multiple user states or actions.

### OTP rate-limit validation

For rate-limiting checks, the extension can:

- Replace a literal `{{OTP}}` value
- Try a bounded sequence of OTP values
- Detect a configured HTTP rate-limit status or marker text
- Report whether the fix appears effective or still vulnerable

### Reporting

The extension can export a detailed report highlighting:

- test case name
- check type
- target URL
- HTTP result
- assertion details
- step-by-step outcomes

## Supported assertion syntax

The extension accepts the following assertion patterns:

- `status == 403`
- `status != 200`
- `body contains "text"`
- `body not_contains "text"`
- `response contains "text"`
- `response not_contains "text"`
- `header["X-Header"] contains "value"`
- `header["X-Header"] not_contains "value"`

Examples:

```text
status == 403
body not_contains "UNIQUE_MARKER"
response contains "login failed"
header["Set-Cookie"] not_contains "admin=true"
```

## Installation

This is a Burp Suite extension for the legacy Jython environment.

### Requirements

- Burp Suite
- Jython (for the legacy Burp Jython Extender API)
- Burp Extender support enabled

### Load the extension

1. Open Burp Suite
2. Go to `Extender` > `Extensions`
3. Click `Add`
4. Select the Jython extension type
5. Choose the file `fix_verification_retester.py`
6. Load the extension

The extension will register a new tab named `Fix Retester` and add custom context menu items in Repeater.

## Usage

### Save a single request as a retest case

1. Send a request to Repeater
2. Right-click the request in Repeater
3. Select `Save as fix-verification test case`
4. Enter a friendly name for the case
5. Provide an assertion like `status == 403`

The case is stored and will appear in the `Fix Retester` tab.

### Run the retest

1. Open the `Fix Retester` tab
2. Select the saved cases
3. Click `Retest all`

The extension replays the saved requests and evaluates each assertion.

### Create a chained check

1. Send the initial request to Repeater
2. Right-click and choose `Start chained security check`
3. Select a check type
4. Configure the steps or OTP parameters
5. Save the chain

Then append additional follow-up requests using:

- `Append request to selected chain`

### Export a report

Use `Export report` in the `Fix Retester` tab to save a text summary of all results.

## Notes

- This project is specifically built around the legacy Burp Jython API.
- It is intended for manual verification workflows in security testing and bug fix review.
- The extension is not a general-purpose automated scanner; it is a targeted retesting helper focused on proof-of-fix validation.

## Repository contents

```text
.
├── fix_verification_retester.py   # Burp extension implementation
├── README.md                      # Project documentation
```

## License

This repository does not currently declare a license file. If you plan to share or redistribute this extension, add an appropriate open-source license before publication.

## Author

Repository: `iamgrepboyy/Fix-Verification-Retester`

## Summary

`Fix Verification Retester` is a Burp Suite helper for verifying whether previously reported security issues remain fixed after remediation. It gives testers a repeatable way to save key requests, define assertions, and confirm secure-state behavior through automated retesting.
