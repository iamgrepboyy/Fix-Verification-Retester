"""Burp Suite fix-verification retester for the legacy Jython Extender API."""

import ast
import base64
import codecs
import json
import os
import re
import time
from datetime import datetime

from burp import IBurpExtender, ITab, IContextMenuFactory
from java.awt import BorderLayout, FlowLayout
from java.awt.event import ActionListener
from java.io import File
from java.util import ArrayList
from javax.swing import (
    JButton,
    JFileChooser,
    JLabel,
    JMenuItem,
    JOptionPane,
    JPanel,
    JScrollPane,
    SwingWorker,
    JTable,
)
from javax.swing.table import DefaultTableModel


_QUOTED = r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')'


def _parse_assertion(expression):
    expression = expression.strip()
    match = re.match(r"^status\s*(==|!=)\s*(\d{3})$", expression, re.I)
    if match:
        return {
            "kind": "status",
            "operator": match.group(1),
            "expected": int(match.group(2)),
        }

    match = re.match(
        r"^(response|body)\s+(contains|not_contains)\s+" + _QUOTED + r"$",
        expression,
        re.I,
    )
    if match:
        return {
            "kind": match.group(1).lower(),
            "operator": match.group(2).lower(),
            "expected": ast.literal_eval(match.group(3)),
        }

    match = re.match(
        r"^header\[\s*" + _QUOTED + r"\s*\]\s+"
        r"(contains|not_contains)\s+" + _QUOTED + r"$",
        expression,
        re.I,
    )
    if match:
        return {
            "kind": "header",
            "header": ast.literal_eval(match.group(1)),
            "operator": match.group(2).lower(),
            "expected": ast.literal_eval(match.group(3)),
        }

    raise ValueError(
        'Use status == 403, body not_contains "text", response contains "text", '
        'or header["X-Header"] not_contains "text".'
    )


class _Action(ActionListener):
    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback()


class _ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Fix-verification retester")
        self.store_path = os.path.join(
            os.path.expanduser("~"), ".burp_fix_verification_cases.json"
        )
        self.cases = []
        self.latest_results = []
        self.running = False
        self._load_cases()
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.printOutput("Fix-verification retester loaded")

    def getTabCaption(self):
        return "Fix Retester"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        if invocation.getToolFlag() != self.callbacks.TOOL_REPEATER:
            return None
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        menu_items = ArrayList()
        save_item = JMenuItem("Save as fix-verification test case")
        save_item.addActionListener(
            _Action(lambda: self._save_selected_request(messages[0]))
        )
        menu_items.add(save_item)
        chain_item = JMenuItem("Start chained security check")
        chain_item.addActionListener(
            _Action(lambda: self._start_chain(messages[0]))
        )
        menu_items.add(chain_item)
        append_item = JMenuItem("Append request to selected chain")
        append_item.addActionListener(
            _Action(lambda: self._append_chain_step(messages[0]))
        )
        menu_items.add(append_item)
        return menu_items

    def _build_ui(self):
        self.panel = JPanel(BorderLayout(8, 8))
        self.model = _ReadOnlyTableModel(
            ["Test case", "Check type", "Steps", "Latest result", "HTTP"], 0
        )
        self.table = JTable(self.model)
        self.table.setAutoCreateRowSorter(True)
        self.panel.add(JScrollPane(self.table), BorderLayout.CENTER)

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.retest_button = JButton("Retest all")
        self.remove_button = JButton("Remove selected")
        self.report_button = JButton("Export report")
        self.retest_button.addActionListener(_Action(self._retest_all))
        self.remove_button.addActionListener(_Action(self._remove_selected))
        self.report_button.addActionListener(_Action(self._export_report))
        controls.add(self.retest_button)
        controls.add(self.remove_button)
        controls.add(self.report_button)
        self.status_label = JLabel("Cases are stored locally in your user profile.")
        controls.add(self.status_label)
        self.panel.add(controls, BorderLayout.SOUTH)
        self._refresh_table()

    def _load_cases(self):
        if not os.path.isfile(self.store_path):
            return
        try:
            with codecs.open(self.store_path, "r", "utf-8") as case_file:
                loaded = json.load(case_file)
            if isinstance(loaded, list):
                self.cases = [
                    case
                    for case in loaded
                    if all(
                        key in case
                        for key in (
                            "name",
                            "host",
                            "port",
                            "protocol",
                            "request_b64",
                            "assertion",
                        )
                    )
                    or (
                        "steps" in case
                        and all(
                            key in case
                            for key in ("name", "host", "port", "protocol", "type")
                        )
                    )
                ]
        except Exception as error:
            self.callbacks.printError("Could not load saved cases: " + str(error))
        self.latest_results = [None] * len(self.cases)

    def _persist_cases(self):
        try:
            with codecs.open(self.store_path, "w", "utf-8") as case_file:
                json.dump(self.cases, case_file, indent=2, ensure_ascii=True)
            return True
        except Exception as error:
            JOptionPane.showMessageDialog(
                self.panel,
                "Could not save test cases: " + str(error),
                "Save failed",
                JOptionPane.ERROR_MESSAGE,
            )
            return False

    def _save_selected_request(self, message_info):
        if self.running:
            return
        service = message_info.getHttpService()
        request = message_info.getRequest()
        if service is None or request is None:
            JOptionPane.showMessageDialog(self.panel, "No request is selected.")
            return

        name = JOptionPane.showInputDialog(
            self.panel, "Test case name:", "Save retest case", JOptionPane.QUESTION_MESSAGE
        )
        if name is None or not str(name).strip():
            return
        expression = JOptionPane.showInputDialog(
            self.panel,
            "Secure-state assertion:",
            'body not_contains "UNIQUE_MARKER"',
        )
        if expression is None:
            return
        try:
            _parse_assertion(expression)
        except Exception as error:
            JOptionPane.showMessageDialog(
                self.panel, str(error), "Invalid assertion", JOptionPane.ERROR_MESSAGE
            )
            return

        request_text = self.helpers.bytesToString(request)
        request_b64 = base64.b64encode(request_text.encode("latin-1"))
        case = {
            "name": str(name).strip(),
            "host": str(service.getHost()),
            "port": int(service.getPort()),
            "protocol": str(service.getProtocol()),
            "request_b64": request_b64,
            "assertion": str(expression).strip(),
        }
        self.cases.append(case)
        self.latest_results.append(None)
        if self._persist_cases():
            self._refresh_table()
            self.status_label.setText("Saved: " + case["name"])
        else:
            self.cases.pop()
            self.latest_results.pop()

    def _start_chain(self, message_info):
        if self.running:
            return
        kinds = [
            "Privilege escalation (sequential requests)",
            "OTP brute force (bounded attempts)",
            "OTP bypass (response-manipulation follow-up)",
        ]
        selected_kind = JOptionPane.showInputDialog(
            self.panel,
            "Choose the check type:",
            "Start chained security check",
            JOptionPane.QUESTION_MESSAGE,
            None,
            kinds,
            kinds[0],
        )
        if selected_kind is None:
            return
        case_type = {
            kinds[0]: "privilege_escalation",
            kinds[1]: "otp_bruteforce",
            kinds[2]: "otp_response_manipulation",
        }[str(selected_kind)]

        service = message_info.getHttpService()
        request = message_info.getRequest()
        if service is None or request is None:
            JOptionPane.showMessageDialog(self.panel, "No request is selected.")
            return
        name = JOptionPane.showInputDialog(self.panel, "Test case name:")
        if name is None or not str(name).strip():
            return
        request_text = self.helpers.bytesToString(request)
        case = {
            "name": str(name).strip(),
            "type": case_type,
            "host": str(service.getHost()),
            "port": int(service.getPort()),
            "protocol": str(service.getProtocol()),
            "steps": [],
        }

        if case_type == "otp_bruteforce":
            if "{{OTP}}" not in request_text:
                JOptionPane.showMessageDialog(
                    self.panel,
                    'Put the literal {{OTP}} in the OTP value in Repeater, then start this check.',
                    "OTP placeholder required",
                    JOptionPane.ERROR_MESSAGE,
                )
                return
            attempt_text = JOptionPane.showInputDialog(
                self.panel, "Maximum attempts (1-10):", "5"
            )
            start_text = JOptionPane.showInputDialog(
                self.panel, "First numeric OTP value:", "000000"
            )
            status_text = JOptionPane.showInputDialog(
                self.panel, "HTTP status indicating rate limiting (e.g. 429):", "429"
            )
            marker_text = JOptionPane.showInputDialog(
                self.panel,
                'Optional response text indicating rate limiting (blank to use status only):',
                "",
            )
            try:
                attempt_count = int(attempt_text)
                otp_start = str(start_text)
                limit_status = int(status_text)
                if not 1 <= attempt_count <= 10:
                    raise ValueError("Attempt count must be between 1 and 10.")
                if not otp_start.isdigit() or len(otp_start) > 12:
                    raise ValueError("Starting OTP must be 1-12 digits.")
                if int(otp_start) + attempt_count - 1 >= 10 ** len(otp_start):
                    raise ValueError("Attempt range must fit within the OTP digit width.")
                if not 100 <= limit_status <= 599:
                    raise ValueError("Enter a valid HTTP status code.")
            except Exception as error:
                JOptionPane.showMessageDialog(
                    self.panel, str(error), "Invalid OTP check", JOptionPane.ERROR_MESSAGE
                )
                return
            case.update(
                {
                    "request_b64": base64.b64encode(request_text.encode("latin-1")),
                    "otp_count": attempt_count,
                    "otp_start": otp_start,
                    "rate_limit_status": limit_status,
                    "rate_limit_marker": str(marker_text or "").strip(),
                }
            )
        else:
            initial_assertion = (
                'status == 200'
                if case_type == "otp_response_manipulation"
                else 'status == 403'
            )
            assertion = JOptionPane.showInputDialog(
                self.panel,
                "Secure-state assertion for this request:",
                initial_assertion,
            )
            if assertion is None:
                return
            try:
                _parse_assertion(assertion)
            except Exception as error:
                JOptionPane.showMessageDialog(
                    self.panel, str(error), "Invalid assertion", JOptionPane.ERROR_MESSAGE
                )
                return
            label = "Initial request"
            if case_type == "otp_response_manipulation":
                label = "OTP verification response to manipulate"
            case["steps"].append(
                {
                    "label": label,
                    "request_b64": base64.b64encode(request_text.encode("latin-1")),
                    "assertion": str(assertion).strip(),
                }
            )

        self.cases.append(case)
        self.latest_results.append(None)
        if self._persist_cases():
            self._refresh_table()
            self.status_label.setText("Started chain: " + case["name"])
        else:
            self.cases.pop()
            self.latest_results.pop()

    def _append_chain_step(self, message_info):
        if self.running:
            return
        candidates = [
            "%d: %s (%s)" % (index + 1, case.get("name", ""), case.get("type", "single"))
            for index, case in enumerate(self.cases)
            if case.get("type") in ("privilege_escalation", "otp_response_manipulation")
        ]
        if not candidates:
            JOptionPane.showMessageDialog(
                self.panel, "Start a privilege-escalation or OTP-bypass chain first."
            )
            return
        chosen = JOptionPane.showInputDialog(
            self.panel,
            "Append to which chain?",
            "Append request step",
            JOptionPane.QUESTION_MESSAGE,
            None,
            candidates,
            candidates[0],
        )
        if chosen is None:
            return
        case_index = int(str(chosen).split(":", 1)[0]) - 1
        case = self.cases[case_index]
        request = message_info.getRequest()
        if request is None:
            return
        service = message_info.getHttpService()
        if (
            service is None
            or str(service.getHost()).lower() != case["host"].lower()
            or int(service.getPort()) != int(case["port"])
            or str(service.getProtocol()).lower() != case["protocol"].lower()
        ):
            JOptionPane.showMessageDialog(
                self.panel,
                "Chain steps must use the same scheme, host, and port.",
                "Target mismatch",
                JOptionPane.ERROR_MESSAGE,
            )
            return
        instructions = (
            "Use the intended user's credentials for this step. For cookies refreshed by "
            "earlier steps, replace the cookie value in the Repeater request with "
            "{{cookie:NAME}}."
        )
        if case["type"] == "otp_response_manipulation":
            instructions += (
                " This extension does not alter HTTP responses; select the follow-up request "
                "sent after you manipulated the client-visible OTP response."
            )
        JOptionPane.showMessageDialog(
            self.panel,
            instructions,
            "Capture chained request",
            JOptionPane.INFORMATION_MESSAGE,
        )
        assertion = JOptionPane.showInputDialog(
            self.panel,
            "Secure-state assertion for this step:",
            'status == 403',
        )
        if assertion is None:
            return
        try:
            _parse_assertion(assertion)
        except Exception as error:
            JOptionPane.showMessageDialog(
                self.panel, str(error), "Invalid assertion", JOptionPane.ERROR_MESSAGE
            )
            return
        default_label = (
            "Request after manipulated OTP response"
            if case["type"] == "otp_response_manipulation"
            else "Follow-up request"
        )
        label = JOptionPane.showInputDialog(self.panel, "Step label:", default_label)
        if label is None:
            return
        request_text = self.helpers.bytesToString(request)
        case["steps"].append(
            {
                "label": str(label).strip(),
                "request_b64": base64.b64encode(request_text.encode("latin-1")),
                "assertion": str(assertion).strip(),
            }
        )
        if self._persist_cases():
            self.latest_results[case_index] = None
            self._refresh_table()
            self.status_label.setText("Added step to: " + case["name"])
        else:
            case["steps"].pop()

    def _refresh_table(self):
        self.model.setRowCount(0)
        for index, case in enumerate(self.cases):
            result = self.latest_results[index] if index < len(self.latest_results) else None
            case_type = case.get("type", "single")
            if case_type == "otp_bruteforce":
                step_count = case.get("otp_count", 0)
                shown_type = "OTP rate limit"
            elif case_type == "single":
                step_count = 1
                shown_type = "Single request"
            else:
                step_count = len(case.get("steps", []))
                shown_type = case_type.replace("_", " ").title()
            self.model.addRow(
                [
                    case.get("name", ""),
                    shown_type,
                    str(step_count),
                    result["result"] if result else "Not tested",
                    result.get("http", "") if result else "",
                ]
            )

    def _remove_selected(self):
        if self.running:
            return
        selected = self.table.getSelectedRows()
        if not selected:
            return
        indices = sorted(
            [self.table.convertRowIndexToModel(row) for row in selected], reverse=True
        )
        for index in indices:
            del self.cases[index]
            del self.latest_results[index]
        if self._persist_cases():
            self._refresh_table()

    def _retest_all(self):
        if self.running or not self.cases:
            return
        self.running = True
        self._set_controls_enabled(False)
        self.status_label.setText("Replaying %d test case(s)..." % len(self.cases))
        extension = self
        cases = list(self.cases)

        class RetestWorker(SwingWorker):
            def doInBackground(worker_self):
                return [extension._retest_case(case) for case in cases]

            def done(worker_self):
                extension.running = False
                extension._set_controls_enabled(True)
                try:
                    extension.latest_results = worker_self.get()
                    extension._refresh_table()
                    extension.status_label.setText(
                        "Retest complete: %d case(s)." % len(extension.cases)
                    )
                except Exception as error:
                    extension.status_label.setText("Retest failed.")
                    JOptionPane.showMessageDialog(
                        extension.panel,
                        "Retest failed: " + str(error),
                        "Retest error",
                        JOptionPane.ERROR_MESSAGE,
                    )

        RetestWorker().execute()

    def _set_controls_enabled(self, enabled):
        self.retest_button.setEnabled(enabled)
        self.remove_button.setEnabled(enabled)
        self.report_button.setEnabled(enabled)

    def _retest_case(self, case):
        try:
            if case.get("type") == "otp_bruteforce":
                return self._retest_otp_rate_limit(case)
            steps = case.get("steps")
            if not steps:
                steps = [
                    {
                        "label": "Request",
                        "request_b64": case["request_b64"],
                        "assertion": case["assertion"],
                    }
                ]
            cookie_values = {}
            details = []
            last_status = ""
            all_passed = True
            for step in steps:
                response_data = self._send_case_request(case, step["request_b64"], cookie_values)
                if response_data is None:
                    return {
                        "result": "Inconclusive",
                        "detail": "%s: no HTTP response." % step.get("label", "Step"),
                        "http": last_status,
                    }
                last_status = str(response_data["status"])
                self._remember_cookies(response_data["headers"], cookie_values)
                passed = self._evaluate_assertion(
                    _parse_assertion(step["assertion"]),
                    response_data["status"],
                    response_data["response"],
                    response_data["body"],
                    response_data["headers"],
                )
                all_passed = all_passed and passed
                details.append(
                    "%s: %s (HTTP %s)"
                    % (
                        step.get("label", "Step"),
                        "assertion held" if passed else "assertion failed",
                        last_status,
                    )
                )
            return {
                "result": "Fixed" if all_passed else "Still vulnerable",
                "detail": "; ".join(details),
                "http": last_status,
            }
        except Exception as error:
            return {
                "result": "Inconclusive",
                "detail": str(error),
                "http": "",
            }

    def _send_case_request(self, case, request_b64, cookie_values):
        request_text = base64.b64decode(request_b64).decode("latin-1")

        def replace_cookie(match):
            return cookie_values.get(match.group(1).lower(), "")

        request_text = re.sub(
            r"\{\{cookie:([^}]+)\}\}", replace_cookie, request_text, flags=re.I
        )
        request = self.helpers.stringToBytes(request_text)
        service = self.helpers.buildHttpService(
            case["host"], int(case["port"]), case["protocol"]
        )
        exchange = self.callbacks.makeHttpRequest(service, request)
        response = exchange.getResponse() if exchange is not None else None
        if response is None:
            return None
        response_info = self.helpers.analyzeResponse(response)
        headers = {}
        for header in response_info.getHeaders():
            if ":" in header:
                key, value = header.split(":", 1)
                normalized_key = key.strip().lower()
                if normalized_key in headers:
                    headers[normalized_key] += ", " + value.strip()
                else:
                    headers[normalized_key] = value.strip()
        return {
            "status": int(response_info.getStatusCode()),
            "response": self.helpers.bytesToString(response),
            "body": self.helpers.bytesToString(
                response[response_info.getBodyOffset():]
            ),
            "headers": headers,
        }

    def _remember_cookies(self, headers, cookie_values):
        for value in headers.get("set-cookie", "").split(","):
            cookie = value.split(";", 1)[0].strip()
            if "=" in cookie:
                name, cookie_value = cookie.split("=", 1)
                cookie_values[name.strip().lower()] = cookie_value.strip()

    def _retest_otp_rate_limit(self, case):
        request_template = base64.b64decode(case["request_b64"]).decode("latin-1")
        start_text = case["otp_start"]
        start_value = int(start_text)
        attempts = int(case["otp_count"])
        expected_status = int(case["rate_limit_status"])
        if not 1 <= attempts <= 10:
            raise ValueError("Saved OTP attempt count is outside the 1-10 safety limit.")
        if "{{OTP}}" not in request_template:
            raise ValueError("Saved OTP request is missing the {{OTP}} placeholder.")
        if start_value + attempts - 1 >= 10 ** len(start_text):
            raise ValueError("Saved OTP range exceeds its configured digit width.")
        marker = case.get("rate_limit_marker", "").lower()
        observed_statuses = []
        for offset in range(attempts):
            otp_value = str(start_value + offset).zfill(len(start_text))
            request_text = request_template.replace("{{OTP}}", otp_value)
            request = self.helpers.stringToBytes(request_text)
            service = self.helpers.buildHttpService(
                case["host"], int(case["port"]), case["protocol"]
            )
            exchange = self.callbacks.makeHttpRequest(service, request)
            response = exchange.getResponse() if exchange is not None else None
            if response is None:
                return {
                    "result": "Inconclusive",
                    "detail": "No response during OTP attempt %d." % (offset + 1),
                    "http": ", ".join(observed_statuses),
                }
            response_info = self.helpers.analyzeResponse(response)
            status = int(response_info.getStatusCode())
            observed_statuses.append(str(status))
            response_text = self.helpers.bytesToString(response)
            if status == expected_status or (marker and marker in response_text.lower()):
                return {
                    "result": "Fixed",
                    "detail": "Rate-limit signal observed on attempt %d of %d."
                    % (offset + 1, attempts),
                    "http": ", ".join(observed_statuses),
                }
            if offset + 1 < attempts:
                time.sleep(0.25)
        return {
            "result": "Still vulnerable",
            "detail": "No configured rate-limit signal was observed in %d bounded attempts."
            % attempts,
            "http": ", ".join(observed_statuses),
        }

    def _evaluate_assertion(self, assertion, status, response_text, body_text, headers):
        kind = assertion["kind"]
        operator = assertion["operator"]
        expected = assertion["expected"]
        if kind == "status":
            return status == expected if operator == "==" else status != expected
        if kind == "header":
            actual = headers.get(assertion["header"].lower(), "")
        elif kind == "body":
            actual = body_text
        else:
            actual = response_text
        contained = expected in actual
        return contained if operator == "contains" else not contained

    def _export_report(self):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("fix-verification-report.txt"))
        if chooser.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        lines = [
            "Fix-verification retest report",
            "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "",
        ]
        for index, case in enumerate(self.cases):
            result = self.latest_results[index] if index < len(self.latest_results) else None
            case_type = case.get("type", "single")
            lines.extend(
                [
                    "Test case: " + case.get("name", ""),
                    "Check type: " + case_type.replace("_", " "),
                    "Target: %s://%s:%s"
                    % (case.get("protocol", ""), case.get("host", ""), case.get("port", "")),
                    "Result: " + (result.get("result", "Not tested") if result else "Not tested"),
                    "HTTP status: " + (result.get("http", "") if result else ""),
                    "Details: " + (result.get("detail", "") if result else ""),
                ]
            )
            if case_type == "otp_bruteforce":
                lines.extend(
                    [
                        "Bounded attempts: " + str(case.get("otp_count", "")),
                        "Rate-limit status expected: " + str(case.get("rate_limit_status", "")),
                        "Rate-limit body marker: " + case.get("rate_limit_marker", ""),
                    ]
                )
            else:
                steps = case.get("steps") or [
                    {
                        "label": "Request",
                        "assertion": case.get("assertion", ""),
                    }
                ]
                for step_number, step in enumerate(steps, 1):
                    lines.append(
                        "Step %d: %s | assertion: %s"
                        % (
                            step_number,
                            step.get("label", "Request"),
                            step.get("assertion", ""),
                        )
                    )
            lines.append("")
        try:
            with codecs.open(path, "w", "utf-8") as report_file:
                report_file.write("\n".join(lines))
            self.status_label.setText("Report exported: " + path)
        except Exception as error:
            JOptionPane.showMessageDialog(
                self.panel,
                "Could not write report: " + str(error),
                "Export failed",
                JOptionPane.ERROR_MESSAGE,
            )