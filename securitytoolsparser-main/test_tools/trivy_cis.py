import json
import logging
from datetime import date

logger = logging.getLogger()


class Trivy_CIS:

    def __init__(self, cmd_args):
        self.test = "Trivy_CIS"
        self.filepath = cmd_args.path
        self.list_rows = list()

    def get_data(self):
        try:
            logger.info(self.filepath)
            with open(self.filepath, 'r') as json_file:
                file_data = json.load(json_file)

            for json_data in file_data['Results']:
                self.get_dict_data(json_data)
            return self.list_rows
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")

    def create_dict_data(self, cwe, severity, title, remediation, description):
        """Helper function to create dictionary for row data."""
        return {
            "Date": str(date.today()),
            "CWE/CVE": cwe,
            "ToolName": self.test,
            "Severity": severity,
            "Title": title,
            "Remediation": remediation,
            "Description": description,
            "SystemInfo": ""
        }

    def get_dict_data(self, json_data):
        try:
            if json_data['Results'] is None:
                json_data['remediation'] = "No remediation is required as the check is passed"
                dict_data = self.create_dict_data(
                    json_data['ID'],
                    json_data['Severity'],
                    json_data['Name'],
                    json_data['remediation'],
                    json_data['Description']
                )
                self.list_rows.append(dict_data)
            else:
                for result in json_data['Results']:
                    for misconfiguration in result['Misconfigurations']:
                        dict_data = self.create_dict_data(
                            json_data['ID'],
                            misconfiguration['Severity'],
                            misconfiguration['Title'],
                            misconfiguration['Resolution'],
                            misconfiguration['Description']
                        )
                        self.list_rows.append(dict_data)
        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_dict_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_dict_data() ")
