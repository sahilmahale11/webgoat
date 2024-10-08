import logging
import xml.etree.ElementTree as XmlTree
from datetime import date
from urllib.request import Request, urlopen
import re


logger = logging.getLogger()


class KubeScape:
    mapping_severity = {"0": "Info", "1": "Low", "2": "Medium", "3": "High"}

    def __init__(self, cmd_args):
        self.test = "Kubescape Scanning"
        self.filepath = cmd_args.path

    def get_severity(self, url_link):
        severity = ['Critical', 'High', 'Medium', 'Low']
        url = Request(url=url_link, headers={'User-Agent': 'Mozilla/5.0'})
        html_content = urlopen(url).read().decode("utf-8")

        # initializing tag for "p" to check severity
        for sev in severity:
            reg_str = "<p>" + sev + "</p>"
            find_string = re.search(reg_str, html_content)
            if find_string is not None:
                return sev
        return "Unknown"

    def get_data(self):
        try:
            tree = XmlTree.parse(self.filepath)
            logger.debug(f"print {tree}")
            items_list = list()

            today = date.today()
            logger.debug(f"Today's date is: {today}")

            cwe_id = "Unknown"

            for node in tree.findall("testsuite"):
                logger.debug(f"print testsuite info : {node}")
                for item in node.findall("testcase"):
                    logger.debug(f"Print testcase info: {item}")
                    items = dict()
                    if not item.findall("failure"):
                        continue
                    for fail_msg in item.findall("failure"):
                        msg = fail_msg.get("message")
                        logger.debug(f"print title for failed tests: {msg}")
                        title = item.get("name")
                        logger.debug(f"Print title {title}")

                        # Retrieve ID and URL for description
                        url = " ".join(ls for ls in msg.split(" ") if ls.startswith("https"))
                        desc = url.split("\n")[0]
                        description = "ID: " + desc.split('/')[-1] + " \n" + desc
                        logger.debug(f"description: {description}")

                        dict_msg = {}
                        # Split failure message to get remediation and namespace
                        for ls in msg.split(";"):
                            dict_msg[ls.split(":")[0].strip()] = ls.split(":")[1].strip()

                        logger.debug(f"Print dict list : {dict_msg}")
                        remediation = dict_msg["Remediation"]
                        logger.debug(f"Print remediation {remediation}")
                        namespace = dict_msg.get("namespace")
                        logger.debug(f"Print namespace {namespace}")

                        # Get the severity from html report
                        severity = self.get_severity(desc)

                        items["Date"] = str(today)
                        items["CWE/CVE"] = cwe_id
                        items["Severity"] = severity
                        items["ToolName"] = self.test
                        items["Title"] = title
                        items["Description"] = description
                        items["Remediation"] = remediation
                        items["SystemInfo"] = namespace
                        items_list.append(items)

            logger.info(items_list)
            return items_list

        except Exception as e:
            logger.fatal(f"Exception occurred in {__name__}.get_data() : {e}")
            raise Exception(f"Exception occurred in {__name__}.get_data() ")
