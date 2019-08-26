import json
import logging
import mimetypes
import pathlib
from library.config import Config


from datetime import datetime, timezone
from io import BytesIO
from copy import deepcopy
from botocore.exceptions import ClientError
from library.utility import jsonDumps
from library.aws.utility import convert_tags


class TrustedAdvisorChecker(object):
    """
    Basic class for gathering trusted advisor checks in account.
    """
    def __init__(self, account, check_id):
        """
        :param account: `Account` instance to grab trusted advisor findings for.
        :param checkID: unique check identification used to grab corresponding results.
        """
        self.account = account
        self.client = account.client("support")
        self.check_id = check_id

    def filter(self, filters, name_metadata, result):
        """
        Apply filters for a specific check.
        """

        resources = result["result"]["flaggedResources"]

        int = 0
        while int < len(resources):
            organized_metadata = {}
            curr = 0
            for val in name_metadata:
                organized_metadata[val] = resources[int]["metadata"][curr]
                curr += 1
            resources[int]["metadata"] = organized_metadata
            for filt in filters:
                #apply all the filters to this resource
                attribute = filt["attribute"]
                standard_value = filt["value"]
                op = filt["operator"]

                current_resource_value = organized_metadata[attribute]
                new_val = self.parse_value(current_resource_value, attribute)
                keep = self.compare(new_val, standard_value, op)
                if not keep:
                    resources.pop(int)
                    result["result"]["resourcesSummary"]["resourcesIgnored"] += 1
                    #stop checking
                    break
            if keep:
                int += 1
        return result

    def parse_value(self, resource_val, filter_type):
        """
        Remove unnecessary values from string to enable comparison to config filters.

        :param resource_val: the string to parse, returned from trusted advisor findings.
        :param filter_type: The data to filter by, specified in the config file as the attribute.

        """
        parsed = resource_val
        if filter_type == "Estimated Monthly Savings":
            parsed = resource_val.replace("$", '')
        if filter_type == "Number of Days Low Utilization":
            parsed = resource_val.replace(" days", '')
        return parsed

    def compare(self, new_value, standard, operator):
        """
        Returns true if the new_value passes the constraints. By default return True.
        :param new_value: the parsed value returned from Trusted Advisor findings of a specific attribute.
        :param standarad: the filter condition specified in config's filter option.
        :param operator: specifies how the new value should be compared to the standard.

            OPTIONS:"gt": greater than
                    "eq": equal
        """
        if operator == "gt":
            return float(new_value) > float(standard)
        if operator == "eq":
            return new_value == standard
        return True

    def get_ta_result(self):
        """
        Call the Trusted Advisor API to describe check results for specified check. Filter and enrich if necessary.

        :param checkId: the ID of the Trusted Advisor check, needed to gather all Trusted Advisor findings.

        :return: a dictionary containing the Trusted Advisor api response
        """
        try:
            response = self.client.describe_trusted_advisor_check_result(checkId=self.check_id, language="en")
            return response
        except:
            logging.exception(f"Failed to call Trusted Advisor initial findings.")
