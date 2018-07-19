"""
Adding Excel worksheets and row data.
"""


class AddRecordsToSheet:
    """
    Class to add Excel worksheet's headers and row data.
    """
    @staticmethod
    def add_header_data(worksheet, sheet_name):
        """
        Adding Security group excel sheet headers.
        :param worksheet:
        :return:
        """
        worksheet.write(0, 0, "Accound ID")
        worksheet.write(0, 1, "Account Name")
        worksheet.write(0, 2, "Issue ID")
        worksheet.write(0, 3, "Issue Name")
        worksheet.write(0, 4, "Region")
        worksheet.write(0, 5, "Jiraticket")
        worksheet.write(0, 6, "Owner_Id")
        worksheet.write(0, 7, "BU")
        worksheet.write(0, 8, "Product")
        if sheet_name == "Insecure Services":
            worksheet.write(0, 9, "CIDR")

    @staticmethod
    def add_records(worksheet, sheet_name, account_id, account_name, issue_details, row_number):
        """
        Adding security group records.
        :param worksheet:
        :param account_id
        :param account_name:
        :param issue_details:
        :param row_number:

        :return:
        """

        worksheet.write(row_number, 0, account_id)
        worksheet.write(row_number, 1, account_name)
        worksheet.write(row_number, 2, issue_details.issue_id)
        worksheet.write(row_number, 3, issue_details.issue_details.name)
        worksheet.write(row_number, 4, issue_details.issue_details.region)
        worksheet.write(row_number, 5, issue_details.jira_details.ticket)
        worksheet.write(row_number, 6, issue_details.jira_details.ticket_assignee_id)
        worksheet.write(row_number, 7, issue_details.jira_details.business_unit)
        worksheet.write(row_number, 8, issue_details.jira_details.product)
        if sheet_name == "Insecure Services":
            worksheet.write(
                row_number, 9,
                ", ".join([perm['cidr'] for perm in issue_details.issue_details.perms])
            )
