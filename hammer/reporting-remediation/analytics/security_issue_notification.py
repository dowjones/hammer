import xlwt
import os


from library.slack_utility import SlackNotification


class SecurityIssuesReport:

    @staticmethod
    def add_header_data(worksheet):
        """
        Adding Security group excel sheet headers.
        :param worksheet:
        :return:
        """
        worksheet.write(0, 0, "Accound ID")
        worksheet.write(0, 1, "Account Name")
        worksheet.write(0, 2, "Region")
        worksheet.write(0, 3, "Issue Summary")
        worksheet.write(0, 4, "Issue Description")
        worksheet.write(0, 5, "BU")
        worksheet.write(0, 6, "Product")

    @staticmethod
    def add_records(worksheet, issue, ticket_summary, desc, account_name, bu, product):
        """
        Adding security group records.
        :param worksheet:
        :param account_id
        :param account_name:
        :param issue_details:

        :return:
        """
        worksheet.write(1, 0, issue.account_id)
        worksheet.write(1, 1, account_name)
        worksheet.write(1, 2, issue.issue_details.region)
        worksheet.write(1, 3, ticket_summary)
        worksheet.write(1, 4, desc)
        worksheet.write(1, 5, bu)
        worksheet.write(1, 6, product)

    @classmethod
    def send_csv_report(cls, issue, ticket_summary, desc, account_name, bu, product, owner_email, security_issue_file_name):
        work_book = xlwt.Workbook()

        worksheet = work_book.add_sheet(security_issue_file_name)
        cls.add_header_data(worksheet)
        cls.add_records(worksheet, issue, ticket_summary, desc, account_name, bu, product)
        work_book.save(security_issue_file_name)
        slack_notificaiton_obj = SlackNotification()
        slack_notificaiton_obj.send_file_notification(file_name=security_issue_file_name, user_mail=owner_email)

        os.remove(security_issue_file_name)
