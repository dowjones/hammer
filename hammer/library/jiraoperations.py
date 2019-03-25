import io
import logging
import urllib3


from collections import namedtuple
from jira import JIRA
from jira import JIRAError
from library.utility import empty_converter


NewIssue = namedtuple('NewIssue', [
    'ticket_id',
    'ticket_assignee_id'
    ])


class JiraReporting(object):
    """ Base class for JIRA reporting """
    def __init__(self, config):
        self.config = config
        self.jira = JiraOperations(self.config)

    def add_issue(self,
                  issue_summary, issue_description,
                  priority, labels,
                  account_id,
                  owner=None,
                  bu=None, product=None,
                  ):
        # TODO: move to decorator
        if not self.config.jira.enabled:
            return None

        project = self.config.owners.ticket_project(
            bu=bu, product=product,
            account=account_id
        )

        issue_data = {
            "project": {"key": project},
            "summary": issue_summary,
            "description": issue_description,
            "issuetype": {"name": self.config.jira.issue_type},
            "priority": {"name": priority},
            "labels": labels
        }
        ticket_id = self.jira.create_ticket(issue_data)

        parent_ticket_id = self.config.owners.ticket_parent(
            bu=bu, product=product,
            account=account_id
        )
        self.jira.create_issue_link(ticket_id, parent_ticket_id)

        # assignee from ticket_owners.json
        fallback_assignee = self.config.owners.ticket_owner(
            bu=bu, product=product,
            account=account_id
        )

        ticket_assignee_id = self.jira.find_valid_assignee(
            project,
            [owner, fallback_assignee, self.jira.current_user]
        )
        if ticket_assignee_id is not None:
            self.jira.assign_user(ticket_id, ticket_assignee_id)
        else:
            # return current assignee
            ticket_assignee_id = self.jira.ticket_assignee(ticket_id)

        self.jira.add_watcher(ticket_id, ticket_assignee_id)

        return NewIssue(ticket_id=ticket_id,
                        ticket_assignee_id=ticket_assignee_id)

    def close_issue(self, ticket_id, comment):
        # TODO: move to decorator
        if not self.config.jira.enabled:
            return

        self.jira.add_comment(ticket_id, comment)
        self.jira.close_issue(ticket_id)
        logging.debug(f"Closed issue ({self.jira.ticket_url(ticket_id)})")

    def update_issue(self, ticket_id, comment):
        # TODO: move to decorator
        if not self.config.jira.enabled:
            return

        # TODO: reopen ticket if closed
        self.jira.add_comment(ticket_id, comment)
        logging.debug(f"Updated issue {self.jira.ticket_url(ticket_id)}")

    def add_attachment(self, ticket_id, filename, text):
        # TODO: move to decorator
        if not self.config.jira.enabled:
            return

        return self.jira.add_attachment(ticket_id, filename, text)

    def remediate_issue(self, ticket_id, comment, reassign):
        # TODO: move to decorator
        if not self.config.jira.enabled:
            return

        if reassign:
            self.jira.assign_user(ticket_id, self.jira.current_user)
        self.jira.add_comment(ticket_id, comment)

    def ticket_url(self, ticket_id):
        return self.jira.ticket_url(ticket_id)

    def add_label(self, ticket_id, label):
        self.jira.add_label(ticket_id, label)

class JiraOperations(object):
    """ Base class for interaction with JIRA """
    def __init__(self, config):
        # do not print excess warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # JIRA configuration from config.json/DDB
        self.config = config
        # JIRA url
        self.server = self.config.jira.server
        # JIRA established session
        self.session = None

        if self.config.jira.enabled:
            self.login_oauth()
        else:
            logging.debug("JIRA integration is disabled")

    @property
    def current_user(self):
        """ :return: JIRA user name, used for connection establishing """
        return self.session.current_user()

    def login_oauth(self):
        """
        Establish JIRA connection using oauth

        :return: boolean, if connection was successful.
        """
        if not self.config.jira.credentials:
            logging.error("Failed to login jira (empty credentials)")
            return False

        try:
            self.session = JIRA(options={'server': self.server, 'verify': False},
                                oauth=self.config.jira.credentials["oauth"])
        except JIRAError:
            logging.exception(f"Failed to create oauth session to {self.server}")
            return False

        logging.debug(f'JIRA session to {self.server} created successfully (oauth)')
        return True

    def login_basic(self):
        """
        Establish JIRA connection using basic authentication

        :return: boolean, if connection was successful.
        """
        if not self.config.jira.credentials:
            logging.error("Failed to login jira (empty credentials)")
            return False

        username = self.config.jira.credentials["basic"]["username"]
        password = self.config.jira.credentials["basic"]["password"]
        options = {'server': self.server, 'verify': False}

        try:
            self.session = JIRA(options, basic_auth=(username, password))
        except Exception:
            logging.exception(f"Failed to create basic session to {self.server}")
            return False

        logging.debug(f'JIRA session to {self.server} created successfully (basic)')
        return True

    def ticket_url(self, ticket_id):
        """ :return: URL to `ticket_id` """
        return f"{self.server}/browse/{ticket_id}"

    def ticket_assignee(self, ticket_id):
        """
        :param ticket_id: JIRA ticket
        :return: name of current assignee for ticket
        """
        ticket = self.session.issue(ticket_id)
        return ticket.fields.assignee.name

    def find_valid_assignee(self, project, assignees):
        """
        Check what record from given list of possible assignees can be used as assignee for given project.

        :param project: name of Jira project to perform check against
        :param assignees: list of possible assignees
        :return:
        """
        for assignee in assignees:
            if assignee is None:
                continue

            try:
                users = self.session.search_assignable_users_for_projects(assignee, project)
            except Exception:
                continue

            # check only exact matches
            if len(users) == 1:
                return users[0].name
        return None

    def create_ticket(self, issue_data):
        """
        Create a JIRA ticket

        :param issue_data: a dict containing field names and the values to use
        """
        resp = self.session.create_issue(fields=issue_data)
        logging.debug(f"Created jira ticket {self.ticket_url(resp.key)}")
        return resp.key

    def create_issue_link(self, inward_issue, outward_issue):
        """
        Linking JIRA tickets with 'relates to' link

        :return: boolean, if linking was successful
        """
        if not (inward_issue or outward_issue):
            return False

        try:
            # JIRA comes with default types of links:
            #  1) relates to / relates to,
            #  2) duplicates / is duplicated by,
            #  3) blocks / is blocked by
            #  4) clones / is cloned by
            link_type = "relates to"
            self.session.create_issue_link(
                type=link_type,
                inwardIssue=inward_issue,
                outwardIssue=outward_issue
            )
        except Exception:
            logging.exception(f"Failed to create issue link {inward_issue} -> {outward_issue}")
            return False

        logging.debug(f"Created issue link {inward_issue} -> {outward_issue}")
        return True

    def assign_user(self, ticket_id, assinee_name):
        """
        Assign `ticket_id` to `assinee_name`.

        :return: boolean, if assigning was successful
        """
        if not (ticket_id or assinee_name):
            return False

        try:
            issue = self.session.issue(ticket_id)
            issue.update(assignee={'name': assinee_name})
        except Exception:
            logging.exception(f"Failed to assign {ticket_id} to {assinee_name}")
            return False

        logging.debug(f"Assigned {ticket_id} to {assinee_name}")
        return True

    def add_label(self, ticket_id, label):
        """
                add label to `ticket_id`.

                :return: boolean, if label update was successful
                """
        if not (ticket_id and label):
            return False

        try:
            issue = self.session.issue(ticket_id)
            issue.fields.labels.append(label)
            issue.update(fields={"labels": issue.fields.labels})

        except Exception:
            logging.exception(f"Failed to add {label} to {ticket_id}")
            return False

        logging.debug(f"Added label {label} to {ticket_id}")
        return True

    def update_ticket(self, ticket_id, updated_issue_data):
        """
        Update JIRA ticket fields as in self.create_ticket(), but for existing ticket

        :param ticket_id: ticket Id to update
        :param updated_issue_data: a dict containing field names and the values to use

        :return: boolean, if updating was successful
        """
        try:
            issue = self.session.issue(ticket_id)
            issue.update(updated_issue_data)
        except Exception:
            logging.exception(f"Failed to update {ticket_id}")
            return False

        logging.debug(f"Updated {ticket_id}")
        return True

    def add_comment(self, ticket_id, comment):
        """
        Add comment to JIRA ticket

        :param ticket_id: ticket Id to add comment to
        :param comment: comment text

        :return: boolean, if operation was successful
        """
        if ticket_id and comment:
            try:
                self.session.add_comment(ticket_id, comment)
            except Exception:
                logging.exception(f"Failed to add comment to {ticket_id}")
                return False
        return True

    def add_watcher(self, ticket_id, user):
        """
        Adding jira ticket watcher.
        
        :param ticket_id: jira ticket id 
        :param user: watcher user id
        :return: nothing
        """

        self.session.add_watcher(ticket_id, user)

    def close_issue(self, ticket_id):
        """
        Transition of ticket to `Closed` state. It checks if issue can be transitioned to `Closed` state.

        :param ticket_id: ticket Id to close

        :return: nothing
        """
        if not ticket_id:
            return

        issue = self.session.issue(ticket_id)
        if issue.fields.status.name == "Closed":
            logging.debug(f"{ticket_id} is already closed")
            return

        for transition in self.session.transitions(issue):
            if transition['name'] == 'Close Issue':
                self.session.transition_issue(ticket_id, transition['id'])
                logging.debug(f"Closed {ticket_id}")
                break
        else:
            logging.error(f"{self.ticket_url(ticket_id)} can't be closed")
            return

    def resolve_issue(self, ticket_id):
        """
        Transition of ticket to `Resolved` state. It checks if issue can be transitioned to `Resolved` state.

        :param ticket_id: ticket Id to resolve

        :return: nothing
        """
        issue = self.session.issue(ticket_id)
        if issue.fields.status.name == "Resolved":
            logging.debug(f"{ticket_id} is already resolved")
            return

        for transition in self.session.transitions(issue):
            if transition['name'] == 'Resolve Issue':
                self.session.transition_issue(ticket_id, transition['id'])
                logging.debug(f"Resolved {ticket_id}")
                break
        else:
            logging.error(f"{self.ticket_url(ticket_id)} can't be resolved")
            return

    def reopen_issue(self, ticket_id):
        """
        Transition of ticket to `Reopen Issue` state. It checks if issue can be transitioned to `Reopen Issue` state.

        :param ticket_id: ticket Id to reopen

        :return: nothing
        """
        issue = self.session.issue(ticket_id)
        if issue.fields.status.name in ["Open", "Reopened"]:
            logging.debug(f"{ticket_id} is already opened")
            return

        for transition in self.session.transitions(issue):
            if transition['name'] == 'Reopen Issue':
                self.session.transition_issue(ticket_id, transition['id'])
                logging.debug(f"Reopened {ticket_id}")
                break
        else:
            logging.error(f"{self.ticket_url(ticket_id)} can't be reopened")
            return

    def add_attachment(self, ticket_id, filename, text):
        """
        Add text as attachment with filename to JIRA ticket

        :param ticket_id: ticket Id to add attachment to
        :param filename: label for attachment
        :param text: attachment text

        :return: attachment object
        """
        attachment = io.StringIO(text)
        filename = filename.replace(':', '-')
        return self.session.add_attachment(issue=ticket_id,
                                           attachment=attachment,
                                           filename=filename)

    @staticmethod
    def build_tags_table(tags):
        """
        Build JIRA table from AWS tags dictionary

        :param tags: dict with tags

        :return: str with JIRA table
        """
        if not tags:
            return ""

        desc = f"*Tags*:\n"
        desc += f"||Key||Value||\n"
        for key, value in tags.items():
            desc += f"|{key}|{empty_converter(value)}|\n"
        return desc
