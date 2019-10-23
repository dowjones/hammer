import copy

from library.config import Config
from library.aws.utility import Account
from library.aws.s3 import S3Operations

class S3Update:

    def __init__(self, config):
        self.config = config

    def s3_update(self):
        # Update account details and grant details from JIRA ticket for rollback

        account_id = ""
        account_name = ""
        bucket_name = ""

        #issues_list = self.config.s3acl.rollback_issues(account_id)

        account = Account(id=account_id,
                          name=account_name,
                          role_name=self.config.aws.role_name_reporting)

        policy = account.client("s3").get_bucket_acl(Bucket=bucket_name)

        new_policy = {}
        new_policy["Owner"] = policy['Owner']
        new_policy["Grants"] = policy['Grants']

        # Add a new grant to the current ACL
        # Update empty values as per requirements/JIRA ticket details
        # URI: "string"   --   Sample URI for all users: http://acs.amazonaws.com/groups/global/AllUsers
        # Type : 'CanonicalUser'|'AmazonCustomerByEmail'|'Group',
        # Permission: 'FULL_CONTROL'|'WRITE'|'WRITE_ACP'|'READ'|'READ_ACP'
        new_grant = {
            'Grantee': {
                'URI': "",
                'Type': ""                
            },
            'Permission': "",
        }

        # If we don't want to modify the original ACL variable, then we
        # must do a deepcopy
        modified_acl = copy.deepcopy(new_policy)
        modified_acl['Grants'].append(new_grant)

        # update_bucket_acl
        # S3Operations.update_bucket_acl(account.client("s3"), bucket_name, modified_acl)
        account.client("s3").put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=modified_acl)

if __name__ == "__main__":
    config = Config()
    
    try:
        class_object = S3Update(config)
        class_object.s3_update()
    except Exception:
        print("Failed to clean S3 public policies")

		
