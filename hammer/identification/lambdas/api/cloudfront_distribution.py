import logging

from responses import server_error
from botocore.exceptions import ClientError


def remediate(security_feature, account, caller_reference, domain_name, origin_id, target_origin_id, cnames):
    cf_client = account.client("cloudfront")

    try:
        response = cf_client.create_distribution(
            DistributionConfig={
                'CallerReference': caller_reference,
                'Aliases': {
                    'Quantity': 4,
                    'Items': cnames
                },
                'DefaultCacheBehavior' :{
                    'TargetOriginId': target_origin_id,
                    'ForwardedValues': {
                        'QueryString': True,
                        'Cookies': {
                            'Forward': 'none'
                        }
                    },
                    'TrustedSigners': {
                        'Enabled': True,
                        'Quantity': 123
                    },
                    'ViewerProtocolPolicy': 'allow-all',
                    'MinTTL': 1
                },
                'Origins': {
                    'Quantity': 1,
                    'Items': [
                        {
                            'Id': origin_id,
                            'DomainName': domain_name,
                        },
                    ]
                },
                'Comment': 'creating new cf distribution with cname list.',
                'Enabled': True,
            },
        )

        return "Success"

    except ClientError as err:
        if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
            logging.error(f"Access denied in {self.account} "
                          f"(cf:{err.operation_name})")
        else:
            logging.exception(f"Failed to create cloud front distribution")

        return server_error(text="Failed to create cloud front distribution")
