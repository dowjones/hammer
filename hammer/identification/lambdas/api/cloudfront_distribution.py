import logging

from responses import server_error
from botocore.exceptions import ClientError


def remediate(security_feature, account, cloudfront_id, cnames):
    cf_client = account.client("cloudfront")

    try:
        dist_config_details = cf_client.get_distribution_config(
            Id=cloudfront_id
        )

        response = cf_client.update_distribution(
            DistributionConfig={
                'CallerReference': dist_config_details["DistributionConfig"]["CallerReference"],
                'Aliases': {
                    'Quantity': len(cnames),
                    'Items': cnames
                },
                'DefaultRootObject': dist_config_details["DistributionConfig"]["DefaultRootObject"],
                'Origins': dist_config_details["DistributionConfig"]["Origins"],
                'DefaultCacheBehavior': dist_config_details["DistributionConfig"]["DefaultCacheBehavior"],
                'CacheBehaviors': dist_config_details["DistributionConfig"]["CacheBehaviors"],
                'CustomErrorResponses': dist_config_details["DistributionConfig"]["CustomErrorResponses"],
                'Comment': 'Updated with CNAME details',
                'Logging': dist_config_details["DistributionConfig"]["Logging"],
                'PriceClass': dist_config_details["DistributionConfig"]["PriceClass"],
                'Enabled': dist_config_details["DistributionConfig"]["Enabled"],
                'ViewerCertificate': dist_config_details["DistributionConfig"]["ViewerCertificate"],
                'Restrictions': dist_config_details["DistributionConfig"]["Restrictions"],
                'WebACLId': dist_config_details["DistributionConfig"]["WebACLId"],
                'HttpVersion': dist_config_details["DistributionConfig"]["HttpVersion"],
                'IsIPV6Enabled': dist_config_details["DistributionConfig"]["IsIPV6Enabled"]
            },
            Id = cloudfront_id,
            IfMatch = dist_config_details["ETag"]
        )
        
        result = "remediated"
        response = {
            security_feature: result
        }

        return response

    except ClientError as err:
        if err.response['Error']['Code'] in ["AccessDenied", "UnauthorizedOperation"]:
            logging.error(f"Access denied in {self.account} "
                          f"(cf:{err.operation_name})")
        else:
            logging.exception(f"Failed to update cloud front distribution")

        return server_error(text="Failed to update cloud front distribution")
