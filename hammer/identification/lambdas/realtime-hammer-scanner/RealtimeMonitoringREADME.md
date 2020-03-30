### Enable realtime monitoring
Get the value of SQSRealtimeScannerArn from Identification stack output
Run this on CloudSecTest Account (replace stack name with your prefix):
```
for region in `aws ec2 describe-regions --output text | cut -f4`
do
    echo "Creating time time monitoring stack in $region"
    aws cloudformation deploy --template-file realtime-hammer-cloudwatch-filter.json --stack-name CloudSecurity-Hammer-Realtime-Scanner-CloudWatch-Filter-Rebase2-Dev-Stack --parameter-overrides SQSRealtimeScannerArn="<SQS ARN>" ResourcesPrefix="rebase2-dev-" --region $region
done
```

### Enable ReatTime Scanning Cross Account in Prod
Note: CrossAccount Scanning is only Supported in Prod as of now.

Run this on CloudSecProd Account:
Unfortuantely EventBusPolicy seems to be bugged for Cloud Formation so we must do this step manually.
Run this on all regions:

AP: "ap-south-1" "ap-northeast-2" "ap-northeast-1" "ap-southeast-1" "ap-southeast-2"
EU: "eu-west-3" "eu-west-2" "eu-west-1" "eu-central-1"
SA: "sa-east-1"
CA: "ca-central-1"
US: "us-east-1" "us-east-2" "us-west-1" "us-west-2"

1) Because of a bug in CloudFormation, we cannot create an EventBus to collect CloudTrail events from all member accounts using CloudFormation. For now, we would need to do this manually. You can use the following script (replace '<ORGID>' with your AWS organization id):
```
for region in `aws ec2 describe-regions --output text | cut -f4`
do
    echo "Setting up EventBus for aggregating CloudTrail events in $region"
    aws events put-permission --action "events:PutEvents" --principal "*" --condition Type="StringEquals",Key="aws:PrincipalOrgID",Value="<ORGID>" --statement-id "realtime-hammer-monitoring" --profile cloudsectest --region $region
done
```

Get the value of SQSRealtimeScannerArn from Identification stack output
Run this on CloudSecProduction Account:
```
for region in `aws ec2 describe-regions --output text | cut -f4`
do
    echo "Creating time time monitoring stack in $region"
    aws cloudformation deploy --template-file realtime-hammer-cloudwatch-filter.json --stack-name CloudSecurity-Hammer-Realtime-Scanner-CloudWatch-Filter-Prod-Stack --parameter-overrides SQSRealtimeScannerArn="<SQS ARN>" ResourcesPrefix="prod-hammer-" --region $region
done
```

Run this on CentralizedDeployment Account:
Deploy the Role to to enable Cross Account Scanning
```
aws cloudformation create-stack-instances --stack-set-name CloudSecurity-Hammer-Crossaccount-CloudTrail-Eventbus-Role --regions "us-east-1" --operation-preferences FailureToleranceCount=100,MaxConcurrentCount=20 --region us-east-1 --accounts <list of accounts>
```

Deply the CloudWatch Alarm Stack Set

Example:
make sure to specify all the regions you wish to select and accounts you wish to enable realtime monitoring
```aws cloudformation update-stack-instances --stack-set-name CloudSecurity-Hammer-Realtime-CloudTrail-Eventbus-US --regions "us-east-1" "us-east-2" "us-west-1" "us-west-2"  --operation-preferences FailureToleranceCount=100,MaxConcurrentCount=20 --region us-east-1 --accounts <list of accounts>```

