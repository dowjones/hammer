# Trusted Advisor Checks

Enabling Trusted Advisor checks with Hammer allows you to add all rules and checks from AWS’s Trusted Advisor with Dow Jones’ Hammer Continuous Monitoring Service.

File Structure:

```

├── trusted-advisor-checks-identification   <-- Parent folder for Trusted Advisor Checks
│   ├── README.md                           <-- This Instructions file
│   ├── initiate-ta-checks.py               <-- Initiate Lambda function
│   ├── describe-ta-checks.py               <-- Describe Lambda function

```

Configuration Specification:

```
{
    "trusted_advisor_recommendations": {
        "enabled": true,
        "refreshtimeoutinminutes": 8,
        "checks": [
            {
                "category": "cost_optimizing",
                "checkname": "Low Utilization Amazon EC2 Instances",
	              "name": "trusted_advisor_recommendations_low_ec2_utilization",
                "accounts": [
                    "Account ID 1",
                    "Account ID 2"
                ],
                "filters": [
                    {
                        "attribute": "Estimated Monthly Savings",
                        "operator": "gt",
                        "value": "500"
                    },
                    {
                        "attribute": "Number of Days Low Utilization",
                        "operator": "eq",
                        "value": "14",
                    }
                ],
                "ddb.table_name": "hammer-trusted-advisor-cost-optimizing-low-utilization-ec2-instances"
            },
            {
                "category": "fault_tolerance",
                "checkname": "Amazon EBS Snapshots",
                "accounts": [
                    "Account 1",
                    "Account 2"
                ],
                "filters": [
                    {
                        "attribute": "status",
                        "operator": "eq",
                        "value": "critical"
                    }
                ],
                "ddb.table_name": "hammer-trusted-advisor-fault-tolerance-ebs-snapshots"
            }
        ]
    }
}
```

#How to configure Trusted Advisor checks:
1. Turn on Trusted Advisor checks by changing "enabled" to true.
2. "refreshtimeoutinminutes" is how long the initiate lambda function will wait for trusted advisor to refresh the check data.
3. Add a check to the "checks" list by specifying Trusted Advisor named category and checkname. Important to specify the EXACT checkname and category as returned by the Trusted Advisor API.
4. Specify the account ID's you would like to enable this TA check on.
5. Specify any filters you'd like to set. A filter tells Trusted Advisor which results to return by looking at the metadata of the check response. For example, for Low Util EC2 you can turn on a filter that looks at the Estimated Monthly Savings attribute and will only return EC2 instances where the Estimated Monthly Savings is greater than $500.

* Attribute must be the name of the category you'd like to filter the check by. To see the attributes of a result, look at the Trusted Advisor API call, trusted-advisor-describe-checks. All possible checks are returned. The metadata section explains possible attributes for a specific check.

```$ aws support describe-trusted-advisor-checks --language en
```

* Operator - "eq" is equal, "gt" is greater than. The operator compares the current value from the describe-checks-result api call to the value specified in the 'value' field.

* Value - adjust depending on how you want to filter
```
{
                        "attribute": "Number of Days Low Utilization",
                        "operator": "eq",
                        "value": "14",
                    }
```
If you do not want to filter the results, filters should be left as an empty list, like so:

```
filters: [],

```

6. "ddb.table_name" is the name of the Dynamo Table that stores the issue details returned from a Trusted Advisor checks. The table must exist before the check can be enabled. DDB tables are check specific.

#How to add your new check's DDB Table:
Add your all ddb information to deployment/cf-templates/ddb.json:
1. Update the reference name of the table
2. “Key Schema”
    Must make the attributes account_id and issue_id
3. “BillingMode”: “PAY_PER_REQUEST”
4. “TableName”:
    Specify your table name,which will follow the resources prefix. This is the name of the table that you will reference in the config file as the new check's ddb.table_name.


#Understanding initiate-ta-checks.py:
The initiate function gathers all specifications from the config file, makes them account specific, and fans out the information to the describe function. The describe function evaluates the checks for ONE account. In other words, one account per describe instance.

account_and_checks: A dictionary to organize check information PER account.
```
          {
              AccountID1: {
                account_id: string
                checks_info: [{}],
                session: account session variable
            },
              AccountID2: {
                account_id: string
                checks_info: [{}],
                session: account session variable,
                refresh_done: boolean
            }
          }
```
checks_info is a list of check objects:
```
      {
        "checkname" : checkname,
        "id" : check_id,
        "name": name,
        "category": category,
        "metadata" : metadata,
        "ddb.table_name" : ddb,
        "filters": filters,
        "refresh_done" : False
        }
```
#Understanding describe-ta-checks.py:

Gathers and filters the Trusted Advisor result for each specific check enabled for the Account.

#Understanding Trusted Advisor API
Trusted Advisor API Calls
The initiate function calls describe-trusted-advisor-checks, refresh-trusted-advisor-check, and describe-trusted-advisor-check-refresh-statuses. The describe function calls describe-trusted-advisor-check-result.

To simmulate it with the CLI follow below commands:

To gather all possible checks and their corresponding IDs:
```
$ aws support describe-trusted-advisor-checks --language en
```
To refresh a specific check's data:
```
$aws support refresh-trusted-advisor-check --check-id Qch7DwouX1
```
To check the refresh status of the check:
```
$ aws support describe-trusted-advisor-check-refresh-statuses --check-ids Qch7DwouX1
```
To get the official Trusted Advisor results of that check:
```
$ aws support describe-trusted-advisor-check-result --check-id Qch7DwouX1 --language en
```
#How to Configure More Slave Accounts for TA Checks
In config.json, go to the trsuted_advisor_recommendations section, and add the account ID for each check you want to enable on that account. Make sure that account has all updated permissions needed for Trusted Advisor checks. These permissions were updated in identificaiton-crossaccount-role.json

#To deploy in AWS Environment through Cloud Formation Templates

Make any applicable changes using above directions to deployment/configs/config-tadev.json

```
$ cd deployment
$ ./build_packages.sh configs/config.json
$ aws s3 sync packages/ s3://{s3 bucket name}

$ cd cf-templates
$ aws cloudformation deploy --template-file identification.json --stack-name New-Test-CloudSecurity-Hammer-Identification-Dev-Stack --parameter-overrides IdentificationIAMRole=new-test-cloudsecurity-master-role NestedStackTemplate=https://ta-checks-test.s3-us-west-2.amazonaws.com/cf-templates/identification-nested.json SourceS3Bucket=ta-checks-test  IdentificationCheckRateExpression="16 * * ? *" ResourcesPrefix="dev-hammer-test" --s3-bucket ta-checks-test --s3-prefix cf-templates --region us-west-2

```
To update lambda code, do the first 3 commands above to sync the s3 bucket and then run:

```
$ aws lambda update-function-code  --function function-name --s3-bucket {s3 bucket} --s3-key scanzipfile
```
An example of this, would be :
```
$ aws lambda update-function-code  --function dev-hammer-describe-ta-checks --{s3 bucket} --s3-key trusted-advisor-checks-identification.zip
```



