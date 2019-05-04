# policy-tools




```bash
== Allowed Actions ==

allow Action: ec2:DescribeInstances
	Statement resides in policy: root-allowlist.json
	Statement:
	, {"Sid": "ReadOnlyPermissionsEc2", "Effect": "Allow", "Resource": "*", "Action": ["ec2:Describe*", "ec2:Get*", "ec2:Search*"]}

== Denied Actions ==

deny Action: rds:CreateDBInstance
deny Type: implicit
```
