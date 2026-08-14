import boto3

def detect_public_s3_buckets():
    """
    Checks every S3 bucket in the account for public accessibility.
    Returns a list of findings (dicts) for any bucket that is publicly readable.
    """
    s3 = boto3.client('s3')
    findings = []

    response = s3.list_buckets()
    buckets = response['Buckets']

    for bucket in buckets:
        bucket_name = bucket['Name']
        is_public = False
        reason = []

        try:
            public_access_block = s3.get_public_access_block(Bucket=bucket_name)
            config = public_access_block['PublicAccessBlockConfiguration']
            if not all(config.values()):
                is_public = True
                reason.append("Block Public Access exists but is not fully enabled (one or more settings are off)")
        except s3.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchPublicAccessBlockConfiguration':
                is_public = True
                reason.append("No Block Public Access configuration exists for this bucket")
            else:
                reason.append(f"Could not check Block Public Access settings: {error_code}")

        try:
            policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
            if policy_status['PolicyStatus']['IsPublic']:
                is_public = True
                reason.append("Bucket policy allows public access")
        except s3.exceptions.ClientError:
            pass

        if is_public:
            findings.append({
                "finding_type": "s3_public_bucket",
                "resource_type": "S3 Bucket",
                "resource_name": bucket_name,
                "issue": "Publicly accessible bucket",
                "details": reason
            })

    return findings

def detect_open_security_groups():
    """
    Checks every security group in the account for inbound rules that allow
    unrestricted access (0.0.0.0/0) on sensitive ports.
    Returns a list of findings for any security group with this exposure.
    """
    ec2 = boto3.client('ec2')
    findings = []

    SENSITIVE_PORTS = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB"
    }

    response = ec2.describe_security_groups()
    security_groups = response['SecurityGroups']

    for sg in security_groups:
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'N/A')
        open_rules = []

        for permission in sg['IpPermissions']:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')

            for ip_range in permission.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    if from_port is not None and to_port is not None:
                        for port, service_name in SENSITIVE_PORTS.items():
                            if from_port <= port <= to_port:
                                open_rules.append({
                                    "port": port,
                                    "service": service_name,
                                    "source": "0.0.0.0/0 (anywhere)"
                                })

        if open_rules:
            findings.append({
                "finding_type": "open_security_group",
                "resource_type": "Security Group",
                "resource_name": sg_name,
                "resource_id": sg_id,
                "issue": "Inbound rule allows unrestricted access on sensitive port(s)",
                "details": open_rules
            })

    return findings

def detect_iam_wildcard_policies():
    """
    Checks every customer-managed IAM policy (and inline policies on users,
    groups, and roles) for statements that grant overly broad access via
    wildcards in Action and/or Resource.
    Returns a list of findings for any policy statement with this exposure.
    """
    iam = boto3.client('iam')
    findings = []

    def as_list(value):
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    def check_statements(statements, resource_type, resource_name, attached_to):
        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue

            actions = as_list(stmt.get('Action'))
            resources = as_list(stmt.get('Resource'))
            not_actions = as_list(stmt.get('NotAction'))

            action_is_wildcard = '*' in actions
            resource_is_wildcard = '*' in resources
            partial_wildcard_actions = [a for a in actions if isinstance(a, str) and '*' in a and a != '*']

            issue = None
            reason = []
            severity_hint = None

            if action_is_wildcard and resource_is_wildcard:
                issue = "IAM policy grants unrestricted admin access (Action:* on Resource:*)"
                reason.append("Statement allows every action on every resource")
                severity_hint = "full_admin"
            elif action_is_wildcard:
                issue = "IAM policy grants all actions on a scoped resource"
                reason.append("Statement allows Action:* even though Resource is scoped")
                severity_hint = "action_wildcard_scoped_resource"
            elif partial_wildcard_actions and resource_is_wildcard:
                issue = "IAM policy grants a service-level wildcard action on all resources"
                reason.append(f"Statement allows {partial_wildcard_actions} on Resource:*")
                severity_hint = "service_wildcard_all_resources"
            elif not_actions and resource_is_wildcard:
                issue = "IAM policy uses NotAction with Resource:*"
                reason.append("Statement implicitly allows all actions except those listed, on every resource")
                severity_hint = "notaction_resource_wildcard"
            elif partial_wildcard_actions:
                issue = "IAM policy uses a partial wildcard action"
                reason.append(f"Statement allows {partial_wildcard_actions} even though resources are scoped")
                severity_hint = "partial_wildcard_scoped"

            if issue:
                findings.append({
                    "finding_type": "iam_wildcard_policy",
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "attached_to": attached_to,
                    "issue": issue,
                    "details": reason,
                    "severity_hint": severity_hint
                })

    paginator = iam.get_paginator('list_policies')
    for page in paginator.paginate(Scope='Local', OnlyAttached=True):
        for policy in page['Policies']:
            policy_arn = policy['Arn']
            policy_name = policy['PolicyName']

            version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy['DefaultVersionId'])
            document = version['PolicyVersion']['Document']
            statements = as_list(document.get('Statement'))

            entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
            attached_to = (
                [u['UserName'] for u in entities.get('PolicyUsers', [])] +
                [g['GroupName'] for g in entities.get('PolicyGroups', [])] +
                [r['RoleName'] for r in entities.get('PolicyRoles', [])]
            )

            check_statements(statements, "IAM Managed Policy", policy_name, attached_to)

    role_paginator = iam.get_paginator('list_roles')
    for page in role_paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            policy_names = iam.list_role_policies(RoleName=role_name).get('PolicyNames', [])

            for policy_name in policy_names:
                doc_response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                statements = as_list(doc_response['PolicyDocument'].get('Statement'))
                check_statements(statements, "IAM Inline Policy (Role)", policy_name, [role_name])

    return findings

def detect_unencrypted_ebs_volumes():
    """
    Checks every EBS volume in the current region for missing encryption at rest.
    Returns a list of findings for any volume that is not encrypted.
    """
    ec2 = boto3.client('ec2')
    findings = []

    response = ec2.describe_volumes()
    volumes = response['Volumes']

    for volume in volumes:
        if volume.get('Encrypted', False):
            continue

        volume_id = volume['VolumeId']

        name_tag = volume_id
        for tag in volume.get('Tags', []):
            if tag.get('Key') == 'Name':
                name_tag = tag.get('Value')

        attached_instances = [a['InstanceId'] for a in volume.get('Attachments', [])]

        details = [f"Volume ID: {volume_id}", f"Size: {volume.get('Size')} GiB", f"Type: {volume.get('VolumeType')}"]
        if attached_instances:
            details.append(f"Attached to instance(s): {attached_instances}")
        else:
            details.append("Currently unattached")

        findings.append({
            "finding_type": "unencrypted_ebs_volume",
            "resource_type": "EBS Volume",
            "resource_name": name_tag,
            "resource_id": volume_id,
            "issue": "Unencrypted EBS volume",
            "details": details,
            "attached_instances": attached_instances
        })

    return findings

def detect_missing_mfa():
    """
    Checks the root account and every IAM user with console access for
    missing multi-factor authentication (MFA).

    IAM users with only programmatic (access key) access are skipped —
    MFA protects human console login events, so a user with no console
    login profile isn't a valid target for this check.
    """
    iam = boto3.client('iam')
    findings = []

    account_summary = iam.get_account_summary()['SummaryMap']
    if account_summary.get('AccountMFAEnabled', 0) == 0:
        findings.append({
            "finding_type": "missing_mfa_root",
            "resource_type": "Root Account",
            "resource_name": "root",
            "issue": "Root account does not have MFA enabled",
            "details": ["The AWS account root user has no MFA device registered — the single highest-priority finding possible, since root access is unrestricted."]
        })

    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            user_name = user['UserName']

            try:
                iam.get_login_profile(UserName=user_name)
            except iam.exceptions.NoSuchEntityException:
                continue

            mfa_devices = iam.list_mfa_devices(UserName=user_name)['MFADevices']
            if not mfa_devices:
                findings.append({
                    "finding_type": "missing_mfa_console_user",
                    "resource_type": "IAM User",
                    "resource_name": user_name,
                    "issue": "IAM user has console access but no MFA device registered",
                    "details": [f"User '{user_name}' can log into the AWS console with just a password, with no second factor required."]
                })

    return findings