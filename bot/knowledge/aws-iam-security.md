# AWS IAM Security - Well-Architected Framework Guidance

This knowledge base covers AWS Identity and Access Management (IAM) security best practices strictly aligned with the AWS Well-Architected Framework (WAF) Security Pillar.

## WAF Security Pillar Mapping

AWS IAM security is the foundation for multiple WAF Security Pillar areas:
- **SEC02**: How do you manage identities for people and machines?
- **SEC03**: How do you manage permissions for people and machines?
- **SEC01**: How do you securely operate your workload? (governance, root account)
- **SEC04**: How do you detect and investigate security events? (IAM monitoring)
- **SEC09**: How do you anticipate, respond to, and recover from incidents? (break-glass access)

## Core IAM Security Principles (WAF-Aligned)

### Strong Identity Foundation (WAF Design Principle)
- Centralize identity management using AWS IAM Identity Center (formerly AWS SSO)
- Eliminate long-term credentials in favor of temporary credentials
- Enforce multi-factor authentication (MFA) for human identities
- Use identity federation for workforce access
- Implement least privilege from the start

## Shared Responsibility Model for IAM (SEC01-BP01)

### AWS Responsibilities (Security OF the Cloud)

AWS is responsible for the infrastructure and foundational security of IAM:
- Physical security of data centers and hardware
- IAM service infrastructure and availability
- Network infrastructure supporting IAM API endpoints
- Patching and maintaining IAM service software
- Disaster recovery and business continuity for IAM service
- Compliance certifications for IAM infrastructure (SOC, PCI-DSS, ISO, etc.)

### Customer Responsibilities (Security IN the Cloud)

Customers are responsible for configuring and securing IAM identities, policies, and access:

**Identity and Access Management (SEC02, SEC03)**
- Creating and managing IAM users, groups, and roles
- Defining and maintaining IAM policies (identity-based, resource-based, SCPs)
- Configuring MFA for all human identities
- Managing access keys, passwords, and credential lifecycle
- Implementing least privilege permissions
- Configuring IAM Identity Center and federated access
- Setting password policies and credential rotation requirements

**Monitoring and Detection (SEC04)**
- Enabling CloudTrail logging for IAM API activity
- Configuring CloudWatch alarms for IAM events
- Enabling IAM Access Analyzer for external access detection
- Deploying AWS Config rules for IAM compliance monitoring
- Reviewing GuardDuty findings for IAM threats
- Analyzing and responding to IAM security events

**Governance and Compliance (SEC01)**
- Securing root account credentials
- Implementing Service Control Policies (SCPs) in AWS Organizations
- Defining and enforcing permissions boundaries
- Regular access reviews and permission audits
- Documenting IAM architecture and procedures
- Ensuring compliance with regulatory requirements

**Incident Response (SEC09)**
- Detecting and responding to compromised credentials
- Implementing break-glass procedures for emergency access
- Revoking permissions and rotating credentials after incidents
- Forensic analysis of IAM-related security events

### Shared Responsibility for IAM Roles Anywhere (SEC02-BP03)
- **AWS**: Provides the IAM Roles Anywhere service infrastructure, certificate validation, and temporary credential issuance
- **Customer**: Manages certificate authority (CA), issues X.509 certificates, configures trust anchors, rotates certificates, and implements certificate revocation

### Least Privilege (SEC03-BP02)
- Grant minimum permissions required to perform a task
- Start with no access and add permissions as needed
- Use managed policies for common use cases
- Regularly review and refine permissions
- Remove unused permissions using IAM Access Analyzer

### Defense in Depth (SEC03-BP06)
- Layer multiple permission controls: IAM policies, resource policies, permission boundaries, SCPs
- Use condition keys to add context-based restrictions
- Implement separation of duties
- Never rely on a single permission control

### Temporary Credentials Over Long-Term (SEC02-BP03)
- Use IAM roles with temporary credentials for all workloads
- Avoid IAM user access keys wherever possible
- Use AWS STS AssumeRole for cross-account and federated access
- Implement short session durations for sensitive operations

### Automation and Traceability (WAF Design Principles)
- Automate permission management and reviews
- Enable comprehensive logging with AWS CloudTrail
- Monitor IAM activity with AWS Config, GuardDuty, and IAM Access Analyzer
- Implement policy-as-code using Infrastructure as Code (IaC)

## Root Account Security

### SEC01-BP01: Secure Root User Access

**Root Account Characteristics**
- Full unrestricted access to all AWS resources and billing
- Cannot be restricted by IAM policies, SCPs, or permission boundaries
- Required for very few tasks (account closure, billing contact changes, some support plan changes)
- Highest risk if compromised

**WAF Root Account Security Requirements**

1. **Enable MFA (MANDATORY)** (SEC02-BP05)
   - Use hardware MFA device (YubiKey, Gemalto) over virtual MFA
   - Store backup codes in physically secured location
   - Never share MFA device or seed

2. **Lock Away Access Keys** (SEC03-BP04)
   - NEVER create root access keys
   - If root access keys exist, DELETE them immediately
   - Use IAM users or roles for programmatic access

3. **Use Root Only for Required Tasks**
   - Document approved root user use cases
   - Require business justification and approval for root access
   - Log all root user activity in CloudTrail

4. **Create Strong Password**
   - Use password manager to generate complex, unique password
   - Never reuse passwords from other accounts
   - Store password in secured vault (separate from MFA device)

5. **Set Up Root Account Monitoring** (SEC04-BP01)
   - CloudWatch alarm for root user API activity
   - EventBridge rule for root login events
   - Security Hub findings for root account usage
   - AWS Config rule: `root-account-mfa-enabled`

**Root Account Monitoring CloudWatch Alarm Pattern**
```json
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "userIdentity": {
      "type": ["Root"]
    }
  }
}
```

6. **Designate Alternative Contacts**
   - Configure billing, operations, and security contacts
   - Reduces need to access root account for notifications

7. **Use AWS Organizations Master Account Protection** (SEC01-BP07)
   - Limit root account to billing and organizational management
   - Never deploy workloads in master account
   - Apply restrictive SCPs even to master account where possible

## IAM Users, Groups, and Roles

### IAM Users (SEC02-BP01)

**WAF Guidance on IAM Users**
- Use IAM users only when IAM Identity Center or federation is not feasible
- Prefer temporary credentials (roles) over permanent user credentials
- Each individual must have unique IAM user (never share credentials)
- Enforce MFA for all human users

**IAM User Security Best Practices**

1. **Password Policy Enforcement** (SEC02-BP04)
   - Minimum length: 14 characters (WAF recommendation)
   - Require uppercase, lowercase, numbers, symbols
   - Password expiration: 90 days (align with organizational policy)
   - Prevent password reuse (at least 24 previous passwords)
   - AWS account-level password policy applies to all IAM users

2. **MFA Enforcement** (SEC02-BP05)
   - Virtual MFA (Google Authenticator, Authy): Acceptable for most users
   - Hardware MFA (YubiKey, Gemalto): Required for privileged users
   - FIDO2 security keys: Highest assurance (phishing-resistant)
   - Use IAM policy condition to deny all actions without MFA:
```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```

3. **Access Key Management** (SEC03-BP04)
   - Minimize use of long-term access keys
   - Never embed access keys in code (use IAM roles for EC2, Lambda, ECS)
   - Rotate access keys every 90 days (AWS Config rule: `access-keys-rotated`)
   - Use IAM credential report to audit key age
   - Delete inactive keys (AWS Config rule: `iam-user-unused-credentials-check`)

4. **Credential Storage**
   - Never store credentials in plaintext
   - Use AWS Secrets Manager or Systems Manager Parameter Store for application credentials
   - Use environment variables or instance metadata for temporary credentials

### IAM Groups (SEC03-BP07)

**WAF Guidance on Groups**
- Assign permissions to groups, not individual users
- Simplifies permission management at scale
- Enables role-based access control (RBAC)
- Easier to audit and maintain

**Group Design Patterns**
- **Job function groups**: Developers, Operators, DBAdmins, SecurityAuditors
- **Environment groups**: Production, Staging, Development
- **Project/team groups**: TeamA-ReadOnly, TeamB-FullAccess
- Use AWS managed policies for job functions where appropriate (ViewOnlyAccess, PowerUserAccess, DatabaseAdministrator)

**Group Security Best Practices**
- Users can belong to multiple groups (permissions are union of all policies)
- Apply least privilege at group level
- Use inline policies sparingly (prefer managed policies for reusability)
- Document group purpose and intended membership

### IAM Roles (SEC02-BP03, SEC03-BP01)

**WAF Roles Philosophy**
- Roles are the primary mechanism for granting permissions in AWS
- Use roles for all programmatic access (EC2, Lambda, ECS, cross-account)
- Use roles for federated users and temporary access
- Roles use temporary security credentials (automatic rotation)

**Role Types and Use Cases**

1. **AWS Service Roles** (SEC02-BP03)
   - EC2 instance profiles
   - Lambda execution roles
   - ECS task roles
   - RDS enhanced monitoring roles
   - Each service role should have least privilege for its specific function

2. **Cross-Account Roles** (SEC03-BP05)
   - Enable secure access between AWS accounts
   - Centralized identity account assumes roles in workload accounts
   - Reduces credential sprawl
   - Trust policy defines who can assume the role
   - Audit cross-account access via CloudTrail

3. **Federated Roles** (SEC02-BP01)
   - Integrate with external identity providers (SAML, OIDC)
   - Use AWS IAM Identity Center for workforce federation
   - Map IdP groups to AWS permission sets
   - Temporary credentials only (no long-term keys)

4. **Service-Linked Roles** (AWS-Managed)
   - Predefined roles for AWS services (AWS Config, AWS Organizations, Backup)
   - Automatically created by service
   - Cannot modify permissions (AWS-managed)
   - Safe to use; follow principle of least privilege for service functionality

**Role Security Best Practices**

1. **Trust Policies** (SEC03-BP03)
   - Define who/what can assume the role
   - Use conditions to restrict assumption (IP address, MFA, time, source account)
   - Never use wildcard principal (`"Principal": "*"`) without strict conditions
   - Cross-account trust example:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-12345"
        },
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    }
  ]
}
```

2. **External ID for Third-Party Access** (SEC03-BP05)
   - Use External ID for confused deputy prevention
   - Generate unique, random External ID for each third-party integration
   - Store External ID securely (never hardcode)

3. **Session Duration** (SEC02-BP03)
   - Set maximum session duration based on security requirements
   - 1 hour for highly privileged roles
   - 12 hours for standard operational roles
   - Require re-authentication (and re-MFA) after session expiration

4. **Role Chaining**
   - Limit role chaining to necessary scenarios only
   - Each AssumeRole call reduces max session duration
   - Complicates audit trail (use CloudTrail to track chain)

## IAM Policies

### Policy Types (SEC03-BP02)

1. **Identity-Based Policies**
   - Attached to IAM users, groups, or roles
   - Managed policies: Reusable across multiple identities
   - Inline policies: Embedded directly in single identity (use sparingly)
   - AWS managed policies: Maintained by AWS for common use cases
   - Customer managed policies: Custom policies you create and maintain

2. **Resource-Based Policies** (SEC03-BP03)
   - Attached to AWS resources (S3 buckets, KMS keys, Lambda functions, SQS queues, SNS topics, Secrets Manager secrets)
   - Define who can access the resource and what actions they can perform
   - Support cross-account access without role assumption
   - Principal element specifies trusted entities
   - Evaluated in combination with identity-based policies for access decisions

### Resource-Based Policies Deep Dive (SEC03-BP03)

**When to Use Resource-Based Policies vs. Identity-Based Policies**

Use **resource-based policies** when:
- Granting cross-account access to specific resources (simpler than roles)
- Centralizing access control on the resource itself
- Allowing access from AWS service principals (Lambda, CloudTrail, etc.)
- Resource access should be managed by resource owner, not identity owner
- Need to grant access without requiring AssumeRole

Use **identity-based policies** when:
- Managing permissions for users, groups, or roles
- Permissions apply across multiple resources
- Access control is centralized with identity management team
- Need to control what identities can do (user-centric model)

**S3 Bucket Policies** (SEC03-BP03)

S3 bucket policies control access to buckets and objects. They are evaluated alongside IAM policies and S3 ACLs (avoid ACLs; prefer bucket policies).

Example 1: Grant cross-account read access to specific prefix
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCrossAccountRead",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/DataAnalystRole"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-shared-bucket",
        "arn:aws:s3:::my-shared-bucket/shared-data/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-1234567890"
        }
      }
    }
  ]
}
```

Example 2: Enforce encryption in transit (require HTTPS)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-secure-bucket",
        "arn:aws:s3:::my-secure-bucket/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

Example 3: Require encryption at rest (deny unencrypted uploads)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedObjectUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-secure-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    }
  ]
}
```

Example 4: CloudTrail bucket policy (allow CloudTrail service to write logs)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::my-cloudtrail-bucket"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-cloudtrail-bucket/AWSLogs/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
```

**KMS Key Policies** (SEC03-BP03)

KMS key policies are the primary access control mechanism for KMS keys. Unlike most AWS services, IAM policies alone cannot grant access to KMS keys without a corresponding key policy.

Example 1: Basic KMS key policy with cross-account decrypt
```json
{
  "Version": "2012-10-17",
  "Id": "key-policy-1",
  "Statement": [
    {
      "Sid": "Enable IAM policies",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow cross-account decrypt via S3",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/S3ReadRole"
      },
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "s3.us-east-1.amazonaws.com"
        }
      }
    }
  ]
}
```

Example 2: KMS key policy with encryption context requirement
```json
{
  "Sid": "AllowEncryptionWithContext",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:role/ApplicationRole"
  },
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:EncryptionContext:Department": "Finance"
    }
  }
}
```

**Lambda Resource Policies** (SEC03-BP03)

Lambda resource policies control who can invoke a function. They enable cross-account and service invocation without IAM roles.

Example 1: Allow S3 to invoke Lambda function
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3Invoke",
      "Effect": "Allow",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
      "Condition": {
        "ArnLike": {
          "AWS:SourceArn": "arn:aws:s3:::my-bucket"
        },
        "StringEquals": {
          "AWS:SourceAccount": "123456789012"
        }
      }
    }
  ]
}
```

Example 2: Allow cross-account Lambda invocation
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCrossAccountInvoke",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/InvokerRole"
      },
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:us-east-1:123456789012:function:shared-function"
    }
  ]
}
```

**SNS Topic Policies** (SEC03-BP03)

SNS topic policies control who can publish to and subscribe to topics.

Example: SNS topic policy allowing CloudWatch alarms and cross-account subscription
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudWatchAlarms",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudwatch.amazonaws.com"
      },
      "Action": [
        "SNS:Publish"
      ],
      "Resource": "arn:aws:sns:us-east-1:123456789012:my-alarm-topic"
    },
    {
      "Sid": "AllowCrossAccountSubscribe",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": [
        "SNS:Subscribe",
        "SNS:Receive"
      ],
      "Resource": "arn:aws:sns:us-east-1:123456789012:my-topic",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-1234567890"
        }
      }
    }
  ]
}
```

**SQS Queue Policies** (SEC03-BP03)

SQS queue policies control who can send and receive messages.

Example: SQS queue policy allowing SNS to send messages and cross-account receive
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSNSPublish",
      "Effect": "Allow",
      "Principal": {
        "Service": "sns.amazonaws.com"
      },
      "Action": "SQS:SendMessage",
      "Resource": "arn:aws:sqs:us-east-1:123456789012:my-queue",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:my-topic"
        }
      }
    },
    {
      "Sid": "AllowCrossAccountReceive",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/ConsumerRole"
      },
      "Action": [
        "SQS:ReceiveMessage",
        "SQS:DeleteMessage",
        "SQS:GetQueueAttributes"
      ],
      "Resource": "arn:aws:sqs:us-east-1:123456789012:my-queue"
    }
  ]
}
```

**Resource-Based Policy Best Practices (SEC03-BP03)**

1. **Use Specific Principals** - Avoid `"Principal": "*"` unless paired with strict conditions
2. **Restrict by Organization ID** - Use `aws:PrincipalOrgID` condition to limit access to your AWS Organization
3. **Require Secure Transport** - Use `aws:SecureTransport` condition to enforce HTTPS
4. **Use Source Account/ARN Conditions** - Prevent confused deputy problem with `AWS:SourceAccount` and `AWS:SourceArn`
5. **Combine with Identity Policies** - Remember effective permissions are intersection/union of both policy types
6. **Enable Resource Policy Validation** - Use IAM Access Analyzer to detect overly permissive resource policies
7. **Document External Access** - Archive intended external access findings in IAM Access Analyzer with justification

3. **Permissions Boundaries** (SEC03-BP06)
   - Advanced feature to set maximum permissions for IAM entities
   - Does not grant permissions; only limits them
   - Use case: Delegate permission management while preventing privilege escalation
   - Example: Allow developers to create roles but only with specific permissions boundary

4. **Service Control Policies (SCPs)** (SEC01-BP07)
   - AWS Organizations feature
   - Set maximum permissions for accounts in organization
   - Do not grant permissions; only restrict them
   - Apply to all users and roles in account (including root, except for exempted actions)
   - Use for organization-wide security guardrails

5. **Session Policies**
   - Passed during AssumeRole, GetFederationToken, or GetSessionToken
   - Further limit permissions of temporary credentials
   - Used for temporary, context-specific access restrictions
   - Effective permissions = intersection of identity policy and session policy

### Least Privilege Policy Design (SEC03-BP02)

**WAF Least Privilege Best Practices**

1. **Start with Deny-by-Default**
   - IAM denies all actions by default
   - Only grant permissions explicitly required
   - Use `NotAction` sparingly (can lead to overly permissive policies)

2. **Use Specific Actions**
   - Avoid `s3:*` or `ec2:*`
   - List specific actions: `s3:GetObject`, `s3:PutObject`
   - Use action wildcards only when appropriate: `s3:Get*` for all read operations

3. **Restrict Resources** (SEC03-BP03)
   - Never use `"Resource": "*"` unless absolutely necessary
   - Specify ARNs for specific resources
   - Use ARN wildcards for prefixes: `arn:aws:s3:::my-bucket/team-a/*`
   - Example: Limit S3 access to specific bucket and prefix:
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": "arn:aws:s3:::my-data-bucket/team-alpha/*"
}
```

4. **Use Conditions for Context** (SEC03-BP02)
   - Add conditions based on: IP address, MFA, time, tag values, request parameters
   - Require MFA for sensitive operations:
```json
{
  "Effect": "Allow",
  "Action": "ec2:TerminateInstances",
  "Resource": "*",
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}
```
   - Restrict access to specific VPC or VPC endpoint:
```json
{
  "Effect": "Deny",
  "Action": "s3:*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:SourceVpce": "vpce-1234567890abcdef0"
    }
  }
}
```

5. **Tag-Based Access Control (ABAC)** (SEC03-BP02)
   - Grant permissions based on tag matching between principal and resource
   - Scalable alternative to creating multiple policies
   - Example: Allow users to manage EC2 instances only if tags match:
```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:StartInstances",
    "ec2:StopInstances"
  ],
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringEquals": {
      "ec2:ResourceTag/Owner": "${aws:PrincipalTag/Owner}"
    }
  }
}
```

### Permission Boundaries (SEC03-BP06)

**Use Cases**
- Delegate IAM role/user creation to developers without risk of privilege escalation
- Enforce organizational security baselines
- Limit maximum permissions for specific teams or projects

**Permission Boundary Pattern**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "dynamodb:*",
        "lambda:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "organizations:*",
        "account:*"
      ],
      "Resource": "*"
    }
  ]
}
```

**Enforcement Pattern** (SEC03-BP06)
- Attach permission boundary to all roles/users created by delegated admins
- Use IAM policy to require permission boundary on CreateUser/CreateRole:
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:CreateUser",
    "iam:CreateRole"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/DeveloperBoundary"
    }
  }
}
```

### Service Control Policies (SCPs) (SEC01-BP07)

**WAF SCP Guidance**
- Apply organization-wide security guardrails
- Prevent accounts from deviating from security baseline
- Layer with IAM policies for defense in depth
- SCPs do not grant permissions; only limit maximum permissions

**Common SCP Patterns**

1. **Deny Public S3 Access**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:AccountLevelPublicAccessBlockConfig/BlockPublicAcls": "true"
        }
      }
    }
  ]
}
```

2. **Require Encryption for EBS Volumes**
```json
{
  "Effect": "Deny",
  "Action": "ec2:CreateVolume",
  "Resource": "*",
  "Condition": {
    "Bool": {
      "ec2:Encrypted": "false"
    }
  }
}
```

3. **Restrict AWS Regions** (SEC05-BP01)
```json
{
  "Effect": "Deny",
  "NotAction": [
    "iam:*",
    "organizations:*",
    "route53:*",
    "cloudfront:*",
    "support:*",
    "budgets:*"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": [
        "us-east-1",
        "us-west-2"
      ]
    }
  }
}
```

4. **Prevent Disabling Security Services**
```json
{
  "Effect": "Deny",
  "Action": [
    "guardduty:DeleteDetector",
    "guardduty:DisassociateFromMasterAccount",
    "securityhub:DisableSecurityHub",
    "config:DeleteConfigurationRecorder",
    "config:StopConfigurationRecorder",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail"
  ],
  "Resource": "*"
}
```

5. **Require MFA for Sensitive Actions**
```json
{
  "Effect": "Deny",
  "Action": [
    "ec2:TerminateInstances",
    "rds:DeleteDBInstance",
    "s3:DeleteBucket"
  ],
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```

**SCP Design Best Practices**
- Start with permissive SCPs; gradually restrict as needed
- Test SCPs in non-production OUs first
- Document SCP purpose and exceptions
- Use SCP inheritance (apply to OUs, inherited by child OUs and accounts)
- FullAWSAccess SCP is attached by default when creating an organization; it can be detached and replaced with custom SCPs that define allowed services

## AWS IAM Identity Center (SSO) (SEC02-BP01)

### WAF Guidance on IAM Identity Center

IAM Identity Center is the **WAF-recommended** solution for workforce identity management:
- Centralized access management for multiple AWS accounts
- Integration with external identity providers (Azure AD, Okta, Google Workspace)
- Temporary credentials only (no long-term access keys)
- Built-in MFA support
- Simplified user experience (single sign-on)

### Identity Center Architecture

**Identity Source Options**
1. **Identity Center directory**: Built-in identity store for users and groups
2. **Active Directory**: AWS Managed Microsoft AD or AD Connector
3. **External IdP**: SAML 2.0 identity provider (Okta, Azure AD, Ping Identity)

**WAF Recommendation**: Use external IdP if already in use; otherwise use Identity Center directory

### Permission Sets (SEC03-BP02)

**What are Permission Sets?**
- Templates that define AWS permissions
- Assigned to users or groups for specific AWS accounts
- Automatically create IAM roles in target accounts
- Centrally managed from Identity Center

**Permission Set Components**
- AWS managed policies
- Customer managed policies (stored in Identity Center)
- Inline policy
- Permissions boundary (optional)
- Session duration (1-12 hours)

**Permission Set Best Practices**
- Create permission sets aligned with job functions (Developer, DataScientist, SecurityAuditor)
- Use descriptive names and descriptions
- Start with AWS managed policies (ViewOnlyAccess, PowerUserAccess)
- Customize with inline policies for specific requirements
- Apply permissions boundary to limit maximum permissions
- Set short session durations for privileged permission sets (1-2 hours)

**Example Permission Set Structure**
- **ReadOnly-AllAccounts**: ViewOnlyAccess policy, 12-hour session
- **Developer-Development**: PowerUserAccess + custom policies, 8-hour session
- **Developer-Production**: Limited change permissions, 4-hour session, MFA required
- **Administrator-Production**: AdministratorAccess, 1-hour session, MFA required, specific users only

### Multi-Account Access Strategy (SEC01-BP07)

**WAF-Aligned Pattern**
1. Identity account: Hosts IAM Identity Center instance and user identities
2. Workload accounts: Production, development, staging, security tooling
3. Permission sets assigned per account with least privilege
4. Users authenticate once, assume roles in multiple accounts

**Benefits**
- No IAM users in workload accounts (all access via federated roles)
- Centralized permission management
- Consistent access patterns across organization
- Automatic credential rotation (temporary credentials)
- Single MFA prompt for all account access

### Identity Center Security Best Practices (SEC02-BP01, SEC02-BP05)

1. **Enable MFA for All Users**
   - Required for access to AWS accounts
   - Use FIDO2 security keys for highest assurance
   - Register multiple MFA devices for recovery

2. **Integrate with Corporate IdP**
   - Use existing identity lifecycle management
   - Automatic provisioning/deprovisioning via SCIM
   - Leverage existing authentication policies (password complexity, MFA)

3. **Apply Least Privilege to Permission Sets**
   - Separate permission sets for different environments (dev vs. prod)
   - Time-bound access for sensitive operations (just-in-time access)
   - Regular review and removal of unused permission sets

4. **Monitor Identity Center Activity** (SEC04-BP01)
   - Enable CloudTrail for Identity Center API calls
   - Monitor authentication failures and permission set changes
   - Alert on assignment of highly privileged permission sets

5. **Session Duration Alignment with Risk**
   - 1 hour: Administrator access, production write access
   - 4 hours: Standard production access
   - 8-12 hours: Development environment, read-only access

## Multi-Factor Authentication (MFA) (SEC02-BP05)

### WAF MFA Guidance

MFA is a **mandatory** WAF Security Pillar best practice for all human identities.

**MFA Types (in order of security strength)**

1. **FIDO2 Security Keys** (Highest Assurance)
   - Hardware-based, phishing-resistant
   - YubiKey, Titan Security Key
   - WAF recommendation for privileged users
   - Supports WebAuthn standard
   - Can be used across multiple accounts

2. **Hardware MFA Devices**
   - Gemalto, SurePassID
   - Time-based one-time password (TOTP)
   - Dedicated physical device
   - Higher cost; suitable for high-security environments

3. **Virtual MFA Devices** (Acceptable for Most Users)
   - Smartphone apps: Google Authenticator, Microsoft Authenticator, Authy
   - TOTP-based
   - Free and convenient
   - Risk: Compromise of smartphone compromises MFA

**MFA Enforcement Strategies**

1. **Policy-Based MFA Requirement** (SEC02-BP05)
   - Deny all actions unless MFA is present:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

2. **SCP-Based MFA Requirement** (organization-wide)
   - Apply SCP requiring MFA for sensitive actions (EC2 termination, S3 deletion, IAM changes)

3. **IAM Identity Center MFA Requirement**
   - Enable MFA at Identity Center level (enforced for all users)
   - Configure MFA challenge frequency (every sign-in vs. context-based)

**MFA for Programmatic Access** (SEC02-BP03)
- `aws sts get-session-token --serial-number arn:aws:iam::123456789012:mfa/user --token-code 123456`
- Generates temporary credentials valid for 12 hours (with MFA) or 1 hour (without MFA)
- Use for AWS CLI/SDK access when using IAM users
- Prefer IAM roles (no MFA required if trust policy enforces MFA for AssumeRole)

**MFA Best Practices**
- Register multiple MFA devices for backup (where supported)
- Securely store MFA recovery codes
- Never share MFA devices or seeds
- Use hardware/FIDO2 MFA for root account and privileged users
- Monitor for MFA device changes (potential account compromise indicator)

## Access Keys and Credential Management (SEC03-BP04)

### WAF Guidance on Access Keys

**Primary Principle**: Avoid long-term access keys. Use IAM roles with temporary credentials instead.

### When Access Keys are Unavoidable

**Limited Valid Use Cases**
- Third-party applications that don't support IAM roles
- Root account backup access (NOT RECOMMENDED; avoid creating root access keys)
- IAM users for developers (prefer IAM Identity Center instead)

### Access Key Security Best Practices

1. **Minimize Creation** (SEC02-BP03)
   - Use IAM roles for EC2, Lambda, ECS, EKS (temporary credentials via instance metadata)
   - Use IAM Identity Center for developer access (temporary credentials)
   - Use IAM roles for cross-account access (AssumeRole)
   - Only create access keys when no alternative exists

2. **Rotate Regularly** (SEC03-BP04)
   - Rotate access keys every 90 days (industry standard)
   - AWS Config rule: `access-keys-rotated` (configurable age threshold)
   - Rotation process:
     1. Create second access key
     2. Update applications to use new key
     3. Verify applications functioning with new key
     4. Deactivate old key (don't delete immediately)
     5. Monitor for errors indicating old key still in use
     6. Delete old key after verification period

3. **Delete Unused Keys** (SEC03-BP04)
   - Use IAM credential report to identify key age and last usage
   - AWS Config rule: `iam-user-unused-credentials-check` (90 days unused threshold)
   - Deactivate keys before deletion (allows re-activation if needed)
   - Document key deletion in change management system

4. **Never Embed in Code** (SEC03-BP04)
   - Never commit access keys to version control (Git, SVN)
   - Use AWS Secrets Manager or Systems Manager Parameter Store for application credentials
   - Use environment variables injected at runtime (from secrets manager)
   - Scan code repositories for exposed credentials (git-secrets, GitHub secret scanning, AWS CodeGuru Reviewer)

5. **Secure Storage** (SEC03-BP04)
   - AWS CLI credentials file: `~/.aws/credentials` (permissions: 600)
   - Use AWS CLI credential profiles to manage multiple keys
   - Encrypt credentials at rest (filesystem encryption, password manager)
   - Never store credentials in plaintext files, documents, or wikis

6. **Monitor Access Key Usage** (SEC04-BP01)
   - CloudTrail logs all API calls with access key ID
   - Alert on access key usage from unexpected IP addresses or locations
   - GuardDuty findings: Exposed access keys, unusual API calls
   - IAM Access Analyzer: External access findings

### Alternatives to Access Keys (WAF-Preferred)

1. **EC2 Instance Profiles** (SEC02-BP03)
   - Attach IAM role to EC2 instance
   - Temporary credentials automatically available via instance metadata (http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name)
   - Credentials auto-rotate every 6 hours
   - No key management required

2. **ECS Task Roles** (SEC02-BP03)
   - IAM role assigned to ECS task definition
   - Temporary credentials injected into container environment
   - Each task can have unique role (better least privilege)

3. **Lambda Execution Roles** (SEC02-BP03)
   - IAM role assumed by Lambda function during execution
   - Temporary credentials available via AWS SDK
   - Automatically managed by Lambda service

4. **CodeBuild Service Role** (SEC02-BP03)
   - IAM role for build project with least privilege permissions
   - No access keys in buildspec.yml or source code

5. **IAM Roles Anywhere** (SEC02-BP03)
   - Obtain temporary AWS credentials for workloads running outside AWS
   - Uses X.509 certificates instead of long-term access keys
   - Supports on-premises servers, containers, IoT devices

### IAM Roles Anywhere (SEC02-BP03)

**What is IAM Roles Anywhere?**

IAM Roles Anywhere extends AWS IAM roles to workloads outside AWS (on-premises servers, containers, IoT devices) using X.509 certificates for authentication. This eliminates the need for long-term access keys in hybrid environments.

**WAF Alignment**: Supports temporary credentials (SEC02-BP03), eliminates long-term access keys (SEC03-BP04), and enables centralized identity management for hybrid workloads.

**IAM Roles Anywhere Architecture Components**

1. **Trust Anchor**: Reference to your certificate authority (CA) that issues X.509 certificates
2. **Profile**: Maps certificates to IAM roles and defines session policies
3. **X.509 Certificate**: Client certificate issued by your CA, used for authentication
4. **Credential Helper**: AWS-provided tool that obtains temporary credentials using certificate
5. **IAM Role**: Standard IAM role assumed by workload after certificate validation

**Trust Anchor Configuration**

Trust anchors link IAM Roles Anywhere to your certificate authority. Two types:

**AWS Certificate Manager Private CA (ACM PCA)**
```json
{
  "trustAnchorArn": "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/a1b2c3d4-5678-90ab-cdef-example11111",
  "sourceType": "AWS_ACM_PCA",
  "sourceData": {
    "acmPcaArn": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012"
  }
}
```

**External Certificate Authority (External CA)**
- Upload CA certificate (PEM format) to IAM Roles Anywhere
- Supports public or private CAs external to AWS
- Requires valid X.509 CA certificate chain

**Profile Configuration** (SEC03-BP02)

Profiles define which IAM roles can be assumed and optional session policies for additional restrictions.

Example Profile:
```json
{
  "profileArn": "arn:aws:rolesanywhere:us-east-1:123456789012:profile/a1b2c3d4-5678-90ab-cdef-example22222",
  "name": "OnPremiseAppProfile",
  "roleArns": [
    "arn:aws:iam::123456789012:role/OnPremiseS3AccessRole"
  ],
  "sessionPolicy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}",
  "durationSeconds": 3600,
  "managedPolicyArns": [],
  "tags": [
    {
      "key": "Environment",
      "value": "Production"
    }
  ]
}
```

**X.509 Certificate Requirements**

Certificates used with IAM Roles Anywhere must meet these criteria:
- Issued by CA registered in trust anchor
- Valid (not expired or revoked)
- RSA (2048-bit minimum) or ECDSA (P-256, P-384, or P-521) key
- Subject or SAN (Subject Alternative Name) field populated
- Certificate chain includes all intermediate certificates

**Certificate Issuance Example** (using OpenSSL):
```bash
# Generate private key
openssl genrsa -out workload-private-key.pem 2048

# Create certificate signing request (CSR)
openssl req -new -key workload-private-key.pem -out workload.csr \
  -subj "/C=US/ST=WA/L=Seattle/O=MyCompany/OU=Engineering/CN=on-prem-server-01"

# Sign CSR with your CA (example using CA private key)
openssl x509 -req -in workload.csr -CA ca-cert.pem -CAkey ca-private-key.pem \
  -CAcreateserial -out workload-cert.pem -days 365 -sha256
```

**Using IAM Roles Anywhere Credential Helper** (SEC02-BP03)

AWS provides a credential helper tool that runs on workloads to obtain temporary credentials.

Installation:
```bash
# Download credential helper (Linux x86_64 example)
wget https://rolesanywhere.amazonaws.com/releases/1.0.0/X86_64/Linux/aws_signing_helper
chmod +x aws_signing_helper
```

Obtaining credentials:
```bash
# Export temporary credentials as environment variables
export $(./aws_signing_helper credential-process \
  --certificate workload-cert.pem \
  --private-key workload-private-key.pem \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/a1b2c3d4... \
  --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/a1b2c3d4... \
  --role-arn arn:aws:iam::123456789012:role/OnPremiseS3AccessRole | jq -r '.[] | "AWS_ACCESS_KEY_ID=\(.AccessKeyId) AWS_SECRET_ACCESS_KEY=\(.SecretAccessKey) AWS_SESSION_TOKEN=\(.SessionToken)"')

# Use AWS CLI with temporary credentials
aws s3 ls s3://my-bucket/
```

AWS CLI configuration (using credential_process):
```ini
# ~/.aws/config
[profile roles-anywhere]
credential_process = /path/to/aws_signing_helper credential-process \
  --certificate /path/to/workload-cert.pem \
  --private-key /path/to/workload-private-key.pem \
  --trust-anchor-arn arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/a1b2c3d4... \
  --profile-arn arn:aws:rolesanywhere:us-east-1:123456789012:profile/a1b2c3d4... \
  --role-arn arn:aws:iam::123456789012:role/OnPremiseS3AccessRole
```

Then use: `aws s3 ls --profile roles-anywhere`

**Certificate Revocation** (SEC03-BP04)

IAM Roles Anywhere supports certificate revocation via Certificate Revocation Lists (CRLs).

CRL Configuration:
1. Generate CRL from your CA (contains serial numbers of revoked certificates)
2. Upload CRL to S3 bucket accessible by IAM Roles Anywhere
3. Configure trust anchor with CRL S3 location
4. IAM Roles Anywhere checks CRL before issuing credentials

Example CRL in trust anchor:
```json
{
  "trustAnchorArn": "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/a1b2c3d4...",
  "crlConfiguration": {
    "enabled": true,
    "crlDistributionPath": "s3://my-crl-bucket/ca.crl"
  }
}
```

**IAM Roles Anywhere Security Best Practices** (SEC02-BP03, SEC03-BP04)

1. **Use Short-Lived Certificates**
   - Issue certificates with 90-day or shorter validity
   - Reduces risk window if certificate compromised
   - Automate certificate renewal and rotation

2. **Implement Certificate Revocation**
   - Enable CRL checking in trust anchor
   - Maintain up-to-date CRL in S3
   - Revoke certificates immediately upon workload decommission or compromise

3. **Secure Private Keys** (SEC06-BP02)
   - Store certificate private keys encrypted at rest
   - Use hardware security modules (HSMs) for high-security environments
   - Never transmit private keys over network
   - Restrict file permissions (chmod 600 for private key files)

4. **Least Privilege IAM Roles** (SEC03-BP02)
   - Grant minimum permissions required for workload function
   - Use session policies in profile for additional restrictions
   - Separate roles for different on-premises workload types

5. **Session Duration Limits**
   - Set profile durationSeconds to minimum needed (default 3600 seconds / 1 hour)
   - Shorter durations for privileged operations
   - Forces regular certificate re-validation

6. **Monitor Certificate Usage** (SEC04-BP01)
   - Enable CloudTrail logging for IAM Roles Anywhere API calls
   - Monitor AssumeRole events with `rolesanywhere.amazonaws.com` as caller
   - Alert on certificate usage from unexpected locations or workloads
   - Track certificate issuance and revocation

7. **Trust Anchor Per Environment**
   - Separate trust anchors for production, staging, development
   - Different CA for each environment enables blast radius reduction
   - Easier certificate lifecycle management per environment

8. **Certificate Subject Validation**
   - Use certificate CN (Common Name) or SAN for workload identification
   - Map certificate subjects to specific IAM roles via profiles
   - Include identifying information in certificate subject (hostname, environment, function)

**On-Premises Integration Pattern** (SEC02-BP03)

Typical architecture for on-premises workloads accessing AWS:

1. **Certificate Authority**: Enterprise CA (Microsoft AD CS, OpenSSL CA, or ACM PCA)
2. **Trust Anchor**: Links CA to IAM Roles Anywhere
3. **On-Premises Workloads**: Servers, containers, or applications with issued certificates
4. **IAM Roles**: Least privilege roles for S3 access, DynamoDB access, etc.
5. **Profiles**: Map certificates to roles with optional session policies
6. **Monitoring**: CloudTrail, CloudWatch, GuardDuty for credential usage monitoring

**Benefits over Long-Term Access Keys**:
- No access key rotation required (temporary credentials auto-rotate)
- Certificate revocation provides immediate access termination
- Centralized identity management (CA-issued certificates)
- Better auditability (CloudTrail shows certificate subject in AssumeRole events)
- Alignment with WAF best practice: eliminate long-term credentials

6. **AWS STS AssumeRoleWithWebIdentity** (SEC02-BP03)
   - Federate access using OpenID Connect (OIDC) identity provider
   - Use case: Mobile apps, web applications, GitHub Actions
   - No long-term credentials stored in application

### Amazon Cognito for Mobile and Web Applications (SEC02-BP02, SEC02-BP03)

**What is Amazon Cognito?**

Amazon Cognito provides authentication, authorization, and user management for web and mobile applications. It supports user sign-up/sign-in, social identity federation, and integration with AWS services via temporary credentials.

**WAF Alignment**: Eliminates long-term credentials in applications (SEC02-BP03), provides identity federation (SEC02-BP01), enables least privilege access for users (SEC03-BP02), and keeps people away from data (WAF design principle).

**Cognito Components**

1. **Cognito User Pools**: User directory for sign-up, sign-in, and user management
2. **Cognito Identity Pools** (Federated Identities): Provide temporary AWS credentials to users
3. **Identity Providers (IdPs)**: External authentication sources (Google, Facebook, SAML, OIDC)

### Cognito User Pools (SEC02-BP02)

**What are User Pools?**

User pools are user directories that provide authentication and user management. They handle user registration, sign-in, password resets, MFA, and user profile management.

**User Pool Features**
- Built-in sign-up and sign-in web UI
- Multi-factor authentication (SMS, TOTP, email)
- Password policies and password reset flows
- Email and phone verification
- User attributes (custom and standard)
- Lambda triggers for custom authentication flows
- Advanced security features (compromised credential detection, adaptive authentication)

**User Pool Security Configuration** (SEC02-BP04, SEC02-BP05)

Password Policy:
```json
{
  "PasswordPolicy": {
    "MinimumLength": 14,
    "RequireUppercase": true,
    "RequireLowercase": true,
    "RequireNumbers": true,
    "RequireSymbols": true,
    "TemporaryPasswordValidityDays": 3
  }
}
```

MFA Configuration (WAF-Recommended):
```json
{
  "MfaConfiguration": "REQUIRED",
  "SoftwareTokenMfaConfiguration": {
    "Enabled": true
  },
  "SmsMfaConfiguration": {
    "SmsAuthenticationMessage": "Your authentication code is {####}",
    "SmsConfiguration": {
      "SnsCallerArn": "arn:aws:iam::123456789012:role/CognitoSNSRole"
    }
  }
}
```

Advanced Security Features (SEC04-BP01):
- **Compromised Credentials Detection**: Checks credentials against known compromised credential databases
- **Adaptive Authentication**: Risk-based authentication (challenge users based on risk score)
- **Event Logging**: CloudWatch Logs for authentication events

**User Pool Authentication Flow**

1. User signs in with username/password to Cognito User Pool
2. User Pool validates credentials and MFA (if enabled)
3. User Pool returns JWT tokens (ID token, access token, refresh token)
4. Application uses tokens to authenticate API requests
5. Application exchanges tokens for AWS credentials via Cognito Identity Pool (if AWS access needed)

### Cognito Identity Pools (Federated Identities) (SEC02-BP03)

**What are Identity Pools?**

Identity pools provide temporary AWS credentials to users authenticated via Cognito User Pools, social IdPs, or SAML providers. They enable mobile/web applications to access AWS services (S3, DynamoDB, Lambda) without hardcoded credentials.

**Identity Pool Architecture**

1. User authenticates with identity provider (Cognito User Pool, Google, Facebook, SAML)
2. Application receives authentication token (JWT, OAuth token, SAML assertion)
3. Application calls `GetId` to obtain Cognito Identity ID
4. Application calls `GetCredentialsForIdentity` with token
5. Cognito validates token with IdP
6. Cognito assumes IAM role on behalf of user (authenticated or unauthenticated role)
7. Cognito returns temporary AWS credentials (access key, secret key, session token)
8. Application uses credentials to access AWS services directly

**Identity Pool IAM Role Configuration** (SEC03-BP02)

Identity pools require two IAM roles:

**Authenticated Role** (for logged-in users):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::user-content-bucket/${cognito-identity.amazonaws.com:sub}/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/UserData",
      "Condition": {
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": ["${cognito-identity.amazonaws.com:sub}"]
        }
      }
    }
  ]
}
```

Trust policy for authenticated role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "us-east-1:12345678-1234-1234-1234-123456789012"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
```

**Unauthenticated Role** (for guest users - use with extreme caution):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::public-content-bucket/public/*"
    }
  ]
}
```

**Best Practice**: Disable unauthenticated access unless absolutely required. Unauthenticated users should have minimal permissions (read-only public data only).

**Enhanced Authentication Flow** (SEC02-BP03)

Use enhanced (simplified) auth flow for better security:

Standard flow:
```
App → GetId → GetCredentialsForIdentity → Credentials
```

Enhanced flow:
```
App → GetCredentialsForIdentity (with token) → Credentials
```

Enhanced flow is simpler and more secure (fewer API calls, reduced credential exposure window).

**STS AssumeRoleWithWebIdentity Integration** (SEC02-BP01)

For direct OIDC integration without Cognito Identity Pools, use `AssumeRoleWithWebIdentity`:

Example: GitHub Actions accessing AWS
```yaml
# .github/workflows/deploy.yml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          role-session-name: github-actions-deploy
          aws-region: us-east-1
      - run: aws s3 sync ./build s3://my-website-bucket/
```

IAM role trust policy for GitHub OIDC:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:*"
        }
      }
    }
  ]
}
```

**Cognito Security Best Practices** (SEC02-BP02, SEC02-BP03, SEC03-BP02)

1. **Enable MFA for User Pools** (SEC02-BP05)
   - Require MFA for all users (or high-risk users via adaptive authentication)
   - Support TOTP (preferred) and SMS MFA
   - Use adaptive authentication to require MFA based on risk signals

2. **Implement Least Privilege for Identity Pool Roles** (SEC03-BP02)
   - Grant minimum permissions required for application function
   - Use policy variables (`${cognito-identity.amazonaws.com:sub}`) to scope permissions to individual users
   - Separate roles for different user types or permission levels

3. **Disable Unauthenticated Access** (SEC03-BP03)
   - Disable unauthenticated identities in identity pool unless required
   - If unauthenticated access needed, grant minimal read-only permissions
   - Monitor unauthenticated access with CloudTrail

4. **Use Enhanced Auth Flow** (SEC02-BP03)
   - Enable enhanced (simplified) authentication flow in identity pools
   - Reduces credential exposure and simplifies client code

5. **Rotate Refresh Tokens Regularly**
   - Configure token expiration in user pool (default: access token 1 hour, refresh token 30 days)
   - Shorter refresh token lifetime for sensitive applications (7 days or less)
   - Revoke refresh tokens when user logs out

6. **Enable Advanced Security Features** (SEC04-BP01)
   - Enable compromised credentials check in user pool
   - Configure adaptive authentication (block, MFA, or allow based on risk)
   - Send authentication events to CloudWatch Logs for monitoring

7. **Use Custom Attributes Carefully** (SEC03-BP03)
   - Custom user attributes are mutable by default
   - Mark sensitive attributes as read-only where appropriate
   - Don't store highly sensitive data in user attributes (use DynamoDB with encryption instead)

8. **Monitor Authentication Events** (SEC04-BP01)
   - Enable CloudWatch Logs for Cognito User Pool
   - Alert on failed login attempts, password resets, MFA changes
   - Use CloudTrail for Cognito API activity (identity pool credential requests)

**Mobile Application Pattern** (SEC02-BP03)

Typical architecture for mobile app with Cognito:

1. **User Authentication**: Mobile app authenticates user via Cognito User Pool (username/password, social login)
2. **Token Exchange**: User Pool returns JWT tokens (ID token, access token, refresh token)
3. **AWS Credentials**: App exchanges tokens for temporary AWS credentials via Cognito Identity Pool
4. **Direct AWS Access**: App uses credentials to access S3 (user photos), DynamoDB (user data), Lambda (backend APIs)
5. **Least Privilege**: IAM role uses policy variables to restrict each user to their own data only

Example S3 path scoping:
```
arn:aws:s3:::user-photos/${cognito-identity.amazonaws.com:sub}/*
```
Each user can only access S3 objects under their unique Cognito identity ID.

**Web Application Pattern** (SEC02-BP01)

Typical architecture for web app with federated login:

1. **Social Login**: User signs in with Google, Facebook, or corporate SAML IdP
2. **Cognito User Pool**: User Pool acts as OIDC/SAML relying party, validates token from IdP
3. **Cognito Identity Pool**: Issues temporary AWS credentials mapped to user identity
4. **Application**: Uses credentials to call AWS services (S3 presigned URLs, DynamoDB queries, Lambda invocations)
5. **No Long-Term Secrets**: No AWS access keys in browser or application code

This architecture eliminates credential management burden and aligns with WAF principle: keep people away from data (users access S3/DynamoDB directly via temporary credentials, not via backend servers).

### Break-Glass Access Keys (Emergency Access)

**WAF-Aligned Pattern** (SEC09-BP03)
- Create single IAM user with access keys for emergency access
- Store access keys in physically secured location (safe, sealed envelope)
- Attach policy allowing only essential recovery actions
- Enable MFA for this user (store MFA seed separately from keys)
- Monitor for any usage (should trigger high-severity alert)
- Rotate access keys annually (even if unused)
- Document break-glass procedure

## IAM Roles for AWS Services (SEC02-BP03)

### Service Role Design Principles

1. **Least Privilege for Function** (SEC03-BP02)
   - Each service role should have minimum permissions for its specific purpose
   - Avoid reusing roles across different functions
   - Use resource restrictions (specific S3 buckets, DynamoDB tables, KMS keys)

2. **Separate Roles per Environment**
   - Development Lambda role vs. Production Lambda role
   - Different resource access based on environment
   - Easier to audit and maintain

3. **Separate Roles per Application/Function**
   - Each Lambda function has unique execution role
   - Each ECS task has unique task role
   - Improves auditability (CloudTrail shows which role performed action)

### EC2 Instance Profiles (SEC02-BP03)

**What is an Instance Profile?**
- Container for IAM role that can be attached to EC2 instance
- Instance profile and role often have same name (AWS Console creates both together)
- EC2 instance metadata service provides temporary credentials to applications running on instance

**Instance Profile Security Best Practices**

1. **Metadata Service Version 2 (IMDSv2)** (SEC05-BP02)
   - Require IMDSv2 to prevent SSRF attacks
   - IMDSv2 uses session-oriented requests (PUT request required before GET)
   - Enforce via IAM policy:
```json
{
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotEquals": {
      "ec2:MetadataHttpTokens": "required"
    }
  }
}
```
   - Enforce via SCP for organization-wide compliance

2. **Least Privilege Instance Role** (SEC03-BP02)
   - Grant only permissions required by applications running on instance
   - Example web server role: S3 read from specific bucket, CloudWatch Logs write, Systems Manager Session Manager
   - Avoid granting IAM permissions to instance roles (prevents privilege escalation)

3. **Hop Limit for IMDSv2**
   - Default hop limit: 1 (prevents metadata access from containers)
   - Increase to 2 only if running Docker containers that need metadata access
   - Prefer ECS task roles over Docker containers using EC2 instance role

4. **Monitor Instance Role Usage** (SEC04-BP01)
   - CloudTrail logs show role session name (includes instance ID)
   - Alert on unexpected API calls from instance roles
   - Use IAM Access Analyzer to identify over-permissive instance roles

**Instance Profile Assignment Pattern**
```bash
# Create role with trust policy for EC2 service
# Attach customer managed policy with least privilege
# Create instance profile
aws iam create-instance-profile --instance-profile-name WebServerProfile

# Add role to instance profile
aws iam add-role-to-instance-profile --instance-profile-name WebServerProfile --role-name WebServerRole

# Launch EC2 instance with instance profile
aws ec2 run-instances --iam-instance-profile Name=WebServerProfile --image-id ami-12345678 --instance-type t3.micro
```

### Lambda Execution Roles (SEC02-BP03)

**Execution Role Components**
- Trust policy: Allows Lambda service to assume role
- Permissions policy: Defines what Lambda function can access
- Temporary credentials: Auto-rotated, available to function via AWS SDK

**Lambda Execution Role Best Practices**

1. **Unique Role per Function** (SEC03-BP02)
   - Each Lambda function has dedicated execution role
   - Simplifies least privilege (role permissions match function requirements exactly)
   - Easier audit trail (CloudTrail shows which function performed action)

2. **Least Privilege Permissions** (SEC03-BP02)
   - Grant only required permissions: S3 read, DynamoDB write, SNS publish, etc.
   - Specify resource ARNs (not `*`)
   - Use condition keys where applicable
   - Example: Lambda function processing S3 events:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::my-input-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-output-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-function:*"
    }
  ]
}
```

3. **VPC Execution Role Permissions** (SEC05-BP01)
   - Lambda functions in VPC require additional permissions:
   - `ec2:CreateNetworkInterface`, `ec2:DescribeNetworkInterfaces`, `ec2:DeleteNetworkInterface`
   - AWS managed policy: `AWSLambdaVPCAccessExecutionRole`
   - Restrict to specific VPC/subnets via resource ARNs where possible

4. **Avoid IAM Permissions in Lambda Roles** (SEC03-BP06)
   - Deny `iam:*` actions unless Lambda function specifically manages IAM (rare)
   - Prevents privilege escalation (Lambda could create admin user/role)
   - Use permissions boundary as additional safeguard

### ECS Task Roles (SEC02-BP03)

**ECS Role Types**
1. **Task Execution Role**: Used by ECS agent to pull container images, write logs (AWS-managed)
2. **Task Role**: Used by application running in container (customer-managed, least privilege)

**Task Role Best Practices**

1. **Unique Task Role per Service** (SEC03-BP02)
   - Each ECS service/task definition has dedicated task role
   - Allows fine-grained access control per microservice
   - Example: Order service task role can access Orders DynamoDB table, not Inventory table

2. **Prefer Task Roles over Instance Roles** (SEC02-BP03)
   - Task roles provide temporary credentials to containers
   - Better isolation between tasks on same EC2 instance
   - CloudTrail shows task ID in role session name (better auditability)

3. **Fargate Task Roles** (SEC05-BP01)
   - Fargate tasks automatically receive task role credentials
   - No access to underlying host (better security isolation)
   - IMDSv2 equivalent protection built-in

4. **Task Role Assignment in Task Definition**
```json
{
  "family": "web-app",
  "taskRoleArn": "arn:aws:iam::123456789012:role/WebAppTaskRole",
  "executionRoleArn": "arn:aws:iam::123456789012:role/ecsTaskExecutionRole",
  "containerDefinitions": [...]
}
```

### Cross-Service IAM Patterns (SEC02-BP03, SEC03-BP02)

The following patterns demonstrate WAF-aligned IAM configurations for common multi-service architectures. Each pattern emphasizes least privilege, temporary credentials, service roles, and resource-based policies where appropriate.

#### Centralized Identity Pattern (SEC02-BP01)

**Architecture**: Separate identity account with IAM Identity Center, workload accounts for applications

**IAM Configuration**:
- **Identity Account**: Hosts IAM Identity Center, manages users and groups, no workloads deployed
- **Workload Accounts**: Production, staging, development accounts with application resources
- **Cross-Account Roles**: IAM roles in each workload account with trust policies allowing identity account principals
- **Permission Sets**: Centrally managed in IAM Identity Center, assigned per account and user group

**Benefits**:
- Single source of truth for identities (SEC02-BP01)
- Temporary credentials only (SEC02-BP03)
- Consistent permission management across accounts
- Easy onboarding/offboarding (modify in identity account, propagates to all workload accounts)

**Example Trust Policy in Workload Account**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "identity-account-workload-access"
        }
      }
    }
  ]
}
```

#### Service Mesh IAM Pattern (SEC02-BP03, SEC05-BP01)

**Architecture**: Microservices on ECS Fargate with App Mesh for service-to-service communication

**IAM Configuration**:
- **ECS Task Roles**: Each microservice has unique task role with least privilege for its dependencies
- **App Mesh Virtual Node Role**: Allows Envoy proxy to communicate with App Mesh control plane
- **Service-to-Service Access**: Controlled via App Mesh policies and IAM task role permissions
- **Cross-Account Service Access**: Task roles in one account can assume roles in another account for shared services

**Example Microservice IAM Roles**:
```json
// Order Service Task Role
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
    },
    {
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:us-east-1:123456789012:order-events"
    }
  ]
}

// Inventory Service Task Role
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Inventory"
    },
    {
      "Effect": "Allow",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:us-east-1:123456789012:inventory-updates"
    }
  ]
}
```

**App Mesh Envoy Role**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "appmesh:StreamAggregatedResources"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Data Pipeline IAM Pattern (SEC02-BP03, SEC03-BP02)

**Architecture**: S3 → Lambda → Glue → Athena → QuickSight data processing pipeline

**IAM Configuration**:
- **S3 Bucket Policies**: Allow CloudTrail, application logs, data ingestion to write
- **Lambda Execution Role**: Read from source S3, trigger Glue jobs, write to destination S3
- **Glue Job Role**: Read from source S3, write to processed data S3, update Glue Data Catalog
- **Athena Execution Role**: Read from processed data S3, query Glue Data Catalog
- **QuickSight Role**: Read from Athena results S3, query via Athena

**Example IAM Roles**:

Lambda Data Processor Role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::raw-data-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "glue:StartJobRun"
      ],
      "Resource": "arn:aws:glue:us-east-1:123456789012:job/data-transformation-job"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/data-processor:*"
    }
  ]
}
```

Glue Job Role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::raw-data-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::processed-data-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "glue:GetTable",
        "glue:UpdateTable",
        "glue:CreateTable"
      ],
      "Resource": [
        "arn:aws:glue:us-east-1:123456789012:catalog",
        "arn:aws:glue:us-east-1:123456789012:database/analytics-db",
        "arn:aws:glue:us-east-1:123456789012:table/analytics-db/*"
      ]
    }
  ]
}
```

#### CI/CD IAM Pattern (SEC02-BP03, SEC03-BP02)

**Architecture**: GitHub Actions → AWS CodeBuild → AWS CodeDeploy → ECS/Lambda

**IAM Configuration**:
- **GitHub OIDC Provider**: Registered in AWS IAM for AssumeRoleWithWebIdentity
- **GitHub Actions Role**: Least privilege to trigger CodeBuild, read/write to artifact S3
- **CodeBuild Service Role**: Pull from ECR, push to ECR, write build artifacts to S3
- **CodeDeploy Service Role**: Deploy to ECS/Lambda, update task definitions, invoke Lambda
- **Deployment Target Roles**: ECS task roles, Lambda execution roles (not modified by pipeline)

**Example IAM Roles**:

GitHub Actions Role (trust policy):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:myorg/myapp:*"
        }
      }
    }
  ]
}
```

GitHub Actions Role (permissions):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codebuild:StartBuild",
        "codebuild:BatchGetBuilds"
      ],
      "Resource": "arn:aws:codebuild:us-east-1:123456789012:project/myapp-build"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::build-artifacts-bucket/myapp/*"
    }
  ]
}
```

CodeBuild Service Role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::build-artifacts-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/codebuild/myapp-build:*"
    }
  ]
}
```

#### Break-Glass IAM Pattern (SEC09-BP03)

**Architecture**: Emergency access mechanism for incident response and account recovery

**IAM Configuration**:
- **Break-Glass IAM User**: Single IAM user with access keys stored in physically secured location
- **Break-Glass Role**: High-privilege role (or AdministratorAccess) for emergency operations
- **MFA Requirement**: Break-glass user requires MFA for AssumeRole (MFA device stored separately from access keys)
- **Monitoring**: CloudWatch alarm, EventBridge rule, and GuardDuty alert for any break-glass usage
- **Session Duration**: 1 hour maximum for break-glass role sessions
- **Audit Trail**: All break-glass actions logged to CloudTrail, reviewed post-incident

**Break-Glass Role Trust Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/break-glass-user"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        },
        "NumericLessThan": {
          "aws:MultiFactorAuthAge": "300"
        }
      }
    }
  ]
}
```

**Break-Glass Role Permissions**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

**Break-Glass Monitoring (EventBridge Rule)**:
```json
{
  "source": ["aws.sts"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["AssumeRole"],
    "requestParameters": {
      "roleArn": ["arn:aws:iam::123456789012:role/BreakGlassRole"]
    }
  }
}
```

**Break-Glass Procedure**:
1. Retrieve break-glass credentials from secured safe (requires two-person approval)
2. Retrieve MFA device from separate secured location
3. Authenticate with break-glass user credentials and MFA
4. Assume break-glass role (requires MFA re-authentication)
5. Perform emergency operation with full audit logging
6. Document all actions taken during break-glass session
7. Post-incident review: analyze CloudTrail logs, rotate break-glass credentials
8. Return credentials and MFA device to secured storage

## IAM Roles for Cross-Account Access (SEC03-BP05)

### WAF Cross-Account Access Guidance

Cross-account access is a core AWS multi-account strategy pattern (WAF-aligned).

**Benefits**
- Centralized identity management (identity account)
- Resource isolation (separate accounts per environment/team)
- Blast radius reduction (compromise of one account doesn't affect others)
- Delegated access without sharing credentials

### Cross-Account Role Architecture

**Components**
1. **Trusting Account** (Resource Account): Contains resources to be accessed
2. **Trusted Account** (Identity Account): Contains users/roles that assume cross-account role
3. **Cross-Account IAM Role**: In trusting account, with trust policy allowing trusted account
4. **Permissions Policy**: Attached to cross-account role, defines allowed actions
5. **Identity Policy**: In trusted account, allows `sts:AssumeRole` for cross-account role

### Cross-Account Role Setup (SEC03-BP05)

**Step 1: Create Role in Trusting Account (Resource Account: 111111111111)**

Trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::222222222222:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-12345"
        },
        "IpAddress": {
          "aws:SourceIp": [
            "203.0.113.0/24",
            "198.51.100.0/24"
          ]
        }
      }
    }
  ]
}
```

Permissions policy (attached to role):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::shared-data-bucket"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::shared-data-bucket/*"
    }
  ]
}
```

**Step 2: Grant AssumeRole Permission in Trusted Account (222222222222)**

Attach policy to user/group/role:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::111111111111:role/CrossAccountS3Access"
    }
  ]
}
```

**Step 3: Assume Role from Trusted Account**

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/CrossAccountS3Access \
  --role-session-name my-session \
  --external-id unique-external-id-12345
```

Returns temporary credentials (access key, secret key, session token) valid for 1-12 hours.

### Cross-Account Security Best Practices (SEC03-BP05)

1. **Use External ID** (SEC03-BP05)
   - Prevents confused deputy problem
   - Generate unique, random External ID for each cross-account relationship
   - Store External ID securely (Secrets Manager, Parameter Store)
   - Required in trust policy condition

2. **Restrict by IP Address or VPC** (SEC03-BP03)
   - Add condition to trust policy restricting source IP or VPC endpoint
   - Ensures cross-account access only from expected network locations

3. **Require MFA for Sensitive Cross-Account Roles** (SEC02-BP05)
```json
{
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}
```

4. **Least Privilege Permissions** (SEC03-BP02)
   - Cross-account roles should have minimal permissions for their purpose
   - Avoid granting AdministratorAccess cross-account
   - Use resource restrictions (specific buckets, databases, KMS keys)

5. **Session Duration Limits**
   - Set maximum session duration on cross-account role (1-12 hours)
   - Shorter durations for privileged roles (1-2 hours)

6. **Monitor Cross-Account Activity** (SEC04-BP01)
   - CloudTrail shows AssumeRole events and subsequent API calls
   - Alert on cross-account role assumption from unexpected accounts
   - Use AWS Config to audit cross-account trust relationships

7. **Use AWS Organizations for Trust** (SEC01-BP07)
   - Trust entire organization or specific OUs instead of individual account IDs
   - Simplifies management when adding/removing accounts
   - Example trust policy using organization condition:
```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "*"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "aws:PrincipalOrgID": "o-1234567890"
    }
  }
}
```

### Cross-Account Resource Access via Resource Policies

**When to Use Resource Policies vs. Cross-Account Roles**
- **Resource policies**: Simpler for limited, specific access (S3 bucket, KMS key, SNS topic)
- **Cross-Account roles**: Better for broad access, multiple resources, user/application access

**Example: S3 Bucket Policy for Cross-Account Access**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::222222222222:role/DataProcessingRole"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::shared-bucket/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-1234567890"
        }
      }
    }
  ]
}
```

**Example: KMS Key Policy for Cross-Account Encryption**
```json
{
  "Sid": "Allow cross-account use of KMS key",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::222222222222:root"
  },
  "Action": [
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:ViaService": [
        "s3.us-east-1.amazonaws.com"
      ]
    }
  }
}
```

## Temporary Credentials and AWS STS (SEC02-BP03)

### WAF Temporary Credentials Guidance

Temporary credentials are the **WAF-preferred** method for all AWS access:
- Automatic expiration (1 hour to 12 hours)
- Automatic rotation
- No long-term credential storage
- Supports federated access and cross-account access

### AWS Security Token Service (STS) Operations

**AssumeRole** (SEC02-BP03)
- Most common STS operation
- Used for cross-account access, federated access, service roles
- Returns temporary credentials (AccessKeyId, SecretAccessKey, SessionToken, Expiration)
- Supports MFA, External ID, session policies, session tags

**AssumeRoleWithSAML** (SEC02-BP01)
- Federate access using SAML 2.0 identity provider
- Used by AWS IAM Identity Center, enterprise SSO solutions
- Maps SAML attributes to IAM policies and session tags

**AssumeRoleWithWebIdentity** (SEC02-BP01)
- Federate access using OpenID Connect (OIDC) identity provider
- Used for mobile apps, web apps, GitHub Actions, GitLab CI
- Example IdPs: Amazon Cognito, Google, Facebook, GitHub

**GetSessionToken** (SEC02-BP05)
- Returns temporary credentials for IAM user (with MFA)
- Used for CLI/SDK access when using IAM users
- Extends session duration up to 12 hours with MFA (1 hour without MFA)
- Does not support cross-account access or permission elevation

**GetFederationToken** (SEC02-BP01)
- Returns temporary credentials for federated user
- Less common; used for custom identity broker solutions
- Supports session policies to further restrict permissions

### Session Policies (SEC03-BP02)

**What are Session Policies?**
- Inline policy passed during AssumeRole, GetFederationToken, or GetSessionToken
- Further restricts permissions of temporary credentials
- Effective permissions = intersection of identity policy AND session policy
- Maximum size: 2048 characters (PackedPolicySize)

**Session Policy Use Cases**
- Temporary access with additional restrictions
- Delegated access with limited scope
- Just-in-time access for specific operations

**Example: AssumeRole with Session Policy**
```bash
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/S3AccessRole \
  --role-session-name temp-session \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::specific-bucket/specific-prefix/*"
      }
    ]
  }'
```

Even if S3AccessRole has broad S3 permissions, this session is limited to GetObject on specific bucket/prefix.

### Session Tags (SEC03-BP02)

**What are Session Tags?**
- Key-value pairs passed during AssumeRole or federated login
- Available as condition keys in IAM policies (`aws:PrincipalTag/TagKey`)
- Used for attribute-based access control (ABAC)
- Can be transitive (passed through role chaining)

**Session Tag Use Cases**
- Tag-based access control (user's department tag matches resource's department tag)
- Dynamic permission assignment based on user attributes
- Simplified policy management (one policy, many users with different tags)

**Example: AssumeRole with Session Tags**
```bash
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/DeveloperRole \
  --role-session-name dev-session \
  --tags Key=Department,Value=Engineering Key=Project,Value=Alpha
```

IAM policy using session tags:
```json
{
  "Effect": "Allow",
  "Action": "ec2:*",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "ec2:ResourceTag/Project": "${aws:PrincipalTag/Project}"
    }
  }
}
```

User can only manage EC2 instances where instance's Project tag matches their session's Project tag.

### SAML Federation Trust Policy Examples

These examples demonstrate WAF-aligned trust policies for federated IAM roles used in workforce identity scenarios. Each example is production-ready and includes specific WAF best practice references.

#### Example 1: Basic SAML 2.0 Federation Trust Policy (SEC02-BP01)

Trust policy for an IAM role that allows assumption via a SAML 2.0 identity provider (corporate SSO). This enables federated workforce access without IAM users.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:saml-provider/YourCompanyIdP"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
```

#### Example 2: SAML 2.0 Federation with MFA and IP Restriction (SEC02-BP01, SEC02-BP05, SEC03-BP03)

Enhanced trust policy that layers additional security controls: MFA requirement and IP address restriction. This demonstrates defense-in-depth for sensitive federated roles.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:saml-provider/YourSAMLProvider"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        },
        "Bool": {
          "SAML:sub_type": "persistent"
        },
        "IpAddress": {
          "aws:SourceIp": [
            "203.0.113.0/24",
            "198.51.100.0/24"
          ]
        },
        "StringLike": {
          "SAML:aud": "https://signin.aws.amazon.com/saml",
          "SAML:edupersonprincipalname": "*@yourcompany.com"
        }
      }
    }
  ]
}
```

**Note**: MFA enforcement should be configured at the identity provider (IdP) level. The `SAML:sub_type` condition ensures persistent user mapping for audit trails. IP restrictions limit access to corporate network ranges.

#### Example 3: Federated Role Permission Policy — Least Privilege (SEC03-BP01, SEC03-BP02)

Permission policy (attached to a federated role) demonstrating least privilege access. This addresses what the federated user can do after assuming the role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyS3BucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Resource": [
        "arn:aws:s3:::your-data-bucket",
        "arn:aws:s3:::your-data-bucket/*"
      ]
    },
    {
      "Sid": "DynamoDBTableAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:DescribeTable"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/YourApplicationTable"
    },
    {
      "Sid": "ListAllBuckets",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "*"
    }
  ]
}
```

**WAF Rationale**: This policy grants the minimum permissions required for a specific workload (SEC03-BP01). Actions are scoped to specific resources rather than using wildcards (SEC03-BP02). The federated user can read from one S3 bucket and query one DynamoDB table, but cannot modify resources.

### Temporary Credential Security Best Practices

1. **Short Session Durations for Privileged Access** (SEC02-BP03)
   - 1 hour for administrator access
   - 4 hours for production write access
   - 12 hours for development/read-only access

2. **Revoke Active Sessions When Role/Policy Changes** (SEC03-BP04)
   - Change role's trust policy or permissions policy
   - Existing sessions remain valid until expiration
   - Use `AWSRevokeOlderSessions` managed policy to invalidate sessions issued before policy update

3. **Monitor Temporary Credential Usage** (SEC04-BP01)
   - CloudTrail logs AssumeRole events with source identity
   - Alert on AssumeRole from unexpected IP, location, or account
   - GuardDuty detects anomalous temporary credential usage

4. **Use Source Identity for Role Chaining** (SEC03-BP05)
   - Source identity persists through role chaining
   - Tracks original identity across multiple AssumeRole calls
   - Helps with auditing and compliance

## Condition Keys and Policy Variables (SEC03-BP02)

### Global Condition Keys (Available for All AWS Services)

**Identity and Authentication**
- `aws:PrincipalType`: Type of principal (User, Role, AssumedRole, FederatedUser, Account, Service)
- `aws:PrincipalArn`: ARN of principal making request
- `aws:PrincipalAccount`: Account ID of principal
- `aws:PrincipalOrgID`: AWS Organization ID of principal
- `aws:PrincipalTag/TagKey`: Tag attached to principal (session tags or role/user tags)
- `aws:userid`: Unique ID of principal
- `aws:username`: Friendly name of principal

**MFA**
- `aws:MultiFactorAuthPresent`: Boolean, true if principal authenticated with MFA
- `aws:MultiFactorAuthAge`: Seconds since MFA authentication

**Network**
- `aws:SourceIp`: IP address of request (supports CIDR notation)
- `aws:SourceVpc`: VPC ID of request (for VPC endpoint requests)
- `aws:SourceVpce`: VPC endpoint ID of request
- `aws:VpcSourceIp`: Private IP address within VPC

**Encryption**
- `aws:SecureTransport`: Boolean, true if request used HTTPS/TLS

**Time**
- `aws:CurrentTime`: Current date/time for request
- `aws:EpochTime`: Current time in epoch seconds

**Request Context**
- `aws:RequestedRegion`: Region of requested resource
- `aws:Referer`: HTTP referer header (web requests)
- `aws:UserAgent`: HTTP user agent header

### Service-Specific Condition Keys

**S3 Condition Keys**
- `s3:x-amz-server-side-encryption`: Encryption method (AES256, aws:kms)
- `s3:x-amz-server-side-encryption-aws-kms-key-id`: KMS key ARN
- `s3:x-amz-acl`: Canned ACL (private, public-read, etc.)
- `s3:prefix`: Prefix being listed
- `s3:delimiter`: Delimiter character for ListBucket
- `s3:VersionId`: Object version ID

**EC2 Condition Keys**
- `ec2:InstanceType`: Instance type being launched/modified
- `ec2:Region`: Region of EC2 resource
- `ec2:Vpc`: VPC ID
- `ec2:Subnet`: Subnet ID
- `ec2:ResourceTag/TagKey`: Tag on EC2 resource
- `ec2:Encrypted`: Boolean, true if EBS volume is encrypted

**IAM Condition Keys**
- `iam:PassedToService`: Service that role is being passed to (for PassRole action)
- `iam:PolicyARN`: ARN of policy being attached
- `iam:PermissionsBoundary`: Permissions boundary ARN

**KMS Condition Keys**
- `kms:ViaService`: AWS service making request on behalf of principal
- `kms:EncryptionContext:ContextKey`: Encryption context key-value pair
- `kms:CallerAccount`: Account ID of caller

### Condition Operators

**String Conditions**
- `StringEquals`, `StringNotEquals`: Case-sensitive exact match
- `StringEqualsIgnoreCase`, `StringNotEqualsIgnoreCase`: Case-insensitive
- `StringLike`, `StringNotLike`: Case-sensitive wildcard match (*, ?)

**Numeric Conditions**
- `NumericEquals`, `NumericNotEquals`, `NumericLessThan`, `NumericLessThanEquals`, `NumericGreaterThan`, `NumericGreaterThanEquals`

**Date Conditions**
- `DateEquals`, `DateNotEquals`, `DateLessThan`, `DateGreaterThan`

**Boolean Conditions**
- `Bool`: True or false

**IP Address Conditions**
- `IpAddress`, `NotIpAddress`: IPv4/IPv6 CIDR match

**ARN Conditions**
- `ArnEquals`, `ArnNotEquals`, `ArnLike`, `ArnNotLike`

**Null Conditions**
- `Null`: Check if condition key is present (true = key absent, false = key present)

**Condition Modifiers**
- `IfExists`: Only apply condition if key is present
- `ForAllValues`: All values in request must match (set operation)
- `ForAnyValue`: At least one value in request must match (set operation)

### Policy Variables

**What are Policy Variables?**
- Placeholders in policy that are dynamically replaced at evaluation time
- Format: `${VariableName}`
- Enables reusable policies that adapt to principal's identity

**Common Policy Variables**
- `${aws:username}`: IAM user name or federated user name
- `${aws:userid}`: Unique ID of principal
- `${aws:PrincipalTag/TagKey}`: Tag value from principal
- `${aws:CurrentTime}`, `${aws:EpochTime}`: Current time
- `${aws:SourceIp}`: IP address of request

### Advanced Condition Patterns (SEC03-BP02)

**1. Require MFA for Sensitive Actions**
```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:StopInstances",
    "ec2:TerminateInstances"
  ],
  "Resource": "*",
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    },
    "NumericLessThan": {
      "aws:MultiFactorAuthAge": "3600"
    }
  }
}
```

**2. Restrict Access to Specific IP Ranges**
```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "NotIpAddress": {
      "aws:SourceIp": [
        "203.0.113.0/24",
        "198.51.100.0/24"
      ]
    },
    "Null": {
      "aws:SourceVpce": "true"
    }
  }
}
```
(Denies if not from allowed IP ranges AND not from VPC endpoint)

**3. Require Encryption for S3 Uploads**
```json
{
  "Effect": "Deny",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::my-bucket/*",
  "Condition": {
    "StringNotEquals": {
      "s3:x-amz-server-side-encryption": "aws:kms"
    }
  }
}
```

**4. Tag-Based Access Control (ABAC)**
```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:StartInstances",
    "ec2:StopInstances"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "ec2:ResourceTag/Owner": "${aws:username}"
    }
  }
}
```

**5. Restrict Access to Organization Resources**
```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:PrincipalOrgID": "o-1234567890"
    }
  }
}
```

**6. Enforce VPC Endpoint Usage**
```json
{
  "Effect": "Deny",
  "Action": "s3:*",
  "Resource": [
    "arn:aws:s3:::sensitive-bucket",
    "arn:aws:s3:::sensitive-bucket/*"
  ],
  "Condition": {
    "StringNotEquals": {
      "aws:SourceVpce": "vpce-1234567890abcdef0"
    }
  }
}
```

**7. Time-Based Access Restrictions**
```json
{
  "Effect": "Allow",
  "Action": "ec2:*",
  "Resource": "*",
  "Condition": {
    "DateGreaterThan": {
      "aws:CurrentTime": "2024-01-01T00:00:00Z"
    },
    "DateLessThan": {
      "aws:CurrentTime": "2024-12-31T23:59:59Z"
    }
  }
}
```

**8. Prevent Privilege Escalation in IAM**
```json
{
  "Effect": "Deny",
  "Action": [
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/DeveloperBoundary"
    }
  }
}
```

## IAM Access Analyzer (SEC04-BP03)

### WAF Guidance on IAM Access Analyzer

IAM Access Analyzer is a **WAF-recommended** tool for:
- Identifying resources shared with external entities (SEC04-BP03)
- Validating IAM policies against security best practices (SEC03-BP02)
- Identifying unused access (SEC03-BP04)

### IAM Access Analyzer Features

**1. External Access Findings** (SEC04-BP03)
- Analyzes resource policies for external access (outside your AWS account or organization)
- Supported resources: S3 buckets, IAM roles, KMS keys, Lambda functions, SQS queues, Secrets Manager secrets, SNS topics, ECR repositories
- Continuous monitoring with automated findings
- Archive findings for intended external access
- Integrates with Security Hub

**Finding Example**
```
Resource: arn:aws:s3:::my-data-bucket
Finding: Bucket policy allows access from external AWS account 999888777666
Access Level: Read, Write
Principal: arn:aws:iam::999888777666:role/ExternalRole
Condition: None
```

**External Access Analyzer Setup** (SEC04-BP03)
1. Create analyzer with organization or account as zone of trust
2. Analyzer continuously scans resource policies
3. Review findings in IAM Access Analyzer console
4. Archive expected external access
5. Remediate unexpected external access
6. Monitor for new findings via EventBridge

**2. Policy Validation** (SEC03-BP02)
- Validates IAM policies against AWS policy grammar and best practices
- Checks for security warnings, errors, suggestions
- Available in IAM console when creating/editing policies
- API/CLI support via `aws accessanalyzer validate-policy`

**Policy Validation Checks**
- **Error**: Policy has syntax error or invalid elements
- **Security Warning**: Policy grants broad permissions or uses wildcards
- **Suggestion**: Optimization or best practice recommendation
- **Warning**: Policy may not function as intended

**Example Validation Findings**
```
Security Warning: Use of wildcard in action
  Action: s3:*
  Recommendation: Specify explicit actions instead of wildcard

Security Warning: Use of wildcard in principal
  Principal: *
  Recommendation: Specify explicit principals

Suggestion: Policy grants unused permissions
  Actions: dynamodb:DeleteTable
  Recommendation: Remove unused actions
```

**3. Unused Access Findings** (SEC03-BP04)
- Analyzes CloudTrail logs to identify unused permissions
- Shows last accessed information for IAM users, roles, and policies
- Recommends removal of unused permissions
- Requires CloudTrail with 90 days of data

**Unused Access Analysis**
- Track last access for services and actions
- Identify roles that haven't been used in 90 days
- Identify policies with unused permissions
- Right-size permissions based on actual usage

**Access Last Used Information**
- Available in IAM console for users, roles, policies
- Shows last service accessed and timestamp
- API: `GetServiceLastAccessedDetails`

### IAM Access Analyzer Best Practices (SEC04-BP03)

1. **Enable Access Analyzer in All Regions** (SEC04-BP03)
   - Create analyzer in every active AWS region
   - Regional resources (S3 buckets in specific region) require regional analyzer

2. **Set Appropriate Zone of Trust**
   - **Organization analyzer**: Flags access from outside AWS Organization (recommended for multi-account)
   - **Account analyzer**: Flags access from outside single AWS account

3. **Review Findings Regularly** (SEC03-BP04)
   - Weekly review of new findings
   - Archive intended external access with justification
   - Remediate unexpected external access immediately
   - Use findings as input for security reviews

4. **Automate Remediation** (SEC04-BP02)
   - EventBridge rule triggered on new Access Analyzer finding
   - Lambda function for automated response (alert, ticket, auto-remediation)
   - Example: Automatically remove public access from S3 bucket if finding detected

5. **Use Policy Validation in CI/CD** (SEC03-BP02)
   - Integrate `validate-policy` API into infrastructure-as-code pipelines
   - Fail deployment if policy has errors or security warnings
   - Enforce policy quality before production deployment

6. **Track Unused Access for Least Privilege** (SEC03-BP04)
   - Quarterly review of unused access findings
   - Remove permissions not used in past 90 days
   - Right-size policies based on actual usage patterns
   - Archive roles not used in 90 days (re-create if needed later)

7. **Integrate with Security Hub** (SEC04-BP02)
   - Automatically send Access Analyzer findings to Security Hub
   - Centralized view of security findings across services
   - Prioritize findings with Security Hub severity scores

### IAM Access Analyzer Archive Rules

**What are Archive Rules?**
- Automatically archive findings matching specified criteria
- Used for expected external access (intended cross-account sharing)
- Reduces noise in findings list

**Archive Rule Example**
```
Rule: ArchiveDevAccountAccess
Criteria:
  - Principal.AWS = arn:aws:iam::123456789012:root (dev account)
  - Resource Type = AWS::S3::Bucket
  - Resource = arn:aws:s3:::shared-dev-bucket
Action: Archive finding
```

Findings matching this rule are automatically archived (not shown in active findings).

## IAM Monitoring and Detection (SEC04-BP01)

### CloudTrail for IAM (SEC04-BP01)

**IAM API Calls Logged by CloudTrail**
- All IAM API calls: CreateUser, DeleteUser, AttachUserPolicy, CreateRole, AssumeRole, etc.
- Policy changes: PutUserPolicy, AttachRolePolicy, CreatePolicy, CreatePolicyVersion
- Credential operations: CreateAccessKey, DeleteAccessKey, EnableMFADevice
- Authentication events: ConsoleLogin (via CloudTrail Insights)

**Critical IAM Events to Monitor** (SEC04-BP01)
1. Root account usage (any API call by root user)
2. IAM policy changes (AttachUserPolicy, PutRolePolicy, CreatePolicy)
3. User/role creation (CreateUser, CreateRole)
4. Access key creation (CreateAccessKey)
5. MFA device changes (EnableMFADevice, DeactivateMFADevice)
6. AssumeRole events (especially cross-account)
7. Failed authentication attempts (ConsoleLogin with errorCode)
8. Privilege escalation attempts (AttachUserPolicy with AdministratorAccess)

**CloudTrail Event Example: AssumeRole**
```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAI123456789EXAMPLE",
    "arn": "arn:aws:iam::111111111111:user/alice",
    "accountId": "111111111111",
    "userName": "alice"
  },
  "eventTime": "2024-01-15T10:30:00Z",
  "eventName": "AssumeRole",
  "requestParameters": {
    "roleArn": "arn:aws:iam::222222222222:role/CrossAccountAdmin",
    "roleSessionName": "alice-session"
  },
  "responseElements": {
    "assumedRoleUser": {
      "assumedRoleId": "AROAI123456789EXAMPLE:alice-session",
      "arn": "arn:aws:sts::222222222222:assumed-role/CrossAccountAdmin/alice-session"
    }
  },
  "sourceIPAddress": "203.0.113.42"
}
```

### AWS Config for IAM (SEC04-BP02)

**IAM-Related Config Rules**

1. **iam-root-access-key-check**
   - Detects if root account has access keys
   - Compliance: NON_COMPLIANT if root access keys exist
   - Remediation: Delete root access keys

2. **root-account-mfa-enabled**
   - Checks if root account has MFA enabled
   - Compliance: NON_COMPLIANT if root MFA not enabled
   - Remediation: Enable MFA on root account

3. **iam-user-mfa-enabled**
   - Checks if IAM users have MFA enabled
   - Compliance: NON_COMPLIANT for users without MFA
   - Remediation: Enable MFA for all users

4. **iam-password-policy**
   - Checks if account password policy meets requirements
   - Configurable parameters: MinimumPasswordLength, RequireSymbols, RequireNumbers, PasswordReusePrevention, MaxPasswordAge
   - Compliance: NON_COMPLIANT if password policy doesn't meet criteria

5. **access-keys-rotated**
   - Checks if access keys are rotated within specified number of days
   - Default: 90 days
   - Compliance: NON_COMPLIANT for keys older than threshold

6. **iam-user-unused-credentials-check**
   - Checks for IAM users with credentials unused for specified number of days
   - Default: 90 days
   - Compliance: NON_COMPLIANT for unused credentials

7. **iam-policy-no-statements-with-admin-access**
   - Checks if IAM policies grant full administrative privileges (Action: *, Resource: *)
   - Compliance: NON_COMPLIANT if policy grants admin access
   - Helps identify overly permissive policies

8. **iam-user-no-policies-check**
   - Checks if IAM users have inline or managed policies directly attached
   - Compliance: NON_COMPLIANT if user has policies (best practice: attach policies to groups, add users to groups)

### Amazon GuardDuty IAM Findings (SEC04-BP01)

**GuardDuty IAM Threat Detection**
- Analyzes CloudTrail logs for suspicious IAM activity
- Machine learning-based anomaly detection
- Threat intelligence integration

**IAM-Related GuardDuty Finding Types**

1. **UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration**
   - EC2 instance credentials used outside EC2
   - Indicates potential credential theft
   - Severity: High

2. **Stealth:IAMUser/CloudTrailLoggingDisabled**
   - Principal disabled CloudTrail logging
   - Indicates attempt to evade detection
   - Severity: Medium

3. **Policy:IAMUser/RootCredentialUsage**
   - Root account credentials used
   - Should trigger investigation (root use should be rare)
   - Severity: Low (unless root access keys exist, then High)

4. **UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B**
   - Successful console login from unusual location or anonymized proxy
   - Potential compromised credentials
   - Severity: Medium

5. **PrivilegeEscalation:IAMUser/AnomalousAdminLogin**
   - User with administrative permissions logged in from unusual location
   - Severity: High

6. **UnauthorizedAccess:IAMUser/MaliciousIPCaller**
   - API calls from known malicious IP address
   - Threat intelligence-based detection
   - Severity: High

7. **PenTest:IAMUser/KaliLinux**
   - API calls from Kali Linux machine
   - May indicate penetration testing or attack
   - Severity: Medium

**GuardDuty Response Actions** (SEC09-BP02)
- Investigate finding in GuardDuty console
- Check CloudTrail for full API activity
- Disable compromised IAM user/access key
- Rotate credentials
- Review and restrict permissions
- Check for unauthorized resource creation
- Report to security team for incident response

### CloudWatch Alarms for IAM (SEC04-BP01)

**Critical IAM Metrics to Monitor**

1. **Root Account Activity**
```
MetricFilter: { $.userIdentity.type = "Root" }
Alarm: Any root account API call
Action: SNS notification to security team
```

2. **IAM Policy Changes**
```
MetricFilter: {
  ($.eventName = AttachUserPolicy) ||
  ($.eventName = AttachRolePolicy) ||
  ($.eventName = PutUserPolicy) ||
  ($.eventName = PutRolePolicy) ||
  ($.eventName = CreatePolicy) ||
  ($.eventName = DeleteUserPolicy)
}
Alarm: IAM policy change detected
Action: SNS notification, create Jira ticket
```

3. **Failed Console Logins**
```
MetricFilter: {
  ($.eventName = ConsoleLogin) &&
  ($.errorMessage = "Failed authentication")
}
Alarm: 5 failed logins in 5 minutes
Action: SNS notification, potential account compromise
```

4. **New Access Key Creation**
```
MetricFilter: { $.eventName = CreateAccessKey }
Alarm: Any access key creation
Action: SNS notification for review
```

5. **MFA Changes**
```
MetricFilter: {
  ($.eventName = DeactivateMFADevice) ||
  ($.eventName = DeleteVirtualMFADevice)
}
Alarm: MFA device deactivated/deleted
Action: SNS notification, potential account takeover
```

### EventBridge Rules for IAM (SEC04-BP02)

**Automated IAM Event Responses**

1. **Root Account Usage Alert**
```json
{
  "source": ["aws.signin"],
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "userIdentity": {
      "type": ["Root"]
    }
  }
}
```
Target: SNS topic, Lambda function, Security Hub

2. **Cross-Account AssumeRole Monitoring**
```json
{
  "source": ["aws.sts"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["AssumeRole"],
    "requestParameters": {
      "roleArn": [{
        "anything-but": {
          "prefix": "arn:aws:iam::123456789012:"
        }
      }]
    }
  }
}
```
Target: Lambda function to log and alert on cross-account role assumptions

3. **Access Key Creation Response**
```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["CreateAccessKey"]
  }
}
```
Target: Lambda function to send notification, log in SIEM, create approval ticket

## AWS Organizations and IAM Governance (SEC01-BP07)

### WAF Organizations Guidance

AWS Organizations is the **WAF-recommended** way to manage multi-account AWS environments:
- Centralized billing and cost allocation
- Hierarchical account organization (OUs)
- Service control policies (SCPs) for security guardrails
- Centralized identity with IAM Identity Center
- Consolidated security monitoring (Security Hub, GuardDuty)

### Organizations Structure for IAM Governance

**Recommended OU Hierarchy**
```
Root
├── Security OU
│   ├── Log Archive Account (CloudTrail, Config, VPC Flow Logs)
│   ├── Security Tooling Account (GuardDuty, Security Hub, Macie)
│   └── Identity Account (IAM Identity Center)
├── Infrastructure OU
│   ├── Network Account (Transit Gateway, VPN, Direct Connect)
│   └── Shared Services Account (AD, DNS)
├── Production OU
│   ├── Production Workload Accounts
│   └── (SCPs: Strict security, no resource deletion without MFA)
├── Development OU
│   ├── Development Workload Accounts
│   └── (SCPs: Developer-friendly, cost controls)
└── Sandbox OU
    ├── Individual sandbox accounts
    └── (SCPs: Region restrictions, cost limits, no production data)
```

### Service Control Policies for IAM (SEC01-BP07)

**SCP Inheritance Model**
- SCPs attached to root apply to all accounts
- SCPs attached to OU apply to all accounts in that OU and child OUs
- SCPs attached to account apply to that account only
- Effective permissions = intersection of all SCPs in hierarchy
- SCPs apply to all principals in account (including root), with limited exceptions

**IAM Security Baseline SCPs**

**1. Prevent Disabling Security Services** (Attach to Root)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:Disassociate FromAdministratorAccount",
        "securityhub:DeleteInvitations",
        "securityhub:DisableSecurityHub",
        "config:DeleteConfigurationRecorder",
        "config:StopConfigurationRecorder"
      ],
      "Resource": "*"
    }
  ]
}
```

**2. Require MFA for Sensitive IAM Actions** (Attach to Production OU)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:DeleteUser",
        "iam:DeleteRole",
        "iam:DeleteUserPolicy",
        "iam:DeleteRolePolicy",
        "iam:DetachUserPolicy",
        "iam:DetachRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

**3. Prevent IAM User Creation** (Attach to Workload OUs)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:CreateAccessKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassRole"
        }
      }
    }
  ]
}
```
(Forces use of IAM Identity Center; allows break-glass role exception)

**4. Restrict Root User Actions** (Attach to Root)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```
**Important Note**: This SCP denies all root user actions. However, SCPs do not affect the root user in the management account (formerly master account) for billing and account management tasks. Root users in member accounts are restricted by SCPs. If applying this SCP, exempt specific actions required for account lifecycle management, or apply only to member account OUs (not the management account).

**5. Enforce Permissions Boundary** (Attach to Development OU)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:CreateRole"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "iam:PermissionsBoundary": "arn:aws:iam::*:policy/DeveloperBoundary"
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": [
        "iam:DeleteUserPermissionsBoundary",
        "iam:DeleteRolePermissionsBoundary"
      ],
      "Resource": "*"
    }
  ]
}
```

### Delegated Administrator Accounts (SEC01-BP07)

**WAF Pattern: Delegate Security Services to Security Account**
- Security Hub delegated administrator: Security Tooling Account
- GuardDuty delegated administrator: Security Tooling Account
- IAM Access Analyzer delegated administrator: Security Tooling Account
- Macie delegated administrator: Security Tooling Account

**Benefits**
- Centralized security monitoring across organization
- Workload accounts don't need direct access to security service management
- Simplified security operations (single pane of glass)
- Consistent security policy enforcement

## General IAM Security Principles

### Least Privilege (SEC03-BP02)

**Definition**: Grant minimum permissions required to perform a task, no more.

**Implementation Strategy**
1. Start with zero permissions
2. Add permissions as needed based on specific use cases
3. Use CloudTrail and IAM Access Analyzer to identify actual usage
4. Remove unused permissions quarterly
5. Prefer specific actions and resources over wildcards
6. Use conditions to add context-based restrictions

**Least Privilege Checklist**
- Are actions limited to specific operations (not `*`)?
- Are resources limited to specific ARNs (not `*`)?
- Are conditions used to add contextual restrictions?
- Are permissions reviewed regularly and refined?
- Are unused permissions identified and removed?
- Is access time-bound where appropriate?

### Defense in Depth (SEC03-BP06)

**Layered IAM Security Controls**
1. **Layer 1: SCPs** - Organization-wide guardrails (maximum permissions)
2. **Layer 2: Permissions boundaries** - Maximum permissions for delegated IAM management
3. **Layer 3: Identity-based policies** - Permissions granted to users/roles
4. **Layer 4: Resource-based policies** - Permissions on resources (S3, KMS, Lambda)
5. **Layer 5: Session policies** - Temporary restrictions on assumed role sessions
6. **Layer 6: VPC endpoint policies** - Restrict accessible resources from VPC

**Defense in Depth Example**
- SCP denies creation of unencrypted EBS volumes (organization-wide)
- Permissions boundary limits developer role to EC2, S3, DynamoDB (maximum scope)
- Identity policy grants specific EC2 actions in specific VPC (least privilege)
- Session policy further restricts to specific instance types (temporary constraint)

### Separation of Duties (SEC03-BP06)

**Definition**: Divide privileged operations among multiple individuals to prevent fraud and errors.

**IAM Separation of Duties Patterns**

1. **Policy Creation vs. Policy Attachment**
   - Security team: Create and manage IAM policies
   - Operations team: Attach policies to roles (from approved policy list)
   - Neither team has both permissions

2. **Infrastructure Deployment vs. Approval**
   - Developers: Create CloudFormation templates, deploy to dev
   - Approvers: Deploy to production after review
   - No individual can deploy to production without approval

3. **IAM Administration vs. Workload Management**
   - IAM admins: Manage users, roles, policies
   - Workload admins: Manage EC2, RDS, S3 (cannot modify own permissions)
   - Use permissions boundary to prevent workload admins from escalating privileges

4. **Read vs. Write Access**
   - Analysts: Read-only access to all resources
   - Operators: Write access to specific resources
   - No single role has both broad read and write

**Implementing Separation of Duties with IAM**
- Use separate IAM roles for different functions
- Use permissions boundaries to enforce maximum permissions
- Use SCPs to prevent privilege escalation
- Require multi-person approval for sensitive operations (via external workflow)
- Audit CloudTrail logs to detect separation of duties violations

### Credential Hygiene (SEC03-BP04)

**WAF Credential Hygiene Best Practices**

1. **Eliminate Long-Term Credentials**
   - Use IAM roles with temporary credentials
   - Delete access keys for IAM users (prefer IAM Identity Center)
   - Use IAM Roles Anywhere for on-premises workloads

2. **Rotate Credentials Regularly**
   - Access keys: 90 days
   - Passwords: 90 days (or per organizational policy)
   - Service account credentials: 90 days
   - Database credentials: Use Secrets Manager with automatic rotation

3. **Secure Credential Storage**
   - Never hardcode credentials in code
   - Use AWS Secrets Manager or Systems Manager Parameter Store
   - Use environment variables injected at runtime
   - Encrypt credentials at rest

4. **Monitor for Exposed Credentials**
   - Use git-secrets to prevent committing credentials to Git
   - Enable GitHub secret scanning
   - Monitor GuardDuty for exposed credential findings
   - Rotate immediately if exposure suspected

5. **Implement Break-Glass Procedures**
   - Documented process for emergency access
   - Sealed credentials in physical safe
   - Logging and alerting on break-glass credential usage
   - Post-incident review and credential rotation

### Automation (WAF Design Principle)

**Automate IAM Security Operations**

1. **Automated Permission Reviews**
   - Scheduled Lambda function analyzes IAM Access Analyzer unused access findings
   - Generates report of unused permissions
   - Creates tickets for permission removal

2. **Automated Credential Rotation**
   - Secrets Manager automatic rotation for database credentials
   - Scheduled Lambda function rotates service account access keys
   - EventBridge rule triggers rotation based on key age

3. **Automated Policy Validation**
   - CI/CD pipeline validates IAM policies using IAM Access Analyzer validate-policy API
   - Fails deployment if policy has errors or security warnings
   - Enforces policy quality and security standards

4. **Automated Incident Response**
   - GuardDuty finding triggers Lambda function
   - Lambda disables compromised IAM user/access key
   - Lambda triggers credential rotation in Secrets Manager
   - Lambda creates incident ticket in Jira/ServiceNow

5. **Infrastructure as Code (IaC)**
   - Define all IAM resources in CloudFormation, CDK, or Terraform
   - Version control for IAM policies (Git)
   - Peer review for IAM changes (pull request approval)
   - Consistent, repeatable IAM deployments

### Traceability (WAF Design Principle)

**Maintain Complete Audit Trail of IAM Activity**

1. **CloudTrail Logging** (SEC04-BP01)
   - Enable CloudTrail in all regions
   - Log to dedicated, secured S3 bucket in log archive account
   - Enable log file validation (integrity protection)
   - Integrate with CloudWatch Logs for real-time analysis

2. **CloudTrail Insights** (SEC04-BP02)
   - Detects unusual API activity (anomaly detection)
   - Identifies spike in IAM policy changes, access key creation, user creation
   - Automatic findings for investigation

3. **AWS Config** (SEC04-BP02)
   - Tracks configuration changes to IAM resources
   - Records who, what, when for every IAM change
   - Enables compliance auditing and security investigations

4. **VPC Flow Logs** (SEC04-BP01)
   - Tracks network traffic (not directly IAM, but supports investigation)
   - Identifies source IPs for API calls
   - Helps correlate IAM activity with network activity

5. **Session Logging for Break-Glass Access**
   - AWS Systems Manager Session Manager logs all shell sessions
   - No SSH keys required (IAM-based authentication)
   - Complete audit trail of commands executed

## IAM Security Checklist (WAF-Aligned)

### SEC02: Identity Management

**Root Account**
- [ ] Root account has MFA enabled (hardware MFA preferred)
- [ ] Root account has no access keys
- [ ] Root account usage is monitored (CloudWatch alarm, EventBridge rule)
- [ ] Root account password stored securely (password manager, safe)
- [ ] Alternative contacts configured (billing, operations, security)

**IAM Users**
- [ ] IAM users only created when IAM Identity Center not feasible
- [ ] All IAM users have unique credentials (no sharing)
- [ ] All IAM users have MFA enabled
- [ ] Password policy enforces 14+ character complexity
- [ ] Access keys rotated every 90 days (or eliminated)
- [ ] Unused credentials identified and removed (90 days)

**IAM Identity Center**
- [ ] IAM Identity Center enabled for workforce access
- [ ] Integrated with corporate identity provider (SAML/OIDC)
- [ ] MFA required for all Identity Center users
- [ ] Permission sets follow least privilege
- [ ] Session durations aligned with risk (1-12 hours)
- [ ] Multi-account access configured via permission sets

**Federated Access**
- [ ] External identity provider integrated (SAML 2.0 or OIDC)
- [ ] Federated users mapped to IAM roles (not users)
- [ ] Temporary credentials only (no long-term keys)
- [ ] MFA enforced at IdP level

### SEC03: Permission Management

**IAM Policies**
- [ ] All policies follow least privilege (specific actions, resources)
- [ ] Wildcard actions (`*`) minimized (only where absolutely necessary)
- [ ] Wildcard resources (`*`) minimized (use specific ARNs)
- [ ] Condition keys used to add contextual restrictions
- [ ] Policies validated using IAM Access Analyzer validate-policy
- [ ] Policies attached to groups, not individual users
- [ ] Inline policies used sparingly (prefer managed policies)

**IAM Roles**
- [ ] IAM roles used for all programmatic access (EC2, Lambda, ECS)
- [ ] Each service/function has dedicated role (not shared)
- [ ] Cross-account roles use External ID (confused deputy prevention)
- [ ] Cross-account roles restricted by IP, MFA, or VPC where appropriate
- [ ] Session durations aligned with risk (1-12 hours)
- [ ] Role trust policies reviewed regularly

**Permissions Boundaries**
- [ ] Permissions boundaries used for delegated IAM management
- [ ] Boundary prevents privilege escalation
- [ ] Boundary enforcement via IAM policy (require boundary on CreateUser/CreateRole)

**Service Control Policies**
- [ ] SCPs enabled in AWS Organizations
- [ ] Baseline SCPs applied to root (prevent disabling security services)
- [ ] Environment-specific SCPs applied to OUs (production, development, sandbox)
- [ ] SCPs tested in non-production before production rollout
- [ ] SCPs documented with purpose and exceptions

**Tag-Based Access Control (ABAC)**
- [ ] Tagging strategy defined (Owner, Project, Environment, DataClassification)
- [ ] Tags enforced on resource creation (via SCPs or IAM policies)
- [ ] IAM policies use tag-based conditions (principal tag matches resource tag)

### SEC04: Detection and Monitoring

**CloudTrail**
- [ ] CloudTrail enabled in all regions
- [ ] CloudTrail logs sent to dedicated S3 bucket in log archive account
- [ ] CloudTrail log file validation enabled
- [ ] CloudTrail integrated with CloudWatch Logs for real-time analysis
- [ ] CloudTrail data events enabled for sensitive resources

**IAM Access Analyzer**
- [ ] IAM Access Analyzer enabled in all regions
- [ ] Zone of trust set to AWS Organization
- [ ] External access findings reviewed weekly
- [ ] Unintended external access remediated immediately
- [ ] Intended external access archived with justification
- [ ] Unused access findings reviewed quarterly
- [ ] Policy validation used in CI/CD pipeline

**AWS Config**
- [ ] AWS Config enabled in all regions
- [ ] IAM-related Config rules deployed (root-account-mfa-enabled, access-keys-rotated, iam-user-unused-credentials-check)
- [ ] Config aggregator configured for multi-account view
- [ ] Non-compliant resources remediated or risk-accepted

**Amazon GuardDuty**
- [ ] GuardDuty enabled in all regions and accounts
- [ ] Delegated administrator configured in security account
- [ ] GuardDuty findings sent to Security Hub
- [ ] High-severity GuardDuty findings trigger automated response
- [ ] IAM-related findings investigated (credential exfiltration, anomalous login)

**CloudWatch and EventBridge**
- [ ] CloudWatch alarms configured for root account usage
- [ ] CloudWatch alarms configured for IAM policy changes
- [ ] CloudWatch alarms configured for failed console logins
- [ ] CloudWatch alarms configured for access key creation
- [ ] EventBridge rules trigger automated responses (SNS, Lambda, Security Hub)

**AWS Security Hub**
- [ ] Security Hub enabled in all regions and accounts
- [ ] Delegated administrator configured in security account
- [ ] Security standards enabled (AWS Foundational Security Best Practices, CIS AWS Foundations)
- [ ] IAM-related findings prioritized and remediated
- [ ] Security Hub integrated with SIEM/ticketing system

### SEC09: Incident Response

**Break-Glass Access**
- [ ] Break-glass IAM user created for emergency access
- [ ] Break-glass credentials stored in physically secured location
- [ ] Break-glass usage monitored and alerted
- [ ] Break-glass procedures documented
- [ ] Break-glass credentials rotated annually

**Incident Response Playbooks**
- [ ] Playbook for compromised IAM credentials (disable user, rotate keys, review activity)
- [ ] Playbook for unauthorized permission changes (revert policy, investigate, lock down)
- [ ] Playbook for GuardDuty IAM findings (investigate, contain, eradicate, recover)

**Automated Incident Response**
- [ ] Lambda function to disable compromised IAM user/access key
- [ ] Lambda function to revert unauthorized IAM policy changes
- [ ] Lambda function to rotate credentials in Secrets Manager
- [ ] EventBridge rules trigger automated response playbooks

---

**End of AWS IAM Security Knowledge Base**

All guidance in this document is derived from the AWS Well-Architected Framework Security Pillar. Implementations should be validated against current AWS service capabilities and organizational requirements.
