# AWS Storage Security - Well-Architected Framework Guidance

This knowledge base covers AWS storage security best practices strictly aligned with the AWS Well-Architected Framework (WAF) Security Pillar.

## WAF Security Pillar Mapping

AWS Storage security primarily addresses:
- **SEC06**: How do you classify your data?
- **SEC07**: How do you protect your data at rest?
- **SEC08**: How do you protect your data in transit?
- **SEC02/SEC03**: Identity and access management (IAM for storage)
- **SEC04**: Detection (logging and monitoring storage access)
- **SEC09**: Incident response (backups, versioning, recovery)

## Core Storage Security Principles (WAF-Aligned)

### Data Classification (SEC06)
- Implement data classification schemes to determine appropriate protection levels
- Use tagging strategies to identify data sensitivity (e.g., `data-classification=confidential`)
- Apply classification-appropriate controls (encryption, access restrictions, retention)
- Use Amazon Macie to discover and classify sensitive data automatically

### Defense in Depth
- Apply security at multiple layers: IAM policies, resource policies, network controls, encryption
- Never rely on a single security control
- Combine preventive and detective controls

### Least Privilege Access (SEC02-BP02, SEC03-BP02)
- Grant minimum required permissions to storage resources
- Use IAM policies, bucket policies, and resource-based policies together
- Regularly review and refine access permissions
- Implement time-bound access where appropriate

### Encryption by Default (SEC07-BP01, SEC08-BP01)
- Enable encryption at rest for all storage services
- Use encryption in transit (TLS 1.2+) for all data movement
- Leverage AWS KMS for centralized key management
- Consider customer-managed keys (CMK) for sensitive data requiring key rotation control

## Amazon S3 Security

### SEC07: Data Protection at Rest

**Encryption Configuration**
- **SSE-S3** (AES-256): AWS-managed keys, suitable for most workloads
- **SSE-KMS**: Customer-managed keys in AWS KMS, provides audit trail via CloudTrail, key rotation, granular access control
- **SSE-C**: Customer-provided keys (customer manages key lifecycle outside AWS)
- **Client-side encryption**: Encrypt before upload (maximum control)
- **Default encryption**: Enable bucket default encryption to ensure all objects are encrypted
- **Enforce encryption**: Use bucket policies to deny uploads without encryption headers

**Bucket Policy Enforcement**
```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::bucket-name/*",
  "Condition": {
    "StringNotEquals": {
      "s3:x-amz-server-side-encryption": "aws:kms"
    }
  }
}
```

### SEC08: Data Protection in Transit

- Enforce HTTPS/TLS for all S3 API requests
- Use bucket policy to deny non-secure transport:
```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": [
    "arn:aws:s3:::bucket-name/*",
    "arn:aws:s3:::bucket-name"
  ],
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "false"
    }
  }
}
```

### SEC02/SEC03: Identity and Access Management

**S3 Block Public Access (SEC03-BP06)**
- Enable at account level and bucket level
- Four settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets
- WAF recommendation: Enable all four settings unless explicit public access required
- Use S3 Access Analyzer to validate access configurations

**Bucket Policies (SEC03-BP03)**
- Define resource-based access control
- Use condition keys: `aws:PrincipalOrgID`, `aws:SourceVpce`, `aws:SourceIp`, `s3:x-amz-acl`
- Prefer bucket policies over ACLs for modern access control
- Restrict access to specific VPC endpoints or IP ranges for sensitive data

**S3 Access Points (SEC03-BP07)**
- Create application-specific access points with dedicated policies
- Simplify access management for shared datasets
- Restrict access points to VPC-only access for internal applications
- Each access point has its own IAM policy and network controls

**IAM Policies for S3 (SEC03-BP02)**
- Grant least privilege access to specific buckets and prefixes
- Use IAM Access Analyzer to identify overly permissive policies
- Implement service control policies (SCPs) to enforce organization-wide S3 security baseline

**Access Control Lists (ACLs)**
- Legacy mechanism; prefer bucket policies and IAM policies
- Disable ACLs using S3 Object Ownership (BucketOwnerEnforced) for new buckets
- If ACLs required, never use "public-read" or "public-read-write"

### SEC04: Detection and Monitoring

**S3 Access Logging (SEC04-BP02)**
- Enable server access logging to capture detailed request records
- Send logs to separate, secured logging bucket
- Use lifecycle policies to manage log retention
- Analyze logs with Amazon Athena or CloudWatch Logs Insights

**AWS CloudTrail S3 Data Events (SEC04-BP01)**
- Enable CloudTrail data events for object-level API activity
- Captures GetObject, PutObject, DeleteObject operations
- Essential for security investigations and compliance audits
- Consider costs for high-volume buckets; use advanced event selectors to filter

**Amazon Macie (SEC06-BP01, SEC04-BP03)**
- Automated sensitive data discovery (PII, credentials, financial data)
- Continuous monitoring of S3 for security and compliance risks
- Custom data identifiers for organization-specific sensitive data
- Integrates with Security Hub and EventBridge for automated response

**S3 Inventory (SEC04-BP02)**
- Scheduled reports of bucket contents (encryption status, storage class, replication status)
- Validate encryption compliance at scale
- Audit object metadata and access control configurations

### SEC09: Incident Response and Data Resilience

**Versioning (SEC09-BP02)**
- Preserve, retrieve, and restore every version of every object
- Protects against accidental deletion and overwrites
- Essential for ransomware resilience
- Combine with lifecycle policies to manage version retention and costs

**S3 Object Lock (SEC09-BP03)**
- WORM (Write-Once-Read-Many) storage model
- **Governance mode**: Users with special permissions can alter retention or delete
- **Compliance mode**: No one can delete or overwrite (including root user) until retention expires
- Use for regulatory compliance (SEC17a-4, HIPAA, GDPR retention)
- Set default retention periods at bucket level or per-object

**S3 Replication (SEC09-BP01)**
- **Cross-Region Replication (CRR)**: Disaster recovery, compliance, latency reduction
- **Same-Region Replication (SRR)**: Aggregate logs, separate production/test
- Replicate encrypted objects (SSE-S3, SSE-KMS, SSE-C supported)
- Replicate Object Lock configuration for compliance use cases
- Enable S3 Replication Time Control (RTC) for predictable replication SLAs

**S3 Lifecycle Policies**
- Automatically transition objects to cost-effective storage classes (S3-IA, Glacier, Deep Archive)
- Expire non-current versions after retention period
- Remove incomplete multipart uploads
- Apply classification-based retention rules

**S3 Access Points + VPC Endpoints (SEC05-BP01)**
- Restrict S3 access to private network paths only
- Use VPC endpoint policies to limit bucket access
- Gateway endpoints (no cost) or Interface endpoints (PrivateLink)

## Amazon EBS Security

### SEC07: Encryption at Rest (SEC07-BP02)

**EBS Encryption**
- AES-256 encryption using AWS KMS
- Encrypts data at rest, snapshots, and data in transit between EC2 and EBS
- Enable encryption by default at region level (account setting)
- Cannot disable encryption once enabled on a volume
- Minimal performance impact (hardware-accelerated)

**Key Management**
- Use AWS-managed key (`aws/ebs`) for standard workloads
- Use customer-managed keys (CMK) for:
  - Cross-account snapshot sharing with controlled access
  - Key rotation policies
  - Granular audit trail via CloudTrail
  - Key usage restrictions via IAM and key policies

**Enforcement (SEC03-BP06)**
- IAM policy to deny unencrypted volume creation:
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
- Use AWS Config rule `encrypted-volumes` to detect non-compliant volumes

### SEC09: Snapshots and Backup

**EBS Snapshots (SEC09-BP02)**
- Incremental backups stored in S3 (abstracted, not direct S3 access)
- Inherit encryption from source volume
- Can copy snapshots to different regions (re-encrypted with target region key)
- Tag snapshots for lifecycle management and cost allocation

**Snapshot Sharing (SEC03-BP03)**
- Share encrypted snapshots across accounts using CMK key policies
- Grant `kms:CreateGrant` and `kms:DescribeKey` to target account
- Never share unencrypted snapshots containing sensitive data
- Use AWS Resource Access Manager (RAM) for organized sharing

**Snapshot Lifecycle (SEC09-BP01)**
- Use Amazon Data Lifecycle Manager (DLM) for automated snapshot creation/deletion
- Define retention policies based on data classification
- Tag-based policies for flexible management
- Cross-region snapshot copy for disaster recovery

### SEC04: Monitoring

**CloudTrail for EBS (SEC04-BP01)**
- Captures CreateVolume, DeleteVolume, CreateSnapshot, ModifyVolume
- Monitor for unencrypted volume creation attempts
- Audit snapshot sharing activity

**AWS Config Rules**
- `encrypted-volumes`: Verify all EBS volumes are encrypted
- `ec2-volume-inuse-check`: Identify unused volumes (cost and security)

## Amazon EFS Security

### SEC07/SEC08: Encryption (SEC07-BP03, SEC08-BP02)

**Encryption at Rest**
- Enable encryption at file system creation (cannot enable post-creation)
- Uses AWS KMS (AWS-managed or customer-managed keys)
- Transparent to applications
- No performance degradation for most workloads

**Encryption in Transit (SEC08-BP02)**
- Enable via EFS mount helper with TLS option (`-o tls`)
- Uses TLS 1.2 between client and EFS
- Strongly recommended for all EFS access, especially across untrusted networks
- Mount command: `mount -t efs -o tls fs-12345:/ /mnt/efs`

### SEC02/SEC03: Access Control

**IAM Authorization for NFS (SEC03-BP02)**
- Enable IAM authorization at file system or access point level
- Use IAM policies to control mount access
- Each NFS client must use EFS mount helper with IAM credentials
- Replaces or augments POSIX permissions

**POSIX Permissions**
- Standard Linux file permissions (user, group, other)
- Applied at file/directory level
- Combine with IAM for defense in depth

**EFS Access Points (SEC03-BP07)**
- Application-specific entry points into EFS
- Enforce IAM policies per access point
- Enforce user identity (UID/GID) for all connections through access point
- Simplify application access without managing POSIX permissions

**EFS File System Policies (SEC03-BP03)**
- Resource-based policy attached to file system
- Enforce encryption in transit:
```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "*",
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "false"
    }
  }
}
```
- Disable root access, enforce read-only access, restrict to VPC

### SEC05: Network Protection (SEC05-BP01)

**VPC Security Groups**
- Control access to EFS mount targets
- Inbound rule: NFS port 2049 from authorized security groups only
- Never expose port 2049 to 0.0.0.0/0
- Apply principle of least privilege

**VPC Mount Targets**
- EFS accessible only from within VPC (or via VPN/Direct Connect)
- Create mount targets in each AZ for high availability
- Use PrivateLink for cross-VPC access without VPC peering

### SEC04: Monitoring

**CloudWatch Metrics**
- Monitor ClientConnections, DataReadIOBytes, DataWriteIOBytes
- Alert on anomalous access patterns

**CloudTrail Integration (SEC04-BP01)**
- Logs CreateFileSystem, DeleteFileSystem, ModifyMountTargetSecurityGroups
- Audit IAM authorization usage

## Amazon FSx Security

### FSx for Windows File Server

**SEC07: Encryption (SEC07-BP04)**
- Encryption at rest enabled by default (AWS-managed or customer-managed KMS keys)
- Encryption in transit via SMB 3.0+ encryption
- Automatic backups are encrypted

**Active Directory Integration (SEC02-BP01)**
- Integrates with AWS Managed Microsoft AD or self-managed AD
- Use AD security groups for access control
- Supports SMB ACLs and Windows NTFS permissions
- Enforce Kerberos authentication

**SEC05: Network Security**
- Deploy in VPC with security groups controlling SMB/CIFS access (port 445)
- Restrict access to authorized instances and on-premises networks via VPN/DX
- Use VPC endpoint policies to limit access

**Backup and Recovery (SEC09-BP02)**
- Daily automatic backups (encrypted, retained 7-35 days)
- User-initiated backups with custom retention
- Cross-region backup copy for DR

### FSx for Lustre

**SEC07: Encryption**
- At-rest encryption via KMS (optional, enabled at creation)
- In-transit encryption for data between file system and S3
- Scratch file systems: ephemeral, encryption recommended for sensitive data

**S3 Integration**
- Link FSx for Lustre to S3 bucket for data repository
- Apply S3 bucket security controls (encryption, policies, logging)
- Export processed data back to S3 with inherited encryption

**SEC05: Network Security**
- VPC-based deployment
- Security groups control Lustre client access
- Limit access to compute clusters requiring high-performance storage

### FSx for NetApp ONTAP and OpenZFS

**Encryption (SEC07)**
- At-rest and in-transit encryption supported
- Integration with AWS KMS for key management

**Access Control**
- POSIX permissions (OpenZFS)
- NTFS ACLs and SMB shares (ONTAP)
- IAM policies for AWS API operations

**Network Security (SEC05)**
- VPC-based, security group controlled
- Multi-AZ deployment for HA

## Amazon S3 Glacier and Glacier Deep Archive

### SEC07: Data Protection at Rest

**Vault Lock (SEC09-BP03)**
- Enforce compliance controls with a lockable policy (WORM)
- Once locked, policy cannot be changed (even by root account)
- Use for regulatory compliance requiring immutable archives
- Define retention periods and legal hold controls
- Example use cases: SEC Rule 17a-4, HIPAA, CJIS

**Vault Access Policies (SEC03-BP03)**
- IAM-like policies attached to vaults
- Control who can upload, retrieve, or delete archives
- Combine with IAM user/role policies for defense in depth
- Restrict access by time, IP address, or MFA requirement

**Encryption**
- All data automatically encrypted at rest (AES-256, AWS-managed keys)
- Encrypted in transit via HTTPS

### SEC04: Monitoring and Logging

**CloudTrail for Glacier (SEC04-BP01)**
- Logs vault creation, policy changes, archive operations
- Audit retrieval requests and completions

**SNS Notifications**
- Configure vault notifications for job completion (retrieval, inventory)
- Use for alerting on unexpected retrieval activity (potential data exfiltration)

### Retrieval Controls

**Vault Retrieval Policies**
- Limit retrieval speed to control costs and detect anomalies
- Set free tier limits and deny faster retrievals
- Helps prevent unauthorized bulk data retrieval

## AWS Backup

### SEC09: Centralized Backup Management (SEC09-BP01, SEC09-BP02)

**Backup Vaults**
- Logical container for recovery points
- Apply encryption using AWS KMS (customer-managed keys recommended)
- Organize backups by data classification or workload

**Backup Vault Lock (SEC09-BP03)**
- Enforce WORM for backup retention
- Prevent deletion of recovery points until retention expires
- Protect against ransomware, insider threats, accidental deletion
- Supports minimum and maximum retention periods

**Backup Policies (SEC03-BP02)**
- Control access to backup vaults and recovery points
- Deny deletion operations except for specific IAM roles
- Use IAM policies and resource-based policies together

**Cross-Account and Cross-Region Backup (SEC09-BP01)**
- Copy backups to separate account for isolation (blast radius reduction)
- Store backups in different region for disaster recovery
- Ensure encryption in transit and at rest during copy
- Use AWS Organizations for centralized backup policy management

**AWS Backup Audit Manager (SEC04-BP02)**
- Continuous compliance monitoring of backup activity
- Pre-built frameworks (HIPAA, PCI, GDPR, etc.)
- Detects non-compliant resources (missing backups, unencrypted backups)
- Integrates with AWS Security Hub

### SEC04: Monitoring

**CloudTrail Integration**
- Logs backup job initiation, completion, failure
- Audit vault policy changes and lock operations

**CloudWatch Alarms**
- Alert on backup job failures
- Monitor recovery point creation trends

**EventBridge Rules**
- Automate responses to backup events (failed jobs, vault lock changes)

## General Storage Security Best Practices (WAF-Aligned)

### Shared Responsibility Model (SEC01)
- AWS secures infrastructure, physical security, and foundational services
- Customer responsible for: encryption configuration, access policies, logging/monitoring, data classification, backup/recovery

### Lifecycle Policies (SEC09-BP01, Cost Optimization)
- Transition data to cost-effective storage classes based on access patterns
- Automatically delete data after retention period expires
- Reduce attack surface by removing unnecessary data
- Ensure lifecycle rules don't conflict with compliance retention requirements

### Tagging Strategy (SEC06-BP01)
- Tag all storage resources with: data-classification, owner, project, environment
- Use tags to enforce encryption policies via tag-based IAM conditions
- Enable cost allocation and resource organization

### Preventive Controls (SEC03-BP06)
- Service Control Policies (SCPs): Block public S3 access, require encryption
- IAM permission boundaries: Limit maximum permissions for storage access
- VPC endpoint policies: Restrict accessible buckets/file systems

### Detective Controls (SEC04)
- AWS Config: Continuous compliance monitoring
- AWS Security Hub: Aggregated security findings across storage services
- Amazon GuardDuty: Threat detection for S3 (suspicious access patterns, credential exposure)
- AWS IAM Access Analyzer: Identify resources shared with external entities

### Automation (WAF Design Principle)
- Use Infrastructure as Code (CloudFormation, CDK, Terraform) to enforce security baselines
- Automate remediation via EventBridge + Lambda (e.g., re-enable S3 Block Public Access if disabled)
- Use AWS Systems Manager for patch management of instances accessing storage

### Keep People Away from Data (WAF Design Principle)
- Minimize direct human access to storage resources
- Use service roles for applications to access storage
- Implement break-glass procedures for emergency access
- Log and alert on all data access by privileged users

### Regular Security Reviews (SEC01-BP05)
- Quarterly access review: Remove unused IAM policies and resource policies
- Annual disaster recovery test: Validate backup restores
- Use AWS Trusted Advisor for S3 bucket permission checks
- Use S3 Storage Lens for organization-wide visibility and anomaly detection

## Cross-Service Storage Security Patterns

### Data Lake Security Pattern
- S3 as central data store with bucket-level and prefix-level access control
- AWS Lake Formation for centralized permissions management
- Encrypt all data with SSE-KMS
- Use S3 Access Points for application-specific access
- Enable CloudTrail data events and Macie for monitoring

### Backup and DR Pattern
- Use AWS Backup for centralized backup across EBS, EFS, FSx, RDS, DynamoDB
- Enable Backup Vault Lock for compliance
- Cross-region and cross-account backup copies
- Regular restore testing in isolated environment
- Immutable backups to protect against ransomware

### High-Security Data Storage Pattern
- S3 with SSE-KMS using customer-managed keys
- S3 Object Lock in compliance mode
- S3 Block Public Access enabled (account and bucket)
- VPC endpoint with restrictive endpoint policy
- CloudTrail data events + Macie + GuardDuty
- Access only via IAM roles with MFA requirement
- Access logging to separate, locked-down logging bucket

## WAF Security Pillar Question Checklist for Storage

**SEC06 (Data Classification)**
- Have you identified and classified all data stored in AWS?
- Are storage configurations appropriate for data sensitivity levels?
- Is sensitive data discovery automated (Macie)?

**SEC07 (Data at Rest)**
- Is encryption at rest enabled for all storage services?
- Are you using appropriate key management (AWS-managed vs. customer-managed)?
- Are encryption settings enforced via policy?

**SEC08 (Data in Transit)**
- Is encryption in transit (TLS 1.2+) enforced for all storage access?
- Are there bucket/file system policies denying non-secure transport?

**SEC02/SEC03 (Access Management)**
- Are you following least privilege for storage access?
- Are public access controls properly configured (S3 Block Public Access)?
- Do you use resource-based policies effectively?
- Is access regularly reviewed and revoked when no longer needed?

**SEC04 (Detection)**
- Are CloudTrail data events enabled for sensitive storage?
- Is access logging enabled (S3, EFS, FSx)?
- Are you monitoring for anomalous access patterns?
- Are you using automated sensitive data discovery?

**SEC09 (Incident Response)**
- Do you have backups of all critical data?
- Are backups immutable (Object Lock, Vault Lock)?
- Are backups stored in separate account/region?
- Have you tested restore procedures?
- Is versioning enabled where appropriate?

---

**End of AWS Storage Security Knowledge Base**

All guidance in this document is derived from the AWS Well-Architected Framework Security Pillar. Implementations should be validated against current AWS service capabilities and organizational requirements.
