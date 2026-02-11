# AWS Network Reference Architectures - Approved VPC Connectivity Patterns

This document defines three approved VPC connectivity patterns for AWS workloads. Each pattern addresses different connectivity requirements while maintaining security controls aligned with the AWS Well-Architected Framework (WAF) Security Pillar. All new workloads must use one of these patterns unless an exception is approved by the security architecture team.

## Pattern Selection Decision Criteria

### Choosing the Right Pattern

Select a VPC connectivity pattern based on the workload's network requirements. The three patterns are ordered from most restrictive (highest security) to least restrictive:

**Pattern 1: Isolated VPC** — No internet access, no peering. Use when:
- Workloads process sensitive data and require complete network isolation
- Batch processing, data analytics, or ETL jobs that only need access to AWS services (S3, DynamoDB, SQS)
- Regulatory requirements mandate no internet connectivity (PCI-DSS CDE, HIPAA restricted data)
- Workloads have no dependency on external APIs, package repositories, or third-party services
- Maximum blast radius reduction is the primary concern

**Pattern 2: Peered VPC (VDI Network Access)** — VPC peering to a VDI/management VPC for administrative access. Use when:
- Operators need interactive access to resources (SSH, RDP, database clients) via a VDI or bastion environment
- Workloads require connectivity to shared services hosted in a central VPC (Active Directory, SIEM, monitoring)
- Applications need to communicate with other internal workloads across VPC boundaries
- Development and staging environments that require developer access from a centralized VDI VPC

**Pattern 3: VPC Endpoints (Isolated VPC with AWS PrivateLink)** — No internet, but private access to AWS services and internal APIs. Use when:
- Workloads in isolated VPCs need access to AWS services beyond S3 and DynamoDB (Secrets Manager, Systems Manager, CloudWatch, ECR)
- Applications consume internal APIs exposed via PrivateLink from other VPCs or accounts
- The workload must remain isolated from the internet but requires programmatic access to AWS control plane services
- Container workloads (ECS, EKS) that need to pull images from ECR without internet access

### Decision Flow

1. Does the workload need internet access? If yes, none of these patterns apply — use a standard VPC with public/private subnets and NAT Gateway (not covered here).
2. Does the workload only need S3 and/or DynamoDB? If yes, use **Isolated VPC** with Gateway Endpoints (free, no PrivateLink needed).
3. Does the workload need access to other AWS services (Secrets Manager, SSM, ECR, CloudWatch)? If yes, use **VPC Endpoints Pattern**.
4. Do operators or applications need interactive network connectivity to a VDI or shared services VPC? If yes, use **Peered VPC Pattern**.
5. If both VPC peering and VPC endpoints are needed, see the **Combining Patterns** section.

### Security Classification Alignment

- **Confidential/Restricted data**: Isolated VPC or VPC Endpoints pattern required. Peered VPC only if peering is restricted to a hardened VDI VPC with audit logging.
- **Internal data**: Any pattern is acceptable. Select based on connectivity requirements.
- **Public data**: Any pattern is acceptable, but consider whether internet access is truly needed before defaulting to a standard VPC.

## Isolated VPC Pattern - Complete Network Isolation

### Architecture Description

The Isolated VPC pattern creates a VPC with no route to the internet. There is no Internet Gateway, no NAT Gateway, and no VPC peering. Resources in the VPC can communicate only with other resources in the same VPC and with S3/DynamoDB through Gateway Endpoints (which are free and do not require PrivateLink).

This pattern provides the strongest network isolation available in AWS. An attacker who compromises a resource in an Isolated VPC cannot reach the internet, other VPCs, or on-premises networks. Data exfiltration is limited to the S3 buckets and DynamoDB tables permitted by the Gateway Endpoint policy.

### Use Cases

- Batch data processing pipelines reading from and writing to S3
- Data analytics workloads using EMR, Glue, or custom ETL on EC2/ECS
- Machine learning training jobs reading training data from S3
- Database-only workloads (RDS, Aurora) accessed exclusively by other resources within the same VPC
- Compliance-sensitive workloads requiring provable network isolation for audit

### Subnet Design

All subnets in an Isolated VPC are isolated subnets — route tables contain only the local VPC route and Gateway Endpoint routes. There are no public subnets and no private subnets with NAT routes.

Recommended subnet layout for a two-AZ deployment:
- **Application subnet A** (e.g., 10.0.1.0/24) in AZ-a — compute resources (EC2, ECS, Lambda)
- **Application subnet B** (e.g., 10.0.2.0/24) in AZ-b — compute resources (EC2, ECS, Lambda)
- **Data subnet A** (e.g., 10.0.3.0/24) in AZ-a — RDS, ElastiCache, other data stores
- **Data subnet B** (e.g., 10.0.4.0/24) in AZ-b — RDS, ElastiCache, other data stores

### Routing Requirements

Route tables contain only:
- Local route (VPC CIDR, automatically added)
- S3 Gateway Endpoint route (prefix list for S3, automatically added when endpoint is created)
- DynamoDB Gateway Endpoint route (prefix list for DynamoDB, if needed)

No 0.0.0.0/0 route exists. Resources cannot resolve public DNS names unless a Route 53 Resolver inbound endpoint is configured in the VPC.

### Security Controls

**Security Groups**: Apply least privilege ingress/egress rules. Since there is no internet connectivity, Security Groups primarily control intra-VPC traffic between application and data tiers.

**NACLs**: Use custom NACLs on data subnets to add a secondary defense layer. Allow only the application subnet CIDRs on required database ports.

**Gateway Endpoint Policies**: Restrict S3 and DynamoDB access to only the specific buckets and tables required by the workload. This is the primary data exfiltration control in an Isolated VPC.

**VPC Flow Logs**: Enable Flow Logs to monitor all traffic within the VPC. In an Isolated VPC, any traffic destined for external IP addresses indicates a misconfiguration or compromise attempt.

**WAF Alignment**: This pattern directly implements SEC05-BP01 (create network layers), SEC05-BP03 (implement network segmentation), and supports SEC03-BP02 (least privilege) through endpoint policies.

### Limitations

- Cannot install software packages from the internet (use pre-baked AMIs, container images pushed to ECR via a separate pipeline, or S3-hosted packages)
- Cannot call AWS services that lack Gateway Endpoints (only S3 and DynamoDB have Gateway Endpoints) — use the VPC Endpoints pattern if other services are needed
- Cannot send logs to external SIEM platforms — use CloudWatch or S3 for log destinations
- DNS resolution for public domains does not work without Route 53 Resolver configuration
- No administrative SSH/RDP access unless a bastion is deployed within the VPC (which is itself isolated)

### Isolated VPC Security Group Example

```json
{
  "Type": "AWS::EC2::SecurityGroup",
  "Properties": {
    "GroupDescription": "Application tier in Isolated VPC - allows outbound to data tier and S3 endpoint only",
    "VpcId": "vpc-isolated-0123456789",
    "SecurityGroupIngress": [],
    "SecurityGroupEgress": [
      {
        "IpProtocol": "tcp",
        "FromPort": 5432,
        "ToPort": 5432,
        "DestinationSecurityGroupId": "sg-data-tier-id",
        "Description": "Allow PostgreSQL to data tier"
      },
      {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "DestinationPrefixListId": "pl-63a5400a",
        "Description": "Allow HTTPS to S3 Gateway Endpoint"
      }
    ],
    "Tags": [
      {
        "Key": "Name",
        "Value": "isolated-vpc-app-tier-sg"
      },
      {
        "Key": "Pattern",
        "Value": "isolated-vpc"
      }
    ]
  }
}
```

This Security Group has no ingress rules (no inbound traffic from outside the VPC) and restricts egress to only the data tier Security Group on PostgreSQL port and the S3 Gateway Endpoint prefix list on HTTPS. This enforces strict least privilege in an Isolated VPC where no internet connectivity exists.

## Peered VPC Pattern - VDI Network Access via VPC Peering

### Architecture Description

The Peered VPC pattern extends an Isolated VPC by adding a VPC peering connection to a centralized VDI (Virtual Desktop Infrastructure) or management VPC. The workload VPC remains isolated from the internet — all operator access flows through the VDI VPC, which serves as the single controlled entry point.

The VDI VPC hosts bastion hosts, VDI instances (Amazon WorkSpaces, AppStream), or jump servers that operators use to access resources in peered workload VPCs. The peering connection is non-transitive: the workload VPC can communicate with the VDI VPC but not with other VPCs peered to the VDI VPC.

### Use Cases

- Production workloads requiring operator SSH/RDP access for maintenance and troubleshooting
- Applications that need connectivity to shared services (Active Directory, centralized monitoring, SIEM agents) hosted in a management VPC
- Development and staging environments accessed by developers through VDI workstations
- Workloads where Systems Manager Session Manager is not available or not approved, requiring traditional bastion access

### Subnet Design

The workload VPC uses isolated subnets (no internet routes), identical to the Isolated VPC pattern. The VDI/management VPC is a separate VPC managed by the platform team.

Recommended subnet layout for the workload VPC (two-AZ):
- **Application subnet A** (e.g., 10.1.1.0/24) in AZ-a
- **Application subnet B** (e.g., 10.1.2.0/24) in AZ-b
- **Data subnet A** (e.g., 10.1.3.0/24) in AZ-a
- **Data subnet B** (e.g., 10.1.4.0/24) in AZ-b

CIDR blocks must not overlap with the VDI VPC CIDR. Use AWS VPC IPAM or a centralized IP allocation process to prevent collisions.

### Routing Requirements

Workload VPC route tables include:
- Local route (workload VPC CIDR)
- VPC peering route: VDI VPC CIDR (or specific VDI subnet CIDRs for least privilege) pointing to the peering connection
- S3/DynamoDB Gateway Endpoint routes (if needed)

The WAF recommends routing only the specific VDI subnet CIDRs rather than the entire VDI VPC CIDR. This prevents unintended access from non-VDI subnets in the management VPC.

VDI VPC route tables include a reciprocal route for the workload VPC CIDR pointing to the peering connection.

### Security Controls

**Security Groups**: Security Groups in the workload VPC must explicitly allow traffic from the VDI VPC. Use cross-VPC Security Group references (within the same Region) to allow traffic only from the VDI bastion Security Group rather than the entire VDI VPC CIDR.

**NACLs**: Apply NACLs on workload VPC subnets to allow traffic only from the VDI VPC CIDR on required ports (SSH/22, RDP/3389, database ports). Deny all other inbound traffic from the peering connection.

**VPC Peering Configuration**: Do not enable DNS resolution from the VDI VPC to the workload VPC unless required. Keep the peering connection as restrictive as possible.

**VPC Flow Logs**: Enable Flow Logs on both VPCs. Monitor peering connection traffic for anomalous access patterns (unusual hours, unexpected source instances, high data transfer volumes).

**WAF Alignment**: This pattern implements SEC05-BP03 (implement network segmentation) through peering with restrictive routing, SEC05-BP02 (control traffic at all layers) through layered SG/NACL controls, and SEC04-BP02 (analyze logs) through VPC Flow Logs on peering traffic.

### Limitations

- VPC peering is non-transitive: the workload VPC cannot reach other VPCs through the VDI VPC (this is a security feature, not a limitation)
- CIDR blocks must not overlap between peered VPCs — plan address space carefully
- Cross-Region peering adds latency; prefer same-Region peering for interactive access
- Security Group cross-VPC references only work within the same Region
- Peering connections increase blast radius compared to a fully isolated VPC — a compromise of the VDI VPC could provide a pivot point to peered workload VPCs

### Peered VPC Application Tier Security Group Example

```json
{
  "Type": "AWS::EC2::SecurityGroup",
  "Properties": {
    "GroupDescription": "Application tier in Peered VPC - allows SSH from VDI bastion SG and outbound to data tier",
    "VpcId": "vpc-workload-0123456789",
    "SecurityGroupIngress": [
      {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "SourceSecurityGroupId": "sg-vdi-bastion-id",
        "SourceSecurityGroupOwnerId": "111222333444",
        "Description": "Allow SSH from VDI bastion hosts only"
      }
    ],
    "SecurityGroupEgress": [
      {
        "IpProtocol": "tcp",
        "FromPort": 5432,
        "ToPort": 5432,
        "DestinationSecurityGroupId": "sg-data-tier-id",
        "Description": "Allow PostgreSQL to data tier"
      },
      {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "DestinationPrefixListId": "pl-63a5400a",
        "Description": "Allow HTTPS to S3 Gateway Endpoint"
      }
    ],
    "Tags": [
      {
        "Key": "Name",
        "Value": "peered-vpc-app-tier-sg"
      },
      {
        "Key": "Pattern",
        "Value": "peered-vpc-vdi"
      }
    ]
  }
}
```

This Security Group allows SSH access only from the VDI bastion Security Group in a cross-account peered VPC (using SourceSecurityGroupOwnerId for cross-account references). Egress is restricted to the data tier and S3 Gateway Endpoint. This enforces least privilege by ensuring only VDI bastion hosts — not arbitrary instances in the VDI VPC — can access the workload.

### Peered VPC Data Subnet NACL Example

```json
[
  {
    "Type": "AWS::EC2::NetworkAclEntry",
    "Properties": {
      "NetworkAclId": "acl-data-subnet-id",
      "RuleNumber": 100,
      "Protocol": 6,
      "RuleAction": "allow",
      "CidrBlock": "10.1.1.0/24",
      "PortRange": {
        "From": 5432,
        "To": 5432
      },
      "Egress": false
    }
  },
  {
    "Type": "AWS::EC2::NetworkAclEntry",
    "Properties": {
      "NetworkAclId": "acl-data-subnet-id",
      "RuleNumber": 110,
      "Protocol": 6,
      "RuleAction": "allow",
      "CidrBlock": "10.1.2.0/24",
      "PortRange": {
        "From": 5432,
        "To": 5432
      },
      "Egress": false
    }
  },
  {
    "Type": "AWS::EC2::NetworkAclEntry",
    "Properties": {
      "NetworkAclId": "acl-data-subnet-id",
      "RuleNumber": 100,
      "Protocol": 6,
      "RuleAction": "allow",
      "CidrBlock": "10.1.1.0/24",
      "PortRange": {
        "From": 1024,
        "To": 65535
      },
      "Egress": true
    }
  },
  {
    "Type": "AWS::EC2::NetworkAclEntry",
    "Properties": {
      "NetworkAclId": "acl-data-subnet-id",
      "RuleNumber": 110,
      "Protocol": 6,
      "RuleAction": "allow",
      "CidrBlock": "10.1.2.0/24",
      "PortRange": {
        "From": 1024,
        "To": 65535
      },
      "Egress": true
    }
  }
]
```

This NACL configuration on the data subnet allows PostgreSQL (port 5432) inbound only from the application subnets (10.1.1.0/24 and 10.1.2.0/24) and ephemeral port egress for return traffic. Traffic from the VDI VPC CIDR is not permitted to reach the data subnet directly — operators must access databases through the application tier. This NACL provides defense-in-depth beyond Security Groups.

## VPC Endpoints Pattern - Isolated VPC with AWS PrivateLink

### Architecture Description

The VPC Endpoints pattern extends the Isolated VPC by adding Interface Endpoints (AWS PrivateLink) for AWS services that lack Gateway Endpoints. The VPC remains isolated from the internet — no IGW, no NAT Gateway, no VPC peering. All AWS service access occurs through VPC endpoints deployed as elastic network interfaces within the VPC's subnets.

This pattern provides network isolation equivalent to the Isolated VPC pattern while enabling access to the full range of AWS services. It is the recommended pattern for containerized workloads (ECS, EKS) that need ECR image pulls, Secrets Manager for configuration, and CloudWatch for logging — all without internet connectivity.

### Use Cases

- Containerized applications (ECS Fargate, EKS) pulling images from ECR in an isolated VPC
- Workloads retrieving secrets from AWS Secrets Manager or parameters from Systems Manager Parameter Store
- Applications sending logs and metrics to CloudWatch without internet access
- Lambda functions in VPC that need to call AWS services (SQS, SNS, Step Functions)
- Workloads using AWS KMS for encryption operations in an isolated network

### Subnet Design

Identical to the Isolated VPC pattern, with the addition of endpoint subnets:

- **Application subnet A** (e.g., 10.2.1.0/24) in AZ-a
- **Application subnet B** (e.g., 10.2.2.0/24) in AZ-b
- **Data subnet A** (e.g., 10.2.3.0/24) in AZ-a
- **Data subnet B** (e.g., 10.2.4.0/24) in AZ-b
- **Endpoint subnet A** (e.g., 10.2.5.0/28) in AZ-a — VPC interface endpoint ENIs
- **Endpoint subnet B** (e.g., 10.2.6.0/28) in AZ-b — VPC interface endpoint ENIs

Endpoint subnets can be small (/28) since they only host endpoint ENIs. Separating endpoint ENIs into dedicated subnets allows applying distinct NACLs to control endpoint access at the subnet level.

### Routing Requirements

Route tables contain only:
- Local route (VPC CIDR)
- S3 Gateway Endpoint route (prefix list, if S3 access is needed)
- DynamoDB Gateway Endpoint route (prefix list, if DynamoDB access is needed)

Interface Endpoints do not require route table entries — they use DNS resolution to direct traffic to the endpoint ENIs within the VPC. Enable private DNS on Interface Endpoints so that standard AWS SDK calls resolve to the endpoint's private IP addresses automatically.

### Security Controls

**Endpoint Policies**: Apply least privilege policies to each VPC endpoint. For example, restrict the Secrets Manager endpoint to only allow GetSecretValue for specific secret ARNs. Restrict the ECR endpoint to only allow image pulls from specific repositories.

**Security Groups for Endpoints**: Create a dedicated Security Group for each VPC endpoint (or group of related endpoints). Allow inbound HTTPS (port 443) only from the application tier Security Group. This prevents unauthorized resources from accessing AWS services through the endpoints.

**Gateway Endpoint Policies**: Apply restrictive policies to S3 and DynamoDB Gateway Endpoints, limiting access to specific buckets and tables.

**NACLs**: Apply NACLs on endpoint subnets to allow HTTPS (port 443) only from application and data subnet CIDRs.

**VPC Flow Logs**: Enable Flow Logs to monitor traffic to endpoint ENIs. Unexpected traffic patterns to endpoints may indicate compromise or misconfiguration.

**WAF Alignment**: This pattern implements SEC05-BP03 (implement network segmentation) by keeping all traffic on the AWS network, SEC05-BP01 (create network layers) through dedicated endpoint subnets, and SEC03-BP02 (least privilege) through endpoint policies and Security Groups.

### Limitations

- Interface Endpoints incur hourly charges (~USD 0.01/hour/AZ) and data processing charges (~USD 0.01/GB) — costs scale with the number of endpoints and data volume
- Each AWS service requires a separate Interface Endpoint — a workload using 10 AWS services needs 10 endpoints (plus Gateway Endpoints for S3/DynamoDB)
- Private DNS requires the VPC to have enableDnsSupport and enableDnsHostnames set to true
- Some AWS services may not have Interface Endpoint support in all Regions
- Cannot access third-party APIs or external services — only AWS services with PrivateLink support are reachable

### S3 Gateway Endpoint Policy Example (VPC Endpoints Pattern)

```json
{
  "Type": "AWS::EC2::VPCEndpoint",
  "Properties": {
    "VpcId": "vpc-endpoints-0123456789",
    "ServiceName": "com.amazonaws.us-east-1.s3",
    "RouteTableIds": [
      "rtb-app-subnet-a",
      "rtb-app-subnet-b",
      "rtb-data-subnet-a",
      "rtb-data-subnet-b"
    ],
    "PolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "AllowAppBucketAccess",
          "Effect": "Allow",
          "Principal": "*",
          "Action": [
            "s3:GetObject",
            "s3:PutObject",
            "s3:ListBucket",
            "s3:GetBucketLocation"
          ],
          "Resource": [
            "arn:aws:s3:::my-org-app-data-bucket",
            "arn:aws:s3:::my-org-app-data-bucket/*"
          ]
        },
        {
          "Sid": "AllowECRLayerAccess",
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::prod-us-east-1-starport-layer-bucket/*"
        }
      ]
    }
  }
}
```

This S3 Gateway Endpoint policy allows access to the application data bucket and the ECR layer bucket (required for ECS/EKS container image pulls). The ECR layer bucket statement is essential in the VPC Endpoints pattern because ECR stores container image layers in S3. Without this statement, container image pulls fail even if the ECR Interface Endpoint is configured.

### VPC Endpoint Security Group Example (VPC Endpoints Pattern)

```json
{
  "Type": "AWS::EC2::SecurityGroup",
  "Properties": {
    "GroupDescription": "Security group for AWS service VPC Interface Endpoints - allows HTTPS from application and data tiers",
    "VpcId": "vpc-endpoints-0123456789",
    "SecurityGroupIngress": [
      {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "SourceSecurityGroupId": "sg-app-tier-id",
        "Description": "Allow HTTPS from application tier to AWS service endpoints"
      },
      {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "SourceSecurityGroupId": "sg-data-tier-id",
        "Description": "Allow HTTPS from data tier to AWS service endpoints"
      }
    ],
    "SecurityGroupEgress": [
      {
        "IpProtocol": "-1",
        "CidrIp": "127.0.0.1/32",
        "Description": "Deny all egress - endpoints do not initiate connections"
      }
    ],
    "Tags": [
      {
        "Key": "Name",
        "Value": "vpc-endpoints-service-sg"
      },
      {
        "Key": "Pattern",
        "Value": "vpc-endpoints"
      }
    ]
  }
}
```

This Security Group protects all Interface Endpoints in the VPC, allowing HTTPS access only from the application and data tier Security Groups. Egress is denied because Interface Endpoints receive connections but do not initiate them. This single Security Group can be shared across all Interface Endpoints in the VPC if they share the same access requirements, or separate Security Groups can be created per endpoint for finer-grained control.

## Combining Patterns - Hybrid Architectures

### When to Combine

Some workloads require elements from multiple patterns. Common combinations:

**Peered VPC + VPC Endpoints**: The workload needs both operator access from the VDI VPC (Peered VPC pattern) and access to AWS services via PrivateLink (VPC Endpoints pattern). This is the most common hybrid. Add Interface Endpoints to a Peered VPC to enable AWS service access without adding internet routes.

**Isolated VPC transitioning to VPC Endpoints**: A workload initially deployed as an Isolated VPC with only S3 Gateway Endpoints later requires Secrets Manager or CloudWatch access. Add Interface Endpoints incrementally without changing the isolation posture.

### Security Considerations for Hybrid Architectures

- Apply the security controls from both patterns: VPC peering controls (restrictive routes, cross-VPC SG references) AND endpoint controls (endpoint policies, endpoint Security Groups)
- Do not relax security controls when combining patterns — each pattern's controls are additive
- VPC Flow Logs become more important in hybrid architectures to detect unexpected traffic flows between peering connections and endpoints
- Document the combined architecture clearly, including trust boundaries, data flows, and all security controls in place
- Review hybrid architectures quarterly to determine if the peering connection or specific endpoints are still required

### Transit Gateway as an Alternative to VPC Peering

For organizations with many workload VPCs requiring VDI access, consider replacing individual VPC peering connections with Transit Gateway. Transit Gateway provides centralized routing and route table isolation, reducing the management overhead of maintaining N peering connections. However, Transit Gateway adds complexity and cost — use VPC peering for simple one-to-one connectivity and Transit Gateway for hub-and-spoke architectures with many spokes.

When using Transit Gateway, apply blackhole routes to enforce isolation between workload VPCs that should not communicate with each other, even though they share the same Transit Gateway.

## Network Architecture Checklist

### Before Deployment

- Confirm the selected pattern matches the workload's connectivity requirements using the decision criteria above
- Verify CIDR blocks do not overlap with any existing VPCs that may require peering
- Ensure VPC has enableDnsSupport and enableDnsHostnames set to true (required for VPC endpoints)
- Plan subnet sizing to accommodate expected resource count plus growth margin
- Identify all AWS services the workload will access and confirm endpoint availability in the target Region

### Security Controls Verification

- All route tables verified: no unintended 0.0.0.0/0 routes, peering routes use specific subnet CIDRs where possible
- Security Groups follow least privilege: ingress restricted to required sources, egress restricted for data tier
- VPC endpoint policies restrict access to only required resources (specific S3 buckets, specific secret ARNs)
- NACLs applied to data subnets with explicit allow rules for required ports and ephemeral port return traffic
- VPC Flow Logs enabled on all subnets with logs sent to S3 or CloudWatch Logs

### Monitoring and Operations

- VPC Flow Logs configured and verified to be capturing traffic
- CloudWatch alarms created for anomalous network patterns (unexpected rejected traffic, unusual data transfer volumes)
- Tagging applied to all VPC resources (VPC, subnets, route tables, Security Groups, endpoints) with pattern name, environment, and data classification
- Runbook documented for common operations: adding a new endpoint, modifying peering routes, responding to Flow Log alerts
- Quarterly review scheduled to assess whether the selected pattern is still appropriate and all security controls remain correctly configured

---

**End of AWS Network Reference Architectures**

These patterns define the organization's approved VPC connectivity models. WAF Security Pillar controls are referenced inline for each pattern. Exceptions require security architecture team approval with documented risk acceptance.
