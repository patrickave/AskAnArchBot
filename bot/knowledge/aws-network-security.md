# AWS Network Security - Well-Architected Framework Guidance

This knowledge base provides AWS Network Security guidance strictly aligned with the AWS Well-Architected Framework (WAF) Security Pillar, covering network protection, traffic control, monitoring, and defense-in-depth strategies.

## WAF Security Pillar Mapping

AWS Network Security guidance maps primarily to:

- **SEC05: Network Protection** — Protecting networks and resources within networks using multiple defense layers, controlling network traffic flow, and implementing network segmentation
- **SEC04: Detection** — Configuring network-level logging and monitoring to detect security events, including VPC Flow Logs and DNS query logging
- **SEC03: Permissions Management** — Applying least privilege to network access controls through Security Groups, NACLs, and endpoint policies
- **SEC01: Security Foundations** — Establishing network security governance, standardizing network architectures, and applying the shared responsibility model to network configurations

Network security is foundational to the WAF Security Pillar design principle "Apply security at all layers" and supports "Keep people away from data" by eliminating direct internet exposure to data-tier resources.

All recommendations in this knowledge base trace back to these WAF Security Pillar areas and their associated best practices.

## Core Network Security Principles (WAF-Aligned)

### Defense in Depth (SEC05-BP01)

The WAF prescribes implementing multiple layers of network security controls rather than relying on a single perimeter defense. In AWS, this means combining VPC design, Security Groups, NACLs, VPC endpoints, AWS Network Firewall, and AWS WAF to create overlapping protective layers. Each layer provides redundancy if another layer is misconfigured or compromised.

Defense in depth acknowledges the shared responsibility model: AWS secures the underlying network infrastructure, while customers must configure VPC-level controls, routing, and access policies.

### Least Privilege Network Access (SEC03-BP02, SEC05-BP02)

Network access controls must enforce least privilege by default. Security Groups and NACLs should deny all traffic by default and explicitly allow only necessary traffic flows. Source specifications should reference Security Group IDs rather than broad CIDR ranges whenever possible to minimize blast radius.

The WAF emphasizes that overly permissive network rules (such as 0.0.0.0/0 for database ports) violate least privilege and increase attack surface.

### Zero Trust Networking (SEC05-BP03)

The WAF supports zero trust principles: never assume trust based on network location alone. Even resources within the same VPC should authenticate and authorize access explicitly. Use VPC endpoints to avoid transiting the public internet, but still apply endpoint policies to restrict access. Implement network segmentation to isolate workloads by sensitivity and function.

Zero trust in AWS means treating the network perimeter as compromised and requiring identity-based access controls (IAM policies, resource policies) in addition to network controls.

### Network Segmentation (SEC05-BP01)

The WAF prescribes logically separating workloads into distinct network segments based on function, sensitivity, and trust level. Use separate subnets for web tier, application tier, and data tier. Use separate VPCs for development, staging, and production environments. Use Transit Gateway or VPC peering with restrictive routing to connect segments only when necessary.

Segmentation limits lateral movement during a security incident and reduces blast radius by constraining network reachability.

### Encryption in Transit (SEC08-BP01)

All network traffic carrying sensitive data must be encrypted in transit using TLS 1.2 or higher. The WAF emphasizes that encryption in transit is non-negotiable for protecting data confidentiality and integrity. Use AWS Certificate Manager for certificate lifecycle management. Terminate TLS at load balancers or CloudFront distributions where appropriate, but re-encrypt backend traffic for sensitive workloads.

## VPC Fundamentals and Subnet Design (SEC05-BP01)

### Public, Private, and Isolated Subnets

The WAF prescribes designing VPC subnets with clear security boundaries. A well-architected VPC typically includes three subnet types:

**Public Subnets**: Route tables include a route to an Internet Gateway (IGW). Only resources that must accept inbound traffic from the internet (such as Application Load Balancers, NAT Gateways, or bastion hosts) should reside here. Public subnets require careful security controls because they are internet-facing.

**Private Subnets**: Route tables include a route to a NAT Gateway or NAT Instance for outbound internet access, but no direct inbound route from the internet. Application tier workloads (EC2 instances, ECS tasks, Lambda functions in VPC) should default to private subnets. Private subnets provide a security boundary while allowing software updates and API calls to AWS services.

**Isolated Subnets**: Route tables have no route to the internet (no IGW, no NAT Gateway). Data tier resources (RDS databases, ElastiCache clusters, sensitive data stores) should reside in isolated subnets. Access to AWS services occurs through VPC endpoints rather than internet routes. Isolated subnets provide the strongest network protection by eliminating internet reachability entirely.

### CIDR Planning and IP Address Management

The WAF emphasizes planning VPC CIDR blocks carefully to avoid overlaps with on-premises networks or other VPCs that may require peering. Use RFC 1918 private address space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Size VPC CIDRs appropriately for growth (typically /16 to /20 for production VPCs). Reserve address space for future subnet additions.

Subnet CIDR sizing must account for AWS reserved IP addresses (first four and last IP in each subnet) and the number of elastic network interfaces needed. Undersized subnets become a constraint that requires costly VPC migrations.

### Availability Zone Placement

The WAF Reliability Pillar intersects with security here: deploy subnets across at least two Availability Zones for resilience. Security configurations (Security Groups, NACLs, route tables) must be consistent across AZs to prevent security gaps. An attacker should not gain advantage by targeting resources in a specific AZ.

### Route Tables and Default Routes

Route table configuration directly impacts security posture. The WAF prescribes reviewing route tables regularly to ensure they enforce intended network boundaries. Key route table security considerations:

- Isolated subnets must never have a 0.0.0.0/0 route pointing to an IGW or NAT Gateway
- Private subnets should route 0.0.0.0/0 through a NAT Gateway only if outbound internet access is required; otherwise, use VPC endpoints and remove the default route
- Public subnets require explicit 0.0.0.0/0 routes to an IGW, but should be limited to only those subnets hosting internet-facing resources
- VPC peering and Transit Gateway routes should be as specific as possible (subnet-level CIDRs) rather than routing entire VPC CIDRs when only a subset of subnets require connectivity

### Isolated Subnet Route Table Example

```json
{
  "Type": "AWS::EC2::RouteTable",
  "Properties": {
    "VpcId": "vpc-0123456789abcdef0",
    "Tags": [
      {
        "Key": "Name",
        "Value": "isolated-subnet-rt-data-tier"
      },
      {
        "Key": "Tier",
        "Value": "data"
      }
    ]
  }
}
```

This route table contains no routes beyond the local VPC route (automatically added by AWS). Resources in subnets associated with this route table cannot reach the internet and can only communicate within the VPC or through VPC endpoints. This configuration is WAF-prescribed for database subnets and other sensitive data stores.

## Security Groups Best Practices (SEC05-BP02)

### Stateful Firewall at the Instance Level

Security Groups are stateful firewalls operating at the elastic network interface level. The WAF identifies Security Groups as the primary network access control mechanism for EC2 instances, RDS databases, Lambda functions in VPCs, and other VPC-attached resources. Stateful operation means return traffic for allowed inbound connections is automatically permitted, simplifying rule management compared to stateless NACLs.

### Deny-by-Default Model

Security Groups deny all traffic by default. The WAF prescribes explicitly allowing only required traffic flows through ingress and egress rules. Never add overly broad rules like 0.0.0.0/0 for ports other than 80/443 on internet-facing load balancers. The absence of an allow rule is an implicit deny.

### Least Privilege with Security Group References

The WAF strongly recommends referencing other Security Groups as sources/destinations rather than CIDR ranges whenever possible. Security Group references automatically track resource membership: as instances scale up or down, the rules remain correct. CIDR-based rules become stale as IP addresses change and require manual updates.

Security Group references also enforce least privilege at the identity level: only resources explicitly attached to the referenced Security Group gain access. This prevents lateral movement from other resources in the same subnet or CIDR block.

### Separation of Duties with Layered Security Groups

The WAF prescribes designing Security Groups by tier and function rather than creating monolithic "application" Security Groups. A well-architected three-tier application uses separate Security Groups for:

- Internet-facing load balancer (allows 443 from 0.0.0.0/0)
- Application tier (allows traffic from load balancer SG only)
- Database tier (allows traffic from application tier SG only)

This layered approach enforces network segmentation and simplifies auditing. A misconfiguration in one tier's Security Group does not compromise the entire stack.

### Security Group Tagging and Naming

The WAF emphasizes tagging Security Groups with metadata indicating their purpose, tier, and data classification. Tags enable AWS Config rules and Security Hub checks to automatically detect misconfigurations. Descriptive names (like "prod-web-alb-sg") improve readability during incident response.

### Egress Filtering

While Security Groups default to allowing all outbound traffic, the WAF recommends restricting egress rules for sensitive tiers. For example, database Security Groups should only allow egress to specific ports and destinations required for replication, backups, or monitoring. Restricting egress prevents data exfiltration and limits attacker options during a compromise.

### Web Tier Security Group Example

```json
{
  "Type": "AWS::EC2::SecurityGroup",
  "Properties": {
    "GroupDescription": "Security group for internet-facing Application Load Balancer - allows HTTPS from internet",
    "VpcId": "vpc-0123456789abcdef0",
    "SecurityGroupIngress": [
      {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "CidrIp": "0.0.0.0/0",
        "Description": "Allow inbound HTTPS from internet"
      }
    ],
    "SecurityGroupEgress": [
      {
        "IpProtocol": "tcp",
        "FromPort": 8443,
        "ToPort": 8443,
        "DestinationSecurityGroupId": "sg-app-tier-id",
        "Description": "Allow outbound to application tier on port 8443"
      }
    ],
    "Tags": [
      {
        "Key": "Name",
        "Value": "prod-web-alb-sg"
      },
      {
        "Key": "Tier",
        "Value": "web"
      }
    ]
  }
}
```

This Security Group allows only HTTPS inbound from the internet and restricts egress to the application tier Security Group on port 8443. It follows WAF least privilege principles by denying all other traffic implicitly.

### Database Tier Security Group Example

```json
{
  "Type": "AWS::EC2::SecurityGroup",
  "Properties": {
    "GroupDescription": "Security group for PostgreSQL RDS database - allows access only from application tier",
    "VpcId": "vpc-0123456789abcdef0",
    "SecurityGroupIngress": [
      {
        "IpProtocol": "tcp",
        "FromPort": 5432,
        "ToPort": 5432,
        "SourceSecurityGroupId": "sg-app-tier-id",
        "Description": "Allow PostgreSQL access from application tier only"
      }
    ],
    "SecurityGroupEgress": [
      {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "CidrIp": "0.0.0.0/0",
        "Description": "Allow HTTPS outbound for RDS monitoring and patching"
      }
    ],
    "Tags": [
      {
        "Key": "Name",
        "Value": "prod-db-rds-sg"
      },
      {
        "Key": "Tier",
        "Value": "data"
      },
      {
        "Key": "DataClassification",
        "Value": "confidential"
      }
    ]
  }
}
```

This Security Group allows PostgreSQL access only from the application tier Security Group, not from broad CIDR ranges. Egress is restricted to HTTPS for AWS service endpoints (RDS monitoring, CloudWatch metrics). This configuration prevents unauthorized database access and limits data exfiltration paths.

## Network ACLs for Subnet Protection (SEC05-BP02)

### Stateless Subnet-Level Firewall

Network ACLs (NACLs) operate at the subnet boundary and are stateless: both inbound and outbound rules must explicitly allow traffic in both directions. The WAF positions NACLs as a secondary defense layer in addition to Security Groups, providing subnet-level protection where Security Groups provide instance-level protection.

NACLs are evaluated before traffic reaches Security Groups. An explicit NACL deny rule blocks traffic even if a Security Group would allow it. This defense-in-depth approach prevents misconfigurations in Security Groups from exposing resources.

### Rule Ordering and Evaluation

NACL rules are evaluated in numerical order starting from the lowest rule number. Once a rule matches, evaluation stops and the rule's action (allow or deny) is applied. The WAF emphasizes careful rule numbering: use increments of 10 or 100 to allow inserting rules later without renumbering the entire NACL.

The default NACL allows all inbound and outbound traffic. Custom NACLs default to denying all traffic, requiring explicit allow rules. The WAF recommends using custom NACLs for sensitive subnets rather than relying on the default NACL.

### Deny Rules for Known Threats

The WAF prescribes using NACL deny rules to block known malicious IP addresses or CIDR blocks at the subnet boundary before traffic reaches resources. This is particularly valuable for blocking traffic from geographic regions where the application has no legitimate users or for implementing temporary blocks during active attacks.

Deny rules should be numbered lower than allow rules to ensure they are evaluated first. For example, a deny rule at 50 will block traffic before an allow rule at 100.

### Ephemeral Port Considerations

Because NACLs are stateless, return traffic for outbound connections requires explicit inbound allow rules for ephemeral ports (typically 1024-65535). The WAF notes this is a common NACL misconfiguration: blocking ephemeral ports breaks return traffic for legitimate connections initiated from within the subnet.

For example, if an application instance initiates an HTTPS connection to an external API, the outbound NACL rule allows port 443 egress, but an inbound NACL rule must allow ephemeral ports for the return traffic. Failing to allow ephemeral ports results in connection timeouts.

### When to Use NACLs vs Security Groups

The WAF recommends Security Groups as the primary access control mechanism and NACLs as a secondary layer for specific use cases:

- Use Security Groups for application-level access control, leveraging Security Group references and stateful operation
- Use NACLs to enforce subnet-level deny rules for known malicious sources
- Use NACLs to provide an additional layer of defense for sensitive subnets (like database subnets) by explicitly allowing only required protocols and ports
- Use NACLs to enforce organizational policies that must apply uniformly to all resources in a subnet

Do not attempt to replicate all Security Group rules in NACLs. This creates management overhead and increases the likelihood of misconfigurations.

### NACL Deny Rule Example

```json
{
  "Type": "AWS::EC2::NetworkAclEntry",
  "Properties": {
    "NetworkAclId": "acl-0123456789abcdef0",
    "RuleNumber": 50,
    "Protocol": -1,
    "RuleAction": "deny",
    "CidrBlock": "203.0.113.0/24",
    "Egress": false
  }
}
```

This NACL rule explicitly denies all inbound traffic from a specific CIDR block known to be malicious. The rule number 50 ensures it is evaluated before any allow rules. This provides subnet-level protection even if Security Groups are misconfigured to allow this source.

### NACL Allow Rule Example with Ephemeral Ports

```json
[
  {
    "Type": "AWS::EC2::NetworkAclEntry",
    "Properties": {
      "NetworkAclId": "acl-0123456789abcdef0",
      "RuleNumber": 100,
      "Protocol": 6,
      "RuleAction": "allow",
      "CidrBlock": "0.0.0.0/0",
      "PortRange": {
        "From": 443,
        "To": 443
      },
      "Egress": false
    }
  },
  {
    "Type": "AWS::EC2::NetworkAclEntry",
    "Properties": {
      "NetworkAclId": "acl-0123456789abcdef0",
      "RuleNumber": 100,
      "Protocol": 6,
      "RuleAction": "allow",
      "CidrBlock": "0.0.0.0/0",
      "PortRange": {
        "From": 1024,
        "To": 65535
      },
      "Egress": true
    }
  }
]
```

This NACL configuration allows inbound HTTPS traffic and outbound ephemeral port traffic. The ephemeral port range is required because NACLs are stateless: the return traffic from resources in the subnet back to internet clients uses ephemeral ports. Without the outbound ephemeral port rule, HTTPS responses would be blocked.

## VPC Flow Logs Configuration (SEC04-BP02)

### Network Traffic Visibility for Detection

VPC Flow Logs capture metadata about IP traffic flowing through VPC network interfaces. The WAF prescribes enabling VPC Flow Logs to support security event detection, network troubleshooting, and compliance auditing. Flow Logs capture accepted traffic, rejected traffic, or both, including source/destination IP, port, protocol, packet count, and byte count.

Flow Logs support the WAF design principle "Maintain traceability" by providing a durable record of network traffic patterns. During incident response, Flow Logs enable forensic analysis to determine what resources were accessed, when, and from where.

### Flow Log Destinations

The WAF recommends choosing a Flow Log destination based on analysis requirements and cost considerations:

**CloudWatch Logs**: Enables real-time monitoring with CloudWatch Logs Insights queries and metric filters. Use CloudWatch Logs when immediate alerting on traffic patterns is required (for example, detecting database access from unexpected sources). CloudWatch Logs Insights supports SQL-like queries for rapid ad-hoc analysis.

**Amazon S3**: Provides cost-effective long-term storage for compliance retention and batch analysis with Amazon Athena. Use S3 when retaining Flow Logs for extended periods (90 days or more) or when cost optimization is a priority. Partition Flow Logs by date in S3 for efficient Athena queries.

**Amazon Kinesis Data Firehose**: Enables streaming Flow Logs to third-party SIEM tools or custom analytics pipelines. Use Kinesis when integrating Flow Logs with external security platforms.

### Flow Log Format and Custom Fields

The default Flow Log format captures essential fields (srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, action). The WAF recommends enabling additional fields for security analysis, including vpc-id, subnet-id, instance-id, and pkt-srcaddr/pkt-dstaddr (which show the original packet source/destination before NAT).

Custom field selection balances visibility requirements with storage costs. More fields provide richer context but increase log volume and storage costs.

### Integration with Amazon Athena

The WAF prescribes analyzing VPC Flow Logs with Amazon Athena for cost-effective historical queries. Create an Athena table over S3-stored Flow Logs partitioned by date. Common security queries include identifying top talkers, detecting port scans, finding rejected connection attempts, and analyzing traffic to specific resources.

Athena queries support threat hunting and incident response by enabling rapid searches across large volumes of historical Flow Logs without maintaining dedicated infrastructure.

### Cost Management

VPC Flow Logs incur charges for data ingestion and storage. The WAF recommends cost optimization strategies including filtering Flow Logs to capture only rejected traffic (reduces volume by excluding accepted connections), aggregating logs at the VPC level rather than per-ENI, and using S3 Intelligent-Tiering for automatic archival of older logs.

For high-traffic environments, enable Flow Logs only on sensitive subnets (like database tiers) rather than the entire VPC to balance visibility with cost.

### VPC Flow Log CloudFormation Example

```json
{
  "Type": "AWS::EC2::FlowLog",
  "Properties": {
    "ResourceType": "VPC",
    "ResourceIds": [
      "vpc-0123456789abcdef0"
    ],
    "TrafficType": "ALL",
    "LogDestinationType": "s3",
    "LogDestination": "arn:aws:s3:::my-org-vpc-flow-logs-bucket/vpc-flow-logs/",
    "LogFormat": "${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id}",
    "MaxAggregationInterval": 60,
    "Tags": [
      {
        "Key": "Name",
        "Value": "prod-vpc-flow-log"
      },
      {
        "Key": "Environment",
        "Value": "production"
      }
    ]
  }
}
```

This Flow Log configuration captures all traffic (accepted and rejected) for an entire VPC and stores logs in S3 for cost-effective long-term retention. The custom log format includes additional fields like vpc-id, subnet-id, and instance-id to support detailed security analysis. The 60-second aggregation interval balances visibility with log volume.

## VPC Endpoints and AWS PrivateLink (SEC05-BP03)

### Keeping Traffic on the AWS Network

VPC Endpoints enable private connectivity to AWS services without traversing the public internet. The WAF prescribes using VPC Endpoints to reduce exposure: traffic never leaves the AWS network, eliminating the attack surface associated with internet gateways and NAT gateways for AWS service access.

VPC Endpoints support the WAF design principle "Keep people away from data" by eliminating the need for resources in isolated subnets to have internet routes for accessing S3, DynamoDB, or other AWS services. This prevents accidental internet exposure and reduces the risk of data exfiltration.

### Gateway Endpoints vs Interface Endpoints

The WAF distinguishes between two types of VPC Endpoints:

**Gateway Endpoints**: Available for S3 and DynamoDB only. Gateway endpoints are route table entries that direct traffic destined for the service to the VPC endpoint rather than the internet. Gateway endpoints have no hourly charges and no data processing charges. The WAF recommends Gateway Endpoints as the default choice for S3 and DynamoDB access due to cost efficiency.

**Interface Endpoints (AWS PrivateLink)**: Available for most AWS services (including EC2, Lambda, Secrets Manager, Systems Manager, CloudWatch, etc.). Interface endpoints are elastic network interfaces deployed in subnets with private IP addresses. They incur hourly charges and data processing charges but provide more granular security controls through Security Groups and DNS resolution within the VPC.

### Endpoint Policies for Least Privilege

VPC Endpoint policies are IAM resource policies that control which AWS resources can be accessed through the endpoint. The WAF prescribes applying least privilege endpoint policies to restrict access to only required resources. For example, an S3 Gateway Endpoint policy should allow access only to specific buckets used by the workload, not all S3 buckets in the account.

Endpoint policies provide defense-in-depth: even if an IAM principal has broad S3 permissions, the VPC Endpoint policy can limit which buckets are reachable from the VPC. This prevents lateral movement to unrelated buckets during a compromise.

### DNS Resolution and Private DNS

Interface endpoints provide private DNS names that resolve to the endpoint's private IP addresses within the VPC. Enabling private DNS for an interface endpoint (the default) overrides the public DNS resolution for the service, ensuring that all traffic to the service from within the VPC automatically routes through the endpoint.

The WAF recommends enabling private DNS for interface endpoints to ensure application code requires no changes: existing AWS SDK calls using public service endpoints automatically use the VPC endpoint.

### Security Groups for Interface Endpoints

Interface endpoints are protected by Security Groups. The WAF prescribes creating dedicated Security Groups for interface endpoints that allow inbound traffic on port 443 from specific source Security Groups (such as application tier Security Groups). This enforces least privilege by restricting which resources can access the AWS service through the endpoint.

Avoid allowing 0.0.0.0/0 inbound to interface endpoint Security Groups, as this negates the security benefits of private connectivity.

### Cost Considerations

Interface endpoints incur hourly charges (approximately USD 0.01 per hour per AZ) and data processing charges (approximately USD 0.01 per GB). For high-volume workloads accessing S3, consider whether the security benefits of Interface Endpoints justify the cost compared to Gateway Endpoints or NAT Gateway routes.

The WAF notes that cost optimization is a pillar-spanning concern: security architecture must balance security benefits with cost impacts. For S3 and DynamoDB, Gateway Endpoints provide equivalent security benefits without cost, making them the WAF-recommended default.

### S3 Gateway Endpoint Policy Example

```json
{
  "Type": "AWS::EC2::VPCEndpoint",
  "Properties": {
    "VpcId": "vpc-0123456789abcdef0",
    "ServiceName": "com.amazonaws.us-east-1.s3",
    "RouteTableIds": [
      "rtb-isolated-subnet-id-1",
      "rtb-isolated-subnet-id-2"
    ],
    "PolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": [
            "s3:GetObject",
            "s3:PutObject",
            "s3:ListBucket"
          ],
          "Resource": [
            "arn:aws:s3:::my-org-app-data-bucket",
            "arn:aws:s3:::my-org-app-data-bucket/*",
            "arn:aws:s3:::my-org-app-logs-bucket",
            "arn:aws:s3:::my-org-app-logs-bucket/*"
          ]
        }
      ]
    }
  }
}
```

This S3 Gateway Endpoint policy restricts access to only two specific buckets required by the application. Resources in the VPC cannot access other S3 buckets through this endpoint, even if their IAM permissions allow it. This enforces least privilege and prevents lateral movement to unrelated data during a compromise.

### Interface Endpoint Security Group Example

```json
{
  "Type": "AWS::EC2::SecurityGroup",
  "Properties": {
    "GroupDescription": "Security group for Secrets Manager VPC Interface Endpoint - allows access from application tier only",
    "VpcId": "vpc-0123456789abcdef0",
    "SecurityGroupIngress": [
      {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "SourceSecurityGroupId": "sg-app-tier-id",
        "Description": "Allow HTTPS from application tier to Secrets Manager endpoint"
      }
    ],
    "SecurityGroupEgress": [
      {
        "IpProtocol": "-1",
        "CidrIp": "127.0.0.1/32",
        "Description": "Deny all egress by default"
      }
    ],
    "Tags": [
      {
        "Key": "Name",
        "Value": "vpce-secrets-manager-sg"
      }
    ]
  }
}
```

This Security Group allows only the application tier to access the Secrets Manager interface endpoint. The egress rule denies all outbound traffic (interface endpoints do not initiate connections, so egress rules are not needed). This configuration enforces least privilege network access to sensitive secrets stored in Secrets Manager.

## VPC Peering Security (SEC05-BP03)

### Non-Transitive Connectivity

VPC Peering creates a one-to-one network connection between two VPCs within the same AWS Region or across Regions. The WAF emphasizes that VPC Peering is non-transitive: if VPC A peers with VPC B, and VPC B peers with VPC C, VPC A cannot communicate with VPC C through VPC B. This non-transitivity provides a security boundary by preventing unintended network paths.

Non-transitivity requires explicit peering relationships for each VPC pair that needs to communicate. While this creates management overhead, it enforces least privilege network connectivity by requiring intentional approval for each connection.

### Cross-Account and Cross-Region Peering

VPC Peering supports connections across AWS accounts and Regions. The WAF prescribes using cross-account peering to connect production workloads in one account with shared services (like centralized logging or directory services) in another account. Cross-account peering enforces organizational boundaries and supports the WAF-recommended multi-account strategy.

Cross-region peering enables disaster recovery architectures and globally distributed applications. The WAF notes that cross-region peering traffic is encrypted in transit automatically, supporting the "Protect data in transit" design principle.

### Route Table Configuration

VPC Peering requires explicit route table entries in both VPCs to direct traffic destined for the peer VPC CIDR through the peering connection. The WAF recommends using specific subnet CIDRs in route entries rather than entire VPC CIDRs when only a subset of subnets need to communicate. This enforces least privilege by limiting reachability.

For example, if VPC A's application tier needs to access VPC B's database tier, add routes only for the database subnet CIDRs, not the entire VPC B CIDR. This prevents unintended connectivity to other subnets in VPC B.

### Security Group References Across Peered VPCs

Security Groups in peered VPCs can reference each other by Security Group ID (within the same Region). The WAF prescribes using cross-VPC Security Group references to enforce least privilege: a database Security Group in VPC B can allow traffic only from a specific application tier Security Group in VPC A, rather than allowing the entire VPC A CIDR.

Cross-VPC Security Group references require enabling within the VPC peering connection configuration. This feature simplifies security group management and reduces the need for CIDR-based rules that become stale as resources are added or removed.

### Overlapping CIDR Prevention

VPC Peering requires non-overlapping CIDR blocks between the two VPCs. The WAF emphasizes CIDR planning during VPC design to ensure future peering is possible. Overlapping CIDRs prevent peering and require costly VPC migrations to remediate.

Use a centralized IPAM (IP Address Management) solution or AWS VPC IPAM to prevent CIDR collisions across the organization.

### Blast Radius and Overly Permissive Peering

The WAF warns against overly permissive VPC peering that increases blast radius. Peering production VPCs directly to development VPCs violates the principle of least privilege and creates a path for attackers to pivot from less-secured development environments to production. Instead, use centralized shared services VPCs or Transit Gateway with route table isolation.

Review peering relationships regularly to ensure they are still required. Remove peering connections that are no longer in use to reduce attack surface.

## Transit Gateway Network Security (SEC05-BP03)

### Centralized Routing for Multi-VPC Architectures

AWS Transit Gateway acts as a regional network hub connecting multiple VPCs, on-premises networks, and VPNs through a single gateway. The WAF prescribes Transit Gateway for organizations with many VPCs to simplify network management and enforce centralized security policies. Unlike VPC Peering (which requires N*(N-1)/2 peering connections for N VPCs), Transit Gateway requires only N attachments.

Transit Gateway supports the WAF Security Pillar by enabling centralized traffic inspection, centralized egress to the internet, and network segmentation through route table isolation.

### Route Table Segmentation and Isolation

Transit Gateway supports multiple route tables, enabling network segmentation by associating VPC attachments with different route tables. The WAF prescribes using separate Transit Gateway route tables for different environments (production, development, shared services) to enforce isolation. VPCs associated with the production route table cannot route to VPCs associated with the development route table.

Route table segmentation creates security boundaries: even if VPCs are attached to the same Transit Gateway, they cannot communicate unless their route tables explicitly allow it. This enforces least privilege network connectivity at scale.

### Blackhole Routes for Explicit Denies

Transit Gateway supports blackhole routes, which explicitly drop traffic destined for a specific CIDR. The WAF recommends using blackhole routes to enforce security policies such as blocking traffic to deprecated VPCs or preventing access to sensitive subnets from untrusted environments.

Blackhole routes are evaluated before routing decisions, providing a fail-safe mechanism to prevent unintended connectivity. During a security incident, adding a blackhole route can immediately isolate a compromised VPC from the rest of the network.

### Shared Services VPC Pattern

A common WAF-aligned pattern is deploying a shared services VPC attached to Transit Gateway, hosting centralized security services like AWS Network Firewall, proxy servers, or centralized egress NAT Gateways. Traffic from spoke VPCs routes through the shared services VPC for inspection before reaching the internet or other destinations.

This pattern enforces defense-in-depth by ensuring all traffic passes through centralized security controls rather than relying on each VPC implementing consistent policies.

### Transit Gateway Attachments and Security Groups

Transit Gateway attachments do not directly support Security Groups (Security Groups apply to ENIs, not Transit Gateway attachments). However, resources in VPCs attached to Transit Gateway are still protected by their own Security Groups and NACLs. The WAF emphasizes that Transit Gateway simplifies routing but does not replace Security Groups: both layers are required.

Use Security Groups to control access at the resource level and Transit Gateway route tables to control reachability at the VPC level.

### Transit Gateway Blackhole Route Example

```json
{
  "Type": "AWS::EC2::TransitGatewayRoute",
  "Properties": {
    "TransitGatewayRouteTableId": "tgw-rtb-0123456789abcdef0",
    "DestinationCidrBlock": "10.100.0.0/16",
    "Blackhole": true
  }
}
```

This Transit Gateway route explicitly drops all traffic destined for the CIDR block 10.100.0.0/16. This configuration is useful for isolating a compromised VPC or blocking access to a deprecated environment. The blackhole route is evaluated before any other routing decisions, ensuring traffic is dropped even if a VPC attachment exists for that CIDR.

## AWS Network Firewall (SEC05-BP01)

### Stateful Inspection and IPS Capabilities

AWS Network Firewall is a managed network firewall service providing stateful inspection, intrusion prevention (IPS), and domain filtering. The WAF prescribes deploying Network Firewall in the network path to inspect traffic between VPCs, between VPCs and the internet, or between VPCs and on-premises networks.

Network Firewall supports the defense-in-depth principle by adding application-aware inspection beyond Security Groups and NACLs. Network Firewall can detect and block Layer 7 threats, malicious domains, and known attack signatures using managed or custom rule groups.

### Stateless vs Stateful Rule Groups

Network Firewall supports two types of rule groups:

**Stateless Rule Groups**: Evaluated first, similar to NACLs. Stateless rules provide high-performance filtering based on 5-tuple (source IP, destination IP, source port, destination port, protocol) without tracking connection state. Use stateless rules for simple allow/deny decisions based on IP addresses or ports.

**Stateful Rule Groups**: Evaluated after stateless rules, providing connection tracking and protocol-aware inspection. Stateful rules support domain filtering (block access to known malicious domains), Suricata-compatible IPS rules, and protocol anomaly detection. The WAF recommends stateful rules for application-layer security controls.

### Domain Filtering for Egress Control

Network Firewall's domain filtering capability blocks access to malicious or unauthorized domains. The WAF prescribes domain filtering to prevent data exfiltration, block command-and-control (C2) traffic, and enforce acceptable use policies. Domain filtering uses DNS query inspection to identify and block requests to disallowed domains before connections are established.

Maintain an allow-list of authorized domains for sensitive workloads rather than a deny-list of known bad domains. Allow-lists provide stronger security by denying all domains except those explicitly approved.

### Centralized Deployment in Inspection VPC

The WAF recommends deploying Network Firewall in a centralized inspection VPC attached to Transit Gateway. All traffic between VPCs or between VPCs and the internet routes through the inspection VPC for centralized policy enforcement. This architecture ensures consistent security policies across all workloads without requiring per-VPC firewall deployments.

Deploy Network Firewall endpoints across multiple Availability Zones for resiliency. Traffic is automatically distributed across AZs, and if one AZ fails, traffic routes through endpoints in other AZs.

### Logging and Integration with Security Hub

Network Firewall logs flow logs (traffic metadata) and alert logs (IPS detections) to CloudWatch Logs, S3, or Kinesis Data Firehose. The WAF prescribes analyzing Network Firewall logs for threat detection and incident response. Integrate Network Firewall alert logs with Amazon GuardDuty and AWS Security Hub for centralized security event management.

### Domain Filtering Rule Group Example

```json
{
  "Type": "AWS::NetworkFirewall::RuleGroup",
  "Properties": {
    "RuleGroupName": "allow-list-domain-filter",
    "Type": "STATEFUL",
    "Capacity": 100,
    "RuleGroup": {
      "RulesSource": {
        "RulesSourceList": {
          "TargetTypes": ["HTTP_HOST", "TLS_SNI"],
          "Targets": [
            ".amazonaws.com",
            ".example.com",
            "api.trusted-partner.com"
          ],
          "GeneratedRulesType": "ALLOWLIST"
        }
      }
    },
    "Description": "Allow-list domain filtering rule group - permits only AWS services and authorized partner domains"
  }
}
```

This Network Firewall stateful rule group implements an allow-list for domain filtering. Only domains matching the specified targets are permitted; all other domains are blocked. This configuration prevents data exfiltration to unauthorized destinations and blocks C2 traffic. The rule inspects both HTTP Host headers and TLS SNI fields to enforce the policy.

## CloudFront, AWS WAF, and DDoS Protection (SEC05-BP01)

### CloudFront as a Security Perimeter

Amazon CloudFront is a global content delivery network (CDN) that also functions as a security perimeter for web applications. The WAF prescribes using CloudFront to distribute content from edge locations near users while protecting origin servers from direct internet exposure. CloudFront integrates with AWS WAF and AWS Shield to provide DDoS protection, web application firewall rules, and geographic restrictions.

CloudFront supports the defense-in-depth principle by adding a security layer at the edge before traffic reaches application load balancers or origin servers. Origin servers can restrict access to CloudFront only (using Security Groups that allow CloudFront prefix lists), preventing direct internet attacks.

### AWS WAF for Web Application Protection

AWS WAF is a web application firewall protecting against common web exploits (SQL injection, cross-site scripting) and enabling custom rate limiting, IP reputation filtering, and geographic blocking. The WAF prescribes deploying AWS WAF on CloudFront distributions or Application Load Balancers to filter malicious traffic before it reaches applications.

AWS WAF uses rule groups containing rules that inspect HTTP requests. Rule groups can be custom-created or use AWS Managed Rules (pre-configured rule sets for common threats maintained by AWS). The WAF recommends starting with AWS Managed Rules and adding custom rules for application-specific threats.

### Rate Limiting to Prevent Abuse

AWS WAF supports rate-based rules that count requests from a single IP address and block sources exceeding a threshold. The WAF prescribes rate limiting to prevent application-layer DDoS attacks, credential stuffing, and API abuse. Rate limits should be tuned based on legitimate user behavior: too low causes false positives, too high fails to block attacks.

Apply different rate limits to different URI paths based on sensitivity. For example, login endpoints may tolerate lower rate limits than static content paths.

### Geo-Blocking and IP Reputation Filtering

AWS WAF supports geographic match conditions to block requests from specific countries where the application has no legitimate users. The WAF recommends geo-blocking as a simple risk reduction measure, noting that determined attackers can use VPNs to bypass geographic restrictions, so geo-blocking should not be the sole security control.

AWS Managed Rules include IP reputation lists (known malicious IPs, botnets, open proxies) maintained by AWS Threat Intelligence. The WAF prescribes enabling IP reputation filtering to block traffic from known bad sources automatically.

### AWS Shield Standard and Advanced

AWS Shield Standard provides automatic DDoS protection for all AWS customers at no additional cost. Shield Standard protects against common network-layer and transport-layer DDoS attacks (SYN floods, UDP reflection attacks). The WAF notes that Shield Standard is always enabled and requires no configuration.

AWS Shield Advanced provides enhanced DDoS protection, cost protection, and 24/7 access to the AWS DDoS Response Team (DRT). Shield Advanced is recommended for internet-facing applications with high availability requirements or revenue impact from downtime. Shield Advanced includes advanced attack mitigation, real-time attack notifications, and post-attack forensics.

### AWS WAF Rate-Limiting Rule Example

```json
{
  "Type": "AWS::WAFv2::WebACL",
  "Properties": {
    "Scope": "CLOUDFRONT",
    "DefaultAction": {
      "Allow": {}
    },
    "Rules": [
      {
        "Name": "rate-limit-login-endpoint",
        "Priority": 1,
        "Statement": {
          "RateBasedStatement": {
            "Limit": 100,
            "AggregateKeyType": "IP",
            "ScopeDownStatement": {
              "ByteMatchStatement": {
                "SearchString": "/api/login",
                "FieldToMatch": {
                  "UriPath": {}
                },
                "TextTransformations": [
                  {
                    "Priority": 0,
                    "Type": "LOWERCASE"
                  }
                ],
                "PositionalConstraint": "STARTS_WITH"
              }
            }
          }
        },
        "Action": {
          "Block": {}
        },
        "VisibilityConfig": {
          "SampledRequestsEnabled": true,
          "CloudWatchMetricsEnabled": true,
          "MetricName": "RateLimitLoginEndpoint"
        }
      }
    ],
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "WebACLMetric"
    }
  }
}
```

This AWS WAF rule implements rate limiting for a login API endpoint, allowing a maximum of 100 requests per 5-minute period from a single IP address. Requests exceeding the limit are blocked, preventing brute force attacks and credential stuffing. The rule uses a scope-down statement to apply rate limiting only to the /api/login path, not to the entire application.

## Route 53 DNS Security (SEC05-BP04)

### DNSSEC for DNS Response Integrity

DNS Security Extensions (DNSSEC) provide cryptographic validation of DNS responses to prevent DNS spoofing and cache poisoning attacks. The WAF prescribes enabling DNSSEC signing for Route 53 hosted zones to ensure clients can verify that DNS responses have not been tampered with in transit.

Route 53 supports DNSSEC signing for public hosted zones. When enabled, Route 53 signs DNS records with private keys managed by AWS KMS and publishes public keys (DNSKEY records) that resolvers use to validate signatures. The WAF notes that DNSSEC requires a chain of trust: the parent zone must contain DS records pointing to the signed zone.

DNSSEC does not encrypt DNS queries (use DNS over HTTPS or DNS over TLS for encryption), but it ensures integrity and authenticity of responses.

### Route 53 Resolver DNS Firewall

Route 53 Resolver DNS Firewall enables filtering DNS queries made by resources in VPCs. The WAF prescribes using DNS Firewall to block queries to known malicious domains, enforce allow-lists of authorized domains, and redirect queries to safe landing pages. DNS Firewall operates at the VPC level, protecting all resources in the VPC without requiring per-instance configuration.

DNS Firewall rule groups define domain lists (allow, block, alert) and actions to take when queries match. AWS Managed Domain Lists provide pre-configured lists of malicious domains maintained by AWS threat intelligence.

### Private Hosted Zones for Internal DNS

Route 53 private hosted zones provide DNS resolution for internal VPC resources using private domain names (like internal.example.com). The WAF recommends using private hosted zones rather than public DNS for internal services to prevent information disclosure. Queries to private hosted zones never leave the AWS network.

Associate private hosted zones with specific VPCs to control which resources can resolve the private domain. Use separate private hosted zones for different environments (production, development) to enforce DNS-level isolation.

### Route 53 Resolver Endpoints

Route 53 Resolver endpoints enable DNS resolution between VPCs and on-premises networks. Inbound endpoints allow on-premises DNS servers to forward queries for AWS-hosted domains to Route 53. Outbound endpoints allow resources in VPCs to forward queries for on-premises domains to on-premises DNS servers.

The WAF prescribes using Resolver endpoints to maintain consistent DNS resolution for hybrid architectures. Resolver endpoints are elastic network interfaces deployed in VPC subnets and protected by Security Groups. Restrict Security Group rules to allow DNS (port 53 UDP/TCP) only from authorized sources.

### Route 53 Query Logging

Route 53 query logging captures all DNS queries made to public hosted zones or Resolver endpoints, including query name, type, response code, and source IP. The WAF prescribes enabling query logging for security event detection and troubleshooting. Send query logs to CloudWatch Logs for real-time analysis or S3 for long-term retention.

Analyze query logs to detect DNS tunneling, identify queries to malicious domains (when not using DNS Firewall), and troubleshoot DNS resolution issues.

## Network Security Checklist (WAF-Aligned)

### SEC05: Network Protection

**SEC05-BP01: Create network layers**
- Deploy resources in private or isolated subnets by default; use public subnets only for internet-facing load balancers and NAT Gateways
- Implement network segmentation using separate subnets for web tier, application tier, and data tier
- Use separate VPCs for production, development, and shared services environments
- Deploy AWS Network Firewall in centralized inspection VPC for multi-VPC architectures
- Use AWS WAF on CloudFront distributions and Application Load Balancers to filter malicious web traffic

**SEC05-BP02: Control traffic at all layers**
- Configure Security Groups with least privilege ingress/egress rules, denying all traffic by default
- Reference Security Groups by ID rather than CIDR ranges to automatically track resource membership
- Apply NACLs to sensitive subnets as a secondary defense layer with explicit deny rules for known threats
- Remove unused Security Group rules and NACLs regularly to reduce complexity and misconfiguration risk
- Tag Security Groups with tier, data classification, and purpose for auditability

**SEC05-BP03: Implement network segmentation**
- Use VPC endpoints (Gateway Endpoints for S3/DynamoDB, Interface Endpoints for other services) to keep AWS service traffic on the AWS network
- Apply least privilege endpoint policies to VPC endpoints, restricting access to only required resources
- Deploy separate Security Groups for VPC interface endpoints allowing access only from specific source Security Groups
- Use Transit Gateway route table isolation to segment production, development, and shared services networks
- Implement blackhole routes in Transit Gateway to explicitly block traffic to deprecated or compromised VPCs

**SEC05-BP04: Protect networks from external threats**
- Enable DNSSEC signing for Route 53 public hosted zones to prevent DNS spoofing
- Deploy Route 53 Resolver DNS Firewall to block queries to malicious domains and enforce allow-lists
- Use private hosted zones for internal service discovery rather than exposing internal DNS publicly
- Configure AWS Shield Standard (enabled by default) and consider Shield Advanced for high-availability workloads
- Implement CloudFront with origin access control to prevent direct internet access to origin servers

### SEC04: Detection

**SEC04-BP02: Analyze logs centrally**
- Enable VPC Flow Logs for all VPCs or sensitive subnets, capturing both accepted and rejected traffic
- Send Flow Logs to S3 for cost-effective long-term storage and analysis with Amazon Athena
- Enable Route 53 query logging to detect DNS tunneling and queries to suspicious domains
- Enable AWS Network Firewall alert logs to capture IPS detections and threat intelligence matches
- Configure CloudWatch metric filters on Flow Logs to alert on suspicious patterns (port scans, rejected connections to databases)

### SEC01: Security Foundations

**SEC01-BP07: Identify and prioritize risks using a threat model**
- Document network architecture diagrams showing trust boundaries, data flows, and security controls
- Identify critical data paths requiring encryption in transit and validate TLS 1.2+ usage
- Review Security Group rules quarterly to identify overly permissive rules (0.0.0.0/0 for non-web ports)
- Conduct tabletop exercises simulating network-layer attacks to validate detection and response

**SEC01-BP03: Separate workloads using accounts**
- Use separate AWS accounts for production, development, and security tooling to enforce network isolation
- Deploy centralized network inspection and egress infrastructure in a dedicated network account
- Use AWS Organizations Service Control Policies to prevent modification of network security controls in member accounts
- Share VPC subnets across accounts using AWS RAM only when required; prefer VPC peering or Transit Gateway for multi-account connectivity

---

**End of AWS Network Security Knowledge Base**

All guidance in this document is strictly aligned with the AWS Well-Architected Framework Security Pillar. Implementations should be validated against current AWS service capabilities and organizational requirements.
