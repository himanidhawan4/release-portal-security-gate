# 🔐 AWS IAM — Basic to Advanced

AWS **Identity and Access Management (IAM)** is an AWS service used to control who can access AWS resources and what actions they are allowed to perform.

IAM is one of the most important security concepts for a DevOps engineer because infrastructure, applications, CI/CD pipelines, and AWS services often require controlled access to AWS resources.

---

# 🧠 1. AWS IAM Overview

## What is IAM?

IAM controls:

- Who can access AWS
- What they can do
- Which resources they can access
- Under which conditions they can access them

The basic IAM model is:

```text
                         AWS IAM
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
      IDENTITIES         POLICIES          SECURITY
          │                 │                 │
    ┌─────┼─────┐       ┌───┼────┐       ┌────┼────┐
    │     │     │       │   │    │       │    │    │
   User  Group  Role  Effect Action Resource MFA Least
                                               Privilege
```

### Viva

**Q: What is AWS IAM?**  
A: IAM is an AWS service used to manage identities and control access to AWS resources.

---

# 🧠 2. Authentication vs Authorization

IAM involves two major concepts:

```text
                    ACCESS CONTROL
                         │
             ┌───────────┴───────────┐
             │                       │
      AUTHENTICATION          AUTHORIZATION
             │                       │
        Who are you?            What can you do?
             │                       │
      Verify identity          Check permissions
```

## Authentication

Authentication verifies the identity of a requester.

Examples:

- Password
- Access keys
- MFA
- Federated identity
- Temporary credentials

```text
Requester
    ↓
Authentication
    ↓
Identity Verified
```

## Authorization

Authorization determines what an authenticated identity is allowed to do.

```text
Authenticated Identity
          ↓
   Policy Evaluation
          ↓
    Allow / Deny
```

### Viva

**Q: What is authentication?**  
A: Authentication verifies who the requester is.

**Q: What is authorization?**  
A: Authorization determines what the authenticated requester is allowed to do.

---

# 🧠 3. AWS Root User

When an AWS account is created, it has a **root user**.

The root user represents the AWS account itself and has extremely broad privileges.

The root user should not be used for normal day-to-day AWS operations.

Recommended practices include:

- Protect the root credentials
- Enable MFA
- Avoid creating root access keys
- Use IAM identities or roles for regular operations

```text
                       AWS ACCOUNT
                            │
              ┌─────────────┴─────────────┐
              │                           │
         ROOT USER                       IAM
                                          │
                              ┌───────────┼───────────┐
                              │           │           │
                            Users       Groups       Roles
```

### Important

An IAM user is **not** the root user.

The root user represents the AWS account, while IAM users are identities created inside the account.

### Viva

**Q: Is an IAM user the same as the root user?**  
A: No, the root user represents the AWS account while an IAM user is an identity created within the account.

---

# 🧠 4. IAM User

An **IAM user** is an identity created within an AWS account.

An IAM user can receive permissions that allow it to access AWS resources.

Example:

```text
IAM User
    ↓
Permissions
    ↓
S3
    ↓
Read Objects
```

Users can receive permissions through mechanisms such as:

- Policies attached directly to the user
- Group membership
- Other applicable AWS policy mechanisms

Long-lived IAM user credentials should be avoided where roles and temporary credentials are suitable.

### Viva

**Q: What is an IAM user?**  
A: An IAM user is an identity within an AWS account that can be granted permissions.

---

# 🧠 5. IAM Group

An IAM group is a collection of IAM users.

Groups are useful when several users require similar permissions.

```text
                  DEVELOPERS GROUP
                         │
             ┌───────────┼───────────┐
             │           │           │
           User A      User B      User C
             │           │           │
             └───────────┼───────────┘
                         │
                    Shared Policy
```

Instead of attaching the same permissions individually to many users, common permissions can be managed through the group.

### Viva

**Q: Why are IAM groups used?**  
A: IAM groups simplify permission management for users with similar access requirements.

---

# 🧠 6. IAM Role

An IAM role is an identity that trusted entities can assume.

Roles are commonly used by:

- EC2
- Lambda
- ECS
- Applications
- CI/CD systems
- Cross-account access
- Federated users

Roles commonly provide temporary credentials.

```text
                 IAM ROLE
                    │
          ┌─────────┴─────────┐
          │                   │
     TRUST POLICY       PERMISSIONS POLICY
          │                   │
    Who can assume?       What can it do?
          │                   │
          └─────────┬─────────┘
                    ↓
             AssumeRole
                    ↓
          Temporary Credentials
                    ↓
              AWS Resources
```

### Viva

**Q: What is an IAM role?**  
A: An IAM role is an identity that trusted entities can assume to obtain permissions, commonly through temporary credentials.

---

# 🧠 7. IAM User vs IAM Role

```text
                  IAM IDENTITY
                       │
             ┌─────────┴─────────┐
             │                   │
            USER                ROLE
             │                   │
       Direct Identity       Assumable Identity
             │                   │
       Long-term access       Temporary access
       may be possible       commonly preferred
```

| IAM User | IAM Role |
|---|---|
| Represents an identity | Represents an assumable identity |
| Can use long-lived credentials | Commonly uses temporary credentials |
| Can belong to groups | Can be assumed by trusted entities |
| Often associated with a person or application identity | Commonly used by workloads and delegated access |

### Viva

**Q: Why are IAM roles preferred for AWS workloads?**  
A: Roles commonly provide temporary credentials without requiring long-lived credentials to be stored in applications.

---

# 🧠 8. IAM Policy

An IAM policy is a document that defines permissions.

A policy commonly contains:

```text
                         IAM POLICY
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
       VERSION            STATEMENT             ...
                              │
              ┌───────────────┼───────────────┐
              │               │               │
            Effect          Action          Resource
                              │
                           Condition
```

Example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::company-bucket/*"
    }
  ]
}
```

### Viva

**Q: What is an IAM policy?**  
A: An IAM policy is a document that defines which actions are allowed or denied on which resources.

---

# 🧠 9. Policy `Version`

The `Version` field specifies the version of the IAM policy language syntax.

Example:

```json
"Version": "2012-10-17"
```

It does **not** mean that the policy was created on that date.

```text
Policy
  ↓
Version
  ↓
Policy Language Version
```

### Viva

**Q: What does the IAM policy Version represent?**  
A: It specifies the version of the IAM policy language syntax.

---

# 🧠 10. Policy `Statement`

`Statement` contains one or more permission rules.

```text
                    STATEMENT
                        │
          ┌─────────────┼─────────────┐
          │             │             │
        Effect        Action       Resource
          │             │             │
       Allow/Deny    What to do    Where
```

Example:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::company-bucket/*"
}
```

A policy can contain multiple statements.

### Viva

**Q: What is a Statement?**  
A: A statement represents an individual permission rule inside an IAM policy.

---

# 🧠 11. `Effect`

`Effect` determines whether a statement allows or denies an action.

Possible values:

```text
Allow
Deny
```

Mind map:

```text
                    EFFECT
                      │
                ┌─────┴─────┐
                │           │
              Allow        Deny
                │           │
             Permit       Block
```

Example:

```json
"Effect": "Allow"
```

### Viva

**Q: What values can Effect have?**  
A: `Allow` and `Deny`.

---

# 🧠 12. `Action`

`Action` defines the AWS API operation that the statement controls.

Examples:

```text
s3:GetObject
s3:PutObject
s3:DeleteObject
ec2:StartInstances
ec2:DescribeInstances
```

The common structure is:

```text
service:operation
```

Mind map:

```text
                       ACTION
                          │
              ┌───────────┴───────────┐
              │                       │
           Specific                Wildcard
              │                       │
        s3:GetObject                s3:*
              │                       │
       One operation          Many service actions
```

### Multiple Actions

```json
"Action": [
  "s3:GetObject",
  "s3:PutObject"
]
```

### Viva

**Q: What does Action specify?**  
A: Action specifies which AWS operation or operations the statement controls.

---

# 🧠 13. `Resource`

`Resource` defines which AWS resources the statement applies to.

Example:

```json
"Resource": "arn:aws:s3:::company-bucket/*"
```

Mind map:

```text
                     RESOURCE
                         │
              ┌──────────┴──────────┐
              │                     │
           Specific              Wildcard
              │                     │
             ARN                    *
              │                     │
      Specific Resource       All Applicable
```

### Viva

**Q: What does Resource define?**  
A: Resource defines which AWS resources the statement applies to.

---

# 🧠 14. ARN

ARN means **Amazon Resource Name**.

It is used to identify AWS resources.

Example:

```text
arn:aws:s3:::company-bucket
```

General structure:

```text
arn:partition:service:region:account-id:resource
```

Mind map:

```text
                         ARN
                          │
          ┌───────────────┼───────────────┐
          │               │               │
       Service          Region         Resource
          │               │               │
          ↓               ↓               ↓
          S3          us-east-1       bucket-name
```

Not every AWS service uses every ARN component.

### Viva

**Q: What is an ARN?**  
A: An ARN is the naming format used to identify AWS resources.

---

# 🧠 15. `Condition`

`Condition` adds additional restrictions to a policy statement.

Example:

```json
"Condition": {
  "Bool": {
    "aws:MultiFactorAuthPresent": "true"
  }
}
```

Mind map:

```text
                    CONDITION
                        │
          ┌─────────────┼─────────────┐
          │             │             │
         MFA            IP           Tags
          │             │             │
       Required      Restricted    Attribute
```

Conditions can be based on:

- MFA
- IP address
- Tags
- Request attributes
- Time
- VPC information
- Principal attributes

### Viva

**Q: What is the purpose of Condition?**  
A: Condition adds additional context-based restrictions to a policy statement.

---

# 🧠 16. `Principal`

`Principal` identifies the entity to which a policy applies in policy contexts that support a principal.

It is especially important in:

- Resource-based policies
- Trust policies

Example:

```json
"Principal": {
  "Service": "ec2.amazonaws.com"
}
```

Mind map:

```text
                     PRINCIPAL
                         │
          ┌──────────────┼──────────────┐
          │              │              │
         AWS           Service       Federated
          │              │              │
        Account         EC2          Identity
```

### Viva

**Q: What is Principal?**  
A: Principal identifies the entity affected by a policy statement where a principal is specified.

---

# 🧠 17. Trust Policy

A trust policy defines **who or what can assume an IAM role**.

Example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Mind map:

```text
                    IAM ROLE
                       │
                 TRUST POLICY
                       │
                       ↓
                 Who can assume?
                       │
                   Principal
                       │
                       ↓
                 sts:AssumeRole
                       │
                       ↓
                Temporary Access
```

### Viva

**Q: What is a trust policy?**  
A: A trust policy defines which principals are allowed to assume an IAM role.

---

# 🧠 18. Permissions Policy

A permissions policy defines what an identity is allowed or denied to do.

```text
                 PERMISSIONS POLICY
                         │
              ┌──────────┼──────────┐
              │          │          │
            Effect     Action     Resource
              │          │          │
           Allow/Deny   What?     Where?
```

### Trust vs Permissions

```text
Trust Policy
     ↓
WHO can assume the role?

Permissions Policy
     ↓
WHAT can the role do?
```

### Viva

**Q: What is the difference between trust and permissions policies?**  
A: A trust policy controls who can assume a role, while a permissions policy controls what that role can do.

---

# 🧠 19. Wildcards

The `*` character represents a broad set of values.

```text
                       WILDCARD *
                           │
              ┌────────────┴────────────┐
              │                         │
           ACTION                    RESOURCE
              │                         │
          s3:* / *                       *
              │                         │
       Broad Actions              Broad Resources
```

Examples:

```json
"Action": "*"
```

```json
"Action": "s3:*"
```

```json
"Resource": "*"
```

### Important Security Point

A wildcard is **not automatically a vulnerability**.

The context matters:

```text
Wildcard
   ↓
Check Action
   ↓
Check Resource
   ↓
Check Effect
   ↓
Check Condition
   ↓
Check Policy Context
   ↓
Determine Risk
```

### Viva

**Q: Is every wildcard dangerous?**  
A: No, the security impact depends on where and how the wildcard is used.

---

# 🧠 20. `Action: "*"` and `Resource: "*"`

Consider:

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

Mind map:

```text
                 ALLOW
                   │
             ┌─────┴─────┐
             │           │
        Action: *    Resource: *
             │           │
        All Actions   All Applicable
                      Resources
             │           │
             └─────┬─────┘
                   ↓
          Extremely Broad Access
                   ↓
          Large Potential Blast Radius
```

This can violate least privilege when such broad access is unnecessary.

### Viva

**Q: Why is `Allow + Action:* + Resource:*` dangerous?**  
A: It grants extremely broad permissions and can significantly increase the blast radius of a compromised identity.

---

# 🧠 21. Principle of Least Privilege

Least privilege means granting only the permissions required for the intended task.

Bad:

```text
Application needs:
s3:GetObject

Granted:
Action   = *
Resource = *
```

Better:

```text
Application needs:
s3:GetObject

Granted:
Action   = s3:GetObject
Resource = specific S3 bucket
```

Mind map:

```text
                 LEAST PRIVILEGE
                        │
          ┌─────────────┼─────────────┐
          │             │             │
     Specific       Specific      Temporary
      Action        Resource       Access
          │             │             │
          └─────────────┼─────────────┘
                        ↓
                 Reduced Risk
                        ↓
                Smaller Blast Radius
```

### Viva

**Q: What is least privilege?**  
A: Least privilege means granting only the minimum permissions required to perform a task.

---

# 🧠 22. Explicit Deny

An explicit `Deny` overrides an applicable `Allow`.

```text
Policy A
Allow s3:DeleteObject
        │
        ↓
Policy B
Deny s3:DeleteObject
        │
        ↓
      DENY
```

Mind map:

```text
                 POLICY EVALUATION
                         │
                   Explicit Deny?
                    ┌────┴────┐
                   YES        NO
                    │          │
                    ↓          ↓
                  DENY     Check Allow
```

### Viva

**Q: Which wins, Allow or explicit Deny?**  
A: Explicit Deny overrides an applicable Allow.

---

# 🧠 23. Implicit Deny

If no applicable policy grants permission, access is implicitly denied.

```text
Request
   ↓
Applicable Allow?
   │
   ├── YES → Allow
   │
   └── NO → Implicit Deny
```

### Viva

**Q: What happens if no policy allows an action?**  
A: The request is implicitly denied.

---

# 🧠 24. IAM Policy Evaluation

AWS evaluates applicable policies before deciding whether a request should be allowed.

Simplified model:

```text
                         AWS REQUEST
                              │
                              ↓
                       Authenticate
                              │
                              ↓
                    Identify Principal
                              │
                              ↓
                 Find Applicable Policies
                              │
                              ↓
                    Policy Evaluation
                              │
                   ┌──────────┴──────────┐
                   │                     │
             Explicit Deny?          No Deny
                   │                     │
                  YES                    ↓
                   │              Applicable Allow?
                   ↓                  │
                 DENY          ┌───────┴───────┐
                               │               │
                              YES              NO
                               │               │
                               ↓               ↓
                             ALLOW           DENY
```

This is a simplified conceptual model; actual AWS policy evaluation involves multiple policy types and additional rules.

### Viva

**Q: What is the most important IAM policy evaluation rule?**  
A: An explicit Deny overrides an applicable Allow.

---

# 🧠 25. Identity-Based Policy

An identity-based policy is associated with an identity such as:

- User
- Group
- Role

```text
                 IDENTITY-BASED POLICY
                           │
              ┌────────────┼────────────┐
              │            │            │
             User        Group         Role
              │            │            │
              └────────────┼────────────┘
                           ↓
                       Permissions
```

### Viva

**Q: What is an identity-based policy?**  
A: It is a policy associated with an IAM identity that defines its permissions.

---

# 🧠 26. Resource-Based Policy

A resource-based policy is attached to a supported AWS resource.

Examples include:

- S3 bucket policies
- SQS queue policies
- SNS topic policies

```text
                    AWS RESOURCE
                         │
                         ↓
               RESOURCE-BASED POLICY
                         │
                         ↓
                      Principal
                         │
                         ↓
                       Access
```

### Viva

**Q: What is a resource-based policy?**  
A: It is a policy attached to a supported resource that controls access to that resource.

---

# 🧠 27. Managed vs Inline Policies

IAM policies can also be managed in different ways.

```text
                       IAM POLICIES
                            │
                 ┌──────────┴──────────┐
                 │                     │
             MANAGED                 INLINE
                 │                     │
          Standalone Policy       Embedded Policy
                 │                     │
        Can be reused            Associated directly
```

Managed policies can be:

- AWS managed
- Customer managed

### Viva

**Q: What is an inline policy?**  
A: An inline policy is embedded directly into a single user, group, or role.

---

# 🧠 28. AWS Managed vs Customer Managed

```text
                    MANAGED POLICY
                          │
                 ┌────────┴────────┐
                 │                 │
          AWS Managed        Customer Managed
                 │                 │
              AWS owns          Customer owns
              policy            policy
```

### Viva

**Q: What is a customer-managed policy?**  
A: It is a standalone IAM policy created and managed by the AWS customer.

---

# 🧠 29. AWS STS

**AWS Security Token Service (STS)** provides temporary security credentials.

```text
                    PRINCIPAL
                        │
                    AssumeRole
                        │
                        ↓
                       STS
                        │
                        ↓
              Temporary Credentials
                        │
                        ↓
                   AWS Resources
```

Temporary credentials generally include:

- Access key ID
- Secret access key
- Session token

### Viva

**Q: What is AWS STS?**  
A: AWS STS provides temporary security credentials for accessing AWS resources.

---

# 🧠 30. Temporary Credentials

Temporary credentials are short-lived credentials used for a limited session.

They are commonly obtained by assuming an IAM role.

```text
Application
    ↓
IAM Role
    ↓
STS
    ↓
Temporary Credentials
    ↓
AWS API
```

This is generally safer than embedding long-lived credentials into applications.

### Viva

**Q: Why are temporary credentials preferred?**  
A: They reduce the risk associated with long-lived credentials by limiting their lifetime.

---

# 🧠 31. Access Keys

Access keys provide programmatic access to AWS.

They contain:

```text
Access Key ID
+
Secret Access Key
```

They must be protected carefully.

Never commit credentials into Git repositories.

```text
❌ Source Code
     ↓
AWS Access Key
     ↓
GitHub

✅ IAM Role
     ↓
Temporary Credentials
     ↓
AWS
```

### Viva

**Q: What are access keys?**  
A: Access keys are credentials used for programmatic access to AWS APIs.

---

# 🧠 32. MFA

MFA means **Multi-Factor Authentication**.

It adds an additional verification factor.

```text
                 AUTHENTICATION
                       │
              ┌────────┴────────┐
              │                 │
           Password            MFA
              │                 │
              └────────┬────────┘
                       ↓
                Stronger Access
```

MFA is particularly important for privileged identities.

### Viva

**Q: What is MFA?**  
A: MFA adds an additional authentication factor to strengthen account security.

---

# 🧠 33. Permission Boundary

A permissions boundary defines the maximum permissions an IAM identity can have.

It does **not** directly grant permissions.

```text
                IAM IDENTITY
                     │
              Identity Policies
                     │
                     +
              Permission Boundary
                     │
                     ↓
             Maximum Permissions
```

### Viva

**Q: What is a permission boundary?**  
A: It defines the maximum permissions an IAM identity can receive without granting permissions by itself.

---

# 🧠 34. Service Control Policy (SCP)

An SCP is used with AWS Organizations to define the maximum available permissions for governed accounts or organizational units.

An SCP does not itself grant permissions.

```text
                   AWS ORGANIZATION
                           │
                           ↓
                          SCP
                           │
                   Maximum Permissions
                           │
                           ↓
                         Account
                           │
                           ↓
                    IAM Permissions
```

### Viva

**Q: What is an SCP?**  
A: An SCP defines the maximum permissions available to accounts or organizational units in AWS Organizations.

---

# 🧠 35. Federation

Federation allows users to authenticate through an external identity provider and access AWS without necessarily creating a separate long-lived IAM user for each person.

```text
                  EMPLOYEE
                     │
                     ↓
            External Identity Provider
                     │
                     ↓
                 Federation
                     │
                     ↓
                    AWS
                     │
                     ↓
            Temporary Access
```

Examples:

- Microsoft Entra ID
- Okta
- Other enterprise identity providers

### Viva

**Q: What is identity federation?**  
A: Federation allows external identities to access AWS through a trusted identity provider.

---

# 🧠 36. IAM Identity Center

IAM Identity Center provides centralized workforce access to AWS accounts and applications.

```text
                 EMPLOYEE
                     │
                     ↓
              Identity Provider
                     │
                     ↓
           IAM Identity Center
                     │
                     ↓
              Permission Set
                     │
                     ↓
                 AWS Account
```

### Viva

**Q: What is IAM Identity Center?**  
A: It provides centralized workforce access to AWS accounts and applications.

---

# 🧠 37. Privilege Escalation

Privilege escalation occurs when an identity can use existing permissions to obtain greater privileges than intended.

```text
              Low-Privilege Identity
                       │
                       ↓
               Dangerous Permission
                       │
                       ↓
              Modify IAM Permissions
                       │
                       ↓
                Higher Privileges
```

Examples can involve permissions that allow an identity to modify roles, policies, or permissions in dangerous ways.

### Viva

**Q: What is IAM privilege escalation?**  
A: It is the ability to use existing permissions to obtain greater privileges than intended.

---

# 🧠 38. Blast Radius

Blast radius represents the potential scope of impact if an identity or resource is compromised.

```text
              COMPROMISED IDENTITY
                       │
             ┌─────────┴─────────┐
             │                   │
       Narrow Access        Broad Access
             │                   │
             ↓                   ↓
      Small Blast Radius   Large Blast Radius
```

### Viva

**Q: What is blast radius?**  
A: Blast radius is the potential scope of impact resulting from a security compromise.

---

# 🧠 39. IAM Access Analyzer

IAM Access Analyzer helps identify unintended resource access and can help validate IAM policies.

```text
                  AWS RESOURCES
                        │
                        ↓
                IAM Access Analyzer
                        │
              ┌─────────┴─────────┐
              │                   │
       Analyze Access       Validate Policies
              │                   │
              └─────────┬─────────┘
                        ↓
                 Security Findings
```

### Viva

**Q: What is IAM Access Analyzer?**  
A: It helps identify unintended access and analyze or validate IAM policies.

---

# 🧠 40. Terraform and IAM

Terraform is an **Infrastructure as Code (IaC)** tool.

It allows AWS infrastructure and IAM configuration to be represented as code.

```text
                         TERRAFORM
                             │
                             ↓
                     Infrastructure Code
                             │
                             ↓
                     AWS IAM Resources
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
         User               Role              Policy
```

Example:

```hcl
resource "aws_iam_policy" "example" {
  name = "example-policy"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::company-bucket/*"
      }
    ]
  })
}
```

### Viva

**Q: Why is Terraform important for IAM?**  
A: Terraform allows IAM infrastructure and permissions to be defined, reviewed, version-controlled, and automated as code.

---

# 🧠 41. JSON and Terraform Relationship

IAM policies are commonly represented as JSON, while Terraform uses HCL to define infrastructure.

```text
                         IAM POLICY
                             │
                  ┌──────────┴──────────┐
                  │                     │
                 JSON               Terraform
                  │                     │
          Policy Document         Infrastructure
                  │                     │
                  │                  .tf file
                  │                     │
                  │                 jsonencode()
                  │                     │
                  └──────────┬──────────┘
                             ↓
                         AWS IAM
```

### Viva

**Q: Why can IAM configuration appear in both JSON and Terraform?**  
A: JSON can directly represent IAM policies, while Terraform can define AWS IAM resources and embed or generate those policies.

---

# 🧠 42. Why Scan `.json` Files?

JSON files can directly contain IAM policy documents.

Example:

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

Therefore:

```text
JSON File
   ↓
IAM Policy
   ↓
Security Analysis
   ↓
Potential Finding
```

### Viva

**Q: Why scan JSON files?**  
A: JSON files can contain IAM policies and therefore may contain excessive permissions.

---

# 🧠 43. Why Scan Terraform `.tf` Files?

Terraform files can define:

- IAM users
- IAM groups
- IAM roles
- IAM policies
- Policy attachments
- Trust policies
- Permission boundaries

```text
                 Terraform .tf
                       │
          ┌────────────┼────────────┐
          │            │            │
         User         Role        Policy
                       │
                 Trust Policy
                       │
                 Permissions
```

### Viva

**Q: Why scan `.tf` files?**  
A: Terraform files can define IAM resources and permissions that may introduce security risks.

---

# 🧠 44. Static Analysis

When `iam.py` examines Terraform or JSON without deploying the infrastructure, it is performing static analysis.

```text
             Configuration
                   │
                   ↓
             Static Analysis
                   │
                   ↓
           Security Rules
                   │
                   ↓
              Finding
```

No AWS resource needs to be created for many code-level checks.

### Viva

**Q: What is static analysis?**  
A: Static analysis examines source code or configuration without executing or deploying it.

---

# 🧠 45. IAM Security Scanning

The IAM security scanner can inspect:

- `Effect`
- `Action`
- `Resource`
- `Principal`
- `Condition`
- Wildcards
- Broad permissions
- Trust relationships
- Other project-defined IAM rules

```text
                       IAM SCANNER
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
      Permissions         Trust            Scope
          │                 │                 │
       Action             Principal        Resource
       Effect             AssumeRole       Condition
          │
          ↓
     Risk Analysis
          │
          ↓
     Security Finding
```

---

# 🧠 46. `iam.py` in This Project

The purpose of `iam.py` in the Pull Request Security Gate is to analyze IAM-related configuration changed in a Pull Request and identify potentially unsafe or overly broad permissions.

```text
                       GitHub PR
                           │
                           ↓
                    Changed Files
                           │
              ┌────────────┴────────────┐
              │                         │
             .json                      .tf
              │                         │
        IAM Policy JSON           Terraform IAM
              │                         │
              └────────────┬────────────┘
                           ↓
                         iam.py
                           │
                           ↓
                  Analyze IAM Configuration
                           │
          ┌────────────────┼────────────────┐
          │                │                │
        Effect           Action          Resource
          │                │                │
          └────────────────┼────────────────┘
                           ↓
                    Security Rules
                           │
                           ↓
                 Potential Finding
                           │
                           ↓
                    Importance Level
                           │
                           ↓
                    Security Gate
```

---

# 🧠 47. What Can `iam.py` Detect?

A basic implementation can detect patterns such as:

```text
Action: "*"
Resource: "*"
```

It can also be extended to detect:

```text
├── Broad service permissions
├── Administrative permissions
├── Dangerous IAM actions
├── Broad trust relationships
├── Potential privilege escalation
├── Excessive resource access
└── Other project-defined IAM rules
```

However, the scanner should consider context.

```text
Wildcard
   ↓
Not automatically a vulnerability
   ↓
Analyze:
   ├── Effect
   ├── Action
   ├── Resource
   ├── Principal
   ├── Condition
   └── Policy Context
   ↓
Determine Risk
```

### Viva

**Q: Is every `*` an IAM vulnerability?**  
A: No, the scanner should consider the action, resource, context, and whether the wildcard is actually excessive.

---

# 🧠 48. IAM Security Gate

Your project can use IAM scanning as one stage of a Pull Request security gate.

```text
                     PULL REQUEST
                           │
                           ↓
                    Retrieve Changes
                           │
          ┌────────────────┼────────────────┐
          │                │                │
        Secrets           IAM             Other
        Scanner         Scanner           Checks
          │                │                │
          └────────────────┼────────────────┘
                           ↓
                     Findings
                           │
                           ↓
                     Importance
                           │
                           ↓
                    Security Gate
                      │         │
                    PASS       FAIL
                      │         │
                    Merge      Fix
```

---

# 🧠 49. Shift-Left Security

Shift-left security means detecting security problems earlier in the software development lifecycle.

Without scanning:

```text
Code
 ↓
Deploy
 ↓
AWS
 ↓
Security Issue Found
```

With shift-left security:

```text
Code
 ↓
Pull Request
 ↓
Security Scan
 ↓
Fix
 ↓
Merge
 ↓
Deploy
```

### Viva

**Q: What is shift-left security?**  
A: Shift-left security means detecting and fixing security issues earlier in the development lifecycle.

---

# 🧠 50. DevSecOps + IAM

IAM security checks fit naturally into DevSecOps.

```text
                         DEVSECOPS
                             │
             ┌───────────────┼───────────────┐
             │               │               │
          DEVELOP           SECURE          OPERATE
             │               │               │
             ↓               ↓               ↓
            Git          IAM Scanning       AWS
             │               │               │
             ↓          Secret Scanning     │
        Pull Request          │              │
             │               ↓               │
             └────────→ Security Gate ←──────┘
                              │
                         PASS / FAIL
```

### Viva

**Q: How does IAM scanning support DevSecOps?**  
A: It integrates permission security checks into the development and CI/CD workflow before deployment.

---

# 🧠 51. CI/CD and IAM

CI/CD systems often need AWS permissions.

For example:

```text
GitHub Actions
      │
      ↓
IAM Role
      │
      ↓
Temporary Credentials
      │
      ↓
AWS Deployment
```

The CI/CD identity should receive only the permissions required by the pipeline.

Avoid unnecessarily broad permissions such as:

```text
Action: *
Resource: *
```

### Viva

**Q: Why is least privilege important for CI/CD?**  
A: A compromised CI/CD identity could affect infrastructure, so limiting its permissions reduces the potential blast radius.

---

# 🧠 52. Common IAM Security Problems

```text
                     IAM SECURITY ISSUES
                              │
       ┌──────────────────────┼──────────────────────┐
       │                      │                      │
  Excessive Access       Credentials            Trust Issues
       │                      │                      │
       ├── Action:*       ├── Hardcoded Keys     ├── Broad Principal
       ├── Resource:*     ├── Leaked Keys        └── Weak Trust
       ├── Admin Access   └── Long-lived Keys
       └── Overpermission
```

Common mistakes include:

- Excessive permissions
- Unnecessary administrator access
- Wildcard actions
- Wildcard resources
- Hardcoded access keys
- Long-lived credentials
- Missing MFA
- Broad trust policies
- Poorly scoped CI/CD permissions
- Unreviewed IAM changes

---

# 🧠 53. Recommended DevOps IAM Practices

```text
                    IAM BEST PRACTICES
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
    ACCESS CONTROL      CREDENTIALS          GOVERNANCE
        │                    │                    │
    Least Privilege      Temporary Creds       SCP
    Specific Actions     IAM Roles             Boundaries
    Specific Resources   MFA                   Reviews
    Conditions           Avoid Hardcoding      Analyzer
```

Recommended practices:

- Follow least privilege
- Prefer IAM roles for workloads
- Use temporary credentials
- Enable MFA
- Avoid hardcoded credentials
- Review IAM changes
- Use permission boundaries where appropriate
- Use SCPs as organizational guardrails
- Use IAM Access Analyzer
- Scan IaC before deployment
- Restrict CI/CD permissions
- Regularly review permissions

---

# 🧠 54. Complete IAM Mental Model

```text
                              AWS IAM
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
      IDENTITIES             POLICIES              SECURITY
          │                      │                      │
    ┌─────┼─────┐          ┌─────┼─────┐        ┌──────┼──────┐
    │     │     │          │     │     │        │      │      │
   User  Group  Role      Effect Action Resource Least  MFA    STS
                                               Privilege
                     │
                     ↓
               Trust Policy
                     │
                     ↓
               AssumeRole
                     │
                     ↓
           Temporary Credentials
                     │
                     ↓
                  AWS API
                     │
                     ↓
              Policy Evaluation
                     │
                ┌────┴────┐
                │         │
             Explicit    Allow
               Deny        │
                │          │
                ↓          ↓
              DENY       ACCESS
```

---

# 🧠 55. Complete Terraform + IAM + Security Mind Map

```text
                         DEVELOPER
                             │
                             ↓
                       Terraform / JSON
                             │
                             ↓
                       Git Repository
                             │
                             ↓
                       Pull Request
                             │
             ┌───────────────┼───────────────┐
             │               │               │
           .tf              .json          Other
             │               │
             └───────┬───────┘
                     │
                     ↓
                   iam.py
                     │
             ┌───────┼────────┐
             │       │        │
           Effect  Action   Resource
             │       │        │
             └───────┼────────┘
                     ↓
              Security Analysis
                     │
        ┌────────────┼────────────┐
        │            │            │
     Wildcard    Excessive     Trust
     Access      Privilege    Policy
        │            │            │
        └────────────┼────────────┘
                     ↓
                  Finding
                     │
                     ↓
                Importance
                     │
                     ↓
               Security Gate
                │          │
              PASS        FAIL
                │          │
              Merge       Fix
                           │
                           ↓
                         Rescan
                           │
                           ↓
                         Deploy
                           │
                           ↓
                           AWS
```

---

# 🎓 56. IAM Viva — Quick Revision

| Question | One-Line Answer |
|---|---|
| What is IAM? | IAM controls identities and access to AWS resources. |
| What is authentication? | Authentication verifies who the requester is. |
| What is authorization? | Authorization determines what the requester can do. |
| What is the root user? | The root user represents the AWS account and has extremely broad privileges. |
| Should root be used daily? | No, root should be protected and avoided for routine operations. |
| What is an IAM user? | An IAM user is an identity created within an AWS account. |
| What is an IAM group? | A group is a collection of IAM users. |
| What is an IAM role? | A role is an identity that trusted entities can assume. |
| Why use IAM roles? | Roles commonly provide temporary credentials without long-lived credentials. |
| What is an IAM policy? | A policy defines which actions are allowed or denied on resources. |
| What is Statement? | A Statement represents an individual permission rule. |
| What is Effect? | Effect specifies Allow or Deny. |
| What is Action? | Action specifies the AWS operation being controlled. |
| What is Resource? | Resource specifies the AWS resource being controlled. |
| What is Condition? | Condition adds additional restrictions to a policy statement. |
| What is Principal? | Principal identifies the entity affected by a policy where Principal is specified. |
| What is an ARN? | An ARN identifies an AWS resource. |
| What does Action `*` mean? | It represents all applicable actions. |
| What does Resource `*` mean? | It represents all applicable resources. |
| Is every wildcard dangerous? | No, its risk depends on the policy context. |
| Why is Allow `*` on `*` dangerous? | It grants extremely broad permissions and increases potential blast radius. |
| What is least privilege? | Grant only the permissions required for the intended task. |
| What is explicit Deny? | An explicit Deny overrides an applicable Allow. |
| What is implicit Deny? | Access is denied when no applicable Allow grants the requested permission. |
| What is a trust policy? | It defines who or what can assume a role. |
| What is a permissions policy? | It defines what an identity can do. |
| What is STS? | STS provides temporary AWS security credentials. |
| What are temporary credentials? | Short-lived credentials used for a limited session. |
| What are access keys? | Credentials used for programmatic AWS access. |
| What is MFA? | MFA adds an additional authentication factor. |
| What is a permission boundary? | It sets the maximum permissions an IAM identity can have. |
| What is an SCP? | An SCP limits maximum permissions for governed AWS accounts or OUs. |
| Does an SCP grant permissions? | No, it only sets permission guardrails. |
| What is federation? | Federation allows external identities to access AWS through a trusted identity provider. |
| What is IAM Identity Center? | It provides centralized workforce access to AWS accounts and applications. |
| What is privilege escalation? | It is obtaining greater privileges through existing permissions. |
| What is blast radius? | It is the potential scope of impact from a compromise. |
| What is IAM Access Analyzer? | It helps identify unintended access and analyze IAM policies. |
| What is static analysis? | It analyzes code or configuration without executing it. |
| Why scan Terraform? | Terraform can define IAM resources and permissions. |
| Why scan JSON? | JSON can directly contain IAM policy documents. |
| What is IaC security? | It is securing infrastructure configuration before deployment. |
| What is shift-left security? | It means detecting security issues earlier in development. |
| What is DevSecOps? | DevSecOps integrates security into development and operations. |
| What does `iam.py` do? | It analyzes IAM-related configuration and reports potentially unsafe permissions. |
| Does `iam.py` enforce AWS permissions? | No, AWS IAM performs authorization while `iam.py` performs pre-deployment analysis. |

---

# ⭐ 57. Final IAM Memory Map

For a viva, remember this sequence:

```text
IAM
 │
 ├── WHO?
 │    ├── User
 │    ├── Group
 │    └── Role
 │
 ├── WHAT?
 │    └── Policy
 │
 ├── WHAT ACTION?
 │    └── Action
 │
 ├── WHERE?
 │    └── Resource
 │
 ├── UNDER WHAT CONDITIONS?
 │    └── Condition
 │
 ├── WHO CAN ASSUME?
 │    └── Trust Policy
 │
 ├── HOW IS ACCESS CONTROLLED?
 │    └── Policy Evaluation
 │
 ├── SECURITY
 │    ├── Least Privilege
 │    ├── MFA
 │    ├── Temporary Credentials
 │    ├── Permission Boundaries
 │    └── SCPs
 │
 └── DEVOPS
      ├── Terraform
      ├── JSON
      ├── IaC Security
      ├── CI/CD
      ├── Security Gate
      └── iam.py
```

## 🔑 One-Line Mental Model

```text
IAM = WHO
Policy = WHAT
Action = DO WHAT
Resource = WHERE
Condition = UNDER WHAT CONDITIONS
Principal = WHO IS INVOLVED
Trust Policy = WHO CAN ASSUME
STS = TEMPORARY CREDENTIALS
Least Privilege = ONLY WHAT IS NEEDED
Terraform = INFRASTRUCTURE AS CODE
iam.py = FIND IAM SECURITY ISSUES BEFORE DEPLOYMENT
DevSecOps = SECURITY THROUGHOUT THE DEVELOPMENT LIFECYCLE
```