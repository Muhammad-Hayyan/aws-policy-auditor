import { IAMDatasetMap } from "./iamDataset";

export type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW';

export interface Finding {
  type: 'pass' | 'warning';
  text: string;
}

export interface PolicyAnalysis {
  riskLevel: RiskLevel;
  riskScore: number;
  badgeText: string;
  badgeSubtext: string;
  translatedActions: {
    critical: string[];
    medium: string[];
    low: string[];
  };
  findings: Finding[];
  questions: string[];
}

const CRITICAL_ACTIONS: Record<string, string> = {
  "*": "Perform ANY action across ALL AWS services",
  "iam:*": "Full control over all user accounts and permissions",
  "sts:AssumeRole": "Impersonate any other user or system role",
  "iam:CreateUser": "Create new user accounts",
  "iam:DeleteUser": "Delete user accounts",
  "iam:AttachUserPolicy": "Grant any permission to any user",
  "iam:AttachRolePolicy": "Grant any permission to any system role",
  "iam:CreateAccessKey": "Generate secret login credentials for any user",
  "iam:UpdateAssumeRolePolicy": "Change who is allowed to impersonate a role",
  "kms:Decrypt": "Decrypt encrypted data and secrets",
  "kms:DeleteKey": "Permanently destroy encryption keys",
  "secretsmanager:GetSecretValue": "Read stored passwords and secret credentials",
  "secretsmanager:DeleteSecret": "Permanently delete stored secrets",
  "s3:DeleteBucket": "Permanently delete an entire file storage container",
  "ec2:TerminateInstances": "Permanently shut down cloud servers",
  "rds:DeleteDBInstance": "Permanently delete a database",
  "rds:ModifyDBInstance": "Change database configuration including access controls",
  "lambda:InvokeFunction": "Execute automated code functions",
  "cloudtrail:DeleteTrail": "Delete the audit log trail",
  "cloudtrail:StopLogging": "Stop recording audit logs",
  "logs:DeleteLogGroup": "Permanently delete activity logs",
  "guardduty:DeleteDetector": "Disable threat detection monitoring"
};

const MEDIUM_ACTIONS: Record<string, string> = {
  "s3:*": "Full control over file storage",
  "s3:GetObject": "Download files from storage",
  "s3:PutObject": "Upload or overwrite files in storage",
  "s3:DeleteObject": "Delete files from storage",
  "s3:PutBucketPolicy": "Change who can access a storage container",
  "s3:PutBucketAcl": "Change access permissions on a storage container",
  "ec2:*": "Full control over cloud servers",
  "ec2:RunInstances": "Launch new cloud servers",
  "ec2:StopInstances": "Stop running cloud servers",
  "ec2:ModifyInstanceAttribute": "Change configuration of cloud servers",
  "ec2:AuthorizeSecurityGroupIngress": "Open network ports on cloud servers",
  "lambda:*": "Full control over automated code functions",
  "lambda:AddPermission": "Grant others access to execute code functions",
  "sns:Publish": "Send messages or notifications",
  "sqs:SendMessage": "Send data to message queues",
  "sts:GetCallerIdentity": "Look up the identity of the current user",
  "ssm:GetParameter": "Read configuration parameters and stored values",
  "ssm:PutParameter": "Write or overwrite configuration parameters"
};

const LOW_ACTIONS: Record<string, string> = {
  "s3:ListBucket": "View the list of files in storage",
  "s3:GetBucketLocation": "Check the location of a storage container",
  "ec2:DescribeInstances": "View information about cloud servers",
  "ec2:DescribeSecurityGroups": "View network security group settings",
  "cloudwatch:GetMetricData": "Read performance monitoring data",
  "cloudwatch:PutMetricData": "Write performance monitoring data",
  "cloudwatch:DescribeAlarms": "View configured monitoring alerts",
  "logs:GetLogEvents": "Read activity log entries",
  "logs:DescribeLogGroups": "View available activity log groups",
  "tag:GetResources": "View resource tags and labels",
  "sts:GetSessionToken": "Retrieve temporary session credentials"
};

const SERVICE_NAMES: Record<string, string> = {
  s3: "File Storage (S3)",
  ec2: "Cloud Servers (EC2)",
  iam: "User Access Management (IAM)",
  rds: "Databases (RDS)",
  lambda: "Automated Functions (Lambda)",
  kms: "Encryption Keys (KMS)",
  cloudtrail: "Audit Logs (CloudTrail)",
  logs: "Activity Logs",
  guardduty: "Threat Detection (GuardDuty)",
  sagemaker: "AI/ML Services (SageMaker)",
  sns: "Notification Service (SNS)",
  sqs: "Message Queues (SQS)",
  ssm: "Systems Configuration (SSM)",
  sts: "Identity & Access Tokens (STS)",
  secretsmanager: "Secrets & Credentials Manager"
};

function accessLevelToRiskTier(access_level: string): 'critical' | 'medium' | 'low' {
  switch (access_level) {
    case "Permissions management":
      return 'critical';
    case "Write":
      return 'medium';
    case "Read":
    case "List":
    case "Tagging":
    default:
      return 'low';
  }
}

function stripGrantsPrefix(description: string): string {
  return description.replace(/^Grants permission to /i, "");
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function analyzePolicy(jsonString: string, iamDataset?: IAMDatasetMap): PolicyAnalysis {
  let policy: any;
  try {
    policy = JSON.parse(jsonString);
  } catch (e) {
    throw new Error("Invalid JSON");
  }

  const statements = Array.isArray(policy.Statement)
    ? policy.Statement
    : policy.Statement
    ? [policy.Statement]
    : [];

  const allActions = new Set<string>();
  let hasWildcardAction = false;
  let hasWildcardResource = false;
  let hasConditions = false;
  let hasExplicitDeny = false;
  let hasScopedResource = false;

  statements.forEach((stmt: any) => {
    if (stmt.Effect === "Deny") hasExplicitDeny = true;
    if (stmt.Condition) hasConditions = true;

    if (stmt.Effect === "Allow") {
      const actions = Array.isArray(stmt.Action)
        ? stmt.Action
        : stmt.Action
        ? [stmt.Action]
        : [];
      actions.forEach((a: string) => {
        allActions.add(a);
        if (a === "*") hasWildcardAction = true;
      });

      const resources = Array.isArray(stmt.Resource)
        ? stmt.Resource
        : stmt.Resource
        ? [stmt.Resource]
        : [];
      resources.forEach((r: string) => {
        if (r === "*") hasWildcardResource = true;
        else if (r) hasScopedResource = true;
      });
    }
  });

  let score = 100;
  const criticalActionsFound: string[] = [];
  const mediumActionsFound: string[] = [];
  const lowActionsFound: string[] = [];
  let criticalScoreDeduction = 0;
  let hasCloudTrailIssue = false;
  let hasIamCreateAccessKey = false;
  let hasIamActions = false;

  allActions.forEach((action) => {
    if (action === "*") return;

    if (action.startsWith("iam:")) hasIamActions = true;
    if (action === "cloudtrail:DeleteTrail" || action === "cloudtrail:StopLogging") {
      hasCloudTrailIssue = true;
    }
    if (action === "iam:CreateAccessKey") hasIamCreateAccessKey = true;

    if (CRITICAL_ACTIONS[action]) {
      criticalActionsFound.push(CRITICAL_ACTIONS[action]);
      criticalScoreDeduction += 10;
    } else if (MEDIUM_ACTIONS[action]) {
      mediumActionsFound.push(MEDIUM_ACTIONS[action]);
    } else if (LOW_ACTIONS[action]) {
      lowActionsFound.push(LOW_ACTIONS[action]);
    } else if (iamDataset && iamDataset[action]) {
      const info = iamDataset[action];
      const tier = accessLevelToRiskTier(info.access_level);
      const label = capitalize(stripGrantsPrefix(info.description));

      if (tier === 'critical') {
        criticalActionsFound.push(label);
        criticalScoreDeduction += 10;
      } else if (tier === 'medium') {
        mediumActionsFound.push(label);
      } else {
        lowActionsFound.push(label);
      }
    } else {
      const service = action.split(":")[0];
      const friendlyName = SERVICE_NAMES[service] || service;
      mediumActionsFound.push(`Perform a technical operation in ${friendlyName}`);
    }
  });

  if (hasWildcardAction) {
    score -= 40;
    criticalActionsFound.unshift(CRITICAL_ACTIONS["*"]);
  }

  if (criticalScoreDeduction > 40) criticalScoreDeduction = 40;
  score -= criticalScoreDeduction;

  if (hasWildcardResource) score -= 20;
  if (!hasConditions) score -= 10;
  if (hasCloudTrailIssue) score -= 15;
  if (hasIamCreateAccessKey) score -= 10;

  if (hasConditions) score += 10;
  if (hasExplicitDeny) score += 10;
  if (hasScopedResource) score += 5;

  score = Math.max(0, Math.min(100, score));

  let riskLevel: RiskLevel;
  let badgeText: string;
  let badgeSubtext: string;

  if (score <= 40) {
    riskLevel = 'HIGH';
    badgeText = "HIGH RISK";
    badgeSubtext = "This policy grants excessive access and poses a significant risk of data breach or misuse.";
  } else if (score <= 70) {
    riskLevel = 'MEDIUM';
    badgeText = "MEDIUM RISK";
    badgeSubtext = "This policy has some concerning permissions that should be reviewed with your cloud team.";
  } else {
    riskLevel = 'LOW';
    badgeText = "LOW RISK";
    badgeSubtext = "This policy appears appropriately scoped. Routine review is still recommended.";
  }

  const findings: Finding[] = [];
  if (hasWildcardAction) findings.push({ type: 'warning', text: "Excessive privileges granted beyond least privilege principle" });
  if (!hasConditions) findings.push({ type: 'warning', text: "No conditional access controls are enforced" });
  if (hasCloudTrailIssue) findings.push({ type: 'warning', text: "Audit logging controls may be at risk" });
  if (hasExplicitDeny) findings.push({ type: 'pass', text: "Explicit deny rules are present" });
  if (hasScopedResource) findings.push({ type: 'pass', text: "Resource scope is appropriately restricted" });

  const questions: string[] = [];
  if (hasWildcardAction) questions.push("Can you list exactly which actions this role needs and remove the rest?");
  if (!hasConditions) questions.push("Can we add a requirement for MFA or restrict this to specific IP addresses?");
  if (hasIamActions) questions.push("Why does this role need the ability to create or modify user accounts?");
  if (hasCloudTrailIssue) questions.push("Why does this role have the ability to modify or delete audit logs?");
  if (hasWildcardResource) questions.push("Can you scope this policy to only the specific resources this role needs?");

  return {
    riskLevel,
    riskScore: score,
    badgeText,
    badgeSubtext,
    translatedActions: {
      critical: Array.from(new Set(criticalActionsFound)),
      medium: Array.from(new Set(mediumActionsFound)),
      low: Array.from(new Set(lowActionsFound))
    },
    findings,
    questions
  };
}
