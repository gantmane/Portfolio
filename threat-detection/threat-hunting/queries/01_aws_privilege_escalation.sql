-- ==============================================================================
-- AWS PRIVILEGE ESCALATION HUNTING QUERY
-- ==============================================================================
-- Author: Evgeniy Gantman
-- Purpose: Detect IAM privilege escalation attempts via policy manipulation
-- MITRE ATT&CK: T1098.003 - Account Manipulation: Additional Cloud Roles
-- Data Source: AWS CloudTrail via Athena
-- ==============================================================================

-- ==============================================================================
-- QUERY 1: Detect overly permissive IAM policy creation
-- ==============================================================================

SELECT
  eventtime,
  useridentity.principalid AS actor,
  useridentity.arn AS actor_arn,
  eventname,
  awsregion,
  sourceipaddress,
  useragent,
  JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') AS policy_document,
  JSON_EXTRACT_SCALAR(requestparameters, '$.userName') AS target_user,
  JSON_EXTRACT_SCALAR(requestparameters, '$.roleName') AS target_role,
  JSON_EXTRACT_SCALAR(requestparameters, '$.groupName') AS target_group,
  CASE
    WHEN JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%"Action":"*"%'
      AND JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%"Resource":"*"%'
    THEN 'CRITICAL: Wildcard Action + Resource'
    WHEN JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%AdministratorAccess%'
    THEN 'CRITICAL: AdministratorAccess granted'
    WHEN JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:CreateAccessKey%'
    THEN 'HIGH: CreateAccessKey permission'
    WHEN JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:PassRole%'
    THEN 'HIGH: PassRole permission (potential privilege escalation)'
    WHEN JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%sts:AssumeRole%'
    THEN 'MEDIUM: AssumeRole permission'
    ELSE 'INFO: Policy modification'
  END AS risk_level,
  errorcode,
  errormessage
FROM
  cloudtrail_logs
WHERE
  -- Last 7 days
  eventtime >= CAST(date_add('day', -7, current_timestamp) AS VARCHAR)

  -- IAM policy manipulation events
  AND eventname IN (
    'PutUserPolicy',
    'PutRolePolicy',
    'PutGroupPolicy',
    'AttachUserPolicy',
    'AttachRolePolicy',
    'AttachGroupPolicy',
    'CreatePolicy',
    'CreatePolicyVersion'
  )

  -- Detect dangerous permissions
  AND (
    -- Wildcard permissions
    JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%"Action":"*"%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%"Resource":"*"%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%AdministratorAccess%'

    -- Privilege escalation techniques
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:CreateAccessKey%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:PassRole%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%sts:AssumeRole%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:AttachUserPolicy%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:AttachRolePolicy%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:PutUserPolicy%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:PutRolePolicy%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:CreatePolicyVersion%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:SetDefaultPolicyVersion%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%lambda:UpdateFunctionCode%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%lambda:CreateFunction%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%ec2:RunInstances%'

    -- Sensitive resource access
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%secretsmanager:GetSecretValue%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%kms:Decrypt%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%s3:GetObject%'
  )

ORDER BY
  eventtime DESC
LIMIT 100;

-- ==============================================================================
-- QUERY 2: Detect rapid succession of privilege changes (escalation chains)
-- ==============================================================================

WITH privilege_changes AS (
  SELECT
    eventtime,
    useridentity.principalid AS actor,
    useridentity.arn AS actor_arn,
    eventname,
    JSON_EXTRACT_SCALAR(requestparameters, '$.userName') AS target_user,
    JSON_EXTRACT_SCALAR(requestparameters, '$.roleName') AS target_role,
    sourceipaddress,
    CAST(eventtime AS TIMESTAMP) AS event_timestamp
  FROM
    cloudtrail_logs
  WHERE
    eventtime >= CAST(date_add('day', -7, current_timestamp) AS VARCHAR)
    AND eventname IN (
      'PutUserPolicy', 'PutRolePolicy', 'AttachUserPolicy', 'AttachRolePolicy',
      'CreateAccessKey', 'CreateUser', 'AddUserToGroup'
    )
),
actor_activity AS (
  SELECT
    actor,
    actor_arn,
    sourceipaddress,
    COUNT(*) AS privilege_change_count,
    COUNT(DISTINCT eventname) AS unique_event_types,
    MIN(event_timestamp) AS first_change,
    MAX(event_timestamp) AS last_change,
    date_diff('minute', MIN(event_timestamp), MAX(event_timestamp)) AS time_window_minutes,
    array_agg(eventname) AS event_sequence
  FROM
    privilege_changes
  GROUP BY
    actor, actor_arn, sourceipaddress
  HAVING
    COUNT(*) >= 3  -- 3 or more privilege changes
    AND date_diff('minute', MIN(event_timestamp), MAX(event_timestamp)) <= 60  -- Within 60 minutes
)
SELECT
  actor,
  actor_arn,
  sourceipaddress,
  privilege_change_count,
  unique_event_types,
  first_change,
  last_change,
  time_window_minutes,
  event_sequence,
  CASE
    WHEN privilege_change_count >= 10 THEN 'CRITICAL: Rapid privilege escalation (10+ changes)'
    WHEN privilege_change_count >= 5 THEN 'HIGH: Multiple privilege changes (5+ changes)'
    WHEN time_window_minutes <= 5 THEN 'HIGH: Very rapid changes (< 5 minutes)'
    ELSE 'MEDIUM: Suspicious privilege modification pattern'
  END AS alert_severity
FROM
  actor_activity
ORDER BY
  privilege_change_count DESC,
  time_window_minutes ASC;

-- ==============================================================================
-- QUERY 3: Detect privilege escalation outside business hours
-- ==============================================================================

SELECT
  eventtime,
  EXTRACT(HOUR FROM CAST(eventtime AS TIMESTAMP)) AS event_hour,
  EXTRACT(DOW FROM CAST(eventtime AS TIMESTAMP)) AS day_of_week,  -- 0=Sunday, 6=Saturday
  useridentity.principalid AS actor,
  useridentity.arn AS actor_arn,
  eventname,
  sourceipaddress,
  awsregion,
  JSON_EXTRACT_SCALAR(requestparameters, '$.userName') AS target_user,
  JSON_EXTRACT_SCALAR(requestparameters, '$.roleName') AS target_role,
  JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') AS policy_document
FROM
  cloudtrail_logs
WHERE
  eventtime >= CAST(date_add('day', -30, current_timestamp) AS VARCHAR)

  AND eventname IN (
    'PutUserPolicy', 'PutRolePolicy', 'AttachUserPolicy', 'AttachRolePolicy',
    'CreatePolicy', 'CreatePolicyVersion', 'CreateAccessKey', 'CreateUser'
  )

  -- Outside business hours (before 8 AM or after 6 PM UTC)
  AND (
    EXTRACT(HOUR FROM CAST(eventtime AS TIMESTAMP)) < 8
    OR EXTRACT(HOUR FROM CAST(eventtime AS TIMESTAMP)) >= 18
    OR EXTRACT(DOW FROM CAST(eventtime AS TIMESTAMP)) IN (0, 6)  -- Weekends
  )

ORDER BY
  eventtime DESC;

-- ==============================================================================
-- QUERY 4: Detect new IAM users created with immediate permission grants
-- ==============================================================================

WITH new_users AS (
  SELECT
    CAST(eventtime AS TIMESTAMP) AS user_creation_time,
    JSON_EXTRACT_SCALAR(requestparameters, '$.userName') AS username,
    useridentity.principalid AS creator,
    sourceipaddress AS creator_ip
  FROM
    cloudtrail_logs
  WHERE
    eventtime >= CAST(date_add('day', -7, current_timestamp) AS VARCHAR)
    AND eventname = 'CreateUser'
),
permission_grants AS (
  SELECT
    CAST(eventtime AS TIMESTAMP) AS permission_grant_time,
    JSON_EXTRACT_SCALAR(requestparameters, '$.userName') AS username,
    eventname AS permission_event,
    JSON_EXTRACT_SCALAR(requestparameters, '$.policyArn') AS policy_arn,
    JSON_EXTRACT_SCALAR(requestparameters, '$.groupName') AS group_name
  FROM
    cloudtrail_logs
  WHERE
    eventtime >= CAST(date_add('day', -7, current_timestamp) AS VARCHAR)
    AND eventname IN ('AttachUserPolicy', 'AddUserToGroup', 'PutUserPolicy')
)
SELECT
  u.user_creation_time,
  u.username,
  u.creator,
  u.creator_ip,
  p.permission_grant_time,
  p.permission_event,
  p.policy_arn,
  p.group_name,
  date_diff('minute', u.user_creation_time, p.permission_grant_time) AS minutes_after_creation,
  CASE
    WHEN date_diff('minute', u.user_creation_time, p.permission_grant_time) <= 5
    THEN 'CRITICAL: Permissions granted within 5 minutes of user creation'
    WHEN date_diff('minute', u.user_creation_time, p.permission_grant_time) <= 30
    THEN 'HIGH: Permissions granted within 30 minutes'
    ELSE 'MEDIUM: Permissions granted same day as user creation'
  END AS risk_level
FROM
  new_users u
JOIN
  permission_grants p ON u.username = p.username
WHERE
  date_diff('hour', u.user_creation_time, p.permission_grant_time) <= 24  -- Within 24 hours
ORDER BY
  minutes_after_creation ASC;

-- ==============================================================================
-- INVESTIGATION CHECKLIST
-- ==============================================================================
-- For each alert, investigate the following:
-- 1. [ ] Is the actor authorized to perform IAM modifications?
-- 2. [ ] Is the source IP expected (VPN, corporate network)?
-- 3. [ ] Was the change approved via change management?
-- 4. [ ] Does the policy follow least-privilege principles?
-- 5. [ ] Are there other suspicious activities from the same actor?
-- 6. [ ] Has the target user/role accessed sensitive resources post-change?
-- 7. [ ] Check for subsequent access key creation or credential usage
-- 8. [ ] Review CloudTrail for lateral movement or data exfiltration
-- ==============================================================================
