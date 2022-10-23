control "IAM_001" {
    title = "IAM-001 - Dormant Okta accounts are accounts that have not logged on in the last 30 days"
    sql = <<EOT
SELECT
    U.email as resource,
    CASE
        WHEN U.status <> 'ACTIVE' THEN 'skip'
        WHEN date_part('day', CURRENT_TIMESTAMP - U.activated) < 30 OR date_part('day', CURRENT_TIMESTAMP - U.last_login) < 30 THEN 'ok'
        ELSE 'alarm'
    END as status,
    CASE
        WHEN U.status <> 'ACTIVE' THEN 'User ' || u.email || ' is no longer active'
        WHEN U.last_login is null THEN 'User ' || u.email || ' has never logged on'
        WHEN date_part('day', CURRENT_TIMESTAMP - U.activated) < 30 OR date_part('day', CURRENT_TIMESTAMP - U.last_login) < 30 THEN 'Last logon was on ' || U.last_login
        ELSE 'User ' || u.email || ' last logon on ' || U.last_login
    END as reason,
    U.email,
    U.last_login
FROM
    okta_user U
EOT
}