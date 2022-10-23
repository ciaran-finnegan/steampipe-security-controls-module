control "IAM_002" {
    title = "IAM-002 - Active Okta accounts with MFA configured"
    sql = <<EOT

WITH OKTA_MFA as (
    SELECT 
        F.user_id
    FROM
        okta_factor F
    WHERE
        F.status = 'ACTIVE'
    AND
        F.factor_type IN ('push','token:software:totp')
)

SELECT
    U.email as resource,
    CASE
        WHEN U.status <> 'ACTIVE' THEN 'skip'
        WHEN COUNT(F.user_id) = 0 THEN 'alarm'
        ELSE 'ok'
    END AS status,
    CASE
        WHEN U.status <> 'ACTIVE' THEN 'User ' || u.email || ' is not active.'
        WHEN COUNT(F.user_id) = 0 THEN 'User ' || u.email || ' does not have MFA configured.'
        ELSE 'User ' || u.email || ' is ok'
    END AS reason,
    U.email,
    U.last_login
FROM
    okta_user U
LEFT JOIN OKTA_MFA F on F.user_id = U.id
GROUP BY
    U.email,
    U.status,
    U.last_login
    
EOT
}