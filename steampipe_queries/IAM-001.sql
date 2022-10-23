SELECT
    
    U.email,
    CAST(
        -- Dormant accounts are accounts that have not logged on in the last 30 days
        (
            CASE
                WHEN date_part('day', CURRENT_TIMESTAMP - U.activated) < 30 OR date_part('day', CURRENT_TIMESTAMP - U.last_login) < 30 THEN 1
                ELSE 0
            END + 
            -- No MFA configured
            CASE
                WHEN date_part('day', CURRENT_TIMESTAMP - U.activated) < 30 OR f.user_id IS NOT NULL THEN 1
                ELSE 0
            END
        ) / 2.0 as float ) as "Compliance"
    ,U.activated
    ,U.last_login
    ,U.password_changed
    ,CASE
        WHEN F.user_id IS NULL THEN 'No MFA configured'
        ELSE 'OK'
    END AS "MFA Configured"
    --,date_part('day', CURRENT_TIMESTAMP - U.last_login) as "Login Age"
    --,date_part('day', CURRENT_TIMESTAMP - U.activated) as "Activated Age",
FROM
    okta_user U
LEFT JOIN
    (
        SELECT DISTINCT
            F.user_id
        FROM
            okta_factor F
        WHERE
            F.status = 'ACTIVE'
        AND
            F.factor_type IN ('push','token:software:totp')

    ) AS F on F.user_id = U.id
WHERE
    U.status = 'ACTIVE'
    