-- The "base" of the measure is the crowdstrike_host table -- that's essentially what we're querying - the # of compliant HOSTS
SELECT
    -- Every Steampipe measure must have a resource (unique), a status (ok, skip, alarm), and a reason
    H.serial_number as resource,
    -- Every measure must have a "Compliance" field - a variable number between 0 and 1 to indicate the level of compliance
    CASE
        WHEN V.Critical is null and V.High is Null then 'ok'
        else 'alarm'
    END as status,
    CASE
        WHEN V.Critical is null and V.High is Null then 'No vulnerabilities'
        else H.serial_number || ' (' || salesforce_krow__project_resources__c.name || ') with vulnerabilities to be patched'
    END as reason,
    -- Everything else is purely cosmetic
    
    salesforce_krow__project_resources__c.name  as "Owner Name",
    H.hostname,
    H.last_seen,
    H.os_version,
    H.title,
    V.Critical,
    V.High
FROM
    crowdstrike_host H
LEFT JOIN (
    -- We then join this with the vulnerability table.  The actual vulnerabilities are not important, just that there is one 
    -- against the host we're checking
    SELECT 
        V.aid,
        COUNT(
            CASE
                WHEN V.cve ->> 'exprt_rating' = 'CRITICAL' AND V.status = 'open' AND V.created_timestamp >= NOW() - INTERVAL '30 DAYS' AND (V.closed_timestamp - V.created_timestamp >= INTERVAL '3 DAYS' OR V.closed_timestamp - V.created_timestamp IS NULL) THEN 1
                ELSE 0
            END
        ) as Critical,
        COUNT(
            CASE
                WHEN V.cve ->> 'exprt_rating' = 'HIGH' AND V.status = 'open' AND V.created_timestamp >= NOW() - INTERVAL '30 DAYS' AND (V.closed_timestamp - V.created_timestamp >= INTERVAL '3 DAYS' OR V.closed_timestamp - V.created_timestamp IS NULL) THEN 1
                ELSE 0
            END
        ) as High
    FROM
        crowdstrike_spotlight_vulnerability V
    WHERE
        V.status = 'open'
    GROUP BY
        V.aid
) V on V.aid = H.device_id

-- Link the serial number to the Salesforce data, so we can find the owner
-- LEFT JOIN is important, in case there isn't a link, we still want to see the data
LEFT JOIN salesforce_fixed_asset__c
    ON H.serial_number = serial_number__c

-- Here an INNER JOIN is necessary.  If the serial number exists in Krow, but no owner, that could indicate a
-- a data inconsistency in Krow, which will break the query.  We want an INNER JOIN, because both entries must exist
INNER JOIN salesforce_krow__project_resources__c
    ON salesforce_fixed_asset__c.project_resource__c = salesforce_krow__project_resources__c.id

WHERE
    H.last_seen >= NOW() - INTERVAL '30 DAYS'


    