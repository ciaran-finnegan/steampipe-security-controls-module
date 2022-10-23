SELECT
    salesforce_krow__project_resources__c.name,
    crowdstrike_spotlight_vulnerability.status,
    cve -> 'exprt_rating' AS exprt_rating,
    host_info -> 'hostname' AS hostname,
    crowdstrike_spotlight_vulnerability.created_timestamp,
    crowdstrike_spotlight_vulnerability.closed_timestamp - crowdstrike_spotlight_vulnerability.created_timestamp AS time_to_close,
    cve -> 'id' AS cve_id,
    cve -> 'description' AS cve_description,
    serial_number,
    krow__slack_account_email__c,
    app -> 'product_name_version' AS product_name_version

FROM crowdstrike_spotlight_vulnerability

LEFT JOIN crowdstrike_host
    ON aid = device_id

LEFT JOIN salesforce_fixed_asset__c
    ON crowdstrike_host.serial_number = serial_number__c

LEFT JOIN salesforce_krow__project_resources__c
    ON salesforce_fixed_asset__c.project_resource__c = salesforce_krow__project_resources__c.id

WHERE 
    cve ->> 'exprt_rating' = 'CRITICAL' AND crowdstrike_spotlight_vulnerability.created_timestamp >= NOW() - INTERVAL '30 DAYS' AND (crowdstrike_spotlight_vulnerability.closed_timestamp - crowdstrike_spotlight_vulnerability.created_timestamp >= INTERVAL '3 DAYS' OR crowdstrike_spotlight_vulnerability.closed_timestamp - crowdstrike_spotlight_vulnerability.created_timestamp IS NULL)


ORDER BY

    created_timestamp DESC