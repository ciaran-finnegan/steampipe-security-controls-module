SELECT
    TO_CHAR(created_timestamp,'DD Mon YYYY'),
    salesforce_krow__project_resources__c.name as assigned_to,
    app -> 'product_name_version' AS product_name_version,
    host_info -> 'hostname' AS hostname,
    cve -> 'exprt_rating' AS exprt_rating,
    cve -> 'id' AS cve_id,
    cve -> 'description' AS cve_description,
    serial_number,
    krow__slack_account_email__c

FROM crowdstrike_spotlight_vulnerability

LEFT JOIN crowdstrike_host
    ON aid = device_id

LEFT JOIN salesforce_fixed_asset__c
    ON crowdstrike_host.serial_number = serial_number__c

LEFT JOIN salesforce_krow__project_resources__c
    ON salesforce_fixed_asset__c.project_resource__c = salesforce_krow__project_resources__c.id

WHERE (cve ->> 'exprt_rating' = 'CRITICAL' OR cve ->> 'exprt_rating' = 'HIGH')
AND crowdstrike_spotlight_vulnerability.status = 'open'

ORDER BY

    salesforce_krow__project_resources__c.name DESC