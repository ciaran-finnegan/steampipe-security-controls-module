SELECT
    COUNT (*)

FROM crowdstrike_spotlight_vulnerability

LEFT JOIN crowdstrike_host
    ON aid = device_id

LEFT JOIN salesforce_fixed_asset__c
    ON crowdstrike_host.serial_number = serial_number__c

LEFT JOIN salesforce_krow__project_resources__c
    ON salesforce_fixed_asset__c.project_resource__c = salesforce_krow__project_resources__c.id

WHERE 
    (cve ->> 'exprt_rating' = 'CRITICAL' OR 'exprt_rating' = 'HIGH') AND crowdstrike_spotlight_vulnerability.created_timestamp >= NOW() - INTERVAL '30 DAYS' AND (crowdstrike_spotlight_vulnerability.closed_timestamp - crowdstrike_spotlight_vulnerability.created_timestamp < INTERVAL '3 DAYS')