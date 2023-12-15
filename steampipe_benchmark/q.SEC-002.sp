control "SEC_002" {
    title = "SEC-002 - % of in-scope personnel compute devices with a Crowdstrike Agent Zero Trust Score for OS of 100"

    sql = <<EOT
SELECT
    ZTA.system_serial_number || ' (' || salesforce_krow__project_resources__c.name || ')' as resource,
    CASE
        WHEN ZTA.assessment ->> 'os' = '100' THEN 'ok'
        ELSE 'alarm'
    END AS status,
    ZTA.system_serial_number || ' (' || salesforce_krow__project_resources__c.name || ' has a score of ' || (ZTA.assessment ->> 'os') as reason,
    jsonb_path_query_array(ZTA.assessment_items['os_signals'], '$[*] ? (@.meets_criteria != "yes").criteria') #>> '{}' as detail
    
FROM    
    crowdstrike_zta_assessment ZTA

-- Link the serial number to the Salesforce data, so we can find the owner
-- LEFT JOIN is important, in case there isn't a link, we still want to see the data
LEFT JOIN salesforce_fixed_asset__c
    ON ZTA.system_serial_number = serial_number__c

-- Here an INNER JOIN is necessary.  If the serial number exists in Krow, but no owner, that could indicate a
-- a data inconsistency in Krow, which will break the query.  We want an INNER JOIN, because both entries must exist
INNER JOIN salesforce_krow__project_resources__c
    ON salesforce_fixed_asset__c.project_resource__c = salesforce_krow__project_resources__c.id


EOT
}