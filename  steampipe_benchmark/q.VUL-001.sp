control "VUL_001" {
    title = "VUL-001 - % of personal compute devices without open critical or high severity vulnerabilities"
    sql = <<EOQ

        SELECT            
            H.serial_number as resource,
            CASE
                WHEN V.Critical is null and V.High is Null then 'ok'
                else 'alarm'
            END as status,
            CASE
                WHEN V.Critical is null and V.High is Null then 'No vulnerabilities on ' || H.serial_number || ' (' || salesforce_krow__project_resources__c.name || ')'
                else H.serial_number || ' (' || salesforce_krow__project_resources__c.name || ') with vulnerabilities to be patched'
            END as reason,
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
            SELECT 
                V.aid,
                COUNT(
                    CASE
                        WHEN V.cve ->> 'exprt_rating' = 'CRITICAL' AND V.status = 'open' THEN 1
                        ELSE 0
                    END
                ) as Critical,
                COUNT(
                    CASE
                        WHEN V.cve ->> 'exprt_rating' = 'HIGH' AND V.status = 'open' THEN 1
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
        LEFT JOIN salesforce_fixed_asset__c
            ON H.serial_number = serial_number__c
        INNER JOIN salesforce_krow__project_resources__c
            ON salesforce_fixed_asset__c.project_resource__c = salesforce_krow__project_resources__c.id

        WHERE
            H.last_seen >= NOW() - INTERVAL '30 DAYS'
EOQ
}