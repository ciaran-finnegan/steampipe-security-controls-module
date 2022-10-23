mod "local" {
  title = "steampipe-dashboard-crowdstrike"
}

query "vul-001-percentage-hosts-with-open-vulnerabilities" {
  sql = <<-EOQ
  SELECT
  'VUL-001 Percentage of devices with no open critical or high severity vulnerabilities, SLO >=95%' AS label,
    (
        SELECT 
            COUNT (DISTINCT  host_info -> 'hostname')
        
        FROM crowdstrike_spotlight_vulnerability
        
        WHERE (cve ->> 'exprt_rating' = 'CRITICAL'
            OR cve ->> 'exprt_rating' = 'HIGH')
            AND crowdstrike_spotlight_vulnerability.status = 'open'

    )
    * 100 /
    (
        SELECT
            COUNT (*)
            
        FROM crowdstrike_host
        
        WHERE last_seen >= NOW() - INTERVAL '30 DAYS'
    )

    || '%' AS "value",
    CASE
        WHEN
        (
        SELECT 
            COUNT (DISTINCT  host_info -> 'hostname')
        
        FROM crowdstrike_spotlight_vulnerability
        
        WHERE (cve ->> 'exprt_rating' = 'CRITICAL'
            OR cve ->> 'exprt_rating' = 'HIGH')
            AND crowdstrike_spotlight_vulnerability.status = 'open'

    )
    * 100 /
    (
        SELECT
            COUNT (*)
            
        FROM crowdstrike_host
        
        WHERE last_seen >= NOW() - INTERVAL '30 DAYS'
    )
        
         <95 then 'alert'
        ELSE 'ok'
      END AS type
EOQ
}

query "vul-002-percentage-vulnerabilties-remediated-within-slo-last-30-days" {
  sql = <<-EOQ
  SELECT
  'VUL-001 Percentage of critical or high vulnerabilities remediated within service level objectives , SLO >=95%' AS label,
     (
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
    )

    * 100 /
     
     (
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
            (cve ->> 'exprt_rating' = 'CRITICAL' OR 'exprt_rating' = 'HIGH') AND crowdstrike_spotlight_vulnerability.created_timestamp >= NOW() - INTERVAL '30 DAYS' AND (crowdstrike_spotlight_vulnerability.closed_timestamp - crowdstrike_spotlight_vulnerability.created_timestamp >= INTERVAL '3 DAYS' OR crowdstrike_spotlight_vulnerability.closed_timestamp - crowdstrike_spotlight_vulnerability.created_timestamp IS NULL)
    )

    || '%' AS "value",
    CASE
        WHEN
        (
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
    )

    * 100 /
     
     (
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
            (cve ->> 'exprt_rating' = 'CRITICAL' OR 'exprt_rating' = 'HIGH') AND crowdstrike_spotlight_vulnerability.created_timestamp >= NOW() - INTERVAL '30 DAYS' AND (crowdstrike_spotlight_vulnerability.closed_timestamp - crowdstrike_spotlight_vulnerability.created_timestamp >= INTERVAL '3 DAYS' OR crowdstrike_spotlight_vulnerability.closed_timestamp - crowdstrike_spotlight_vulnerability.created_timestamp IS NULL)
    )
         <95 then 'alert'
        ELSE 'ok'
      END AS type

EOQ
}

query "hosts-and-team-members-with-open-vulnerabilities" {
  sql = <<-EOQ
  SELECT
    TO_CHAR(created_timestamp,'DD Mon YYYY') as opened_date,
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

EOQ
}

query "vulnerabilities-opened-in-last-7-days" {
  sql = <<-EOQ
  SELECT
    TO_CHAR(created_timestamp,'DD Mon YYYY') as "Opened date",
    salesforce_krow__project_resources__c.name as "Device owner",
    app -> 'product_name_version' AS "Product",
    host_info -> 'hostname' AS "Hostname",
    cve -> 'exprt_rating' AS "Severity",
    cve -> 'id' AS "CVE Id",
    cve -> 'description' AS "Description",
    serial_number AS "Serial number",
    krow__slack_account_email__c AS "Email"

  FROM crowdstrike_spotlight_vulnerability

  LEFT JOIN crowdstrike_host
      ON aid = device_id

  LEFT JOIN salesforce_fixed_asset__c
      ON crowdstrike_host.serial_number = serial_number__c

  LEFT JOIN salesforce_krow__project_resources__c
      ON salesforce_fixed_asset__c.project_resource__c = salesforce_krow__project_resources__c.id

  WHERE (cve ->> 'exprt_rating' = 'CRITICAL' or cve ->> 'exprt_rating' = 'HIGH')
  AND crowdstrike_spotlight_vulnerability.status = 'open'
  AND created_timestamp >= (NOW() - INTERVAL '7 DAYS')



  ORDER BY

  salesforce_krow__project_resources__c.name DESC

EOQ
}

query "time-to-close-distribution" {
  sql = <<-EOQ
        SELECT
            cve -> 'id' AS "CVE Id",
            CEIL (EXTRACT(epoch FROM crowdstrike_spotlight_vulnerability.closed_timestamp - crowdstrike_spotlight_vulnerability.created_timestamp) / 86400) AS "Number of days to close (if closed)"

        FROM crowdstrike_spotlight_vulnerability

        WHERE 
            cve ->> 'exprt_rating' = 'CRITICAL' or cve ->> 'exprt_rating' = 'HIGH'
  EOQ
}

query "critical-high-vulnerabilities-by-product" {
  sql = <<-EOQ
        SELECT
            DISTINCT (app -> 'product_name_version') AS product,
            COUNT (cve ->> 'exprt_rating')
            
        FROM 
            crowdstrike_spotlight_vulnerability

        WHERE 
            cve ->> 'exprt_rating' = 'CRITICAL' or cve ->> 'exprt_rating' = 'HIGH'
        GROUP BY
        product
  EOQ
}

query "crtiical-vulnerabilities-by-host" {
  sql = <<-EOQ
  SELECT
            DISTINCT (host_info -> 'hostname') AS hostname,
            COUNT (cve ->> 'exprt_rating')
            
        FROM 
            crowdstrike_spotlight_vulnerability

        WHERE 
            cve ->> 'exprt_rating' = 'CRITICAL' AND crowdstrike_spotlight_vulnerability.status = 'open'
        GROUP BY
        hostname

EOQ
}