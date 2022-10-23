SELECT
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

    AS VUL_001_percentage_hosts_with_open_critical_or_high_severity_vulnerabilities