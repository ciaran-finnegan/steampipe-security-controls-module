SELECT 
    host_info -> 'hostname' AS hostname,
    crowdstrike_spotlight_vulnerability.status,
    cve ->> 'exprt_rating' AS exprt_rating

FROM crowdstrike_spotlight_vulnerability

WHERE (cve ->> 'exprt_rating' = 'CRITICAL' 
    OR cve ->> 'exprt_rating' = 'HIGH')
    AND crowdstrike_spotlight_vulnerability.status = 'open'
    AND created_timestamp >= (NOW() - INTERVAL '30 DAYS')

ORDER BY

    host_info -> 'hostname' DESC