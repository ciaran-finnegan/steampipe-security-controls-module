select  count (distinct  host_info -> 'hostname') from crowdstrike_spotlight_vulnerability where (cve ->> 'exprt_rating' = 'CRITICAL' or cve ->> 'exprt_rating' = 'HIGH') and crowdstrike_spotlight_vulnerability.status = 'open' and created_timestamp >= (NOW() - INTERVAL '30 DAYS')