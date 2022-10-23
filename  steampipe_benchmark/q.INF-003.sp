control "INF_003" {
    title = "INF-003 - Organisational email domains without DKIM configured"
    description = "Protect against spoofing & phishing, and help prevent messages from being marked as spam. See https://support.google.com/a/topic/2752442?hl=en&ref_topic=9061731 for more details."
    sql = <<EOT

        WITH ASSET_LIST as (
            SELECT
                D.domain,
                concat('google._domainkey.',D.domain) as dkim,
                COUNT(N.*) as MXCount
            FROM
                csv.domains D
            LEFT JOIN net_dns_record N on  N.domain = D.domain and N.type = 'MX'
            GROUP BY
                D.domain,
                concat('google._domainkey.',D.domain) 
        )

        SELECT
            A.domain as resource,
            CASE
                WHEN A.MXCount = 0 then 'skip'
                WHEN N.value LIKE 'v=DKIM%' THEN 'ok'
                ELSE 'alarm'
            END as status,
            CASE
                WHEN A.MXCount = 0 then 'No MX record for domain ' || A.domain
                WHEN N.value LIKE 'v=DKIM%' THEN 'Domain ' || A.domain || ' has a DKIM record.'
                ELSE 'Domain ' || A.dkim || ' is missing a DKIM entry'
            END as reason
        FROM
            ASSET_LIST A
        LEFT JOIN net_dns_record N on N.domain = A.dkim and N.type = 'TXT' and N.value like 'v=DKIM%'

    EOT
}