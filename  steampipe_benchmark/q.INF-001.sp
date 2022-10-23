control "INF_001" {
    title = "INF-001 - Organisational email domains without DMARC configured"
    description = "Protect against spoofing & phishing, and help prevent messages from being marked as spam. See https://support.google.com/a/answer/2466563?hl=en for more details."
    sql = <<EOT

        WITH ASSET_LIST as (
            SELECT
                D.domain,
                concat('_dmarc.',D.domain) as dmarc,
                COUNT(N.*) as MXCount
            FROM
                csv.domains D
            LEFT JOIN net_dns_record N on  N.domain = D.domain and N.type = 'MX'
            GROUP BY
                D.domain,
                concat('_dmarc.',D.domain)
        )

        SELECT
            A.domain as resource,
            CASE
                WHEN A.MXCount = 0 then 'skip'
                WHEN N.value LIKE '%p=reject;%' THEN 'ok'
                WHEN N.value LIKE '%p=quarantine;%' THEN 'ok'
                ELSE 'alarm'
            END as status,
            CASE
                WHEN A.MXCount = 0 then 'No MX record for domain ' || A.domain
                WHEN N.value LIKE '%p=reject;%' THEN 'Domain ' || A.domain || ' has a reject policy.'
                WHEN N.value LIKE '%p=quarantine;%' THEN 'Domain ' || A.domain || ' has a quarantine policy.  Consider making it reject.'
                WHEN N.value IS NULL THEN 'Domain ' || A.domain || ' has no DMARC policy defined.'
                WHEN N.value LIKE '%p=none;%' THEN 'Domain ' || A.domain || ' has a dmarc policy of none.'
                ELSE 'Domain ' || A.domain || ' has no DMARC policy'
            END as reason,
            A.domain as domain
        FROM
            ASSET_LIST A
        LEFT JOIN net_dns_record N on N.domain = A.dmarc and N.type = 'TXT' and N.value like 'v=DMARC1%'

    EOT
}