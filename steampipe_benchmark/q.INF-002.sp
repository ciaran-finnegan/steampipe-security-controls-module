control "INF_002" {
    title = "INF-002 - Organisational email domains without SPF configured"
    description = "Protect against spoofing & phishing, and help prevent messages from being marked as spam. See https://support.google.com/a/answer/33786?hl=en for more details."
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
                WHEN N.value LIKE '%include:_spf.google.com%' THEN 'ok'
                ELSE 'alarm'
            END as status,
            CASE
                WHEN A.MXCount = 0 then 'No MX record for domain ' || A.domain
                WHEN N.value LIKE '%include:_spf.google.com%' THEN 'Domain ' || A.domain || ' has a valid SPF policy.'
                ELSE 'Domain ' || A.domain || ' has no SPF policy'
            END as reason,
            N.value as spfs
        FROM
            ASSET_LIST A
        LEFT JOIN net_dns_record N on N.domain = A.domain and N.type = 'TXT' and N.value like 'v=spf1%'

    EOT
}