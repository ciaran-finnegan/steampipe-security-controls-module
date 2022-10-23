dashboard "dashboard_crowdstrike" {
  title = "Crowdstrike Service Level Objective Performance Dashboard"

text {
    value = "This dashboard provides a realtime summary of security metrics derived from the Crowdstrike endpoint protection service."
  }

container {
  width = 6
  card {
    type = "info"
    icon = "bell"
    sql = query.vul-001-percentage-hosts-with-open-vulnerabilities.sql
  }
}

container {
  width = 6
  card {
    type = "info"
    icon = "bell"
    sql = query.vul-002-percentage-vulnerabilties-remediated-within-slo-last-30-days.sql
  }
}

container {
  width = 6
  chart {
    title = "Crtical and high severity vulnerability distribution by product"
    type = "pie"
    sql = query.critical-high-vulnerabilities-by-product.sql
  }
}

container {
  width = 6
  chart {
    title = "Hosts with open critical severity vulnerabilities"
    type = "pie"
    sql = query.crtiical-vulnerabilities-by-host.sql
  }
}

container {
  width = 12
  chart {
    title = "Days to close critical and high severity vulnerabilities"
    type = "column"
    sql = query.time-to-close-distribution.sql
    axes {
    y {
      title {
        value  = "Number of days to close"
      }
      labels {
        display = "show"
      }
      min    = 0
    }
  }
  }
}

table {
  title = "Critical and high severity vulnerabilities opened in the last 7 days"
  width = 12
  sql   = query.vulnerabilities-opened-in-last-7-days.sql
  column "Description" {
      wrap = "all"
    }
  column "serial_number" {
      display = "none"
    }
  column "krow__slack_account_email__c" {
      display = "none"
    }
}

table {
  title = "All open critical and high severity vulnerabilities"
  sql   = query.hosts-and-team-members-with-open-vulnerabilities.sql
  column "cve_description" {
      wrap = "all"
    }
  column "serial_number" {
      display = "none"
    }
  column "cve_id" {
      display = "none"
    }
  column "Email" {
      display = "none"
    }
}
}