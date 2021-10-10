import json


def get_vulnerability_report(target, os_data, vulners_linux_audit_data):
    report_dict = dict()
    bulls = list()
    levels = set()
    necessary_levels = ['High', 'Medium', 'Critical']
    for package in vulners_linux_audit_data['data']['packages']:
        for bul_id in vulners_linux_audit_data['data']['packages'][package]:
            for vuln in vulners_linux_audit_data['data']['packages'][package][bul_id]:
                level = get_level_from_cvss_base_score(vuln['cvss']['score'])
                if level in necessary_levels:
                    vuln_report_data = {
                        'Level': level,
                        'CVSS': vuln['cvss'],
                        'CVE List': vuln['cvelist']
                    }
                    if package not in report_dict:
                        report_dict[package] = dict()
                    if bul_id not in report_dict[package]:
                        report_dict[package][bul_id] = vuln_report_data
                        bulls.append(bul_id)
                        levels.add(level)
    if "os_name" not in target and "host" in target:
        target['os_name'] = target['host']
    report_text = "Vulnerability Report for " + target['host'] + " (" + target['assement_type'] + ")" + '\n' \
                  + str(len(bulls)) + " vulnerabilities with levels " + str(list(levels)) + " were found" + \
                  '\n---\n'
    if report_dict != dict():
        report_text += json.dumps(report_dict, indent=2)
    return {'report_text': report_text, 'report_dict': report_dict}


def get_all_cve_report(vulners_audit_data):
    report = list()
    all_cves = list()
    for package in vulners_audit_data['data']['packages']:
        for bul_id in vulners_audit_data['data']['packages'][package]:
            for vuln in vulners_audit_data['data']['packages'][package][bul_id]:
                all_cves += vuln['cvelist']
        report.append("---")
    report.append("All CVES")
    all_cves = set(all_cves)
    all_cves = list(all_cves)
    all_cves.sort()
    report += all_cves
    return "\n".join(report)


def get_level_from_cvss_base_score(cvss_base_score):
    # Low
    # 0.1 - 3.9
    # Medium
    # 4.0 - 6.9
    # High
    # 7.0 - 8.9
    # Critical
    # 9.0 - 10.0
    level = "Unknown"
    if 0 <= cvss_base_score <= 3.9:
        level = "Low"
    if 4.0 <= cvss_base_score <= 6.9:
        level = "Medium"
    if 7.0 <= cvss_base_score <= 8.9:
        level = "High"
    if 9.0 <= cvss_base_score <= 10.0:
        level = "Critical"
    return level
