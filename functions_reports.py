import json
from beautifultable import BeautifulTable

def get_vulnerability_report(target, os_data, vulners_linux_audit_data):
    report_dict = dict()
    levels = set()
    necessary_levels = ['Critical', 'High', 'Medium']
    bull_to_criticality = dict()
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
                    if bul_id not in report_dict:
                        report_dict[bul_id] = dict()
                        report_dict[bul_id]['packages'] = dict()
                        report_dict[bul_id]['vuln'] = vuln_report_data
                        bull_to_criticality[bul_id] = level
                        levels.add(level)
                    if package not in report_dict[bul_id]:
                        report_dict[bul_id]['packages'][package] = {
                            'operator': vuln['operator'],
                            'bulletinVersion': vuln['bulletinVersion']
                        }

    bul_id_sorted_list = list()
    bul_id_to_criticality_keys = list(bull_to_criticality.keys())
    bul_id_to_criticality_keys.sort()
    for level in necessary_levels:
        for bul_id in bul_id_to_criticality_keys:
            if bull_to_criticality[bul_id] == level:
                bul_id_sorted_list.append(bul_id)

    levels_sorted_list = list()
    for necessary_level in necessary_levels:
        for level in levels:
            if level == necessary_level:
                levels_sorted_list.append(level)

    n = 1
    table = BeautifulTable(maxwidth=4000)
    table.columns.header = ["N", "Level", "Bulletin", "CVE", "Proof"]
    for bul_id in bul_id_sorted_list:
        line = list()
        line.append(str(n))
        line.append(report_dict[bul_id]['vuln']['Level'])
        line.append(bul_id)

        line.append("\n".join(report_dict[bul_id]['vuln']['CVE List']))

        proof_lines = list()
        for package in report_dict[bul_id]['packages']:
            operator = report_dict[bul_id]['packages'][package]['operator']
            if operator == "lt":
                operator = "<"
            elif operator == "gt":
                operator = ">"
            proof_lines.append(package + " " + operator +
                               " " + report_dict[bul_id]['packages'][package]['bulletinVersion'] )
        proof_line = "\n".join(proof_lines)
        line.append(proof_line)
        table.rows.append(line)
        n += 1

    if 'host' in target:
        target_id = target['host']
    elif 'docker_image' in target:
        target_id = target['docker_image']
    elif 'inventory_file' in target:
        target_id = target['inventory_file']

    report_text = "Vulnerability Report for " + target_id + " (" + target['assessment_type'] + \
                  ", " + os_data["os_name"] + " " +  os_data["os_version"] + ", " + str(len(os_data["package_list"])) \
                  + " packages)" + '\n' + str(len(bul_id_sorted_list)) + " vulnerabilities with levels " + str(list(levels)) +\
                  " were found\n"


    if report_dict != dict():
        report_text += str(table)
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
