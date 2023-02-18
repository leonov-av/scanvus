import re
import json
from beautifultable import BeautifulTable

necessary_levels = ['Critical', 'High', 'Medium']


def get_vulners_vulnerability_report(target, os_data, vulners_linux_audit_data):
    report_dict = dict()
    levels = set()
    bull_to_criticality = dict()
    if 'packages' in vulners_linux_audit_data['data']:
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

    report_text = get_text_vulnerability_report(target, os_data, report_dict, bull_to_criticality, levels)

    return {'report_text': report_text, 'report_dict': report_dict}


def get_vulnsio_vulnerability_report(target, os_data, vulnsio_linux_audit_data):
    report_dict = dict()
    levels = set()
    bull_to_criticality = dict()
    bull_without_advisory = dict()

    def set_vulnsio_report_data(advisory_id, cve_id, package, cve_reason, cve_metrics):
        if advisory_id not in report_dict:
            report_dict[advisory_id] = {
               "packages": dict(),
               "vuln": {
                   "Level": "",
                   "CVSS": {"score": 0, "vector": ""},
                   "CVE List": set()
               }
            }
        report_dict[advisory_id]['vuln']['CVE List'].add(cve_id)
        reason = re.search(r"^.*([><]=?)(.*)$", cve_reason)
        report_dict[advisory_id]['packages'][package] = {
            'operator': '' if not reason else reason.group(1),
            'bulletinVersion': '' if not reason else reason.group(2)
        }
        max_metric = get_max_metrics(cve_metrics)
        level = get_level_from_cvss_base_score(max_metric['score'])
        if max_metric['score'] > report_dict[advisory_id]['vuln']['CVSS']['score'] and level in necessary_levels:
            report_dict[advisory_id]['vuln']['CVSS'] = max_metric
            report_dict[advisory_id]['vuln']['Level'] = level
            bull_to_criticality[advisory_id] = level
            levels.add(level)

    if vulnsio_linux_audit_data['isVulnerable']:
        for vulnerableObject in vulnsio_linux_audit_data['vulnerableObjects']:
            package = f'{vulnerableObject["name"]}-{vulnerableObject["version"]}.{vulnerableObject["arch"]}'
            for vuln in vulnerableObject['vulns']:
                is_added = False
                if vuln['related']:
                    for bull_id in vuln['related']:
                        if bull_id in vulnsio_linux_audit_data['cumulativeData']['vulns']:
                            vuln_id = vuln['id']
                            bull = vulnsio_linux_audit_data['cumulativeData']['vulns'][bull_id]

                            if vuln['type'] == 'advisory' and bull['type'] == 'cve':
                                is_added = True
                                set_vulnsio_report_data(vuln_id, bull_id, package, bull.get('reason', ''), bull['metrics'])

                            if vuln['type'] == 'cve' and bull['type'] == 'advisory':
                                is_added = True
                                set_vulnsio_report_data(bull_id, vuln_id, package, vuln.get('reason', ''), vulnsio_linux_audit_data['cumulativeData']['vulns'][vuln_id]['metrics'])

                # if cve was not added to the report, then it does not have a reference to the advisory
                if not is_added and vuln['id'] not in report_dict:
                    if vuln['id'] not in bull_without_advisory:
                        bull_without_advisory[vuln['id']] = {
                            'packages': dict(),
                            'metrics': vulnsio_linux_audit_data['cumulativeData']['vulns'][vuln['id']]['metrics']
                        }
                    bull_without_advisory[vuln['id']]['packages'][package] = vuln.get('reason', '')

    # add cve without advisory separately
    for bull_id in bull_without_advisory:
        if bull_id not in report_dict:
            max_metric = get_max_metrics(bull_without_advisory[bull_id]['metrics'])
            level = get_level_from_cvss_base_score(max_metric['score'])
            for package in bull_without_advisory[bull_id]['packages']:
                set_vulnsio_report_data(f'_no_advisory_{level.lower()}', bull_id, package, bull_without_advisory[bull_id]['packages'][package], bull_without_advisory[bull_id]['metrics'])

    report_text = get_text_vulnerability_report(target, os_data, report_dict, bull_to_criticality, levels)

    return {'report_text': report_text, 'report_dict': report_dict}

    
def get_text_vulnerability_report(target, os_data, report_dict, bull_to_criticality, levels):
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
        line.append(bul_id if '_no_advisory_' not in bul_id else 'no advisory')

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
    elif 'hostname' in os_data:
        target_id = target['hostname']
    elif 'inventory_file' in target:
        target_id = target['inventory_file']

    report_text = "Vulnerability Report for " + target_id + " (" + target['assessment_type'] \
                  + ", " + os_data["os_name"] + " " +  os_data["os_version"] + ", linux kernel " \
                  + str(os_data["linux_kernel"]) + ", " + str(len(os_data["package_list"])) \
                  + " packages)" + '\n'
    if len(bul_id_sorted_list) == 0:
        report_text += str(len(bul_id_sorted_list)) + " vulnerabilities were found\n"
    else:
        report_text += str(len(bul_id_sorted_list)) + " vulnerabilities with levels " \
                  + str(list(levels)) + " were found\n"

    if report_dict != dict():
        report_text += str(table)

    return report_text


def get_max_metrics(metrics):
    if not metrics:
        return {'score': 0, 'vector': ''}

    max_metric = max(metrics, key=lambda x: float(x.get('cvss', {}).get('score', 0)))
    if 'cvss' in max_metric:
        max_metric['cvss']['score'] = float(max_metric['cvss']['score'])
    else:
        max_metric['cvss'] = {'score': 0, 'vector': ''}

    return max_metric['cvss']


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
