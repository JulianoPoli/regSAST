import re
import json
import os
import sys
from pathlib import Path
import time

FINDINGS = []
REPO_PATH = sys.argv[1]
bad_score = 0
BYPASS_EXT = ["jpg","png","xml","gitignore","pdf", "js", "yml"]

def read_file(file_path):
    meuArquivo = open(file_path, 'r', encoding='iso8859-1')
    file_full = meuArquivo.readlines()
    return file_full

def regex_run_analisy(file_full, path_report):
    global FINDINGS
    with open('roles/general.json','r') as file:
        role_dict = json.load(file)

    cont = 0
    while cont < len(file_full):
        file_line_filter = file_full[cont].replace('\n', '')
        cont_regex = 0
        while cont_regex < len(role_dict):
            regex = role_dict[cont_regex]["Regex"]
            try:
                re.compile(regex)
 
            except re.error:
                print(f"Non valid regex pattern: {regex}")
                exit()
            result = re.match(regex, file_line_filter)
            if result != None:
                FINDINGS.append([
                    role_dict[cont_regex]["Vuln_name"],
                    role_dict[cont_regex]["CWE"],
                    role_dict[cont_regex]["CVE"],
                    role_dict[cont_regex]["Score"],
                    file_line_filter,
                    path_report,
                    cont

                ])
            cont_regex += 1
        cont += 1

def path_filter():
    select_elegivel_path = []
    for p, _, files in os.walk(os.path.abspath(REPO_PATH)):
        for file_name in files:

            block_mode = True
            for formatb in BYPASS_EXT:
                if file_name.rfind(f'.{formatb}') != -1:
                    block_mode = True
                    break
                else:
                    block_mode = False
            if block_mode == False:
                select_elegivel_path.append(os.path.join(p, file_name))
    return select_elegivel_path

class Report():
    def __init__(self, severity, title, line, file_path, description, cweid, cveid):
        self.title = str(title)
        self.cwe = str(cweid)
        self.cve = str(cveid)
        self.severity = severity
        self.line = int(line+1)
        self.file_path = str(file_path)
        self.description = str(description)

def report_generic():
    global bad_score
    report = list()
    for finding in FINDINGS:
        report_object = Report(finding[3], finding[0], finding[6], {finding[5]}, {finding[4]}, {finding[1]}, {finding[2]})
        report.append(report_object.__dict__)
        final_report = {"findings": report}
        bad_score += float(finding[3])
    
    f = open('generic_report.json', 'w')
    f.write(json.dumps(final_report, indent=4))
    f.close()

select_elegivel_path = path_filter()
for i in select_elegivel_path:
    file_full = read_file(i)
    regex_run_analisy(file_full, i)

report_generic()

print("="*38 + f"\n[!] Finding {len(FINDINGS)} itens in {len(select_elegivel_path)} Paths")
print(f"[!] Project Bad Score: {int(bad_score)}\n"+"="*38)