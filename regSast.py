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
            result = re.match(f'{role_dict[cont_regex]["Regex"]}', file_line_filter)
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

select_elegivel_path = path_filter()
for i in select_elegivel_path:
    file_full = read_file(i)
    regex_run_analisy(file_full, i)

for finding in FINDINGS:
    print(f"[!] Find item: {finding[0]} - {finding[1]}")
    print(f"--> Info: {finding[4]}"[0:250]+"...")
    print(f"--> Line: {finding[6]}")
    print(f"--> Path: {finding[5]}\n")
    bad_score += float(finding[3])
print(f"[!] Finding {len(FINDINGS)} in {len(select_elegivel_path)} Paths")
print(f"[!] Project Bad Score: {int(bad_score)}")