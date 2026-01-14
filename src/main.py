import sys
import csv
import os
import time
import pytz
import base64
import gzip
import shutil
import requests
import gat_importer as gat
import xml.etree.ElementTree as ElementTree
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from datetime import datetime, date, timedelta
import re
import base64
from gvm.transforms import EtreeTransform

class Credential:
    def __init__(self, gat_url, gat_token, custom_parser_name):
        self.gat_url = gat_url
        self.gat_token = gat_token
        self.custom_parser_name = custom_parser_name

def extract_report_base64(xml_str: str) -> str | None:
    # pega o conteúdo entre </report_format> e <filters (ou </report>)
    m = re.search(r"</report_format>\s*([A-Za-z0-9+/=\s]+)\s*(?:<filters\b|</report>)", xml_str)
    if not m:
        return None
    b64 = re.sub(r"\s+", "", m.group(1))  # remove espaços e quebras
    return b64 if b64 else None

def get_reports_csv(gmp, report_ids, csv_results_id):
    qod_value = os.getenv("QOD", "0")

    for report_id in report_ids:
        resp = gmp.get_report(
            report_id,
            report_format_id=csv_results_id,
            filter_string=f"apply_overrides=0 min_qod={qod_value} first=1 rows=100000",
            ignore_pagination=True,
            details=True
        )

        xml_str = ElementTree.tostring(resp, encoding="unicode")
#         root = ElementTree.fromstring(xml_str)
#
#         result_count = root.findtext(".//report/result_count")
#         if not result_count or int(result_count) == 0:
#             print(f"[SKIP] Report {report_id}: sem resultados")
#             continue

        b64 = extract_report_base64(xml_str)
        if not b64:
           print(f"[WARN] Report {report_id}: base64 não encontrado no XML")
           print(xml_str)
           continue

        decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
        decoded = decoded.strip() + "\n"
        if decoded.count(chr(10)) == 1:
            print(f"[SKIP] Report {report_id}, com {decoded.count(chr(10))} resultados")
            continue
        csv_file_path = f"/app/csvs/{report_id}.csv"
        with open(csv_file_path, "w", encoding="utf-8", newline="") as f:
           f.write(decoded)

        print(f"[OK] Report {report_id}: bytes={len(decoded)} linhas={decoded.count(chr(10))}")

    
def delete_reports(gmp, report_ids):
    for report_id in report_ids:
        gmp.delete_report(report_id)     

def load_epss_data(epss_file):
    epss_data = {}
    with open(epss_file, 'r', encoding='utf-8') as file:
        next(file)
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            epss_data[row['cve']] = float(row['epss'])
    return epss_data

def classify_severity(epss):
    if epss < 0.10:
        return "Low", "EPSS < 10%"
    elif epss < 0.75:
        return "Medium", "EPSS > 10% e < 75%"
    elif epss < 0.90:
        return "High", "EPSS > 75% e < 90%"
    else:
        return "Critical", "EPSS > 90%"

def download_and_extract_epss_data(output_folder):
    os.makedirs(output_folder, exist_ok=True)

    today = date.today()

    # 1) tenta arquivos por data
    base_dated = "https://epss.cyentia.com"
    # 2) fallback final: arquivo mais recente (current)
    url_current = "https://epss.cyentia.com/epss_scores-current.csv.gz"

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; GAT-EPSS-Downloader/1.0)"
    }

    # tenta ontem até 4 dias atrás
    for i in range(1, 5):
        d = today - timedelta(days=i)
        filename_gz = f"epss_scores-{d:%Y-%m-%d}.csv.gz"
        filename_csv = f"epss_scores-{d:%Y-%m-%d}.csv"

        file_path_gz = os.path.join(output_folder, filename_gz)
        file_path_csv = os.path.join(output_folder, filename_csv)

        if os.path.exists(file_path_csv):
            print("Arquivo já existe. Download ignorado.")
            cleanup_files(output_folder, filename_csv)
            return file_path_csv

        url = f"{base_dated}/{filename_gz}"
        try:
            print(f"Baixando o arquivo {filename_gz}")
            r = requests.get(url, headers=headers, timeout=120, stream=True, allow_redirects=True)
            r.raise_for_status()

            with open(file_path_gz, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)

            print("Download concluído.")

            print(f"Descompactando o arquivo {filename_gz} para {filename_csv}")
            with gzip.open(file_path_gz, "rb") as f_in, open(file_path_csv, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            print("Descompactação concluída.")

            cleanup_files(output_folder, filename_csv)
            return file_path_csv

        except requests.HTTPError as e:
            # limpa gz parcial e tenta próxima data
            try:
                if os.path.exists(file_path_gz):
                    os.remove(file_path_gz)
            except:
                pass
            print(f"Falhou {filename_gz}: {e}. Tentando data anterior...")
            continue

    # fallback: current
    filename_gz = "epss_scores-current.csv.gz"
    filename_csv = "epss_scores-current.csv"
    file_path_gz = os.path.join(output_folder, filename_gz)
    file_path_csv = os.path.join(output_folder, filename_csv)

    print("Tentando fallback EPSS current (mais recente)")
    r = requests.get(url_current, headers=headers, timeout=120, stream=True, allow_redirects=True)
    r.raise_for_status()

    with open(file_path_gz, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)

    with gzip.open(file_path_gz, "rb") as f_in, open(file_path_csv, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)

    cleanup_files(output_folder, filename_csv)
    return file_path_csv

def cleanup_files(output_folder, keep_file):
    for file in os.listdir(output_folder):
        file_path = os.path.join(output_folder, file)
        if file != keep_file:
            os.remove(file_path)
            print(f"Removido: {file_path}")
    
def main():
    local_timezone = pytz.timezone(os.getenv('TIMEZONE', 'UTC'))
    today = datetime.now(local_timezone).strftime('%Y-%m-%d')
    
    epss_file_path = f'/app/epss/epss_scores-{today}.csv'
    if not os.path.exists(epss_file_path):
        print(f"Arquivo {epss_file_path} não encontrado. Baixando e extraindo dados EPSS.")
        os.makedirs('/app/epss', exist_ok=True)
        epss_file_path = download_and_extract_epss_data('/app/epss')
        time.sleep(10)    
        
    epss_data = {}
    if 'EPSS' in os.environ:
        epss_data = load_epss_data(epss_file_path)
  
    path = '/run/gvmd/gvmd.sock'
    connection = UnixSocketConnection(path=path)
    transform = EtreeCheckCommandTransform()

    username = os.getenv('OPENVAS_USERNAME')
    password = os.getenv('OPENVAS_PASSWORD')
    on_premise = os.getenv('ONPREMISE')

    csv_path = '/app/csvs/'
    
    credential = Credential(
        gat_url=os.getenv('GAT_URL'),
        gat_token=os.getenv('GAT_TOKEN'),
        custom_parser_name='OpenVAS'
    )
    version = "1.0"

    try:
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(username, password)
            formats = gmp.get_report_formats()
            for report_format in formats.findall('.//report_format'):
                name = report_format.find('name')
                if name is not None and name.text == 'CSV Results':
                    csv_results_id = report_format.get('id')
                    break 

            reports = gmp.get_reports(details=False, ignore_pagination=True)
            report_response_str = ElementTree.tostring(reports, encoding='unicode')
            
            root = ElementTree.fromstring(report_response_str)
            report_ids = []
            for report in root.findall('.//report'):
                scan_status = report.find('scan_run_status')
                if scan_status is not None and scan_status.text == 'Done':
                    report_ids.append(report.get('id'))
            unique_report_ids = list(set(report_ids))
            
            get_reports_csv(gmp, unique_report_ids, csv_results_id)
                                    
            for filename in os.listdir(csv_path):
                if filename.endswith('.csv'):
                    file_path = os.path.join(csv_path, filename)
                    print(f"Processando o arquivo: {filename}")
                    filename_without_extension = os.path.splitext(filename)[0]

                    with open(file_path, 'r', encoding='utf-8') as file_input:
                        csv_reader = list(csv.reader(file_input))
                    
                    with open(file_path, 'w', newline='', encoding='utf-8') as file_output:
                        csv_writer = csv.writer(file_output)
                        
                        if csv_reader:
                            original_header = csv_reader[0]
                            original_header[18] = "RECOMENDATION"
                            original_header[19] = "MITIGATION"
                            original_header[20] = "TEST"

                            cve_headers = ["CVE_LIST"] * 25

                            # ✅ 25 pares alternados: TITLE_REFERENCE, URL_REFERENCE, ...
                            ref_headers = []
                            for _ in range(25):
                                ref_headers += ["TITLE_REFERENCE", "URL_REFERENCE"]


                            header = (
                                ["FERRAMENTA"]
                                + original_header[:12]
                                + cve_headers
                                + ["EPSS", "DESCRIPTION"]
                                + original_header[13:18]  # C14..C18

                                + ["TITLE_RECOMENDATION"] + [original_header[18]]  # C19
                                + ["TITLE_MITIGATION"]   + [original_header[19]]   # C20

                                # seus 3 TEST (C21/C22/C23)
                                + ["TITLE_TEST"] + [original_header[20]]
                                + ["TITLE_TEST"] + [original_header[20]]
                                + ["TITLE_TEST"] + [original_header[20]]

                                # ✅ antes da C24 (index 23)
                                + ref_headers

                                + original_header[23:]  # C24 em diante (mantém a C24 original e o resto)
                            )

                            csv_writer.writerow(header)


                        for row in csv_reader[1:]:
                            if any(field.strip() for field in row):

                                # ✅ agora precisa ter pelo menos 24 colunas (índice 23)
                                if len(row) < 24:
                                    row = row + [""] * (24 - len(row))

                                if str(row[5]).strip() == "Log":
                                    row[5] = "INFO"

                                impact_info = f"<br/><br/>Impact: {row[17]}" if row[17] else ""
                                vulnerability_insights = f"<br/><br/>Vulnerability Insights: {row[20]}" if row[20] else ""
                                vulnerability_method = f"<br/><br/>Vulnerability Detection Method: {row[21]}" if row[21] else ""
                                row[9] = f"{row[9]}{impact_info}{vulnerability_insights}{vulnerability_method}"

                                row.append(row[18])
                                row[14] = ''
                                if not row[2]:
                                    row[2] = 0
                                if not row[3]:
                                    row[3] = 'tcp'

                                # garante mínimo pro seu acesso até row[22] também
                                if len(row) < 24:
                                    row = row + [""] * (24 - len(row))

                                description = "\n".join(x for x in [row[9], row[10], row[17]] if str(x).strip())

                                title_recomendation = row[18][:100] if row[18] else ""
                                title_mitigation   = row[19][:100] if row[19] else ""
                                title_test_c20 = row[20][:100] if row[20] else ""
                                title_test_c21 = row[21][:100] if row[21] else ""
                                title_test_c22 = row[22][:100] if row[22] else ""

                                # CVEs
                                cves_raw = row[12] if len(row) > 12 else ""
                                cve_list = [c.strip() for c in cves_raw.split(",") if c.strip()]
                                cve_cols = (cve_list + [""] * 25)[:25]
                                cve_0 = cve_cols[0]

                                epss_score = ""
                                if ('EPSS' in os.environ) and cve_0 and (cve_0 in epss_data):
                                    epss_score = epss_data[cve_0]

                                # ✅ C24 split (index 23)
                                refs_raw = row[24] if len(row) > 24 else ""
                                refs_list = [r.strip() for r in refs_raw.split(",") if r.strip()]

                                ref_pairs = []
                                for i in range(25):
                                    v = refs_list[i] if i < len(refs_list) else ""
                                    ref_pairs += [v, v]

                                # ✅ monta linha final inserindo 50 colunas antes da C24 original
                                row = (
                                    row[:12]
                                    + cve_cols
                                    + [epss_score, description]
                                    + row[13:18]
                                    + [title_recomendation, row[18]]
                                    + [title_mitigation,   row[19]]
                                    + [title_test_c20,     row[20]]
                                    + [title_test_c21,     row[21]]
                                    + [title_test_c22,     row[22]]

                                    + ref_pairs             # ✅ alternado

                                    + row[23:]              # mantém C24 original e resto
                                )

                                csv_writer.writerow(["OpenVAS"] + row)


                    print(f"Arquivo {filename} processado com sucesso.\n")
                    gat.upload_all_scan_files(credential, version, filename_without_extension, csv_path, os.path.join(csv_path, filename), on_premise, 1)
            # delete_reports(gmp, unique_report_ids)        
        print("Execução concluída.\n")

    except GvmError as e:
        print('An error occurred:', e, file=sys.stderr)

if __name__ == '__main__':
    main()