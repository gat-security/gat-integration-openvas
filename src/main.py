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

# Header fixo do CSV (global)
FIXED_HEADER = [
    "FERRAMENTA", "IP", "Hostname", "Port", "Port Protocol", "CVSS", "Severity", "QoD",
    "Solution Type", "NVT Name", "Summary", "Specific Result", "NVT OID",
    "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST",
    "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST",
    "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST", "CVE_LIST",
    "CVE_LIST", "CVE_LIST", "CVE_LIST",
    "EPSS", "DESCRIPTION", "Task ID", "Task Name", "Timestamp", "Result ID", "Impact",
    "TITLE_RECOMENDATION", "RECOMENDATION", "TITLE_MITIGATION", "MITIGATION",
    "TITLE_TEST", "TEST", "TITLE_TEST", "TEST", "TITLE_TEST", "TEST",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE", "TITLE_REFERENCE", "URL_REFERENCE",
    "TITLE_REFERENCE", "URL_REFERENCE",
    "BIDs", "CERTs", "Other References"
]

# número de colunas do "out" (sem a coluna FERRAMENTA)
TOTAL_OUT_COLS = len(FIXED_HEADER) - 1

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

def get_reports_csv(gmp, report_ids, csv_results_id, csv_output_path):
    qod_value = os.getenv("QOD", "0")

    # Array para armazenar caminhos dos CSVs gerados
    generated_csv_paths = []

    # Criar subdiretório com o timestamp
    os.makedirs(csv_output_path, exist_ok=True)

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
        csv_file_path = f"{csv_output_path}/{report_id}.csv"
        with open(csv_file_path, "w", encoding="utf-8", newline="") as f:
           f.write(decoded)

        print(f"[OK] Report {report_id}: bytes={len(decoded)} linhas={decoded.count(chr(10))}")

        # Adicionar caminho ao array
        generated_csv_paths.append(csv_file_path)

    return generated_csv_paths

    
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

def get_last_import_date(file_path='/app/reports_last_import_date'):
    """
    Lê a data da última importação do arquivo.
    Se o arquivo não existir, cria um com a data de hoje - 1 dia (UTC).

    Args:
        file_path (str): Caminho do arquivo com a data da última importação

    Returns:
        datetime: Data da última importação em UTC
    """
    if os.path.exists(file_path):
        # Ler data do arquivo existente
        with open(file_path, 'r', encoding='utf-8') as f:
            date_str = f.read().strip()
            try:
                last_import_date = datetime.fromisoformat(date_str)
                print(f"Data da última importação lida: {last_import_date}")
                return last_import_date
            except ValueError:
                print(f"Erro ao parsear data do arquivo: {date_str}")
                last_import_date = datetime.now(pytz.UTC) - timedelta(days=1)
                return last_import_date
    else:
        # Criar arquivo com data de hoje - 1 dia (UTC)
        last_import_date = datetime.now(pytz.UTC) - timedelta(days=1)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(last_import_date.isoformat())
        print(f"Arquivo '{file_path}' criado com data: {last_import_date}")
        return last_import_date

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

def clip100(s: str) -> str:
    s = "" if s is None else str(s)
    return s[:100]

def safe_str(v) -> str:
    return "" if v is None else str(v)

def split_csv_list(raw: str) -> list[str]:
    if not raw:
        return []
    return [x.strip() for x in str(raw).split(",") if x.strip()]

def build_out_row_from_openvas_src(
    src: list[str],
    epss_data: dict,
    epss_enabled: bool
) -> list[str]:

    if src is None:
        src = []
    src = [safe_str(x) for x in src]


    # =============== Normalizações do que você já fazia ===============
    # Severity "Log" vira "INFO"
    severity = src[5].strip() if len(src) > 5 else ""
    if severity == "Log":
        severity = "INFO"

    # Port default
    port = src[2].strip() if len(src) > 2 else ""
    if not port:
        port = "0"

    protocol = src[3].strip() if len(src) > 3 else ""
    if not protocol:
        protocol = "tcp"

    # montar descrição (Summary + Specific Result + Impact) como você fazia
    summary = src[9] if len(src) > 9 else ""
    specific_result = src[10] if len(src) > 10 else ""
    impact_text = src[17] if len(src) > 17 else ""
    description = "\n".join(x for x in [summary, specific_result, impact_text] if str(x).strip())

    # adicionar (Impact/Insights/Method) no summary (igual seu código)
    vulnerability_insights = f"<br/><br/>Vulnerability Insights: {src[20]}" if len(src) > 20 and src[20] else ""
    vulnerability_method   = f"<br/><br/>Vulnerability Detection Method: {src[21]}" if len(src) > 21 and src[21] else ""
    impact_info            = f"<br/><br/>Impact: {impact_text}" if impact_text else ""
    summary_augmented = f"{summary}{impact_info}{vulnerability_insights}{vulnerability_method}"

    # CVEs em 25 colunas (seu header tem 25 CVE_LIST repetidos)
    cves_raw = src[12] if len(src) > 12 else ""
    cve_list = split_csv_list(cves_raw)
    cve_cols = (cve_list + [""] * 25)[:25]
    cve_0 = cve_cols[0]

    # EPSS usando o primeiro CVE
    epss_score = ""
    if epss_enabled and cve_0 and cve_0 in epss_data:
        epss_score = epss_data[cve_0]

    # References em 25 pares (TITLE, URL) => 50 colunas
    refs_raw = src[24] if len(src) > 24 else ""
    refs_list = split_csv_list(refs_raw)
    ref_pairs: list[str] = []
    for idx in range(25):
        v = refs_list[idx] if idx < len(refs_list) else ""
        # title=url=mesmo valor (seu padrão)
        ref_pairs.extend([v, v])

    # Titles truncados 100
    recommendation = src[18] if len(src) > 18 else ""
    mitigation     = src[19] if len(src) > 19 else ""
    test20         = src[20] if len(src) > 20 else ""
    test21         = src[21] if len(src) > 21 else ""
    test22         = src[22] if len(src) > 22 else ""

    title_recommendation = clip100(recommendation)
    title_mitigation     = clip100(mitigation)
    title_test_c20       = clip100(test20)
    title_test_c21       = clip100(test21)
    title_test_c22       = clip100(test22)

    # =============== Preenchimento determinístico conforme FIXED_HEADER ===============
    # FIXED_HEADER:
    #  0  FERRAMENTA (fora)
    #  1  IP
    #  2  Hostname
    #  3  Port
    #  4  Port Protocol
    #  5  CVSS
    #  6  Severity
    #  7  QoD
    #  8  Solution Type
    #  9  NVT Name
    # 10  Summary
    # 11  Specific Result
    # 12  NVT OID
    # 13..37 CVE_LIST (25)
    # 38 EPSS
    # 39 DESCRIPTION
    # 40 Task ID
    # 41 Task Name
    # 42 Timestamp
    # 43 Result ID
    # 44 Impact
    # 45 TITLE_RECOMENDATION
    # 46 RECOMENDATION
    # 47 TITLE_MITIGATION
    # 48 MITIGATION
    # 49 TITLE_TEST
    # 50 TEST
    # 51 TITLE_TEST
    # 52 TEST
    # 53 TITLE_TEST
    # 54 TEST
    # 55..104 (50 cols) References (25 pares)
    # 105 BIDs
    # 106 CERTs
    # 107 Other References
    out = [""] * len(FIXED_HEADER)
    out[0] = (src[0].strip() if len(src) > 0 else "")  # IP
    out[1] = (src[1].strip() if len(src) > 1 else "")  # Hostname
    out[2] = port                                     # Port
    out[3] = protocol                                 # Port Protocol
    out[4] = (src[4].strip() if len(src) > 4 else "")  # CVSS (ajuste se seu CSV não tiver aqui)
    out[5] = severity                                  # Severity
    out[6] = (src[6].strip() if len(src) > 6 else "")  # QoD
    out[7] = (src[7].strip() if len(src) > 7 else "")  # Solution Type
    out[8] = (src[8].strip() if len(src) > 8 else "")  # NVT Name
    out[9] = summary_augmented                         # Summary
    out[10] = specific_result                          # Specific Result
    out[11] = (src[11].strip() if len(src) > 11 else "") # NVT OID

    # CVE_LIST 25 colunas: out[12..36]
    base_cve_idx = 12
    for k in range(25):
        out[base_cve_idx + k] = cve_cols[k]

    # EPSS, DESCRIPTION
    out[37] = safe_str(epss_score)    # EPSS
    out[38] = description             # DESCRIPTION

    # Task ID..Impact (5 colunas)
    # No seu slice antigo era row[13:18] => 5 colunas.
    # Aqui vou manter src[13..17] por compatibilidade com o que você fazia.
    out[39] = (src[13].strip() if len(src) > 13 else "")  # Task ID
    out[40] = (src[14].strip() if len(src) > 14 else "")  # Task Name
    out[41] = (src[15].strip() if len(src) > 15 else "")  # Timestamp
    out[42] = (src[16].strip() if len(src) > 16 else "")  # Result ID
    out[43] = impact_text                                  # Impact

    # Recommendation / mitigation / tests (cada um title + conteúdo)
    out[44] = title_recommendation
    out[45] = recommendation
    out[46] = title_mitigation
    out[47] = mitigation

    out[48] = title_test_c20
    out[49] = test20
    out[50] = title_test_c21
    out[51] = test21
    out[52] = title_test_c22
    out[53] = test22

    # References: 25 pares => 50 cols
    # começam em out[54] até out[103]
    ref_start = FIXED_HEADER.index("TITLE_REFERENCE")
    needed = ref_start + len(ref_pairs)  # 54 + 50 = 104
    if len(out) < needed:
        out.extend([""] * (needed - len(out)))
    for k in range(50):
        out[ref_start + k] = ref_pairs[k]
    assert len(out) == len(FIXED_HEADER), f"out={len(out)} header={len(FIXED_HEADER)} header={FIXED_HEADER}"
    # Últimos: BIDs, CERTs, Other References
    # Você tem no header, mas seu CSV de entrada pode ou não ter essas infos.
    # Ajuste os índices conforme seu CSV real.
    out[104] = (src[25].strip() if len(src) > 25 else "")  # BIDs
    out[105] = (src[26].strip() if len(src) > 26 else "")  # CERTs
    out[106] = (src[27].strip() if len(src) > 27 else "")  # Other References

    # Garantia final de tamanho
    if len(out) != TOTAL_OUT_COLS:
        raise Exception(f"out row size mismatch: {len(out)} != {TOTAL_OUT_COLS}")

    return out

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
            print(f"Total de reports encontrados: {len(reports.findall('.//report'))}")
            
            root = ElementTree.fromstring(report_response_str)

            # Obter data da última importação
            reports_last_import_date = get_last_import_date()

            report_ids = []
            for report in root.findall('.//report'):
                report_ids.append(report.get('id'))
                scan_status = report.find('scan_run_status')
                report_scan_end_datetime = report.find('scan_end')

                # Verificar se status é 'Done' E se a data de término é posterior à última importação
                if scan_status is not None and scan_status.text == 'Done':
                    if report_scan_end_datetime is not None and report_scan_end_datetime.text:
                        try:
                            # Parse da data de término do scan
                            scan_end_dt = datetime.fromisoformat(report_scan_end_datetime.text.replace('Z', '+00:00'))

                            # Comparar com a data da última importação
                            if scan_end_dt > reports_last_import_date:
                                report_ids.append(report.get('id'))
                                print(f"  -> Relatório incluído (data {scan_end_dt} > {reports_last_import_date})")
                            else:
                                print(f"  -> Relatório ignorado (data {scan_end_dt} <= {reports_last_import_date})")
                        except ValueError as e:
                            print(f"  -> Erro ao parsear data do scan: {report_scan_end_datetime.text} - {e}")
                    else:
                        print(f"  -> Relatório sem data de término, adicionado por padrão")
                        report_ids.append(report.get('id'))
            unique_report_ids = list(set(report_ids))
            print(f"Total de reports únicos com status 'Done': {len(unique_report_ids)}")

            # Gerar timestamp para o subdiretório
            generation_timestamp = datetime.now(local_timezone).strftime('%Y%m%d_%H%M%S')
            csv_path = '/app/csvs/{}'.format(generation_timestamp)
            reports_csv_paths = get_reports_csv(gmp, unique_report_ids, csv_results_id, csv_path)
            print(f"Total de CSVs gerados: {len(reports_csv_paths)}")

            # Dicionário para mapear/contar registros por chave (primeira coluna)
            # Estrutura: { "target/IP": { "count": N, "file_number": M } }
            target_counts = {}
            # MOCK DATA PARA TESTES - Comentar para usar dados reais dos CSVs
            # target_counts = {
            #     "127.0.0.1": {"count": 7000, "file_number": 0},
            #     "127.0.0.2": {"count": 2000, "file_number": 0},
            #     "127.0.0.3": {"count": 2500, "file_number": 0},
            #     "127.0.0.4": {"count": 1000, "file_number": 0},
            #     "127.0.0.5": {"count": 4500, "file_number": 0},
            # }
            max_targets_per_file = 5000

            for file_path in reports_csv_paths:
                print(f"Processando o arquivo: {file_path}")

                with open(file_path, 'r', encoding='utf-8') as file_input:
                    csv_reader = list(csv.reader(file_input))

                for row in csv_reader[1:]:
                    if any(field.strip() for field in row):
                        # Extrai a chave (IP/target) da primeira coluna
                        key = row[0].strip() if row else ""
                        if key:
                            if key not in target_counts:
                                target_counts[key] = {
                                    "count": 0,
                                    "file_number": 0
                                }
                            target_counts[key]["count"] += 1

            # Determinar quantos arquivos serão necessários para cada target/IP com base no limite máximo
            # Todos os registros de um mesmo target/IP devem ser agrupados, mesmo que ultrapasse o total de 5000 registros, para evitar fragmentação dos dados. O número do arquivo é incrementado apenas quando um novo target/IP é processado e o limite for ser atingido
            # Exemplo 1: Se um target/IP tiver 12000 registros, ele será processado em um único arquivo (file_number = 0) para manter os dados agrupados, mesmo que ultrapasse o limite de 5000 registros. O próximo target/IP começará a ser processado no próximo arquivo (file_number = 1).
            # Exemplo 2: Se um target/IP tiver 3000 registros, ele será processado em um único arquivo (file_number = 0) e o próximo target/IP começará a ser processado no mesmo arquivo (file_number = 0) até que o total de registros atinja o limite de 5000. Quando o limite for atingido, o próximo target/IP
            # Exemplo 3: Se um target/IP tiver 4000 registros e o próximo target/IP tiver 2000 registros, eles serão colocados em arquivos diferentes pois o limite será ultrapassado
            # Calcular file_number para cada target/IP
            current_file_number = 0
            records_in_current_file = 0

            # Ordenar targets por contagem decrescente (maiores primeiro - First Fit Decreasing)
            sorted_targets = sorted(target_counts.items(), key=lambda x: x[1]["count"], reverse=True)

            for target_key, target_info in sorted_targets:
                target_record_count = target_info["count"]

                # Verificar se adicionar este target ultrapassaria o limite
                if records_in_current_file + target_record_count > max_targets_per_file and records_in_current_file > 0:
                    # Incrementar para próximo arquivo
                    current_file_number += 1
                    records_in_current_file = 0

                # Atribuir file_number ao target
                target_counts[target_key]["file_number"] = current_file_number

                # Adicionar contagem ao arquivo atual
                records_in_current_file += target_record_count

            # Criar e inicializar arquivos de saída com headers
            output_files = {}
            max_file_number = max([target_counts[key]["file_number"] for key in target_counts], default=0)

            for file_num in range(max_file_number + 1):
                output_filename = f'openvas_{generation_timestamp}_{file_num}.csv'
                output_path = f'{csv_path}/{output_filename}'
                output_files[file_num] = {
                    'path': output_path,
                    'filename': output_filename,
                    'writer': None,
                    'file_handle': open(output_path, 'w', newline='', encoding='utf-8')
                }
                csv_writer = csv.writer(output_files[file_num]['file_handle'])
                csv_writer.writerow(FIXED_HEADER)
                output_files[file_num]['writer'] = csv_writer

            # Processar arquivos de entrada (relatórios)
            for file_path in reports_csv_paths:
                print(f"Processando o report: {file_path}")

                with open(file_path, 'r', encoding='utf-8') as file_input:
                    csv_reader = list(csv.reader(file_input))

                # Processar dados
                for row in csv_reader[1:]:
                    if any(field.strip() for field in row):
                        # Obter IP (primeira coluna) para determinar o arquivo de saída
                        target_ip = row[0].strip() if row else ""

                        # Se o IP não está em target_counts, pular
                        if target_ip not in target_counts:
                            continue

                        output_file_number = target_counts[target_ip]["file_number"]

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

                        refs_raw = row[24] if len(row) > 24 else ""
                        refs_list = [r.strip() for r in refs_raw.split(",") if r.strip()]

                        ref_pairs = []
                        for i in range(25):
                            v = refs_list[i] if i < len(refs_list) else ""
                            ref_pairs += [v, v]

                        src = row[:]  # snapshot do input (antes de qualquer alteração)

                        epss_enabled = ('EPSS' in os.environ)
                        out = build_out_row_from_openvas_src(src, epss_data, epss_enabled)

                        output_files[output_file_number]['writer'].writerow(["OpenVAS"] + out)


                print(f"Report {file_path} processado com sucesso.\n")

            # Fechar todos os arquivos de saída
            for file_num in output_files:
                output_files[file_num]['file_handle'].close()
                print(f"Arquivo de saída {output_files[file_num]['filename']} finalizado.")

                filename_without_extension = os.path.splitext(os.path.basename(output_files[file_num]['path']))[0]
                print(f"Enviando {output_files[file_num]['path']} para GAT...")
                gat.upload_all_scan_files(credential, version, filename_without_extension, csv_path, output_files[file_num]['path'], on_premise, 1)

            # Atualizar o arquivo reports_last_import_date com o timestamp atual
            with open('/app/reports_last_import_date', 'w', encoding='utf-8') as f:
                f.write(datetime.now(pytz.UTC).isoformat())

        # Deletar o csv_path e o conteúdo
        # Vamos manter por enquanto para análise e debug, mas a intenção é limpar após o envio para o GAT
        # shutil.rmtree(csv_path)

        gmp.authenticate(username, password)
        delete_reports(gmp, unique_report_ids)
        print("Execução concluída.\n")

    except GvmError as e:
        print('An error occurred:', e, file=sys.stderr)

if __name__ == '__main__':
    main()