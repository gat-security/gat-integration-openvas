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
from datetime import datetime


class Credential:
    def __init__(self, gat_url, gat_token, custom_parser_name):
        self.gat_url = gat_url
        self.gat_token = gat_token
        self.custom_parser_name = custom_parser_name

def get_reports_csv(gmp, report_ids, csv_results_id):
    qod_value = os.getenv('QOD', '30')
    for report_id in report_ids:
        # Chama a função get_report para cada ID com os parâmetros apropriados
        response = gmp.get_report(report_id,
                                  filter_string=f'apply_overrides=0 levels=hml min_qod={qod_value}',
                                  report_format_id=csv_results_id,
                                  ignore_pagination=True,  
                                  details=True) 

        # Converter a resposta em string XML
        report_xml_str = ElementTree.tostring(response, encoding='unicode')
        root = ElementTree.fromstring(report_xml_str)

        report_xml_str = report_xml_str.replace('</report_format>', '</report_format><csv>')
        report_xml_str = report_xml_str.replace('</report>', '</csv></report>')

        xml_file_path = f'/app/xmls/{report_id}.xml'
        with open(xml_file_path, 'w', encoding='utf-8') as xml_file:
            xml_file.write(report_xml_str)
            
        tree = ElementTree.parse(xml_file_path)
        root = tree.getroot()

        base64_contents = []
        # Iterar sobre todos os elementos para encontrar o conteúdo em base64
        for elem in root.iter('csv'):
            if elem.text:
                try:
                    decoded_content = base64.b64decode(elem.text).decode('utf-8')
                    base64_contents.append(decoded_content)
                except Exception as e:
                    print(f"Erro ao decodificar base64: {e}")

        # Salvar o conteúdo decodificado em um arquivo CSV
        csv_file_path = f'/app/csvs/{report_id}.csv'
        with open(csv_file_path, 'w', encoding='utf-8') as file:
            for content in base64_contents:
                file.write(content + '\n')    
        os.remove(xml_file_path)   
    
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
    today = datetime.now().strftime('%Y-%m-%d')
    url = f"https://epss.cyentia.com/epss_scores-{today}.csv.gz"
    filename_gz = f"epss_scores-{today}.csv.gz"
    filename_csv = f"epss_scores-{today}.csv"

    file_path_gz = os.path.join(output_folder, filename_gz)
    file_path_csv = os.path.join(output_folder, filename_csv)

    if os.path.exists(file_path_csv):
        print("Arquivo já existe. Download ignorado.")
        return file_path_csv

    print(f"Baixando o arquivo {filename_gz}")
    response = requests.get(url)
    response.raise_for_status()

    with open(file_path_gz, 'wb') as f:
        f.write(response.content)
    print("Download concluído.")

    print(f"Descompactando o arquivo {filename_gz} para {filename_csv}")
    with gzip.open(file_path_gz, 'rb') as f_in:
        with open(file_path_csv, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    print("Descompactação concluída.")

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
        custom_parser_name='gatscan'
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
                            csv_writer.writerow(['FERRAMENTA'] + csv_reader[0])
                        
                        for row in csv_reader[1:]:  # Exclui a linha de cabeçalho
                            if len(row) > 21 and any(field.strip() for field in row):
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
                                if row[12]:
                                    cve_list = row[12].split(',')
                                    cve = cve_list[0]
                                    if 'EPSS' in os.environ and cve in epss_data:
                                        epss_score = epss_data[cve]
                                        severity, tag = classify_severity(epss_score)
                                        #row[5] = severity
                                        row[14] = tag
                                csv_writer.writerow(['OpenVAS']+row)

                    print(f"Arquivo {filename} processado com sucesso.\n")
                    gat.upload_all_scan_files(credential, version, filename_without_extension, csv_path, os.path.join(csv_path, filename), on_premise, 1)
            # delete_reports(gmp, unique_report_ids)        
        print("Execução concluída.\n")

    except GvmError as e:
        print('An error occurred:', e, file=sys.stderr)

if __name__ == '__main__':
    main()