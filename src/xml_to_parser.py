import base64
import os
import json
import csv
import requests
import math
from datetime import datetime


CSVS_PATH = '../csvs'
LOG_FILE = '/shared/logs.txt'

def log_message(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = '[{}] {}'.format(timestamp, message)
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(log_entry + '\n')
    print(log_entry)
        

def openvas_risk_to_gat_risk(risk):
    if risk < 0 or risk > 10:
        raise ValueError('Risk severity inválido: {}. Necessário ser entre 0 e 10.'.format(risk))
    else:
        return math.trunc((risk / 10) * 4 + 1)


def json_to_csv(json_path):
    with open(json_path, 'r') as json_file:
        data = json.load(json_file)

    csv_filename = os.path.splitext(os.path.basename(json_path))[0] + '.csv'

    with open(os.path.join(CSVS_PATH, csv_filename), 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)

        csv_header = ['description', 'service_name', 'vulnerability_name', 'vulnerability_severity',
                      'vulnerability_severity_str', 'vulnerability_type', 'vulnerability_url', 'titulo_referencia',
                      'ip', 'port']

        csv_writer.writerow(csv_header)

        for key, value in data['vulnerable'].items():
            for ips_key, ips_ports in value['locations'].items():
                for port in ips_ports:
                    for vulnerability in value['vulnerabilities']:
                        csv_rows = []

                        description = vulnerability['description']
                        vulnerability_name = vulnerability['name']
                        vulnerability_severity = flan_risk_to_gat_risk(vulnerability['severity'])
                        vulnerability_severity_str = vulnerability['severity_str']
                        vulnerability_type = vulnerability['type']
                        vulnerability_url = vulnerability['url']
                        titulo_referencia = vulnerability['url']

                        csv_rows.append(
                            [description, key, vulnerability_name, vulnerability_severity, vulnerability_severity_str,
                             vulnerability_type, vulnerability_url, titulo_referencia, ips_key, port])

                        csv_writer.writerows(csv_rows)

    return os.path.join(CSVS_PATH, csv_filename)


def parse_json(files_path):
    if not os.path.exists(CSVS_PATH):
        os.makedirs(CSVS_PATH)

    parsed_files = {}

    for root, _, files in os.walk(files_path):
        for filename in files:
            if filename.endswith('.json'):
                json_path = os.path.join(root, filename)
                csv_filename = json_to_csv(json_path)
                parsed_files[filename] = [
                    json_path,
                    csv_filename
                ]

    return parsed_files


def get_api_url(gat_api_host, custom_parser_name):
    if "localhost" in gat_api_host:
        return "http://{}/vulnerability/upload/api/{}".format(gat_api_host, custom_parser_name)
    else:
        return "https://{}/app/vulnerability/upload/api/{}".format(gat_api_host, custom_parser_name)


def send_to_gat_api(parsed_files, gat_api_host, gat_api_key, custom_parser_name, delete_source):
    gat_api_full_url = get_api_url(gat_api_host, custom_parser_name)
    gat_api_key = base64.b64decode(gat_api_key).decode()
    
    headers = {
        'Authorization': 'Bearer ' + gat_api_key,
        'cache-control': 'no-cache'
    }
    for key, value in parsed_files.items():
        # [0] => Arquivo JSON
        # [1] => Arquivo CSV
        with open(value[1], 'r') as csv_file:
            lines = csv_file.readlines()
            if len(lines) <= 1:
                log_message('CSV {} contém apenas o cabeçalho ou está vazio. Ignorando envio.'.format(value[1]))
                if delete_source:
                    os.remove(value[0])
                os.remove(value[1])
                continue
        
        with open(value[1], 'rb') as csv_file:
            file_dict = {'file': (os.path.basename(value[1]), csv_file, "text/csv", {'Expires': "0"})}
            try:
                
                response = requests.post(gat_api_full_url, headers=headers, files=file_dict)

                if response.status_code == 200:
                    log_message('CSV {} enviado com sucesso para a API do GAT Core.'.format(value[1]))
                    if delete_source:
                        os.remove(value[0])
                    os.remove(value[1])
                else:
                    log_message('Erro ao enviar o CSV {} para a API do GAT. Status code: {}'.format(value[1], response.status_code))
            except Exception as e:
                log_message('Erro ao enviar o CSV {} para a API do GAT. Exception: {}'.format(value[1], e))
