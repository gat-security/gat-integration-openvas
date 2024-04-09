import sys
import csv
import re
import os
import xml.etree.ElementTree as ElementTree
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
import GATimporter as gat

class Credential:
    def __init__(self, gat_url, gat_token, custom_parser_name):
        self.gat_url = gat_url
        self.gat_token = gat_token
        self.custom_parser_name = custom_parser_name

#Substitui aspas duplas por aspas simples em um campo.
def troca_aspas(field):
    return field.replace('"', "'") if field else ''

#Extrai os títulos e URLs das referências, garantindo que as URLs sejam válidas.
def extrai_referencias(references):
    ref_data = []
    for i in range(16):
        if i < len(references):
            ref_title = troca_aspas(references[i].get('id'))
            ref_url = troca_aspas(references[i].get('type'))
            if ref_url.startswith('http://') or ref_url.startswith('https://'):
                ref_data.extend([ref_title, ref_url])
            else:
                ref_data.extend(['', ''])
        else:
            ref_data.extend(['', ''])
    return ref_data

def main():
    path = '/run/gvmd/gvmd.sock'
    connection = UnixSocketConnection(path=path)
    transform = EtreeCheckCommandTransform()

    username = os.getenv('OPENVAS_USERNAME')
    password = os.getenv('OPENVAS_PASSWORD')
    isOnpremise = os.getenv('ONPREMISE')

    csv_path = '/app/csvs/'
    csv_filename = 'report.csv'
    
    xml_file_path = '/app/xmls/report.xml'
    csv_file_path = csv_path+csv_filename

    csv_header = ["address", "port", "protocol", "os", "certainty", "test_status", "id", "title", "severity", "cvssScore",
                  "malware", "exploit_id", "exploit_title", "published", "added", "modified", "riskScore", "description",
                  "tags", "solution", "hostname", "netbios", "root_cause"]
    for i in range(1, 17):
        csv_header.extend([f"REFERENCE TITLE {i}", f"REFERENCE URL {i}"])

    try:
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(username, password)
            reports = gmp.get_reports(details=True)
            report_response_str = ElementTree.tostring(reports, encoding='unicode')

            with open(xml_file_path, 'w', encoding='utf-8') as xml_file:
                xml_file.write(report_response_str)

            tree = ElementTree.parse(xml_file_path)
            root = tree.getroot()

            with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
                csv_writer = csv.writer(csv_file, delimiter=';', quoting=csv.QUOTE_ALL)
                csv_writer.writerow(csv_header)

                for result in root.findall('.//result'):
                    port_protocol = result.find('port').text.split('/')
                    port = port_protocol[0] if len(port_protocol) > 0 else ''
                    protocol = port_protocol[1].upper() if len(port_protocol) > 1 else ''
                    row = [
                        result.find('host').text,
                        port,
                        protocol,
                        '',
                        '',
                        '',
                        result.find('nvt').get('oid'),
                        result.find('nvt/name').text,
                        result.find('severity').text,
                        result.find('nvt/cvss_base').text if result.find('nvt/cvss_base') is not None else '',
                        '',
                        '',
                        '',
                        '',
                        result.find('creation_time').text,
                        result.find('modification_time').text,
                        '',
                        troca_aspas(result.find('nvt/tags').text),
                        '',
                        result.find('nvt/solution').text if result.find('nvt/solution') is not None else '',
                        result.find('host/hostname').text if result.find('host/hostname') is not None else '',
                        '',
                        ''
                    ]
                    row.extend(extrai_referencias(result.findall('nvt/refs/ref')))
                    csv_writer.writerow(row)
                    
        credential = Credential(
            gat_url=os.getenv('GAT_URL'),
            gat_token=os.getenv('GAT_TOKEN'),
            custom_parser_name=csv_filename
        )
        version = "2.0"

        gat.upload_all_scan_files(credential, version, csv_filename, csv_path, csv_file_path, isOnpremise, 1)

        print("success")

    except GvmError as e:
        print('An error occurred:', e, file=sys.stderr)

if __name__ == '__main__':
    main()
