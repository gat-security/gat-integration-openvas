import sys
import csv
import re
import os
import pytz
import xml.etree.ElementTree as ElementTree
from icalendar import Calendar, Event
from datetime import datetime
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from sync_hosts_from_assets import sync_hosts_from_assets

def generate_ical(schedule_type, schedule_date, schedule_time, timezone):
    cal = Calendar()
    cal.add('prodid', '-//OpenVAS Schedule//')
    cal.add('version', '2.0')

    tz = pytz.timezone(timezone)
    event = Event()
    event.add('dtstamp', datetime.now(tz=pytz.UTC))

    # Converter a data e o horário da primeira execução para um objeto datetime com o timezone especificado
    first_datetime = datetime.strptime(f"{schedule_date} {schedule_time}", '%Y-%m-%d %H:%M')
    first_datetime = tz.localize(first_datetime)
    event.add('dtstart', first_datetime.astimezone(pytz.utc))

    # Adicionar recorrência com base no tipo de agendamento
    if schedule_type != 'Once':
        event.add('rrule', {'freq': schedule_type.upper(), 'interval': 1})

    cal.add_component(event)

    return cal.to_ical().decode('utf-8')


def get_scanner_id(gmp):
    # Substitua 'OpenVAS Default' pelo nome do seu scanner, se necessário
    scanners_response = gmp.get_scanners()
    for scanner in scanners_response.findall('scanner'):
        if scanner.find('name').text == 'OpenVAS Default':
            return scanner.get('id')
    return None

def get_config_id(gmp, config_name='Full and fast'):
    configs_response = gmp.get_scan_configs()
    for config in configs_response.findall('config'):
        if config.find('name').text == config_name:
            return config.get('id')
    return None

def get_schedule_id(gmp, schedule_type, schedule_date, schedule_time):
    timezone = os.getenv('TIMEZONE', 'UTC')
    ical_data = generate_ical(schedule_type, schedule_date, schedule_time, timezone)
    name = f"Schedule {schedule_type} at {schedule_time} on {schedule_date} ({timezone})"
    
    schedules_response = gmp.get_schedules()
    for schedule in schedules_response.findall('schedule'):
        if schedule.find('name').text == name:
            print(f"Agendamento '{name}' já existe. ID: {schedule.get('id')}")
            return schedule.get('id')
        
    schedule_response = gmp.create_schedule(
        name=f"Schedule {schedule_type} at {schedule_time} on {schedule_date} ({timezone})",
        icalendar=ical_data,
        timezone=timezone
    )
    print(f"Agendamento '{name}' criado com sucesso. ID: {schedule_response.get('id')}")
    return schedule_response.get('id')

def normalize_host_name(host: str) -> str:
    return host.replace("/", "_").replace(":", "_")

def build_task_name(host):
    return f"GAT-Scan-{host}"

def create_target(gmp, host):
    target_name = f"GAT-{normalize_host_name(host)}"

    targets_response = gmp.get_targets()
    for target in targets_response.findall('target'):
        name_el = target.find('name')
        hosts_el = target.find('hosts')

        if name_el is not None and name_el.text == target_name:
            print(f"Target já existe: {target_name}")
            return target.get('id')

        # segurança extra: mesmo host
        if hosts_el is not None and host in hosts_el.text.split(','):
            print(f"Target com host {host} já existe")
            return target.get('id')

    target_response = gmp.create_target(
        name=target_name,
        hosts=[host],
        port_range='1-65000'
    )

    print(f"Target criado: {target_name}")
    return target_response.get('id')

def create_task(gmp, host, target_id, config_id, scanner_id, schedule_id):
    task_name = build_task_name(host)

    tasks_response = gmp.get_tasks()
    for task in tasks_response.findall('task'):
        name_el = task.find('name')
        if name_el is not None and name_el.text == task_name:
            print(f"Task já existe: {task_name}")
            return task.get('id')

    task_response = gmp.create_task(
        name=task_name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id,
        schedule_id=schedule_id,
        alterable=True
    )

    print(f"Task criada: {task_name}")
    return task_response.get('id')


def execute_task(gmp, task_id):
    start_task = gmp.start_task(task_id)
    return start_task.get('id')

def main():
    path = '/run/gvmd/gvmd.sock'
    connection = UnixSocketConnection(path=path)
    transform = EtreeTransform()

    schedule_type = os.getenv('SCHEDULE_TYPE', 'Daily')
    schedule_time = os.getenv('SCHEDULE_TIME', '12:00')
    schedule_date = os.getenv('SCHEDULE_FIRST_DATE', '2024-04-10')
    execute_now = (os.getenv('EXECUTE_NOW') or 'false')

    try:
        sync_hosts_from_assets()
    except Exception as e:
        print(f"[WARN] Falha ao sincronizar hosts do GAT: {e}")

    try:
        with Gmp(connection=connection, transform=transform) as gmp:
            print('Iniciando...')
            gmp.authenticate(os.getenv('OPENVAS_USERNAME'), os.getenv('OPENVAS_PASSWORD'))

            scanner_id = get_scanner_id(gmp)
            config_id = get_config_id(gmp)
            schedule_id = get_schedule_id(gmp, schedule_type, schedule_date, schedule_time)

            if not scanner_id or not config_id:
                print('Error: Scanner ID ou Config ID não encontrado')
                return

            with open('/app/hosts', 'r') as file:
                for line in file:
                    host = line.strip()
                    if host:
                        target_id = create_target(gmp, host)
                        if target_id:
                            task_id = create_task(gmp, host, target_id, config_id, scanner_id, schedule_id)
                            if execute_now.lower() == 'true':
                                execute_task(gmp, task_id)                            
                            print(f'Task ID: {task_id}')
                        else:
                            print(f'Failed to create target for {host}')

    except GvmError as e:
        print('Um erro ocorreu:', e, file=sys.stderr)

if __name__ == '__main__':
    main()