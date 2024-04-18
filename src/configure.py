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
from gvm.transforms import EtreeCheckCommandTransform

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
    schedule_response = gmp.create_schedule(
        name=f"Schedule {schedule_type} at {schedule_time} on {schedule_date} ({timezone})",
        icalendar=ical_data,
        timezone=timezone
    )
    return schedule_response.get('id')

def create_target(gmp, host):
    target_name = f"Target: {host}"
    target_response = gmp.create_target(
        name=target_name,
        hosts=[host],
        port_range='1-65000' 
    )
    return target_response.get('id')

def create_task(gmp, target_id, config_id, scanner_id, schedule_id):
    task_name = f"Task for Target: {target_id}"
    task_response = gmp.create_task(
        name=task_name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id,
        schedule_id=schedule_id
    )
    return task_response.get('id')

def execute_task(gmp, task_id):
    start_task = gmp.start_task(task_id)
    return start_task.get('id')

def main():
    path = '/run/gvmd/gvmd.sock'
    connection = UnixSocketConnection(path=path)
    transform = EtreeCheckCommandTransform()
    schedule_type = os.getenv('SCHEDULE_TYPE', 'Daily')
    schedule_time = os.getenv('SCHEDULE_TIME', '12:00')
    schedule_date = os.getenv('SCHEDULE_FIRST_DATE', '2024-04-10')
    execute_now = os.getenv('EXECUTE_NOW')

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
                            task_id = create_task(gmp, target_id, config_id, scanner_id, schedule_id)
                            if execute_now == 'True':
                                execute_task(gmp, task_id)                            
                            print(f'Task ID: {task_id}')
                        else:
                            print(f'Failed to create target for {host}')

    except GvmError as e:
        print('Um erro ocorreu:', e, file=sys.stderr)

if __name__ == '__main__':
    main()