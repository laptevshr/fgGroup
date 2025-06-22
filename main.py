from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from pymongo import MongoClient
from pymongo import ReturnDocument
from datetime import datetime
from bson.objectid import ObjectId
from fwCode import fwCode
from fwNetAddress import fwNetAddress
import requests
import urllib3
import ipaddress
import asyncio
#import aiohttp
from functools import partial
import pandas as pd
import os
from io import BytesIO

# 13-05-2025

# DNS RESOLVE >>>
import dns.resolver
import dns.reversename
import dns.query
# DNS RESOLVE <<<

from concurrent.futures import ThreadPoolExecutor


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'



# MongoDB configuration
client = MongoClient('mongodb://localhost:27017/')
db = client['fortigate_manager']

# Collections
users = db.users
nets = db.nets
groups = db.groups
sites = db.sites
typeNets = db.typeNets
firewalls = db.firewalls
state = db.state


# >>>>>>>>>>>>>>>>>>>>>>>>>>>> DNS RESOLVE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Добавим коллекцию DNS серверов
dns_servers = db.dns_servers

# Инициализация стандартных серверов если коллекция пуста
if dns_servers.count_documents({}) == 0:
    dns_servers.insert_many([
        {"name": "Google DNS", "ip": "8.8.8.8", "default": True},
        {"name": "Cloudflare DNS", "ip": "1.1.1.1", "default": False}
    ])
# <<<<<<<<<<<<<<<<<<<<<<<<<<<< DNS RESOLVE <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<




# Статус синхронизации, если нет записей в БД, создаем новую
if state.count_documents({"param_name": "sync_fg"}) == 0:
    state.insert_one(
        {"param_name": "sync_fg",
         "value": False})



def create_or_update_site_type_group(site_id, type_id, net_name):
    """Создает или обновляет группу площадка_Nets_тип"""
    group_name = f"d-{site_id}_Nets_{type_id}"

    # Ищем или создаем группу
    group = groups.find_one_and_update(
        {"name": group_name},
        {"$addToSet": {"members": net_name}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )

    # Если группа только что создана, добавляем базовые поля
    if group.get('created_at') is None:
        groups.update_one(
            {"_id": group['_id']},
            {"$set": {
                "site": site_id,
                "type": type_id,
                "createOrder": 20,
                "description": f"Автоматически созданная группа сетей площадки {site_id} типа {type_id}",
                "hands": False,  # Не для ручного редактирования
                "created_at": datetime.now(),
                "created_by": "system"
            }}
        )

    return group_name


def create_or_update_global_type_group(type_id, site_group_name):
    """Создает или обновляет глобальную группу по типу GLB_Nets_тип"""
    group_name = f"d-GLB_Nets_{type_id}"

    groups.update_one(
        {"name": group_name},
        {"$addToSet": {"members": site_group_name}},
        upsert=True
    )

    # Если группа только что создана
    if groups.count_documents({"name": group_name, "created_at": {"$exists": False}}) > 0:
        groups.update_one(
            {"name": group_name},
            {"$set": {
                "type": type_id,
                "createOrder": 70,
                "description": f"Глобальная группа сетей типа {type_id}",
                "hands": False,
                "created_at": datetime.now(),
                "created_by": "system"
            }}
        )

    return group_name


def create_or_update_site_group(site_id, site_type_group_name):
    """Создает или обновляет группу площадка_Nets"""
    group_name = f"d-{site_id}_Nets"

    groups.update_one(
        {"name": group_name},
        {"$addToSet": {"members": site_type_group_name}},
        upsert=True
    )

    # Если группа только что создана
    if groups.count_documents({"name": group_name, "created_at": {"$exists": False}}) > 0:
        groups.update_one(
            {"name": group_name},
            {"$set": {
                "site": site_id,
                "createOrder": 100,
                "description": f"Группа всех сетей площадки {site_id}",
                "hands": False,
                "created_at": datetime.now(),
                "created_by": "system"
            }}
        )

    return group_name


def create_or_update_global_group(site_group_name):
    """Создает или обновляет глобальную группу GLB_Nets"""
    group_name = "d-GLB_Nets"

    groups.update_one(
        {"name": group_name},
        {"$addToSet": {"members": site_group_name}},
        upsert=True
    )

    # Если группа только что создана
    if groups.count_documents({"name": group_name, "created_at": {"$exists": False}}) > 0:
        groups.update_one(
            {"name": group_name},
            {"$set": {
                "description": "Глобальная группа всех сетей",
                "createOrder": 199,
                "hands": False,
                "created_at": datetime.now(),
                "created_by": "system"
            }}
        )

    return group_name


def is_group_exists(fw_name, group_name):
    """
    Проверяет существование группы на указанном межсетевом экране
    Возвращает:
        True - группа существует
        False - группа не существует или произошла ошибка
    """
    try:
        # 1. Поиск межсетевого экрана в БД
        firewall = firewalls.find_one({"name": fw_name.get('name')})
        if not firewall:
            print(f"Межсетевой экран {fw_name} не найден")
            return False

        # 2. Формирование URL API
        if (firewall['ipv4'] == '10.128.34.220'):
            base_url = f"http://{firewall['ipv4']}/api/v2"
        else:
            base_url = f"https://{firewall['ipv4']}/api/v2"


        # 3. Подготовка заголовков и параметров
        headers = {
            "Authorization": f"Bearer {firewall['apikey']}",
            "Content-Type": "application/json"
        }
        params = {"vdom": firewall['VDOM']}

        # 4. Отправка запроса к API FortiGate
        response = requests.get(
            f"{base_url}/cmdb/firewall/addrgrp/{group_name}",
            headers=headers,
            params=params,
            verify=False,
            timeout=5
        )

        # 5. Анализ ответа
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            print(f"Ошибка проверки группы: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        print(f"Ошибка при проверке группы: {str(e)}")
        return False


def group_members(fw_name, group_name):
    """
    Проверяет существование группы на указанном межсетевом экране
    Возвращает:
        True - группа существует
        False - группа не существует или произошла ошибка
    """
    try:
        # 1. Поиск межсетевого экрана в БД
        firewall = firewalls.find_one({"name": fw_name.get('name')})
        if not firewall:
            print(f"Межсетевой экран {fw_name} не найден")
            return False

        # 2. Формирование URL API
        if (firewall['ipv4'] == '10.128.34.220'):
            base_url = f"http://{firewall['ipv4']}/api/v2"
        else:
            base_url = f"https://{firewall['ipv4']}/api/v2"


        # 3. Подготовка заголовков и параметров
        headers = {
            "Authorization": f"Bearer {firewall['apikey']}",
            "Content-Type": "application/json"
        }
        params = {"vdom": firewall['VDOM']}

        # 4. Отправка запроса к API FortiGate
        response = requests.get(
            f"{base_url}/cmdb/firewall/addrgrp/{group_name}",
            headers=headers,
            params=params,
            verify=False,
            timeout=5
        )

        # 5. Анализ ответа
        if response.status_code == 200:
            return response.json()['results'][0]['member']
        elif response.status_code == 404:
            return None
        else:
            print(f"Ошибка проверки группы: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print(f"Ошибка при проверке группы: {str(e)}")
        return None



# Initialize some default data if collections are empty
if sites.count_documents({}) == 0:
    sites.insert_many([
        {"name": "Site A", "description": "Main datacenter", "id": "site_a"},
        {"name": "Site B", "description": "Backup site", "id": "site_b"}
    ])

if typeNets.count_documents({}) == 0:
    typeNets.insert_many([
        {"name": "Production", "description": "Production networks", "id": "prod"},
        {"name": "Development", "description": "Development networks", "id": "dev"}
    ])

if firewalls.count_documents({}) == 0:
    firewalls.insert_one({
        "NameNGFW": "Main Firewall",
        "VDOM": "VDOM_Global",
        "ipv4": "10.10.10.10",
        "apikey": "w4e5",
        "description": "Primary firewall",
        "name": "FW1",
        "id": "fw1"
    })

if users.count_documents({}) == 0:
    users.insert_one({
        "username": "admin",
        "password": "admin",  # In production, use hashed passwords!
        "fullname": "Administrator"
    })


@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Получаем статистику синхронизации
    sync_fg_status = state.find_one({"param_name": "sync_fg"})["value"]

    # Получаем количество записей из коллекций
    nets_count = nets.count_documents({})
    firewalls_count = firewalls.count_documents({})

    return render_template('home.html',
                         nets_count=nets_count,
                         sync_fg_status=sync_fg_status,
                         firewalls_count=firewalls_count)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.find_one({"username": username, "password": password})
        if user:
            session['username'] = username
            session['fullname'] = user['fullname']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/code', methods=['GET', 'POST'])
def code():
    if 'username' not in session:
        return redirect(url_for('login'))

    firewall_list = list(firewalls.find())

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Добавьте здесь обработку формы, если нужно

    return render_template('code.html', firewalls=firewall_list)


def getPrefixSiteByAddress(target_ip):
    """
    Находит site, к которому принадлежит IP-адрес, проверяя вхождение в подсети из коллекции Nets
    """
    try:
        # Преобразуем целевой IP в объект IPv4Address для сравнения
        ip_obj = ipaddress.IPv4Network(target_ip)
    except ipaddress.AddressValueError:
        print(f"Ошибка: {target_ip} не является валидным IPv4 адресом")
        return None

    # Ищем все документы в коллекции Nets, где поле ipv4 содержит подсеть
    for net in nets.find({"ipv4": {"$exists": True}}):
        try:
            # Пытаемся создать объект сети из значения поля ipv4
            network = ipaddress.IPv4Network(net['ipv4'], strict=False)
            if ip_obj.subnet_of(network):
                return net.get('site')  # Возвращаем значение поля site
        except (ValueError, ipaddress.AddressValueError):
            # Пропускаем невалидные записи подсетей
            continue

    return None  # Если ни одна подсеть не подошла



def createFortigateAddress(_firewall):
    """
    Создает объекты адресов в FortiGate на основе словаря

    :param address_dict: словарь {имя_фаервола: [адреса]}
    :param firewalls_db: справочник фаерволов из MongoDB
    :return: словарь с результатами для каждого фаервола
    """
    results = {}
    for fw_name, addresses in _firewall.items():
        firewall = firewalls.find_one({"name": fw_name})
        if not firewall:
            results[fw_name] = {"status": "error", "message": f"Firewall {fw_name} not found"}
            continue
        else:
            if (firewall['ipv4'] == '10.128.34.220'):
                FORTIGATE_BASE_URL = f"http://{firewall['ipv4']}/api/v2"
            else:
                FORTIGATE_BASE_URL = f"https://{firewall['ipv4']}/api/v2"

            FORTIGATE_API_HEADERS = {
                "Authorization": f"Bearer {firewall['apikey']}",
                "Content-Type": "application/json"
            }
            FORTIGATE_API_PARAMS = {
                "vdom": firewall['VDOM']
            }
            FORTIGATE_ADDRESS_URL = f"{FORTIGATE_BASE_URL}/cmdb/firewall/address"

            fw_results = []

            for address in addresses:
                # Определяем тип адреса
                addr_type = fwNetAddress(address).type
                if addr_type in ('ip', 'subnet'):
                    prefix = getPrefixSiteByAddress(address) or ("ext")
                    name_addr = f"{prefix}_{address}"
                else:
                    name_addr = address

                object_data = {
                    "name": address,
                    "comment": f"Created address automatically from code {name_addr}"
                }

                # Формируем данные в зависимости от типа адреса
                if addr_type == 'ip':
                    object_data["type"] = "ipmask"
                    object_data["subnet"] = f"{address} 255.255.255.255"
                elif addr_type == 'subnet':
                    object_data["type"] = "ipmask"
                    object_data["subnet"] = address
                elif addr_type == 'fqdn':
                    object_data["type"] = "fqdn"
                    object_data["fqdn"] = address
                else:
                    fw_results.append({
                        "address": address,
                        "status": "skipped",
                        "reason": "Invalid address type"
                    })
                    continue

                try:
                    response = requests.post(FORTIGATE_ADDRESS_URL,
                                        headers=FORTIGATE_API_HEADERS,
                                        params=FORTIGATE_API_PARAMS,
                                        json=object_data,
                                        verify=False)

                    if response.status_code == 200:
                        fw_results.append({
                            "address": address,
                            "status": "created",
                            "type": addr_type
                        })
                    else:
                        error_msg = response.json().get("message", "Unknown error")
                        fw_results.append({
                            "address": address,
                            "status": "error",
                            "error": error_msg
                        })
                except Exception as e:
                    fw_results.append({
                        "address": address,
                        "status": "error",
                        "error": str(e)
                    })

            results[fw_name] = fw_results

    return results


@app.route('/code_review', methods=['POST'])
def code_review():
    try:
        code_data = request.get_json()
        if not code_data or 'code' not in code_data:
            return jsonify({'success': False, 'message': 'Отсутствует код'})

        myCode = fwCode(code_data['code'])
        myCode.remove_trailing_spaces()
        myCode.remove_comments()

        # Проверка символов
        valid_chars, chars_msg = myCode.check_allowed_chars()
        if not valid_chars:
            return jsonify({'success': False, 'message': chars_msg})

        # Извлечение данных
        myCode.extract_configuration()
        report = myCode.generate_report()

        app.logger.info(f"Generated Report:\n{report}")  # Логируем отчет

        return jsonify({
            'success': True,
            'message': 'Проверка успешна',
            'report': report,
            'code': myCode.get_code()
        })

    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'success': False, 'message': f'Ошибка: {str(e)}'})



def create_fortigate_group(firewall, group_name, members, exist_members):
    try:
        if firewall['ipv4'] == '10.128.34.220':
            base_url = f"http://{firewall['ipv4']}/api/v2"
        else:
            base_url = f"https://{firewall['ipv4']}/api/v2"

        headers = {
            "Authorization": f"Bearer {firewall['apikey']}",
            "Content-Type": "application/json"
        }
        params = {"vdom": firewall['VDOM']}



        if exist_members: # группа существует
            for member in members:
                # Добавляем новый адрес (проверяем дубликаты)
                if not any(m['name'] == member for m in exist_members):
                    exist_members.append({"name": member})
                else:
                    print(f"Адрес {member} уже в группе")
                    continue

                group_data = {
                    "member": exist_members,
                    "comment": "Updated with new member"
                }
                response = requests.put(
                    f"{base_url}/cmdb/firewall/addrgrp/{group_name}",
                    headers=headers,
                    params=params,
                    json=group_data,
                    verify=False
                )
                return response.status_code == 200
        else: # группы нет, создаем
            group_data = {
                "name": group_name,
                "member": [{"name": m} for m in members],
                "comment": "Создано автоматически"
            }

            response = requests.post(
                f"{base_url}/cmdb/firewall/addrgrp",
                headers=headers,
                params=params,
                json=group_data,
                verify=False
            )
            return response.status_code == 200

    except Exception as e:
        print(f"Error creating group: {str(e)}")
        return False


# Создание сервисов в FortiGate
def create_fortigate_service(firewall, service_name, protocol, port_start, port_end=None):
    """
    Создает сервис (порт) в FortiGate

    :param firewall: словарь с данными о МЭ
    :param service_name: имя сервиса
    :param protocol: протокол (tcp/udp)
    :param port_start: начальный порт
    :param port_end: конечный порт (для диапазона)
    :return: True если сервис создан успешно
    """
    try:
        if firewall['ipv4'] == '10.128.34.220':
            base_url = f"http://{firewall['ipv4']}/api/v2"
        else:
            base_url = f"https://{firewall['ipv4']}/api/v2"

        headers = {
            "Authorization": f"Bearer {firewall['apikey']}",
            "Content-Type": "application/json"
        }
        params = {"vdom": firewall['VDOM']}

        # Базовые данные для сервиса
        service_data = {
            "name": service_name,
            "comment": "Создано автоматически из кода",
            "protocol": protocol.lower(),
            "tcp-portrange" if protocol.lower() == "tcp" else "udp-portrange":
                f"{port_start}-{port_end}" if port_end else str(port_start)
        }

        # Проверяем существование сервиса
        check_response = requests.get(
            f"{base_url}/cmdb/firewall.service/custom/{service_name}",
            headers=headers,
            params=params,
            verify=False
        )

        # Если сервис уже существует, обновляем его
        if check_response.status_code == 200:
            response = requests.put(
                f"{base_url}/cmdb/firewall.service/custom/{service_name}",
                headers=headers,
                params=params,
                json=service_data,
                verify=False
            )
        else:
            # Создаем новый сервис
            response = requests.post(
                f"{base_url}/cmdb/firewall.service/custom",
                headers=headers,
                params=params,
                json=service_data,
                verify=False
            )

        return response.status_code in [200, 201, 204]

    except Exception as e:
        print(f"Ошибка при создании сервиса {service_name}: {str(e)}")
        return False


def create_fortigate_service_group(firewall, group_name, members, exist_members=None):
    """
    Создает или обновляет группу сервисов в FortiGate

    :param firewall: словарь с данными о МЭ
    :param group_name: имя группы сервисов
    :param members: список имен сервисов-членов группы
    :param exist_members: существующие члены группы (если группа уже существует)
    :return: True если группа создана/обновлена успешно
    """
    try:
        if firewall['ipv4'] == '10.128.34.220':
            base_url = f"http://{firewall['ipv4']}/api/v2"
        else:
            base_url = f"https://{firewall['ipv4']}/api/v2"

        headers = {
            "Authorization": f"Bearer {firewall['apikey']}",
            "Content-Type": "application/json"
        }
        params = {"vdom": firewall['VDOM']}

        # Форматируем членов группы для API
        formatted_members = [{"name": member} for member in members]

        if exist_members:
            # Обновляем существующую группу
            group_data = {
                "member": formatted_members,
                "comment": "Обновлено автоматически"
            }

            response = requests.put(
                f"{base_url}/cmdb/firewall.service/group/{group_name}",
                headers=headers,
                params=params,
                json=group_data,
                verify=False
            )
        else:
            # Создаем новую группу
            group_data = {
                "name": group_name,
                "member": formatted_members,
                "comment": "Создано автоматически"
            }

            response = requests.post(
                f"{base_url}/cmdb/firewall.service/group",
                headers=headers,
                params=params,
                json=group_data,
                verify=False
            )

        return response.status_code in [200, 201, 204]

    except Exception as e:
        print(f"Ошибка при создании/обновлении группы сервисов {group_name}: {str(e)}")
        return False


# Функция для извлечения информации о порте из строки формата 't123' или 'u456-789'
def parse_port_string(port_str):
    """
    Парсит строку с описанием порта в формате t123 или u456-789

    :param port_str: строка с описанием порта
    :return: tuple (protocol, port_start, port_end)
    """
    protocol = "tcp" if port_str.lower().startswith('t') else "udp"
    port_range = port_str[1:]  # Убираем первый символ (t или u)

    if '-' in port_range:
        start, end = port_range.split('-')
        return protocol, int(start), int(end)
    else:
        return protocol, int(port_range), None





def create_fortigate_policy(firewall, policy_data):
    try:
        if firewall['ipv4'] == '10.128.34.220':
            print(f"Just http protocol")
            base_url = f"http://{firewall['ipv4']}/api/v2"
        else:
            print(f"https protocol")
            base_url = f"https://{firewall['ipv4']}/api/v2"

        headers = {
            "Authorization": f"Bearer {firewall['apikey']}",
            "Content-Type": "application/json"
        }
        params = {"vdom": firewall['VDOM']}

        services = []
        if policy_data.get('svc') and len(policy_data['svc']) > 0:
            services = [{"name": svc} for svc in policy_data['svc']]
        else:
            services = [{"name": "ALL"}]  # Всегда добавляем DEFAULT сервис, если список пуст


        if policy_data.get('sif'):
            rrr=policy_data

        policy_json = {
            "name": policy_data['name'],
            "srcintf": [{"name": policy_data['sif'] if policy_data.get('sif') else 'any'}],
            "dstintf": [{"name": policy_data['dif'] if policy_data.get('dif') else 'any'}],
            "srcaddr": [{"name": addr} for addr in policy_data['src']],
            "dstaddr": [{"name": addr} for addr in policy_data['dst']],
            "service": services,
            "action": "accept",
            "status": "disable",
            "comments": "Create automatically",
            "schedule": "always",
            "logtraffic": "all",
            "logtraffic-start": "enable"
        }

        policy_json = {
            "json": policy_json
        }
        response = requests.post(
            f"{base_url}/cmdb/firewall/policy",
            headers=headers,
            params=params,
            json=policy_json,
            verify=False
        )
        # Добавляем логирование ответа для отладки
        print(f"Status code: {response.status_code}")
        print(f"Response content: {response.text}")


        if response.status_code in [200, 201, 204]:
            response_data = response.json()
            mkey = response_data.get('mkey')

            if policy_data['after']:
                params = {
                    "vdom": firewall['VDOM'],
                    "action": "move",
                    "after": str(policy_data['after'])
                }

                response = requests.put(
                    f"{base_url}/cmdb/firewall/policy/{mkey}",
                    headers=headers,
                    params=params,
                    verify=False
                )

                if response.status_code not in [200, 201, 204]:
                    return {
                        'status': 'error',
                        'message': f"HTTP {response.status_code}: {response.text}",
                        'response': response.json()
                    }
                else:
                    return {
                        'status': 'succes',
                        'message': f"HTTP {response.status_code}: {response.text}",
                        'response': response.json()
                    }
        else:
            return {
                'status': 'error',
                'message': f"HTTP {response.status_code}: {response.text}",
                'response': response.json()
            }

    except Exception as e:
        print(f"Error creating policy: {str(e)}")
        return False


@app.route('/apply_code', methods=['POST'])
def apply_code():
    try:
        code_data = request.get_json()
        code_text = code_data.get('code', '')

        # Обрабатываем код
        myCode = fwCode(code_text)
        myCode.remove_trailing_spaces()
        myCode.remove_comments()

        # Проверка символов
        valid_chars, chars_msg = myCode.check_allowed_chars()
        if not valid_chars:
            return jsonify({'success': False, 'message': chars_msg})

        # Извлекаем конфигурацию
        myCode.extract_configuration()

        # Создаем адреса, группы и политики
        results = {
            'addresses': createFortigateAddress(myCode.addresses),
            'groups': {},
            'services': {},  # Для отдельных сервисов
            'service_groups': {},  # Для групп сервисов
            'policies': {}
        }

        # Создаем группы
        for fw, groups in myCode.groups.items():
            firewall = firewalls.find_one({'name': fw})
            if not firewall:
                continue
            results['groups'][fw] = []
            for group_name, members in groups.items():
                exist_members = group_members(firewall, group_name)
                success = create_fortigate_group(firewall, group_name, members, exist_members)
                results['groups'][fw].append({'group': group_name, 'status': 'created' if success else 'error'})

        # Создаем отдельные сервисы (порты)
        for fw, services in myCode.services.items():
            firewall = firewalls.find_one({'name': fw})
            if not firewall:
                continue

            results['services'][fw] = []

            for service in services:
                # Парсинг строки порта (t123 или u456-789)
                protocol = "tcp" if service.startswith('t') else "udp"
                port_range = service[1:]  # Убираем первый символ (t или u)

                if '-' in port_range:
                    start, end = port_range.split('-')
                    port_start, port_end = int(start), int(end)
                else:
                    port_start, port_end = int(port_range), None

                # Формируем имя сервиса
                service_name = f"{protocol}_{port_range}"

                # Создаем сервис
                success = create_fortigate_service(
                    firewall,
                    service_name,
                    protocol,
                    port_start,
                    port_end
                )
                results['services'][fw].append({
                    'service': service_name,
                    'status': 'created' if success else 'error'
                })

        # Создаем группы сервисов
        for fw, service_groups in myCode.service_groups.items():
            firewall = firewalls.find_one({'name': fw})
            if not firewall:
                continue

            results['service_groups'][fw] = []

            for group_name, members in service_groups.items():
                # Преобразуем определения портов в имена сервисов
                service_members = []
                for member in members:
                    if member.startswith('t') or member.startswith('u'):
                        # Формируем имя сервиса из определения порта
                        protocol = "tcp" if member.startswith('t') else "udp"
                        port_range = member[1:]
                        service_name = f"{protocol}_{port_range}"
                        service_members.append(service_name)
                    else:
                        # Для других членов - используем имя как есть
                        service_members.append(member)

                # Создаем группу сервисов
                success = create_fortigate_service_group(
                    firewall,
                    group_name,
                    service_members
                )
                results['service_groups'][fw].append({
                    'group': group_name,
                    'status': 'created' if success else 'error'
                })

        # Создаем политики
        for fw, policies in myCode.policies.items():
            firewall = firewalls.find_one({'name': fw})
            if not firewall:
                continue
            results['policies'][fw] = []
            for policy in policies:
                # Преобразуем определения портов в имена сервисов в политике
                transformed_policy = policy.copy()
                transformed_svc = []

                for svc in policy['svc']:
                    if svc.startswith('t') or svc.startswith('u'):
                        # Это прямое определение порта
                        protocol = "tcp" if svc.startswith('t') else "udp"
                        port_range = svc[1:]
                        service_name = f"{protocol}_{port_range}"
                        transformed_svc.append(service_name)
                    else:
                        # Имя сервиса или группы как есть
                        transformed_svc.append(svc)

                transformed_policy['svc'] = transformed_svc
                success = create_fortigate_policy(firewall, transformed_policy)
                if success.get('status') in 'error':
                    return jsonify({
                        'success': False,
                        'message': success.get('message'),
                        'results': None
                    })
                else:
                    results['policies'][fw].append({'policy': policy['name'], 'status': 'created' if success else 'error'})

        return jsonify({
            'success': True,
            'message': 'Конфигурация применена',
            'results': results
        })

    except Exception as e:
        import traceback
        return jsonify({'success': False, 'message': f'Ошибка: {str(e)}\n{traceback.format_exc()}'}), 500


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('fullname', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


@app.route('/nets')
def show_nets():
    if 'username' not in session:
        return redirect(url_for('login'))

    filter_name = request.args.get('filter', '')
    network_filter = request.args.get('network_filter', '')

    # Параметр направления поиска (по умолчанию оба)
    search_direction = request.args.get('search_direction', 'both')

    # Базовый запрос
    query = {}

    # Применяем фильтр по имени, если он указан
    if filter_name:
        query["name"] = {"$regex": filter_name, "$options": "i"}

    # Получаем список сетей из базы
    network_list = list(nets.find(query))

    # Если указан фильтр по сети, отфильтруем результаты
    search_info = ""
    if network_filter:
        try:
            # Создаем объект фильтруемой сети
            search_network = ipaddress.IPv4Network(network_filter, strict=False)

            # Отфильтрованный список сетей
            filtered_networks = []

            for net in network_list:
                try:
                    # Создаем объект проверяемой сети
                    target_network = ipaddress.IPv4Network(net['ipv4'], strict=False)

                    # Проверяем условия в зависимости от режима поиска
                    include_network = False

                    if search_direction == 'contains' or search_direction == 'both':
                        # Поиск сетей, содержащих искомую
                        if search_network.subnet_of(target_network) or search_network == target_network:
                            include_network = True

                    if search_direction == 'inside' or search_direction == 'both':
                        # Поиск сетей, входящих в искомую
                        if target_network.subnet_of(search_network):
                            include_network = True

                    if include_network:
                        filtered_networks.append(net)

                except (ValueError, ipaddress.AddressValueError):
                    # Пропускаем некорректные записи
                    continue

            # Заменяем список на отфильтрованный
            network_list = filtered_networks

            # Добавляем информацию о поиске
            search_info = f"Найдено сетей: {len(filtered_networks)}"

        except (ValueError, ipaddress.AddressValueError):
            # Если введена некорректная сеть, добавим сообщение об ошибке
            flash('Некорректный формат сети. Используйте формат IP/маска, например: 192.168.1.0/24', 'danger')

    return render_template('nets.html',
                           nets=network_list,
                           filter_value=filter_name,
                           network_filter_value=network_filter,
                           search_direction=search_direction,
                           search_info=search_info)


@app.route('/groups')
def show_groups():
    if 'username' not in session:
        return redirect(url_for('login'))

    filter_name = request.args.get('filter', '')
    query = {}
    if filter_name:
        query = {"name": {"$regex": filter_name, "$options": "i"}}

    group_list = list(groups.find(query))

    # Get FortiGate groups if configured
    fortigate_groups = []
    firewall = firewalls.find_one()
    if firewall:
        try:
            if (firewall['ipv4'] == '10.128.34.220'):
                FORTIGATE_BASE_URL = f"http://{firewall['ipv4']}/api/v2"
            else:
                FORTIGATE_BASE_URL = f"https://{firewall['ipv4']}/api/v2"

            FORTIGATE_API_HEADERS = {
                "Authorization": f"Bearer {firewall['apikey']}",
                "Content-Type": "application/json"
            }
            FORTIGATE_API_PARAMS = {
                "vdom": firewall['VDOM']
            }
            FORTIGATE_ADDRESS_GROUPS_URL = f"{FORTIGATE_BASE_URL}/cmdb/firewall/addrgrp"

            response = requests.get(FORTIGATE_ADDRESS_GROUPS_URL,
                                    headers=FORTIGATE_API_HEADERS,
                                    params=FORTIGATE_API_PARAMS,
                                    verify=False)
            if response.status_code == 200:
                fortigate_groups = response.json().get('results', [])
        except Exception as e:
            flash(f'Error fetching FortiGate groups: {str(e)}', 'danger')

        nets_names = [net['name'] for net in nets.find({}, {'name': 1})]

    return render_template('groups.html',
                           local_groups=group_list,
                           nets_names=nets_names,
                           fortigate_groups=fortigate_groups,
                           filter_value=filter_name)









def remove_net_from_all_groups(net_name):
    """Удаляет сеть из всех групп, где она упоминается"""
    # Обновляем все группы, удаляя сеть из members
    result = groups.update_many(
        {"members": net_name},
        {"$pull": {"members": net_name}}
    )

    # Возвращаем количество обновленных групп
    return result.modified_count




def check_group_inclusion_in_fortigate(group_name):
    """Проверяет, входит ли группа в другие группы на всех межсетевых экранах"""
    included_in = []
    firewalls_list = list(firewalls.find())

    for fw in firewalls_list:
        try:
            if (fw['ipv4'] == '10.128.34.220'):
                FORTIGATE_BASE_URL = f"http://{fw['ipv4']}/api/v2"
            else:
                FORTIGATE_BASE_URL = f"https://{fw['ipv4']}/api/v2"

            FORTIGATE_API_HEADERS = {
                "Authorization": f"Bearer {fw['apikey']}",
                "Content-Type": "application/json"
            }
            FORTIGATE_API_PARAMS = {"vdom": fw['VDOM']}

            # Проверяем все группы на МСЭ, где текущая группа является членом
            response = requests.get(
                f"{FORTIGATE_BASE_URL}/cmdb/firewall/addrgrp",
                params=FORTIGATE_API_PARAMS,
                headers=FORTIGATE_API_HEADERS,
                verify=False
            )

            if response.status_code == 200:
                addrgrp_list = response.json().get('results', [])
                for addrgrp in addrgrp_list:
                    # Проверяем каждого члена группы
                    for member in addrgrp.get('member', []):
                        # Если член группы - объект с полем 'name', сравниваем его
                        if isinstance(member, dict) and 'name' in member:
                            if member['name'] == group_name:
                                included_in.append({
                                    'firewall': fw['name'],
                                    'group': addrgrp['name'],
                                    'vdom': fw['VDOM']
                                })
                                break
                        # Если член группы - просто строка (имя), сравниваем напрямую
                        elif isinstance(member, str) and member == group_name:
                            included_in.append({
                                'firewall': fw['name'],
                                'group': addrgrp['name'],
                                'vdom': fw['VDOM']
                            })
                            break
        except Exception as e:
            print(f"Error checking group inclusion on {fw['name']}: {str(e)}")

    return included_in if included_in else None


def check_group_usage_in_rules(group_name):
    """Проверяет использование группы в правилах межсетевых экранов"""
    usage_info = []
    firewalls_list = list(firewalls.find())

    for fw in firewalls_list:
        try:
            if (fw['ipv4'] == '10.128.34.220'):
                FORTIGATE_BASE_URL = f"http://{fw['ipv4']}/api/v2"
            else:
                FORTIGATE_BASE_URL = f"https://{fw['ipv4']}/api/v2"

            FORTIGATE_API_HEADERS = {
                "Authorization": f"Bearer {fw['apikey']}",
                "Content-Type": "application/json"
            }
            FORTIGATE_API_PARAMS = {"vdom": fw['VDOM']}

            # Проверяем использование в качестве source
            src_response = requests.get(
                f"{FORTIGATE_BASE_URL}/cmdb/firewall/policy",
                params={**FORTIGATE_API_PARAMS, **{"filter": f"srcaddr=@{group_name}"}},
                headers=FORTIGATE_API_HEADERS,
                verify=False
            )

            # Проверяем использование в качестве destination
            dst_response = requests.get(
                f"{FORTIGATE_BASE_URL}/cmdb/firewall/policy",
                params={**FORTIGATE_API_PARAMS, **{"filter": f"dstaddr=@{group_name}"}},
                headers=FORTIGATE_API_HEADERS,
                verify=False
            )

            src_rules = src_response.json().get('results', [])
            dst_rules = dst_response.json().get('results', [])

            if src_rules or dst_rules:
                usage_info.append({
                    'firewall': fw['name'],
                    'ip': fw['ipv4'],
                    'src_rules': [r['policyid'] for r in src_rules],
                    'dst_rules': [r['policyid'] for r in dst_rules]
                })

        except Exception as e:
            print(f"Error checking group usage on {fw['name']}: {str(e)}")

    return usage_info if usage_info else None


def sync_address_to_fortigate(net_data, firewall):
    """Синхронизирует адрес (сеть) с FortiGate"""
    try:
        if (firewall['ipv4'] == '10.128.34.220'):
            FORTIGATE_BASE_URL = f"http://{firewall['ipv4']}/api/v2"
        else:
            FORTIGATE_BASE_URL = f"https://{firewall['ipv4']}/api/v2"

        FORTIGATE_API_HEADERS = {
            "Authorization": f"Bearer {firewall['apikey']}",
            "Content-Type": "application/json"
        }
        FORTIGATE_API_PARAMS = {"vdom": firewall['VDOM']}

        # Проверяем существование адреса
        check_url = f"{FORTIGATE_BASE_URL}/cmdb/firewall/address?filter=name=@{net_data['name']}"

        response = requests.get(
            check_url,
            headers=FORTIGATE_API_HEADERS,
            params=FORTIGATE_API_PARAMS,
            verify=False
        )
        # Если запрос не удался
        if response.status_code != 200:
            return False

        response_data = response.json()

        address_data = {
            "name": net_data['name'],
            "subnet": net_data['ipv4'],
            "comment": net_data.get('description', ''),
            "type": "ipmask"
        }

        # Проверяем по matched_count
        if response_data.get('matched_count', 0) == 0:
            # Создаем новый адрес
            requests.post(
                f"{FORTIGATE_BASE_URL}/cmdb/firewall/address",
                headers=FORTIGATE_API_HEADERS,
                params=FORTIGATE_API_PARAMS,
                json=address_data,
                verify=False
            )

        return True
    except Exception as e:
        print(f"Error syncing address to FortiGate: {str(e)}")
        return False

def sync_group_to_fortigate(group_name, desired_members, firewall):
    """Синхронизирует группу с FortiGate с корректным экранированием URL"""
    try:
        from urllib.parse import quote

        if (firewall['ipv4'] == '10.128.34.220'):
            FORTIGATE_BASE_URL = f"http://{firewall['ipv4']}/api/v2"
        else:
            FORTIGATE_BASE_URL = f"https://{firewall['ipv4']}/api/v2"

        FORTIGATE_API_HEADERS = {
            "Authorization": f"Bearer {firewall['apikey']}",
            "Content-Type": "application/json"
        }
        FORTIGATE_API_PARAMS = {"vdom": firewall['VDOM']}

        # Экранируем имя группы для URL
        encoded_group_name = quote(group_name, safe='')

        # 1. Получаем текущих членов группы
        group_url = f"{FORTIGATE_BASE_URL}/cmdb/firewall/addrgrp/{encoded_group_name}"
        response = requests.get(
            group_url,
            headers=FORTIGATE_API_HEADERS,
            params=FORTIGATE_API_PARAMS,
            verify=False
        )

        if response.status_code != 200:
            # Создаем новую группу если не существует
            local_group = groups.find_one({"name": group_name})
            description = local_group.get('description', '') if local_group else ''

            create_response = requests.post(
                f"{FORTIGATE_BASE_URL}/cmdb/firewall/addrgrp",
                headers=FORTIGATE_API_HEADERS,
                params=FORTIGATE_API_PARAMS,
                json={
                    "name": group_name,
                    "member": desired_members,
                    "comment": description
                },
                verify=False
            )
            return create_response.status_code == 200

        # 2. Получаем текущих членов
        current_members = []
        group_data = response.json()
        for member in group_data.get('results', [{}])[0].get('member', []):
            member_name = member['name'] if isinstance(member, dict) else member

            current_members.append(member_name)

        # 3. Определяем разницу
        desired_member_names = [m['name'] for m in desired_members]
        members_to_add = [m for m in desired_member_names if m not in current_members]
        members_to_remove = [m for m in current_members if m not in desired_member_names]

        # 4. Добавляем новых членов
        for member in members_to_add:
            add_url = f"{group_url}/member"
            add_response = requests.post(
                add_url,
                headers=FORTIGATE_API_HEADERS,
                params=FORTIGATE_API_PARAMS,
                json={"name": member},
                verify=False
            )
            if add_response.status_code != 200:
                print(f"Ошибка добавления {member} в {group_name}: {add_response.text}")

        # 5. Удаляем лишних членов (с экранированием)
        for member in members_to_remove:
            encoded_member = quote(member, safe='')
            del_url = f"{group_url}/member/{encoded_member}"
            del_response = requests.delete(
                del_url,
                headers=FORTIGATE_API_HEADERS,
                params=FORTIGATE_API_PARAMS,
                verify=False
            )
            if del_response.status_code != 200:
                print(f"Ошибка удаления {member} из {group_name}: {del_response.text}")

        # 6. Обновляем описание
        local_group = groups.find_one({"name": group_name})
        if local_group and local_group.get('description'):
            update_response = requests.put(
                group_url,
                headers=FORTIGATE_API_HEADERS,
                params=FORTIGATE_API_PARAMS,
                json={"comment": local_group['description']},
                verify=False
            )
            return update_response.status_code == 200

        return True

    except Exception as e:
        print(f"Ошибка синхронизации группы {group_name}: {str(e)}")
        return False


def full_sync_with_fortigate():
    """Полная синхронизация всех сетей и групп с FortiGate с оптимизацией запросов"""
    firewalls_list = list(firewalls.find())
    if not firewalls_list:
        return {'success': False, 'message': 'Нет настроенных FortiGate'}

    # Получаем все сети из базы данных
    nets_list = list(nets.find())

    # Получаем все группы из базы данных с сортировкой по createOrder
    groups_list = list(groups.find().sort('createOrder', 1))

    # Предварительно формируем данные групп
    group_members = {}
    for group in groups_list:
        members = []
        for member in group.get('members', []):
            members.append({"name": member})
        group_members[group['name']] = members

    # Обрабатываем каждый межсетевой экран
    for fw in firewalls_list:
        try:
            print(f"Синхронизация с {fw['name']}...")

            # Настраиваем базовый URL в зависимости от IP
            if (fw['ipv4'] == '10.128.34.220'):
                FORTIGATE_BASE_URL = f"http://{fw['ipv4']}/api/v2"
            else:
                FORTIGATE_BASE_URL = f"https://{fw['ipv4']}/api/v2"

            FORTIGATE_API_HEADERS = {
                "Authorization": f"Bearer {fw['apikey']}",
                "Content-Type": "application/json"
            }
            FORTIGATE_API_PARAMS = {"vdom": fw['VDOM']}

            # 1. Получаем ВСЕ адреса с FortiGate ОДНИМ запросом
            print(f"Получение всех адресов с {fw['name']}...")
            addresses_response = requests.get(
                f"{FORTIGATE_BASE_URL}/cmdb/firewall/address",
                headers=FORTIGATE_API_HEADERS,
                params={**FORTIGATE_API_PARAMS, "count": 100000},
                verify=False
            )

            if addresses_response.status_code != 200:
                print(f"Ошибка получения адресов: {addresses_response.text}")
                continue

            # Создаем словарь существующих адресов для быстрого поиска
            existing_addresses = {}
            for addr in addresses_response.json().get('results', []):
                existing_addresses[addr['name']] = addr

            # 2. Получаем ВСЕ группы с FortiGate ОДНИМ запросом
            print(f"Получение всех групп с {fw['name']}...")
            groups_response = requests.get(
                f"{FORTIGATE_BASE_URL}/cmdb/firewall/addrgrp",
                headers=FORTIGATE_API_HEADERS,
                params={**FORTIGATE_API_PARAMS, "count": 100000},
                verify=False
            )

            if groups_response.status_code != 200:
                print(f"Ошибка получения групп: {groups_response.text}")
                continue

            # Создаем словарь существующих групп для быстрого поиска
            existing_groups = {}
            for grp in groups_response.json().get('results', []):
                # Нормализуем представление членов группы
                members_set = set()
                for member in grp.get('member', []):
                    if isinstance(member, dict):
                        members_set.add(member.get('name', ''))
                    else:
                        members_set.add(member)

                existing_groups[grp['name']] = {
                    'members': members_set,
                    'comment': grp.get('comment', '')
                }

            # 3. Синхронизируем адреса - добавляем только те, которых нет
            print(f"Синхронизация адресов...")
            for net in nets_list:
                # Проверяем наличие адреса
                if net['name'] not in existing_addresses:
                    # Адреса нет - создаем его
                    address_data = {
                        "name": net['name'],
                        "subnet": net['ipv4'],
                        "comment": net.get('description', ''),
                        "type": "ipmask"
                    }

                    try:
                        response = requests.post(
                            f"{FORTIGATE_BASE_URL}/cmdb/firewall/address",
                            headers=FORTIGATE_API_HEADERS,
                            params=FORTIGATE_API_PARAMS,
                            json=address_data,
                            verify=False
                        )

                        if response.status_code != 200:
                            print(f"Ошибка создания адреса {net['name']}: {response.text}")
                    except Exception as e:
                        print(f"Исключение при создании адреса {net['name']}: {str(e)}")

            # 4. Синхронизируем группы - добавляем только те, которых нет или обновляем если изменились
            print(f"Синхронизация групп...")
            for group in groups_list:
                group_name = group['name']

                group_description = group.get('description', '')
                desired_members = [m['name'] for m in group_members.get(group_name, [])]

                # Проверяем существование и актуальность группы
                if group_name not in existing_groups:
                    # Группы нет - создаем ее
                    group_data = {
                        "name": group_name,
                        "member": group_members.get(group_name, []),
                        "comment": group_description
                    }

                    try:
                        response = requests.post(
                            f"{FORTIGATE_BASE_URL}/cmdb/firewall/addrgrp",
                            headers=FORTIGATE_API_HEADERS,
                            params=FORTIGATE_API_PARAMS,
                            json=group_data,
                            verify=False
                        )

                        if response.status_code != 200:
                            print(f"Ошибка создания группы {group_name}: {response.text}")
                    except Exception as e:
                        print(f"Исключение при создании группы {group_name}: {str(e)}")

                else:
                    # Группа есть - проверяем изменения
                    existing_group = existing_groups[group_name]
                    existing_members = existing_group['members']
                    existing_comment = existing_group['comment']

                    # Если есть отличия в составе или описании - обновляем
                    if set(desired_members) != existing_members or group_description != existing_comment:
                        group_data = {
                            "member": group_members.get(group_name, []),
                            "comment": group_description
                        }

                        try:
                            response = requests.put(
                                f"{FORTIGATE_BASE_URL}/cmdb/firewall/addrgrp/{group_name}",
                                headers=FORTIGATE_API_HEADERS,
                                params=FORTIGATE_API_PARAMS,
                                json=group_data,
                                verify=False
                            )

                            if response.status_code != 200:
                                print(f"Ошибка обновления группы {group_name}: {response.text}")
                        except Exception as e:
                            print(f"Исключение при обновлении группы {group_name}: {str(e)}")

        except Exception as e:
            print(f"Ошибка при синхронизации с {fw['name']}: {str(e)}")

    # Устанавливаем статус синхронизации в True
    state.update_one(
        {"param_name": "sync_fg"},
        {"$set": {"value": True}}
    )

    return {'success': True, 'message': 'Синхронизация завершена'}





@app.route('/sync_groups', methods=['POST'])
def sync_groups():
    if 'username' not in session:
        return redirect(url_for('login'))

    result = full_sync_with_fortigate()
    if result['success']:
        flash(result['message'], 'success')
        state.update_one(
            {"param_name": "sync_fg"},
            {"$set": {
                "value": True
            }})
    else:
        flash(result['message'], 'danger')

    return redirect(url_for('home'))




@app.route('/delete_group/<group_name>', methods=['POST'])
def delete_group(group_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Проверяем возможность удаления
    usage_info = check_group_usage_in_rules(group_name)
    group = groups.find_one({"name": group_name})
    has_members = bool(group.get('members'))

    if usage_info or has_members:
        flash('Группа не может быть удалена, так как она используется', 'danger')
        return redirect(url_for('group_usage', group_name=group_name))

    try:
        # Удаляем группу из FortiGate (если настроено)
        firewall = firewalls.find_one()
        if firewall:
            try:
                if (firewall['ipv4'] == '10.128.34.220'):
                    FORTIGATE_BASE_URL = f"http://{firewall['ipv4']}/api/v2"
                else:
                    FORTIGATE_BASE_URL = f"https://{firewall['ipv4']}/api/v2"

                FORTIGATE_API_HEADERS = {
                    "Authorization": f"Bearer {firewall['apikey']}",
                    "Content-Type": "application/json"
                }
                FORTIGATE_API_PARAMS = {"vdom": firewall['VDOM']}

                requests.delete(
                    f"{FORTIGATE_BASE_URL}/cmdb/firewall/addrgrp/{group_name}",
                    headers=FORTIGATE_API_HEADERS,
                    params=FORTIGATE_API_PARAMS,
                    verify=False
                )
            except Exception as e:
                flash(f'Ошибка при удалении группы из FortiGate: {str(e)}', 'warning')

        # Удаляем группу из MongoDB
        result = groups.delete_one({"name": group_name})

        if result.deleted_count > 0:
            flash(f'Группа "{group_name}" успешно удалена', 'success')
            return redirect(url_for('show_groups'))
        else:
            flash('Группа не найдена', 'danger')
            return redirect(url_for('group_usage', group_name=group_name))

    except Exception as e:
        flash(f'Ошибка при удалении группы: {str(e)}', 'danger')
        return redirect(url_for('group_usage', group_name=group_name))


@app.route('/group_usage/<group_name>')
def group_usage(group_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    group = groups.find_one({"name": group_name})
    if not group:
        flash('Группа не найдена', 'danger')
        return redirect(url_for('show_groups'))

    # Проверка использования в правилах МСЭ
    usage_info = check_group_usage_in_rules(group_name)

    # Проверка вхождения в другие группы на МСЭ
    fortigate_inclusions = check_group_inclusion_in_fortigate(group_name)

    # Проверка в локальной базе (для полноты информации)
    local_parent_groups = list(groups.find({"members": group_name}))

    # Проверка возможности удаления
    can_delete = not (usage_info or fortigate_inclusions or group.get('members'))

    nets_names = [net['name'] for net in nets.find({}, {'name': 1})]

    return render_template('group_usage.html',
                           group_name=group_name,
                           group=group,
                           group_description=group.get('description', ''),
                           usage_info=usage_info,
                           fortigate_inclusions=fortigate_inclusions,
                           local_parent_groups=local_parent_groups,
                           can_delete=can_delete,
                           nets_names=nets_names)





@app.route('/delete_net/<net_id>', methods=['POST'])
def delete_net(net_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        # Находим сеть перед удалением
        net = nets.find_one({"_id": ObjectId(net_id)})
        if not net:
            flash('Сеть не найдена', 'danger')
            return redirect(url_for('show_nets'))

        net_name = net['name']

        # 1. Удаляем сеть из всех групп
        groups_updated = remove_net_from_all_groups(net_name)

        # 2. Удаляем саму сеть
        nets.delete_one({"_id": ObjectId(net_id)})

        sync_all_affected_groups(net_name)

        flash(f'Сеть "{net_name}" удалена. Обновлено групп: {groups_updated}', 'success')
    except Exception as e:
        flash(f'Ошибка при удалении сети: {str(e)}', 'danger')

    return redirect(url_for('show_nets'))



@app.route('/edit_net/<net_id>', methods=['POST'])
def edit_net(net_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        # Находим сеть для редактирования
        net = nets.find_one({"_id": ObjectId(net_id)})
        if not net:
            flash('Сеть не найдена', 'danger')
            return redirect(url_for('show_nets'))

        net_name = net['name']

    except Exception as e:
        flash(f'Ошибка при изменении сети: {str(e)}', 'danger')

    return redirect(url_for('show_nets'))

def sync_all_affected_groups(net_name):
    """Синхронизирует все группы, содержавшие удаленную сеть"""
    affected_groups = groups.find({"members": net_name})


@app.route('/add_net', methods=['GET', 'POST'])
def add_net():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            site_id = request.form['site']
            type_id = request.form['type']
            net_name = request.form['name']
            ipv4_raw = request.form.get('ipv4', '')

            # Удаляем пробелы до и после IP-адреса
            ipv4 = ipv4_raw.strip()

            # Проверка корректности формата сети
            try:
                # Пытаемся создать объект IPv4Network для проверки
                ipaddress.IPv4Network(ipv4, strict=False)

                # Проверяем, есть ли уже такая сеть в базе
                if nets.find_one({"ipv4": ipv4}):
                    flash(f'Сеть с IP {ipv4} уже существует', 'danger')
                    return redirect(url_for('add_net'))
            except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                # Отображаем ошибку, если формат сети некорректный
                flash(f'Некорректный формат сети: "{ipv4}". Используйте формат IP/маска, например: 192.168.1.0/24',
                      'danger')
                return redirect(url_for('add_net'))

            net_data = {
                "name": net_name,
                "site": site_id,
                "ipv4": ipv4,  # Используем очищенный и проверенный IP
                "type": type_id,
                "description": request.form.get('description', ''),
                "groups": request.form.getlist('groups', []),
                "created_by": session['username'],
                "created_at": datetime.now()
            }
            nets.insert_one(net_data)

            # 1. Создаем/обновляем группу площадка_Nets_тип
            site_type_group = create_or_update_site_type_group(site_id, type_id, net_name)

            # 2. Создаем/обновляем группу площадка_Nets
            site_group = create_or_update_site_group(site_id, site_type_group)

            # 3. Создаем/обновляем глобальную группу по типу GLB_Nets_тип
            global_type_group = create_or_update_global_type_group(type_id, site_type_group)

            # 4. Создаем/обновляем глобальную группу GLB_Nets
            global_group = create_or_update_global_group(site_group)

            # сбрасываем статус синхронизации в значение False
            state.update_one(
                {"param_name": "sync_fg"},
                {"$set": {
                    "value": False
                }})

            flash('Сеть и связанные группы успешно обновлены!', 'success')
            return redirect(url_for('show_nets'))

        except KeyError as e:
            flash(f'Отсутствует обязательное поле: {str(e)}', 'danger')
            return redirect(url_for('add_net'))

    # Остальная логика GET-запроса...
    site_list = list(sites.find())
    type_list = list(typeNets.find())
    group_list = list(groups.find({"hands": True}))

    return render_template('add_net.html',
                           sites=site_list,
                           types=type_list,
                           groups=group_list)


# >>>>>>>>>>>>>>>>>>>>>>>>>>>> DNS RESOLVE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

@app.route('/show_resolve', methods=['GET', 'POST'])
def show_resolve():
    if 'username' not in session:
        return redirect(url_for('login'))

    servers = list(dns_servers.find())
    default_server = dns_servers.find_one({"default": True}) or servers[0] if servers else None

    if request.method == 'POST':
        input_text = request.form.get('input_text', '')
        server_ip = request.form.get('dns_server', default_server['ip'] if default_server else '8.8.8.8')

        # Парсим входные данные
        addresses = parse_input_addresses(input_text)

        # Выполняем резолвинг
        results = resolve_addresses(addresses, server_ip)

        return render_template('resolve.html',
                               servers=servers,
                               default_server=default_server['ip'] if default_server else '',
                               input_text=input_text,
                               results=results)

    return render_template('resolve.html',
                           servers=servers,
                           default_server=default_server['ip'] if default_server else '',
                           input_text='',
                           results=None)



def parse_input_addresses(input_text):
    """Парсит входной текст и извлекает адреса"""
    separators = [',', ';', '\n', '\t', ' ']
    for sep in separators:
        input_text = input_text.replace(sep, '\n')
    return [addr.strip() for addr in input_text.split('\n') if addr.strip()]


def resolve_addresses(addresses, dns_server):
    """Выполняет резолвинг списка адресов"""
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for address in addresses:
            futures.append(executor.submit(resolve_single_address, address, dns_server))

        for future in futures:
            original, resolved = future.result()
            results.append({'original': original, 'resolved': resolved})

    return results


def resolve_single_address(address, dns_server):
    """Резолвит один адрес (IP или FQDN)"""
    try:
        # Пробуем определить, это IP или FQDN
        if is_valid_ip(address):
            # Это IP - делаем PTR запрос
            query = dns.reversename.from_address(address)
            response = dns.query.tcp(
                dns.message.make_query(query, dns.rdatatype.PTR),
                dns_server,
                timeout=5
            )
            for answer in response.answer:
                for item in answer.items:
                    return address, str(item)
            return address, "FQDN не найден"
        else:
            # Это FQDN - проверяем, содержит ли точка
            if '.' not in address:
                address += '.interrao.ru'  # Добавляем домен по умолчанию

            # Делаем A запрос
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            answers = resolver.resolve(address, 'A')
            ips = [str(r) for r in answers]
            return address, ', '.join(ips) if ips else "IP не найден"
    except dns.exception.Timeout:
        return address, "Таймаут соединения"
    except dns.exception.DNSException as e:
        return address, f"Ошибка DNS: {e}"
    except Exception as e:
        return address, f"Ошибка: {str(e)}"

def is_valid_ip(address):
    """Проверяет, является ли строка валидным IP-адресом"""
    parts = address.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

# <<<<<<<<<<<<<<<<<<<<<<<<<<<< DNS RESOLVE <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<




# >>>>>>>>>>>>>>>>>>>>>>>>>>> добавление динамических сетей через шаблон excecl >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
@app.route('/download_template', methods=['GET'])
def download_template():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Получаем списки для выпадающих списков
    site_list = list(sites.find({}, {'id': 1, 'name': 1, 'description': 1}))
    type_list = list(typeNets.find({}, {'id': 1, 'name': 1, 'description': 1}))

    # Создаём DataFrame для шаблона
    df = pd.DataFrame({
        'site_id': [''] * 5,  # 5 пустых строк для примера
        'ipv4': [''] * 5,
        'type_id': [''] * 5,
        'description': [''] * 5
    })

    # Создаём буфер в памяти для файла Excel
    buffer = BytesIO()

    # Создаём Excel файл в этом буфере
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        # Записываем основной шаблон на первый лист
        df.to_excel(writer, sheet_name='Сети для импорта', index=False)

        # Создаем справочный лист с площадками
        sites_df = pd.DataFrame({
            'id': [site['id'] for site in site_list],
            'name': [site['name'] for site in site_list],
            'description': [site.get('description', '') for site in site_list]
        })
        sites_df.to_excel(writer, sheet_name='Справочник площадок', index=False)

        # Создаем справочный лист с типами сетей
        types_df = pd.DataFrame({
            'id': [type['id'] for type in type_list],
            'name': [type['name'] for type in type_list],
            'description': [type.get('description', '') for type in type_list]
        })
        types_df.to_excel(writer, sheet_name='Справочник типов сетей', index=False)

    # Перемещаем указатель в начало буфера
    buffer.seek(0)

    # Отправляем файл
    return send_file(
        buffer,
        as_attachment=True,
        download_name='template_networks_import.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


@app.route('/upload_excel', methods=['POST'])
def upload_excel():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Проверяем, что файл был отправлен
    if 'excel_file' not in request.files:
        flash('Не выбран файл', 'danger')
        return redirect(url_for('add_net'))

    file = request.files['excel_file']
    if file.filename == '':
        flash('Не выбран файл', 'danger')
        return redirect(url_for('add_net'))

    if not file.filename.endswith('.xlsx'):
        flash('Неверный формат файла. Загрузите файл Excel (.xlsx)', 'danger')
        return redirect(url_for('add_net'))

    try:
        # Читаем файл Excel
        df = pd.read_excel(file, sheet_name='Сети для импорта')

        # Проверяем структуру файла
        required_columns = ['site_id', 'ipv4', 'type_id']
        if not all(col in df.columns for col in required_columns):
            flash('Неверная структура файла. Убедитесь, что используете правильный шаблон', 'danger')
            return redirect(url_for('add_net'))

        # Счетчики для статистики
        total_rows = len(df)
        successful_count = 0
        errors_count = 0

        # Обрабатываем каждую строку
        for index, row in df.iterrows():
            try:
                # Проверяем обязательные поля
                if pd.isna(row['site_id']) or pd.isna(row['ipv4']) or pd.isna(row['type_id']):
                    raise ValueError(f"В строке {index + 1} отсутствуют обязательные данные")

                site_id = str(row['site_id']).strip()
                ipv4 = str(row['ipv4']).strip()
                type_id = str(row['type_id']).strip()
                description = str(row['description']).strip() if 'description' in row and not pd.isna(
                    row['description']) else ''

                # Проверяем, что площадка и тип существуют
                site = sites.find_one({"id": site_id})
                net_type = typeNets.find_one({"id": type_id})

                if not site:
                    raise ValueError(f"В строке {index + 1}: Площадка '{site_id}' не найдена")

                if not net_type:
                    raise ValueError(f"В строке {index + 1}: Тип сети '{type_id}' не найден")

                # Генерируем имя сети (аналогично логике в add_net.html)
                net_name = f"{site_id}_{ipv4}_{type_id}"

                # Проверяем, не существует ли сеть с таким именем
                existing_net = nets.find_one({"name": net_name})
                if existing_net:
                    raise ValueError(f"В строке {index + 1}: Сеть с именем '{net_name}' уже существует")

                # Добавляем сеть
                net_data = {
                    "name": net_name,
                    "site": site_id,
                    "ipv4": ipv4,
                    "type": type_id,
                    "description": description,
                    "created_by": session['username'],
                    "created_at": datetime.now()
                }

                nets.insert_one(net_data)

                # Создаем/обновляем группы (как в функции add_net)
                site_type_group = create_or_update_site_type_group(site_id, type_id, net_name)
                site_group = create_or_update_site_group(site_id, site_type_group)
                global_type_group = create_or_update_global_type_group(type_id, site_type_group)
                global_group = create_or_update_global_group(site_group)

                successful_count += 1

            except Exception as e:
                errors_count += 1
                flash(f"Ошибка в строке {index + 1}: {str(e)}", 'danger')
                continue

        # Сбрасываем статус синхронизации
        state.update_one(
            {"param_name": "sync_fg"},
            {"$set": {"value": False}}
        )

        # Выводим итоговое сообщение
        if successful_count > 0:
            flash(f'Успешно импортировано сетей: {successful_count} из {total_rows}', 'success')
        else:
            flash('Не удалось импортировать ни одной сети', 'danger')

        if errors_count > 0:
            flash(f'Обнаружены ошибки в {errors_count} строках', 'warning')

        return redirect(url_for('show_nets'))

    except Exception as e:
        flash(f'Ошибка при обработке файла: {str(e)}', 'danger')
        return redirect(url_for('add_net'))


# <<<<<<<<<<<<<<<<<<<<<<<<<<< добавление динамических сетей через шаблон excecl <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
















@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    tab = request.args.get('tab', 'sites')

    if request.method == 'POST':
        if tab == 'sites':
            if 'delete_id' in request.form:
                sites.delete_one({"_id": ObjectId(request.form['delete_id'])})
                flash('Site deleted successfully!', 'success')
            else:
                site_data = {
                    "name": request.form['name'],
                    "description": request.form['description'],
                    "id": request.form['id']
                }

                if 'existing_id' in request.form and request.form['existing_id']:
                    sites.update_one({"_id": ObjectId(request.form['existing_id'])},
                                     {"$set": site_data})
                    flash('Site updated successfully!', 'success')
                else:
                    sites.insert_one(site_data)
                    flash('Site added successfully!', 'success')

        elif tab == 'typenets':
            if 'delete_id' in request.form:
                typeNets.delete_one({"_id": ObjectId(request.form['delete_id'])})
                flash('Type deleted successfully!', 'success')
            else:
                type_data = {
                    "name": request.form['name'],
                    "description": request.form['description'],
                    "id": request.form['id']
                }

                if 'existing_id' in request.form and request.form['existing_id']:
                    typeNets.update_one({"_id": ObjectId(request.form['existing_id'])},
                                        {"$set": type_data})
                    flash('Type updated successfully!', 'success')
                else:
                    typeNets.insert_one(type_data)
                    flash('Type added successfully!', 'success')

        elif tab == 'firewalls':
            if 'delete_id' in request.form:
                firewalls.delete_one({"_id": ObjectId(request.form['delete_id'])})
                flash('Firewall deleted successfully!', 'success')
            else:
                firewall_data = {
                    "NameNGFW": request.form['NameNGFW'],
                    "VDOM": request.form['VDOM'],
                    "ipv4": request.form['ipv4'],
                    "apikey": request.form['apikey'],
                    "description": request.form['description'],
                    "name": request.form['name'],
                    "id": request.form['id']
                }

                if 'existing_id' in request.form and request.form['existing_id']:
                    firewalls.update_one({"_id": ObjectId(request.form['existing_id'])},
                                         {"$set": firewall_data})
                    flash('Firewall updated successfully!', 'success')
                else:
                    firewalls.insert_one(firewall_data)
                    flash('Firewall added successfully!', 'success')

        elif tab == 'dns_servers':
            if 'delete_id' in request.form:
                dns_servers.delete_one({"_id": ObjectId(request.form['delete_id'])})
                flash('DNS сервер удален', 'success')
            else:
                server_data = {
                    "name": request.form['name'],
                    "ip": request.form['ip'],
                    "description": request.form['description'],
                    "default": 'default' in request.form
                }

                if 'default' in request.form:
                    # Сбрасываем default у всех других серверов
                    dns_servers.update_many({}, {"$set": {"default": False}})

                if 'existing_id' in request.form and request.form['existing_id']:
                    dns_servers.update_one(
                        {"_id": ObjectId(request.form['existing_id'])},
                        {"$set": server_data}
                    )
                    flash('DNS сервер обновлен', 'success')
                else:
                    dns_servers.insert_one(server_data)
                    flash('DNS сервер добавлен', 'success')

            return redirect(url_for('settings', tab=tab))


        return redirect(url_for('settings', tab=tab))

    site_list = list(sites.find())
    type_list = list(typeNets.find())
    firewall_list = list(firewalls.find())
    dns_servers_list = list(dns_servers.find())

    return render_template('settings.html',
                           tab=tab,
                           sites=site_list,
                           types=type_list,
                           firewalls=firewall_list,
                           dns_servers=dns_servers_list)


if __name__ == '__main__':
    app.run(debug=True)
