import re
from fwNetAddress import fwNetAddress

class fwCode:
    def __init__(self, code_text):
        self.fwcode = code_text
        self.lines = self.fwcode.split('\n')
        self.current_fws = []
        self.addresses = {}  # Явная инициализация
        self.groups = {}  # Явная инициализация
        self.policies = {}  # Явная инициализация

    def remove_trailing_spaces(self):
        """Удаляет пробелы в конце каждой строки."""
        self.lines = [line.rstrip() for line in self.lines]
        self.fwcode = '\n'.join(self.lines)
        return self.fwcode

    def remove_comments(self):
        """
        Удаляет комментарии из кода:
        - Если строка начинается с # - удаляет всю строку
        - Если # встречается в середине строки - удаляет всё начиная с #
        Возвращает очищенный текст
        """
        cleaned_lines = []

        for line in self.lines:
            # Удаляем строки, которые начинаются с #
            if line.strip().startswith('#'):
                continue

            # Удаляем части строк после #
            comment_pos = line.find('#')
            if comment_pos >= 0:
                line = line[:comment_pos]

            # Добавляем строку, если она не пустая после обработки
            if line.strip():
                cleaned_lines.append(line)

        self.lines = cleaned_lines
        self.fwcode = '\n'.join(self.lines)

        return self.fwcode

    def normalize_case(self):
        """Приводит все команды к верхнему регистру."""
        self.lines = [line.upper() for line in self.lines]
        self.fwcode = '\n'.join(self.lines)
        return self.fwcode

    def validate_syntax(self):
        """Проверяет базовый синтаксис (например, наличие известных команд)."""
        valid_commands = {'PRINT', 'SET', 'ADD'}
        errors = []
        for i, line in enumerate(self.lines, 1):
            stripped = line.strip()
            if stripped:  # Игнорируем пустые строки
                command = stripped.split()[0].upper()
                if command not in valid_commands:
                    errors.append(f"Line {i}: Unknown command '{command}'")
        return errors if errors else "Syntax is valid"





    def check_allowed_chars(self):
        """Проверяет, используются ли только разрешённые символы."""
        # Базовые разрешённые символы
        allowed_chars = set(
            'abcdefghijklmnopqrstuvwxyz'
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            '0123456789'
            '=!{}/.,"-_#* '  # Пробел в конце
        )

        # Разрешённые спецсимволы (перевод строки, табуляция)
        allowed_special = {'\n', '\t', '\r'}

        forbidden_chars = set()

        for line_num, line in enumerate(self.lines, 1):
            for char in line:
                # Пропускаем разрешённые спецсимволы
                if char in allowed_special:
                    continue

                # Проверяем основной набор символов
                if char not in allowed_chars:
                    forbidden_chars.add((char, line_num))

        if forbidden_chars:
            # Форматируем вывод для непечатаемых символов
            error_messages = []
            for char, line_num in forbidden_chars:
                # Для непечатаемых символов показываем hex-код
                if ord(char) < 32 or ord(char) > 126:
                    char_repr = f"0x{ord(char):02x}"
                else:
                    char_repr = f"'{char}'"
                error_messages.append(f"Недопустимый символ {char_repr} в строке {line_num}")

            return False, "Найдены недопустимые символы:\n" + "\n".join(error_messages)
        return True, "Все символы допустимы"

    def extract_addresses_with_fw(self):
        """
        Извлекает адреса с указанием фаервола, к которому они относятся.
        Возвращает словарь вида {fw_name: [address1, address2, ...]}
        """
        result = {}
        fw_pattern = re.compile(r'^\s*set\s+fw\s*=\s*([^\s#]+)', re.IGNORECASE)
        addr_pattern = re.compile(r'(?:src|dst)\s*=\s*[\'"]?([^\s\'"]+)', re.IGNORECASE)

        # Состояние парсера
        current_fw = None
        in_group = False
        group_addresses = []

        for line in self.lines:
            # Проверяем смену контекста фаервола
            fw_match = fw_pattern.search(line)
            if fw_match:
                current_fw = fw_match.group(1)
                if current_fw not in result:
                    result[current_fw] = []
                continue

            # Пропускаем пока не задан МЭ
            if not current_fw:
                continue

            # Обработка начала группы
            if not in_group and re.match(r'^\s*Group\s+\w+\s*\{', line, re.IGNORECASE):
                in_group = True
                group_addresses = []
                continue

            # Обработка конца группы
            if in_group and '}' in line:
                in_group = False
                if current_fw and group_addresses:
                    result[current_fw].extend(group_addresses)
                continue

            # Если внутри группы - собираем адреса
            if in_group:
                address = line.strip()
                if address:
                    _address=fwNetAddress(address)
                    if _address.is_valid: # берем только адреса с типом ip, fqdn, subnet
                        group_addresses.append(address)
                continue

            # Стандартная обработка src/dst (только если не внутри группы)
            if current_fw and not in_group:
                addr_match = addr_pattern.search(line)
                if addr_match:
                    address = addr_match.group(1).strip('\'"')
                    _address = fwNetAddress(address)
                    if _address.is_valid: # берем только адреса с типом ip, fqdn, subnet
                        result[current_fw].append(address)

        return result

    def get_addresses_report(self):
        """Возвращает форматированный отчет о распределении адресов по фаерволам"""
        addresses = self.extract_addresses_with_fw()
        report = []

        for fw, addr_list in addresses.items():
            report.append(f"Фаервол: {fw}")
            for addr in addr_list:
                report.append(f"  - {addr}")
            report.append("")  # Пустая строка для разделения

        return "\n".join(report)



    def replace_command(self, old_command, new_command):
        """Заменяет одну команду на другую."""
        self.lines = [line.replace(old_command, new_command, 1) for line in self.lines]
        self.fwcode = '\n'.join(self.lines)
        return self.fwcode

    def add_line_numbers(self):
        """Добавляет номера строк в начало каждой строки."""
        self.lines = [f"{i + 1}: {line}" for i, line in enumerate(self.lines)]
        self.fwcode = '\n'.join(self.lines)
        return self.fwcode

    def execute(self):
        """Эмулирует выполнение кода (простая интерпретация)."""
        variables = {}
        output = []
        for line in self.lines:
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split()
            command = parts[0].upper()

            if command == 'PRINT':
                if len(parts) > 1:
                    output.append(' '.join(parts[1:]))
            elif command == 'SET':
                if len(parts) == 3:
                    variables[parts[1]] = parts[2]
            elif command == 'ADD':
                if len(parts) == 4 and parts[1] in variables:
                    try:
                        variables[parts[1]] = str(int(variables.get(parts[1], 0)) + int(parts[3]))
                    except ValueError:
                        output.append(f"Error: Invalid number in ADD at line: {line}")

        return {'output': output, 'variables': variables}

    def extract_configuration(self):
        self.current_fws = []
        self.addresses = {}
        self.groups = {}
        self.policies = {}
        current_group = None
        current_policy = None

        for line in self.lines:
            line = line.strip()
            if not line:
                continue

            # Обработка SET
            set_match = re.match(r'^set\s+([^\s#]+)', line, re.IGNORECASE)
            if set_match:
                self.current_fws = [fw.strip() for fw in set_match.group(1).split(',')]
                continue

            # Обработка групп
            group_match = re.match(r'^Group\s+([\w-]+)\s*{', line, re.IGNORECASE)
            if group_match:
                current_group = {
                    'name': group_match.group(1),
                    'members': []
                }
                continue

            if current_group and '}' in line:
                for fw in self.current_fws:
                    if fw not in self.groups:
                        self.groups[fw] = {}
                    self.groups[fw][current_group['name']] = current_group['members']
                current_group = None
                continue

            if current_group:
                member = line.strip(' ,;')
                if member:
                    current_group['members'].append(member)
                    # Добавление адресов из групп
                    for fw in self.current_fws:
                        if fw not in self.addresses:
                            self.addresses[fw] = []
                        if member not in self.addresses[fw]:
                            self.addresses[fw].append(member)
                continue

            # Обработка политик
            policy_match = re.match(r'^Policy\s+([\w\-\.]+)\s*{', line, re.IGNORECASE)
            if policy_match:
                current_policy = {
                    'name': policy_match.group(1),
                    'src': [],
                    'dst': [],
                    'svc': [],
                    'sec': 'base',
                    'after': None
                }
                continue

            if current_policy:
                if '}' in line:
                    for fw in self.current_fws:
                        if fw not in self.policies:
                            self.policies[fw] = []
                        self.policies[fw].append(current_policy)
                    current_policy = None
                    continue
                # Обработка только src/dst как адресов
                key_value = re.split(r'\s*=\s*', line, 1)
                if len(key_value) == 2:
                    key = key_value[0].strip().lower()
                    value = key_value[1].strip()

                    # Обработка адресов
                    if key in ('src', 'dst'):
                        addresses = [a.strip() for a in value.split(',')]
                        for addr in addresses:
                            addr_obj = fwNetAddress(addr)
                            if addr_obj.is_valid:
                                for fw in self.current_fws:
                                    if fw not in self.addresses:
                                        self.addresses[fw] = []
                                    if addr not in self.addresses[fw]:
                                        self.addresses[fw].append(addr)
                        # Добавляем только в соответствующие поля политики
                        current_policy[key].extend(addresses)

                    # Обработка сервисов и других параметров
                    elif key == 'svc':
                        current_policy['svc'].extend([s.strip() for s in value.split(',')])
                    elif key == 'sec':
                        current_policy['sec'] = value
                    elif key == 'after':
                        current_policy['after'] = int(value)






    def generate_report(self):
        try:
            report = []
            fws = set()
            fws.update(self.addresses.keys())
            fws.update(self.groups.keys())
            fws.update(self.policies.keys())

            for fw in fws:
                report.append(f"\n=== Межсетевой экран: {fw} ===")

                if fw in self.addresses and self.addresses[fw]:
                    report.append("\nСоздаваемые адреса:")
                    for addr in self.addresses[fw]:
                        addr_type = fwNetAddress(addr).type
                        report.append(f"  - {addr} ({addr_type})")

                if fw in self.groups and self.groups[fw]:
                    report.append("\nСоздаваемые группы:")
                    for group, members in self.groups[fw].items():
                        report.append(f"  Группа: {group}")
                        for member in members:
                            report.append(f"    - {member}")

                if fw in self.policies and self.policies[fw]:
                    report.append("\nСоздаваемые политики:")
                    for policy in self.policies[fw]:
                        report.append(f"  Политика: {policy['name']}")
                        report.append(f"    Источники: {', '.join(policy['src'])}")
                        report.append(f"    Назначения: {', '.join(policy['dst'])}")
                        report.append(f"    Сервисы: {', '.join(policy['svc'])}")
                        report.append(f"    Профиль безопасности: {policy['sec']}")
                        if policy['after']:
                            report.append(f"    Разместить после правила: {policy['after']}")

            return "\n".join(report) if report else "Нет изменений для применения"
        except Exception as e:
            return f"Ошибка генерации отчета: {str(e)}"


    def get_code(self):
        """Возвращает текущий код."""
        return self.fwcode