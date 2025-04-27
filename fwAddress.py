import ipaddress
import re
import socket


class fwNetAddress:
    def __init__(self, address):
        """
        Инициализация объекта адреса
        :param address: строка с IP, подсетью или FQDN
        """
        self.original_address = str(address).strip()
        self.address_type = self._determine_address_type()
        self.valid = self._validate_address()

    def _determine_address_type(self):
        """Определяет тип адреса: ip, subnet, fqdn или other"""
        # Проверяем на IP/подсеть
        try:
            ipaddress.IPv4Network(self.original_address, strict=False)
            return 'ip' if '/' not in self.original_address else 'subnet'
        except ValueError:
            pass

        # Проверяем на FQDN
        if self._is_valid_fqdn(self.original_address):
            return 'fqdn'

        return 'other'

    def _is_valid_fqdn(self, fqdn):
        """Проверяет валидность FQDN"""
        if not fqdn or len(fqdn) > 255:
            return False
        if fqdn[-1] == ".":
            fqdn = fqdn[:-1]
        allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in fqdn.split("."))

    def _validate_address(self):
        """Проверяет валидность адреса в зависимости от его типа"""
        if self.address_type in ('ip', 'subnet'):
            try:
                ipaddress.IPv4Network(self.original_address, strict=False)
                return True
            except ValueError:
                return False
        elif self.address_type == 'fqdn':
            return self._is_valid_fqdn(self.original_address)
        return False  # Для типа 'other' считаем невалидным

    def contains(self, other_address):
        """
        Проверяет, входит ли другой адрес в текущую подсеть
        :param other_address: строка с IP адресом для проверки
        :return: bool
        """
        if self.address_type != 'subnet':
            return False

        try:
            network = ipaddress.IPv4Network(self.original_address, strict=False)
            other_ip = ipaddress.IPv4Address(other_address)
            return other_ip in network
        except (ValueError, ipaddress.AddressValueError):
            return False

    def __str__(self):
        return f"fwIPv4(type={self.address_type}, address={self.original_address}, valid={self.valid})"

    @property
    def is_valid(self):
        """Возвращает True если адрес валидный"""
        return self.valid

    @property
    def type(self):
        """Возвращает тип адреса"""
        return self.address_type
