"""Модуль описывает тесты для проверки методов, реализемых в классе
   VirusTotalAPI.
   
   Константы:
       API_KEY - должна содержать строку с вашим ключем доступа к API.
       TEST_TIMEOUT - необходима для проверки методов при превышении времени
           ожидания ответа от сервера.
       TEST_FILE_PATH - должен содержать путь к файлу, используемому для
           тестирования.
       TEST_HASH - тестовое значение MD5-хэша.
       TEST_HASH_LIST - тестовый список из 4-х MD5-хэшей.
       TEST_URL - тестовое значение URL-адреса.
       TEST_URL_LIST - тестовый список из 4-х URL-адресов.
       TEST_IP - тестовое значение IP-адреса.
       TEST_DOMAIN - тестовое значение имени домена.
       TEST_PROXI - тестовое значение  протокола и URL-адрес прокси-сервера
           (необходимо для моделирования ошибки соединения с сервером).
       TIME_DELAY - необходима для обеспечения возможности многократной
           отправки запросов на сервер без превышения лимита.
"""
import unittest
import time

from virustotalapi import VirusTotalAPI

API_KEY = '<ключ доступа к API virustotal>'

TEST_TIMEOUT = 0.05

TEST_FILE_PATH = 'eicar.com'

TEST_HASH = '99017f6eebbac24f351415dd410d522d'

TEST_HASH_LIST = ('eb5911054939bd90a7448e804e9da52a,'
                  '3cbf18fee357d5a33aab56795238b097,'
                  'df6c18ddf76bc0240d4ad73068dd4353,'
                  'b18844bf115530b317a0aed8426efaa4')

TEST_URL = 'www.github.com/drobotun'

TEST_URL_LIST = ('www.github.com/drobotun\n'
                 'www.xakep.ru/author/drobotun\n'
                 'www.habr.com/ru/users/drobotun\n'
                 'www.virustotal.com/gui/user/drobotun/comments')

TEST_IP = '216.239.38.21'

TEST_DOMAIN = 'www.virustotal.com'

TEST_PROXI = {'http': '10.10.1.10:3128',
              'https': '10.10.1.10:1080',
              'ftp': '10.10.1.10:3128'}

TIME_DELAY = 30


class TestFileReport(unittest.TestCase):
    """Класс для проверки метода 'file_report'. Проверяется:
       - работа метода при корректных входных параметрах;
       - работа метода при корректных входных параметрах в виде строки из
         4 хэшей;
       - работа метода при ошибке соединения с сервером;
       - работа метода при превышении времени ожидания ответа от сервера;
       - работа метода с использованием неверного ключа доступа к API;
       - работа метода при некорректных входных параметрах;
       - работа метода при превышении лимита запросов (более 4-х запросов
         в минуту).
    """

    def test_file_report_correct_param(self):
        """Проверка метода 'file_report' с корректными входными параметрами.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_report(TEST_HASH)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'],
                         vt_api.ERROR_SUCCESS)

    def test_file_report_correct_param_list(self):
        """Проверка метода 'file_report' с корректными входными параметрами
           в виде строки из 4 хэшей;
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_report(TEST_HASH_LIST)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'],
                         vt_api.ERROR_SUCCESS)

    def test_file_report_connection_error(self):
        """Проверка метода 'file_report' при ошибке соединения с сервером.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_report(TEST_HASH, None, TEST_PROXI)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_CONNECT)

    def test_file_report_timeout(self):
        """Проверка метода 'file_report' при превышении времени ожидании
           ответа от сервера.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_report(TEST_HASH, TEST_TIMEOUT)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_TIMEOUT)

    def test_file_report_invalid_api_key(self):
        """Проверка метода 'file_report' с использованием неверного
           ключа доступа к API.
        """
        vt_invalid_api_key = VirusTotalAPI()
        time.sleep(TIME_DELAY)
        response = vt_invalid_api_key.file_report(TEST_HASH)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_invalid_api_key.ERROR_HTTP)

    def test_file_report_incorrect_param(self):
        """Проверка метода 'file_report' с некорректными входными параметрами.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_report('This is an incorrect hash value')
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_file_report_limit(self):
        """Проверка метода 'file_report' при превышении лмита запросов
        (более 4-х запросов в минуту).
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_report(TEST_HASH)
        response = vt_api.file_report(TEST_HASH)
        response = vt_api.file_report(TEST_HASH)
        response = vt_api.file_report(TEST_HASH)
        response = vt_api.file_report(TEST_HASH)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_HTTP)


class TestFileScan(unittest.TestCase):
    """Класс для проверки метода 'file_scan'. Проверяется:
       - работа метода при корректных входных параметрах (валидный путь
         к сканируемому файлу);
       - работа метода при ошибке соединения с сервером;
       - работа метода при превышении времени ожидания ответа от сервера;
       - работа метода с использованием неверного ключа доступа к API;
       - работа метода при отправке файла размером более 32 MB;
       - работа метода при некорректных входных параметрах (невалидный
         путь к сканируемому файлу).
    """

    def test_file_scan_correct_param(self):
        """Проверка метода 'file_scan' при корректных входных параметрах
           (валидный путь к сканируемому файлу).
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_scan(TEST_FILE_PATH)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_file_scan_connect_error(self):
        """Проверка метода 'file_scan' при ошибке соединения с сервером.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_scan(TEST_FILE_PATH, None, TEST_PROXI)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_CONNECT)

    def test_file_scan_timeout(self):
        """Проверка метода 'file_scan' при превышении времени ожидания ответа
           от сервера.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_scan(TEST_FILE_PATH, TEST_TIMEOUT)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_TIMEOUT)

    def test_file_scan_invalid_api_key(self):
        """Проверка метода 'file_scan' при неверном ключе доступа к API.
        """
        vt_invalid_api_key = VirusTotalAPI()
        time.sleep(TIME_DELAY)
        response = vt_invalid_api_key.file_scan(TEST_FILE_PATH)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_invalid_api_key.ERROR_HTTP)

    def test_file_scan_file_size_error(self):
        """Проверка метода 'file_scan' при отправке файла размером
           более 32 MB.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_scan('d:/test_file.zip')  ## файл более 32 MB
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_HTTP)

    def test_file_scan_file_name_error(self):
        """Проверка метода 'file_scan' при некорректных входных параметрах
          (невалидный путь к сканируемому файлу).
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.file_scan(' ')
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_FILE)


class TestURLReport(unittest.TestCase):
    """Класс для проверки метода 'url_report'. Проверяется:
       - работа метода при корректных входных параметрах (валидный
         URL-адрес);
       - работа метода при корректных входных параметрах (валидный
         URL-адрес) с использованием параметра 'scan';
       - работа метода при корректных входных параметрах (список из
         4-х валидных URL-адресов);
       - работа метода при корректных входных параметрах (список из
         4-х валидных URL-адресов) с использованием параметра 'scan';
       - работа метода при ошибке соединения с сервером;
       - работа метода при превышении времени ожидания ответа от сервера;
       - работа метода с использованием неверного ключа доступа к API;
       - работа метода при некорректных входных параметрах;
       - работа метода при превышении лимита запросов (более 4-х запросов
         в минуту).
    """

    def test_url_report_correct_param(self):
        """Проверка метода 'url_report' при корректных входных параметрах.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_report(TEST_URL)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_url_report_correct_param_scan(self):
        """Проверка метода 'url_report' при корректных входных параметрах
           с использованием параметра 'scan'.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_report(TEST_URL, '1')
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_url_report_correct_param_list(self):
        """Проверка метода 'url_report' при корректных входных параметрах
           в виде списка из 4-х URL-адресов.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_report(TEST_URL_LIST)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_url_report_correct_param_list_scan(self):
        """Проверка метода 'url_report' при корректных входных параметрах
           в виде списка из 4-х URL-адресов с использованием параметра
           'scan'.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_report(TEST_URL_LIST, '1')
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_url_report_connect_error(self):
        """Проверка метода 'url_report' при ошибке соединения с сервером.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_report(TEST_URL, 0, None, TEST_PROXI)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_CONNECT)

    def test_url_report_timeout(self):
        """Проверка метода 'url_report' при превышении времени ожидания от
           сервера.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_report(TEST_URL, 0, TEST_TIMEOUT)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_TIMEOUT)

    def test_url_report_invalid_api_key(self):
        """Проверка метода 'url_report' при неверном ключе доступа к API.
        """
        vt_api_invalid_api_key = VirusTotalAPI()
        time.sleep(TIME_DELAY)
        response = vt_api_invalid_api_key.url_report(TEST_URL)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api_invalid_api_key.ERROR_HTTP)

    def test_url_report_incorrect_param(self):
        """Проверка метода 'url_report' при некорректных входных параметрах.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_report('This is an invalid URL value')
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_url_report_limit(self):
        """Проверка метода 'url_report' при превышении лмита запросов
           (более 4-х запросов в минуту).
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_report(TEST_URL)
        response = vt_api.url_report(TEST_URL)
        response = vt_api.url_report(TEST_URL)
        response = vt_api.url_report(TEST_URL)
        response = vt_api.url_report(TEST_URL)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_HTTP)


class TestURLScan(unittest.TestCase):
    """Класс для проверки метода 'url_scan'. Проверяется:
       - работа метода при корректных входных параметрах (валидный
         URL-адрес);
       - работа метода при корректных входных параметрах (список из
         4-х валидных URL-адресов);
       - работа метода при ошибке соединения с сервером;
       - работа метода при превышении времени ожидания ответа от сервера;
       - работа метода с использованием неверного ключа доступа к API;
       - работа метода при некорректных входных параметрах;
       - работа метода при превышении лимита запросов (более 4-х запросов
         в минуту).
    """

    def test_url_scan_correct_param(self):
        """Проверка метода 'url_scan' при корректных входных параметрах.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_scan(TEST_URL)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_url_scan_correct_param_list(self):
        """Проверка метода 'url_scan' при корректных входных параметрах
           в виде списка из 4-х URL-адресов.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_scan(TEST_URL_LIST)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_url_scan_connect_error(self):
        """Проверка метода 'url_scan' при ошибке соединения с сервером.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_scan(TEST_URL, None, TEST_PROXI)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_CONNECT)

    def test_url_scan_timeout(self):
        """Проверка метода 'url_scan' при превышении времени ожидания
           ответа от сервера.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_scan(TEST_URL, TEST_TIMEOUT)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_TIMEOUT)

    def test_url_scan_invalid_api_key(self):
        """Проверка метода 'url_scan' при неверном ключе доступа к API.
        """
        vt_invalid_api_key = VirusTotalAPI()
        time.sleep(TIME_DELAY)
        response = vt_invalid_api_key.url_scan(TEST_URL)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'],
                         vt_invalid_api_key.ERROR_HTTP)

    def test_url_scan_incorrect_param(self):
        """Проверка метода 'url_scan' при некорректных входных параметрах.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_scan('This is an invalid URL value')
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_url_scan_limit(self):
        """Проверка метода 'url_scan' при превышении лмита запросов
           (более 4-х запросов в минуту).
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.url_scan(TEST_URL)
        response = vt_api.url_scan(TEST_URL)
        response = vt_api.url_scan(TEST_URL)
        response = vt_api.url_scan(TEST_URL)
        response = vt_api.url_scan(TEST_URL)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_HTTP)


class TestIPReport(unittest.TestCase):
    """Класс для проверки метода 'ip_report'. Проверяется:
       - работа метода при корректных входных параметрах (валидный
         IP-адрес);
       - работа метода при ошибке соединения с сервером;
       - работа метода при превышении времени ожидания ответа от сервера;
       - работа метода с использованием неверного ключа доступа к API;
       - работа метода при некорректных входных параметрах;
       - работа метода при превышении лимита запросов (более 4-х запросов
         в минуту).
    """

    def test_ip_report_correct_param(self):
        """Проверка метода 'ip_report' при корректных входных параметрах.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.ip_report(TEST_IP)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_ip_report_connect_error(self):
        """Проверка метода 'ip_report' при ошибке соединения с сервером.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.ip_report(TEST_IP, None, TEST_PROXI)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_CONNECT)

    def test_ip_report_timeout(self):
        """Проверка метода 'ip_report' при превышении времени ожидания
           ответа от сервера.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.ip_report(TEST_IP, TEST_TIMEOUT)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_TIMEOUT)

    def test_ip_report_invalid_api_key(self):
        """Проверка метода 'ip_report' при неверном ключе доступа к API.
        """
        vt_invalid_api_key = VirusTotalAPI()
        time.sleep(TIME_DELAY)
        response = vt_invalid_api_key.ip_report(TEST_IP)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_invalid_api_key.ERROR_HTTP)

    def test_ip_report_incorrect_param(self):
        """Проверка метода 'url_report' при некорректных входных параметрах.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.ip_report('This is an invalid IP value')
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_ip_report_limit(self):
        """Проверка метода 'ip_report' при превышении лмита запросов
           (более 4-х запросов в минуту).
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.ip_report(TEST_IP)
        response = vt_api.ip_report(TEST_IP)
        response = vt_api.ip_report(TEST_IP)
        response = vt_api.ip_report(TEST_IP)
        response = vt_api.ip_report(TEST_IP)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_HTTP)


class TestDpmainReport(unittest.TestCase):
    """Класс для проверки метода 'domain_report'. Проверяется:
       - работа метода при корректных входных параметрах (валидное
         имя домена);
       - работа метода при ошибке соединения с сервером;
       - работа метода при превышении времени ожидания ответа от сервера;
       - работа метода с использованием неверного ключа доступа к API;
       - работа метода при некорректных входных параметрах;
       - работа метода при превышении лимита запросов (более 4-х запросов
         в минуту).
    """

    def test_domain_report_correct_param(self):
        """Проверка метода 'domain_report' при корректных входных параметрах.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.domain_report(TEST_DOMAIN)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_domain_report_connection_error(self):
        """Проверка метода 'domain_report' при ошибке соединения с сервером.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.domain_report(TEST_DOMAIN, None, TEST_PROXI)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_CONNECT)

    def test_domain_report_timeout(self):
        """Проверка метода 'domain_report' при превышении времени ожидания
           ответа от сервера.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.domain_report(TEST_DOMAIN, TEST_TIMEOUT)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_TIMEOUT)

    def test_domain_report_invalid_api_key(self):
        """Проверка метода 'domain_report' при неверном ключе доступа к API.
        """
        vt_invalid_api_key = VirusTotalAPI()
        time.sleep(TIME_DELAY)
        response = vt_invalid_api_key.domain_report(TEST_DOMAIN)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_invalid_api_key.ERROR_HTTP)

    def test_domain_report_incorrect_param(self):
        """Проверка метода 'domain_report' при некорректных входных
           параметрах.
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.domain_report('This is an invalid domain value')
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_SUCCESS)

    def test_domain_report_limit(self):
        """Проверка метода 'idomain_report' при превышении лмита запросов
           (более 4-х запросов в минуту).
        """
        vt_api = VirusTotalAPI(API_KEY)
        time.sleep(TIME_DELAY)
        response = vt_api.domain_report(TEST_DOMAIN)
        response = vt_api.domain_report(TEST_DOMAIN)
        response = vt_api.domain_report(TEST_DOMAIN)
        response = vt_api.domain_report(TEST_DOMAIN)
        response = vt_api.domain_report(TEST_DOMAIN)
        time.sleep(TIME_DELAY)
        self.assertEqual(response['error_code'], vt_api.ERROR_HTTP)


if __name__ == '__main__':
    unittest.main()
