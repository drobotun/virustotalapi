"""Модуль описывает класс VirusTotalAPI, реализующий доступ к функциям API
   сервиса virustotai.com.

   Евгений Дроботун (с) 2019
   Лицензия: MIT ()

   Открытый API VirusTotal позволяет загружать и сканировать файлы, отправлять
   и сканировать URL-адреса, получать отчеты о завершенном сканировании файлов
   и URL-адресов без необходимости использования интерфейса веб-сайта
   www.virustotal.com.

   Более подробная информация на:
   https://www.virustotal.com/en/documentation/public-api/

   Пример использования:

   import json
   from virustotalapi import VirusTotalAPI

   vt_api = VirusTotalAPI(<Здесь необходима строка с ключом доступа к API>)
   response = vt_api.file_report('8abd3f80059113ffd4693be25ba3f691')
       ...
   print('Error code = ', response['error_code'])
   print(json.dumps(response['result'], sort_keys=False, indent=4))
      ...
"""
import requests


class VirusTotalAPI(object):
    """Методы класса реализует функции открытого API сервиса virustotal.com,
       доступные с использованием открытого ключа доступа к API.

       Константы:
         ERROR_SUCCESS - константа, возвращаемая методами в случае успешного
           завершения метода.
         ERROR_HTTP - константа, возвращаемая методами в случае ответа сервера
           с HTTP-статус кодом не равном 200
         ERROR_CONNECT - константа, возвращаемая методами в случае ошибки
           соединения с сервером.
         ERROR_TIMEOUT - константа, возвращаемая методами в случае превышения
           времени ожидания ответа от сервера.
         ERROR_FILE - константа, возвращаемая методом 'file_scan' в случае
           ошибки чтения сканируемого файла.

       Методы:
         file_report: Получение результатов сканирования файлов.
         file_scan: Отправка файла на сервер для сканирования.
         url_report: Получение результатов сканирования URL-адреса.
         url_scan: Отправка URL-адреса для сканирования на сервер.
         ip_report: Получение результатов сканирования IP-адреса.
         domain_report: Получение результатов сканирования имени домена.
    """
    ERROR_SUCCESS = 0x00
    ERROR_HTTP = 0x64
    ERROR_CONNECT = 0x65
    ERROR_TIMEOUT = 0x66
    ERROR_FILE = 0x67

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/vtapi/v2'
        self.version_api = 2

    def file_report(self, resource, timeout=None, proxies=None):
        """Получение результатов сканирования файлов.

           Аргументы:
              resource: Строка, содержащая хэш файла (MD5, SHA1 или SHA256) или
                 параметр 'scan_id', полученный с помощью метода 'file_scan'.
                 Также возможно передать строку, содержащую до четырех хэшей
                 или 'scan_id', разделенных запятыми.
              timout: Время (в секундах), в течение которого будет ожидаться
                 ответ от сервера (необязательный параметр).
              proxies: Протокол и URL-адрес прокси-сервера (необязательный
                 параметр).

           Возвращаемое значение:
              Словарь вида {'error_code': < error_code>, 'result': <result>}.
              Если метод завершился удачно ('error_code' равен ERROR_SUCCESS),
              то 'result' содержит ответ сервера в виде JSON. В обратном
              случае ('error_code' не равен ERROR_SUCCESS) 'result' содержит
              наименование ошибки.
        """
        api_url = self.base_url + '/file/report'
        params = dict(apikey=self.api_key, resource=resource)
        try:
            response = requests.get(api_url, params=params,
                                    timeout=timeout, proxies=proxies)
        except requests.ConnectionError:
            return dict(error_code=self.ERROR_CONNECT,
                        result='Connection error')
        except requests.Timeout:
            return dict(error_code=self.ERROR_TIMEOUT,
                        result='Timeout error')
        else:
            return _return_result(response)

    def file_scan(self, path_file_scan, timeout=None, proxies=None):
        """Отправка файла на сервер для сканирования.

           Аргументы:
              path_file_scan: Строка, содержащая путь к сканируемому файлу.
              timout: Время (в секундах), в течение которого будет ожидаться
                 ответ от сервера (необязательный параметр).
              proxies: Протокол и URL-адрес прокси-сервера (необязательный
                 параметр).

           Возвращаемое значение:
              Словарь вида {'error_code': < error_code>, 'result': <result>}.
              Если метод завершился удачно ('error_code' равен ERROR_SUCCESS),
              то 'result' содержит ответ сервера в виде JSON. В обратном
              случае ('error_code' не равен ERROR_SUCCESS) 'result' содержит
              наименование ошибки.
        """
        api_url = self.base_url + '/file/scan'
        params = dict(apikey=self.api_key)
        try:
            with open(path_file_scan, 'rb') as file:
                files = dict(file=(path_file_scan, file))
                response = requests.post(api_url, files=files, params=params,
                                         timeout=timeout, proxies=proxies)
        except requests.ConnectionError:
            return dict(error_code=self.ERROR_CONNECT,
                        result='Connection error')
        except requests.Timeout:
            return dict(error_code=self.ERROR_TIMEOUT,
                        result='Timeout error')
        except IOError:
            return dict(error_code=self.ERROR_FILE,
                        result='File not found or file read error')
        else:
            return _return_result(response)

    def url_report(self, resource, scan='0', timeout=None, proxies=None):
        """Получение результатов сканирования URL-адреса.

           Аргументы:
              resource: Строка, содержащая URL-адрес, для которого необходимо
                 получить отчет. Также можно указать 'scan_id' ,возвращаемый
                 функцией 'url_scan' для доступа к определенному отчету.
              scan: При установке значения '1' автоматически отправляет
                 URL-адрес для анализа, если для него не найден отчет в базе
                 данных VirusTotal.
              timout: Время (в секундах), в течение которого будет ожидаться
                 ответ от сервера (необязательный параметр).
              proxies: Протокол и URL-адрес прокси-сервера (необязательный
                 параметр).

           Возвращаемое значение:
              Словарь вида {'error_code': < error_code>, 'result': <result>}.
              Если метод завершился удачно ('error_code' равен ERROR_SUCCESS),
              то 'result' содержит ответ сервера в виде JSON. В обратном
              случае ('error_code' не равен ERROR_SUCCESS) 'result' содержит
              наименование ошибки.
        """
        api_url = self.base_url + '/url/report'
        params = dict(apikey=self.api_key, resource=resource, scan=scan)
        try:
            response = requests.get(api_url, params=params,
                                    timeout=timeout, proxies=proxies)
        except requests.ConnectionError:
            return dict(error_code=self.ERROR_CONNECT,
                        result='Connection error')
        except requests.Timeout:
            return dict(error_code=self.ERROR_TIMEOUT,
                        result='Timeout error')
        return _return_result(response)

    def url_scan(self, url, timeout=None, proxies=None):
        """Отправка URL-адреса для сканирования на сервер.

           Аргументы:
              url: Строка, содержащая URL-адрес, который должен быть
                 отсканирован.
              timout: Время (в секундах), в течение которого будет ожидаться
                 ответ от сервера (необязательный параметр).
              proxies: Протокол и URL-адрес прокси-сервера (необязательный
                 параметр).

           Возвращаемое значение:
              Словарь вида {'error_code': < error_code>, 'result': <result>}.
              Если метод завершился удачно ('error_code' равен ERROR_SUCCESS),
              то 'result' содержит ответ сервера в виде JSON. В обратном
              случае ('error_code' не равен ERROR_SUCCESS) 'result' содержит
              наименование ошибки.
        """
        api_url = self.base_url + '/url/scan'
        params = dict(apikey=self.api_key, url=url)
        try:
            response = requests.post(api_url, data=params,
                                     timeout=timeout, proxies=proxies)
        except requests.ConnectionError:
            return dict(error_code=self.ERROR_CONNECT,
                        result='Connection error')
        except requests.Timeout:
            return dict(error_code=self.ERROR_TIMEOUT,
                        result='Timeout error')
        else:
            return _return_result(response)

    def ip_report(self, ip, timeout=None, proxies=None):
        """Получение результатов сканирования IP-адреса.

           Аргументы:
              ip: Строка, содержащая IP-адрес, для которого необходимо получить
                 отчет.
              timout: Время (в секундах), в течение которого будет ожидаться
                 ответ от сервера (необязательный параметр).
              proxies: Протокол и URL-адрес прокси-сервера (необязательный
                 параметр).

           Возвращаемое значение:
              Словарь вида {'error_code': < error_code>, 'result': <result>}.
              Если метод завершился удачно ('error_code' равен ERROR_SUCCESS),
              то 'result' содержит ответ сервера в виде JSON. В обратном
              случае ('error_code' не равен ERROR_SUCCESS) 'result' содержит
              наименование ошибки.
        """
        api_url = self.base_url + '/ip-address/report'
        params = dict(apikey=self.api_key, ip=ip)
        try:
            response = requests.get(api_url, params=params,
                                    timeout=timeout, proxies=proxies)
        except requests.ConnectionError:
            return dict(error_code=self.ERROR_CONNECT,
                        result='Connection error')
        except requests.Timeout:
            return dict(error_code=self.ERROR_TIMEOUT,
                        result='Timeout error')
        else:
            return _return_result(response)

    def domain_report(self, domain, timeout=None, proxies=None):
        """Получение результатов сканирования имени домена.

           Аргументы:
              domain: Строка, содержащая имя домена, для которого необходимо
                 получить отчет.
              timout: Время (в секундах), в течение которого будет ожидаться
                 ответ от сервера (необязательный параметр).
              proxies: Протокол и URL-адрес прокси-сервера (необязательный
                 параметр).

           Возвращаемое значение:
              Словарь вида {'error_code': < error_code>, 'result': <result>}.
              Если метод завершился удачно ('error_code' равен ERROR_SUCCESS),
              то 'result' содержит ответ сервера в виде JSON. В обратном
              случае ('error_code' не равен ERROR_SUCCESS) 'result' содержит
              наименование ошибки.
        """
        api_url = self.base_url + '/domain/report'
        params = dict(apikey=self.api_key, domain=domain)
        try:
            response = requests.get(api_url, params=params,
                                    timeout=timeout, proxies=proxies)
        except requests.ConnectionError:
            return dict(error_code=self.ERROR_CONNECT,
                        result='Connection error')
        except requests.Timeout:
            return dict(error_code=self.ERROR_TIMEOUT,
                        result='Timeout error')
        else:
            return _return_result(response)


def _return_result(response):
    if response.status_code == 200:
        return dict(error_code=VirusTotalAPI.ERROR_SUCCESS,
                    result=response.json())
    elif response.status_code == 204:
        return dict(error_code=VirusTotalAPI.ERROR_HTTP,
                    result='HTTP errorr [204]. Request limit exceeded')
    elif response.status_code == 400:
        return dict(error_code=VirusTotalAPI.ERROR_HTTP,
                    result='HTTP errorr [400]. Bad request')
    elif response.status_code == 403:
        return dict(error_code=VirusTotalAPI.ERROR_HTTP,
                    result='HTTP errorr [403]. Invalid API key')
    elif response.status_code == 413:
        return dict(error_code=VirusTotalAPI.ERROR_HTTP,
                    result='HTTP errorr [413]. File upload error')
    else:
        return dict(error_code=VirusTotalAPI.ERROR_HTTP,
                    result='Unknown HTTP error')
