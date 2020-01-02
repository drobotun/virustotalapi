# VirusTotal API
Модуль, реализующий функции API сервиса www.virustotal.com (2 версии), доступных с использованием открытого ключа.
Подробное описание API смотри на: https://www.virustotal.com/en/documentation/public-api/

## Пример использования:

```python
import json
from virustotalapi import VirusTotalAPI
    ...
vt_api = VirusTotalAPI(<Здесь необходима строка с ключом доступа к API>)
response = vt_api.file_report('8abd3f80059113ffd4693be25ba3f691')
    ...
print('Error code = ', response['error_code'])
print(json.dumps(response['result'], sort_keys=False, indent=4))
    ...
```
