import os 		# Модуль для работы с операционной системой
import json 		# Модуль для работы с JSON-файлами
import time 		# Модуль для работы со временем
import requests 	# Модуль для отправки HTTP-запросов
import re 		# Модуль для работы с регулярными выражениями
import paramiko 	# Модуль для работы с SSH-подключениями

# Загрузка базы уязвимостей из файла JSON
def load_vulnerability_database(vulnerability_database):

"""
    Загружает базу уязвимостей из файла JSON.
    Parameters:
    vulnerability_database (str): Путь к файлу с базой уязвимостей.
    Returns:
        list: Список уязвимостей.
"""

          # Проверка существования файла с базой уязвимостей
    if os.path.isfile(vulnerability_database):
        # Если файл существует, открываем его и загружаем данные
        with open(vulnerability_database, 'r') as f:
            return json.load(f)
    else:

        # Если файла не существует, выводим ошибку
        print("Ошибка: Некорректный путь к файлу с базой уязвимостей")
        return []

# Запись результатов сканирования в файл JSON
def write_findings_to_file(findings, output_file):

"""
    Записывает найденные уязвимости в файл JSON.

    Parameters:
        findings (list): Список найденных уязвимостей.
        output_file (str): Имя файла для записи результатов.
"""

    # Открытие файла для записи
    with open(output_file, 'w') as f:
        # Запись результатов в файл с отступами для удобного чтения
        json.dump(findings, f, indent=4)



# Загрузка отчета о найденных уязвимостях в DefectDojo
def upload_report_to_defectdojo(report_data, url, api_key, product_name, engagement_name):

"""
    Загружает отчет о найденных уязвимостях в DefectDojo.

    Parameters:
        report_data (dict): Данные отчета.
        url (str): URL DefectDojo.
        api_key (str): API ключ.
        product_name (str): Название продукта.
        engagement_name (str): Название проекта.
"""

    # Формирование заголовков запроса
    headers = {
        'Authorization': f'Token {api_key}',
        'Content-Type': 'application/json'
    }

    try:

        # Отправка POST-запроса на указанный URL
        response = requests.post(url, headers=headers, json=report_data)

        # Проверка статуса ответа
        if response.status_code == 201:
            print("Отчет успешно загружен в DefectDojo.")
        else:

                             # Вывод ошибки при неудачной загрузке отчета
            print(f"Ошибка при загрузке отчета в DefectDojo: {response.status_code} - {response.text}")
    except Exception as e:

        # Вывод ошибки при возникновении исключения
        print(f"Ошибка при отправке запроса: {e}")

# Подключение к удаленному хосту по SSH
def ssh_connect(host, username, password):

"""
    Устанавливает SSH-соединение с удаленным хостом.
    Parameters:
        host (str): IP-адрес хоста.
        username (str): Имя пользователя.
        password (str): Пароль.

    Returns:
        paramiko.SSHClient: Объект клиента SSH.
"""

    try:

        # Создание объекта SSH-клиента
        client = paramiko.SSHClient()
        # Установка политики добавления новых хостов в список доверенных
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Подключение к удаленному хосту
        client.connect(host, username=username, password=password)
        return client
    except paramiko.AuthenticationException:

        # Обработка ошибки аутентификации
        print("Ошибка аутентификации. Проверьте правильность имени пользователя и пароля.")
        return None
    except paramiko.SSHException as e:

        # Обработка ошибки SSH
        print("Ошибка SSH:", str(e))
        return None

# Сканирование PHP-файла на уязвимости
def scan_php_file(file_path, ssh_client, vulnerabilities):

"""
    Сканирует PHP-файл на наличие уязвимостей.
    Parameters:
        file_path (str): Путь к PHP-файлу.
        ssh_client (paramiko.SSHClient): Объект клиента SSH.
        vulnerabilities (list): Список уязвимостей.
    Returns:
        list: Список найденных уязвимостей.
"""

    findings = []

    # Получение содержимого PHP-файла через SSH
    stdin, stdout, stderr = ssh_client.exec_command("cat " + file_path)
    php_code = stdout.read().decode('utf-8')

    # Поиск уязвимостей в коде PHP
    for vuln in vulnerabilities:
        if vuln in php_code:

 # Если уязвимость найдена, добавляем информацию о ней в результаты
            findings.append({
                "title": vuln,
                "description": f"Уязвимость {vuln} обнаружена в файле: {file_path}",
                "date": time.strftime("%Y-%m-%d %H:%M:%S")
            })

    # Поиск типовых уязвимостей (SQL Injection, XSS, CSRF)
    sql_pattern = re.compile(r'\b(select|insert|update|delete|drop|truncate|create|alter)\b', re.IGNORECASE)
    xss_pattern = re.compile(r'<script>', re.IGNORECASE)
    csrf_pattern = re.compile(r'<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>', re.IGNORECASE)

    if sql_pattern.search(php_code):
        findings.append({
            "title": "SQL Injection",
            "description": f"SQL Injection vulnerability found in file: {file_path}",
            "date": time.strftime("%Y-%m-%d %H:%M:%S")
        })

    if xss_pattern.search(php_code):
        findings.append({
            "title": "XSS",
            "description": f"XSS vulnerability found in file: {file_path}",
            "date": time.strftime("%Y-%m-%d %H:%M:%S")
        })

    if csrf_pattern.search(php_code):
        findings.append({
            "title": "CSRF",
            "description": f"CSRF vulnerability found in file: {file_path}",
            "date": time.strftime("%Y-%m-%d %H:%M:%S")
        })

    return findings

# Преобразование результатов сканирования в формат DefectDojo
def convert_to_defectdojo(input_json):

"""
    Преобразует список уязвимостей в формат для загрузки в DefectDojo.
    Parameters:
        input_json (list): Список уязвимостей.
    Returns:
        dict: Данные в формате DefectDojo.
"""

    defectdojo_json = {
        "product": {
            "name": "Название продукта",  
            "description": "Описание продукта"  
        },
        "engagement": {
            "name": "Название проекта",  
            "description": "Описание проекта",  
            "target_start": "YYYY-MM-DD",  
            "target_end": "YYYY-MM-DD"  
        },
        "test": {
            "test_type": "Тип тестирования",  
            "environment": "Окружение тестирования"  
        },
        "findings": []
    }

    # Преобразование каждого элемента JSON в объект finding для DefectDojo
    for item in input_json:
        finding = {
            "title": item["title"],
            "file_path": item["file"],
            "severity": "Low",
            "description": "Описание уязвимости"
        }
        defectdojo_json["findings"].append(finding)

    return defectdojo_json

# Основная функция
def main():

    # Получение данных для подключения к удаленному хосту
    host = input("Введите IP-адрес хоста для подключения: ")
    username = input("Введите имя пользователя: ")
    password = input("Введите пароль: ")

    # Установка SSH-соединения
    ssh_client = ssh_connect(host, username, password)

    if ssh_client:
        try:

    # Получение пути к директории для сканирования PHP-файлов
            directory_path = input("Введите путь до директории для сканирования PHP-файлов на хосте {}: ".format(host))
            vulnerability_database = "nvdcve-1.1-modified.json"

            # Загрузка базы уязвимостей
            vulnerabilities = load_vulnerability_database(vulnerability_database)
            findings = []

            # Поиск PHP-файлов в указанной директории
            stdin, stdout, stderr = ssh_client.exec_command("find " + directory_path + " -name '*.php'")
            php_files = stdout.read().decode('utf-8').split('\n')
            php_files = php_files[:-1]

            # Сканирование каждого PHP-файла на уязвимости
            for file_path in php_files:
                findings.extend(scan_php_file(file_path, ssh_client, vulnerabilities))

            if findings:

# Если найдены уязвимости, записываем результаты в файл и выводим отчет в формате DefectDojo
                print("Найдены уязвимости:")
                for finding in findings:
                    print(finding)
                output_file = "finding.json"
                write_findings_to_file(findings, output_file)
                
                # Преобразование результатов в формат DefectDojo
                defectdojo_data = convert_to_defectdojo(findings)
                print("Отчет в формате DefectDojo:")
                print(json.dumps(defectdojo_data, indent=4))
            else:

 # Если уязвимостей не найдено, выводим соответствующее сообщение
                print("Уязвимостей не найдено.")

        except Exception as e:

            # Обработка общих ошибок выполнения программы
            print("Произошла ошибка:", str(e))
        finally:

            # Закрытие SSH-соединения при завершении программы
            ssh_client.close()

if __name__ == "__main__":
    main()

