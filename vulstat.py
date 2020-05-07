#!/usr/bin/python3

import time
import os
import sys
import signal
import threading
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options

STAT_PREPARATIONS       = 1
STAT_PROCESSING         = 2
STAT_STOPPED            = 3

EVERYONE_HAVE_TO_CLOSE = 0

CVE_DETAILS_PAGES = [   "https://www.cvedetails.com/vulnerability-list/opdos-1/denial-of-service.html",
                        "https://www.cvedetails.com/vulnerability-list/opec-1/execute-code.html",
                        "https://www.cvedetails.com/vulnerability-list/opov-1/overflow.html",
                        "https://www.cvedetails.com/vulnerability-list/opmemc-1/memory-corruption.html",
                        "https://www.cvedetails.com/vulnerability-list/opsqli-1/sql-injection.html",
                        "https://www.cvedetails.com/vulnerability-list/opxss-1/xss.html",
                        "https://www.cvedetails.com/vulnerability-list/opdirt-1/directory-traversal.html",
                        "https://www.cvedetails.com/vulnerability-list/ophttprs-1/http-response-splitting.html",
                        "https://www.cvedetails.com/vulnerability-list/opbyp-1/bypass.html",
                        "https://www.cvedetails.com/vulnerability-list/opginf-1/gain-information.html",
                        "https://www.cvedetails.com/vulnerability-list/opgpriv-1/gain-privilege.html",
                        "https://www.cvedetails.com/vulnerability-list/opcsrf-1/csrf.html",
                        "https://www.cvedetails.com/vulnerability-list/opfileinc-1/file-inclusion.html"]

L7_NAMES = [    "ADC","AFP,","BACnet,",
                "BitTorrent","BOOTP,","DIAMETER","DICOM",
                "DICT","DNS","DHCP,","ED2K",
                "FTP","Finger","Gnutella","Gopher",
                "HTTP,","IMAP,","IRC","ISUP,",
                "XMPP","LDAP","MIME,","MSNP,",
                "MAP,","NetBIOS","NNTP","NTP",
                "NTCIP,","POP3","RADIUS","Rlogin",
                "rsync","RTP,","RTSP,","SSH,",
                "SISNAPI,","SIP,","SMTP,","SNMP,",
                "SOAP,","STUN,","TUP,","Telnet",
                "TCAP,","TFTP,","WebDAV,","DSM",
                "MIME"]



is_l7 = 0
is_other = 0

fp = webdriver.FirefoxProfile()
fp.set_preference("permissions.default.stylesheet", 2)
fp.set_preference("permissions.default.image", 2)
fp.set_preference("permissions.default.script", 2)
fp.set_preference("javascript.enabled", False)
o = Options()
#Опция для запуска движка браузера в фоновом режиме
o.headless = True

if len(sys.argv) < 2:
    print("vulstat file")
    sys.exit(0)

driver = webdriver.Firefox(firefox_profile=fp, options=o)
driver.implicitly_wait(15)
data_file = open(sys.argv[1], 'w')

'''
    При выключении программы сигналом SIGINT (Ctrl-C)
     программа попытается нормально закрыть файл записи
     и движок браузера.
'''
def signal_handler(sig, frame):
    global EVERYONE_HAVE_TO_CLOSE
    global data_file
    global driver
    global stats_state
    
    print("\nOkay, no problem")
    EVERYONE_HAVE_TO_CLOSE = 1
    data_file.close()
    driver.close()
    sys.exit(0)


'''
    Функция для потока считывания команд
'''
def read_requests():
    global EVERYONE_HAVE_TO_CLOSE
    global data_file
    global driver
    global stats_state

    while True:
        request = input()

        if request == "exit":
            EVERYONE_HAVE_TO_CLOSE = 1
            sys.exit(0)


'''
    Функция для потока вывода статистики
'''
def print_statistics():
    global pgs_nmb
    global global_page
    global stats_state
    global start_time

    while True:
        if EVERYONE_HAVE_TO_CLOSE:
            sys.exit(0)

        time.sleep(1)
        os.system('clear')

        print("Uptime:", int(time.time() - start_time), "seconds")

        if stats_state == STAT_PREPARATIONS:
            print("Making some preparations")
        elif stats_state == STAT_PROCESSING:
            perc = int(global_page / pgs_nmb * 100)
            print(str(perc) + "%", "[", end="")
            for i in range(20):
                if perc - i * 5 > 0:
                    print("\u2588", end="")
                else:
                    print(".", end="")
            print("]\nL7:", str(is_l7) + "; Others:", is_other)
        elif stats_state == STAT_STOPPED:
            print("L7:", str(is_l7) + "; Others:", is_other)
            print("Done")
            break


'''
    Подсчет общего количества страниц для
     сканирования
'''
def pages_total_number():
    global page_amount

    for i in CVE_DETAILS_PAGES:
        if EVERYONE_HAVE_TO_CLOSE:
            data_file.close()
            driver.close()
            sys.exit(0)

        driver.get(i)
        for page_number in driver.find_element_by_id("pagingb").find_elements_by_tag_name("a"):
            page_counter = int(page_number.get_attribute("textContent"))
        page_amount.append(page_counter)
    return sum(page_amount)


'''
    Получение дополнительной информации о
     уязвимости
'''
def get_vuln_data(data):
    out = ""
    data_els = data.find_elements_by_tag_name("td")
    #CVE Number
    out += data_els[1].find_element_by_tag_name("a").get_attribute("textContent") + ";"
    #Vulner type
    out += data_els[4].get_attribute("textContent").strip() + ";"
    #Publish date
    out += data_els[5].get_attribute("textContent") + ";"
    #Vuln score (from 0 to 10)
    out += data_els[7].find_element_by_tag_name("div").get_attribute("textContent")
    return out

'''
    Обработка непосредственно данных о уязвимостях
'''
def page_process():
    global is_l7
    global is_other
    global data_counter
    
    #Найдем таблицу уязвимостями
    table = driver.find_element_by_id("vulnslisttable")

    #Найдем данные о уязвимостях и их описания
    datas = table.find_elements_by_class_name("srrowns")
    texts = table.find_elements_by_class_name("cvesummarylong")
    
    #Найдем нужную информацию
    for i in range(len(datas)):
        l7_found = 0
        text = texts[i].get_attribute("textContent")
        for j in L7_NAMES:
            if text.find(j) != -1:
                l7_found = 1
                data_counter += 1
                data = str(data_counter) + ";L7;"
                data += get_vuln_data(datas[i])
                data_file = open(sys.argv[1], 'a')
                data_file.write(data + "\n")
                data_file.close()
                break
        if l7_found:
            is_l7 += 1
        else:
            is_other += 1



def main_processing():
    global global_page

    current_main_page = 0
    for i in CVE_DETAILS_PAGES:
        driver.get(i)

        #Теперь будем переходить на каждую страницу зная
        # ее номер
        local_page = 0
        while (local_page < page_amount[current_main_page]):
            if EVERYONE_HAVE_TO_CLOSE:
                data_file.close()
                driver.close()
                sys.exit(0)
            local_page += 1
            global_page += 1
            title_name = "Go to page " + str(local_page)
            button = driver.find_element_by_xpath("//a[@title='" + title_name + "']")
            button.click()
            #Сейчас находимся на странице, которую необходимо обработать
            page_process()
        current_main_page += 1


page_amount = []
global_page = 0

#Режим вывода статистики
stats_state = 0
start_time = time.time()
pgs_nmb = 0
data_counter = 0

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)

    #Инициализация потока вывода статистики
    stats_state = STAT_PREPARATIONS
    stt_t = threading.Thread(target=print_statistics)
    stt_t.start()

    #Инициализация потока чтения команд
    req_t = threading.Thread(target=read_requests)
    req_t.start()

    #Подсчет общего количества проверяемых страниц
    pgs_nmb = pages_total_number()

    #Установка статистики в режим вывода основной информации
    stats_state = STAT_PROCESSING

    #Парсинг всех страниц
    main_processing()

    #Установка статистики в режим окончания работы
    # Необходимо для закрытия потока
    stats_state = STAT_STOPPED

    #Закрытие всего, что закрывается
    data_file.close()
    driver.close()
