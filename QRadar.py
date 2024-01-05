import requests
from bs4 import BeautifulSoup
import re
import csv

def getCVEList():
# 対象のURL
    url = input("Please enter url: ")
    # HTTPリクエストを送信してHTMLを取得
    response = requests.get(url)
    html = response.text

    # BeautifulSoupオブジェクトを作成   
    soup = BeautifulSoup(html, 'html.parser')

    # CVEとCVSSのパターンを定義
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
    cvss_pattern = re.compile(r'CVSS Base score: (\d+\.\d+)')

    # CVEとCVSSのデータを抽出
    cve_data = soup.find_all(text=cve_pattern)
    cvss_data = soup.find_all(text=cvss_pattern)

    # 出力データのリストを作成
    output_data = []

    # CVEとCVSSのデータを組み合わせて出力データを作成
    for cve, cvss in zip(cve_data, cvss_data):
        cve_match = cve_pattern.search(cve)
        cvss_match = cvss_pattern.search(cvss)
        
        if cve_match and cvss_match:
            cve_id = cve_match.group()
            cvss_score = cvss_match.group(1)
            output_data.append([cve_id, cvss_score])

    return output_data

def get_cvss(cve):
    api_key="3df10090-8307-40ee-b63c-058137c67cd9"
    headers = {
    'Authorization': "{api_key}"
    }
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    # リクエストを送り、レスポンスを取得
    response = requests.get(url,headers=headers)
    data = response.json()
    api_data = data

# CVSSスコアとソース情報を抽出して出力
    results = []
    # Vulnerabilitiesから情報を取得
    try:
        for vulnerability in api_data['vulnerabilities']:
            cve_id = vulnerability['cve']['id']
            for metric in vulnerability['cve']['metrics']['cvssMetricV31']:
                score = metric['cvssData']['baseScore']
                source = metric['source']
                results.append(score)
                results.append(source)
        return results
    except:
        results.append("Not Provided")
        results.append("None")
        return results

def cvssFromCVEList(cve_list):
    #result_list = [['CVE-2023-1111','8.8','nvd'],[]...]
    results_list = []
    for cve in cve_list:
        tmp_list = []
        #results = [CVE,CVSS,Source]
        results = get_cvss(cve[0])
        tmp_list.append(cve[0])
        tmp_list.append(results[0])
        tmp_list.append(cve[1])              
        results_list.append(tmp_list)
    return results_list

def main():
    cve_IBMCVSS_list = getCVEList()
    results_list = cvssFromCVEList(cve_IBMCVSS_list)
    results_list = [["CVE","CVSS(nvd)","CVSS(IBM)","Version","attack","damage","update","workaround"]] + results_list
    #print(results_list)
    filename = input("Please input output filename(if you don't need csv file, enter \'None\'): ") +".csv"
    if filename == "None.csv":
        print("this is cvss list")
        for element in results_list:
            print(element)
        exit(0)
    # Open the file in write mode
    with open(filename, 'w', newline='') as file:
        # Create a writer object
        writer = csv.writer(file)
        
        # Write all rows at once
        writer.writerows(results_list)
main()
    
    
