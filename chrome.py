
import requests
import csv
import re
api_key="3df10090-8307-40ee-b63c-058137c67cd9"

def getCVEfromURL(url):
    #url = 'https://chromereleases.googleblog.com/2023/12/stable-channel-update-for-desktop_12.html'

    # リクエストを送ってHTMLを取得
    response = requests.get(url)
    data = response.text
    # CVE番号のパターン（通常はCVE-年-番号の形式）
    pattern = r'CVE-\d{4}-\d{4,7}'

    # 正規表現でCVE番号をすべて検索
    cve_numbers = re.findall(pattern, data)

    # 重複を削除（セットに変換してからリストに戻す）
    cve_numbers = list(set(cve_numbers))

    # 結果の出力
    print("here is cve list")
    for cve in cve_numbers:
        print(cve)
    print("cve_num is ",len(cve_numbers))
    return cve_numbers


def get_cvss(cve):
    headers = {
    'Authorization': "{api_key}"
    }
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    # リクエストを送り、レスポンスを取得
    response = requests.get(url,headers=headers)
    data = response.json()
    api_data = data

# CVSSスコアとソース情報を抽出して出力

    # Vulnerabilitiesから情報を取得
    try:
        for vulnerability in api_data['vulnerabilities']:
            cve_id = vulnerability['cve']['id']
            for metric in vulnerability['cve']['metrics']['cvssMetricV31']:
                score = metric['cvssData']['baseScore']
                source = metric['source']
                scoreType = metric['type']
                results= score
        return results
    except:
        results = "None"
        return results

def cvssFromCVEList(cve_list):
    #result_list = [['CVE-2023-1111','8.8','nvd'],[]...]
    results_list = []
    for cve in cve_list:
        tmp_list = []
        tmp_list.append(cve)
        tmp_list.append(get_cvss(cve))
        
        results_list.append(tmp_list)
    return results_list

def main(url):
    #urlからCVEのリストを作成
    #cve_list = ['CVE-2023-1111','CVE-2023-2222',...]
    cve_list = getCVEfromURL(url) 
    
    #各CVEのCVSS値を取得
    #cvss_list = [['CVE-2023-1111','8.9',NVD'],[]...]
    cvss_list = cvssFromCVEList(cve_list)
    #print(cvss_list)
    cvss_list = [['CVE','CVSS(NVD)','version','attack','damage','update','workaround']] + cvss_list
    
    filename = input("Please input output filename(if you don't need csv file, enter \'None\'): ") +".csv"
    if filename == "None.csv":
        print("this is cvss list")
        for element in cvss_list:
            print(element)
        exit(0)
    # Open the file in write mode
    with open(filename, 'w', newline='') as file:
        # Create a writer object
        writer = csv.writer(file)
        
        # Write all rows at once
        writer.writerows(cvss_list)

if __name__ =="__main__":
    url = input("Please enter the URL: ")
    main(url)
    


