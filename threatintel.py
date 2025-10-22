import requests, json, time
VT_API_KEY = "95708369c4038add4cae55de1686fdcb9d50e1dce3292df0bcea3aafe7f6e875"
ABUSE_KEY = "e85c332ca38fa7304642c1a741e26759a0ae8eea9f2ca7e07a3ada44437cff4b1936bec5a5ca523c"
def check_vt(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    return r.json() if r.status_code==200 else {"error":"no data"}
def check_abuse(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    r = requests.get(url, headers=headers)
    return r.json() if r.status_code==200 else {"error":"no data"}
def analyze():
    with open("iocs.txt") as f: iocs=[x.strip() for x in f]
    result={}
    for ioc in iocs:
        print(f"[+] {ioc}")
        result[ioc]={"VT":check_vt(ioc),"Abuse":check_abuse(ioc)}
        time.sleep(15)
    json.dump(result, open("report.json","w"), indent=2)
    print("✅ Report generated: report.json")
if __name__=="__main__": analyze()
