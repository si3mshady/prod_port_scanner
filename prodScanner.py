from tld import get_tld
import subprocess
import pprint
import ipcalc


ROOT  = __file__


def execute_command(cmd):
     result = subprocess.Popen(cmd,stdout=subprocess.PIPE,shell=True)
     output, _ = result.communicate()  
     return output.decode('utf-8')

    


def getIpRangeFromCIDR(network='10.10.0.0',cidr=24):
    ip_list =  [ip for ip in ipcalc.Network(f"{network}/{cidr}")]
    return ip_list

def format_domain_name(url):
    tld = get_tld(url, as_object=True)
    domain  = tld.domain
    return f"{domain}.{tld}"   

def fqdn_to_ip(fqdn='google.com'):
    cmd = f'dig short google.com | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep -i {fqdn}'    
    result = execute_command(cmd)
    
    

def scanTarget(intensity=0,target='google.com',target_port=80):
    if 'http' in target:
        fqdn = format_domain_name(target)

       

    
    #scans target retrieving port and application version
    cmd = f"nmap -F -sV --version-intensity {intensity} {target}"
      #get command output
    

    

# scanTarget()

# print(ROOT)

# print(getIpRangeFromCIDR())

# pp = pprint.PrettyPrinter(width=41, compact=True)
# pp.pprint((scanTarget(0,"54.242.56.0")))
# print(tld.get_tld('https://www.yahoo.com/'))
# print(tld.get_tld('https://yahoo.com/'))
# print(tld.get_tld('https://yahoo.com'))
r = get_tld('https://www.yahoo.com',as_object=True)
print(r)
print(r.domain)

# https://pypi.org/project/tld/