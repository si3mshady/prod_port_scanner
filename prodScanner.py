from tld import get_tld
import subprocess
import ipcalc


def execute_command(cmd):
    result = subprocess.Popen(cmd,stdout=subprocess.PIPE,shell=True)     
    output, _ = result.communicate()       
    if type(output) == type('string'):
        return output    
    else:
        return output.decode('utf-8')


def get_ip_range_from_cidr(network='0.0.0.0',cidr=24):
    if cidr <= 32 and cidr >= 8:
        ip_list =  [ip for ip in ipcalc.Network(f"{network}/{cidr}")]
        return ip_list
    else:
        print('Invalid CIDR range provided. 8 - 32 accepted')

def format_domain_name(url):
    tld = get_tld(url, as_object=True)
    domain  = tld.domain
    return f"{domain}.{tld}"   

def fqdn_to_ip(fqdn='google.com'):
    cmd = f'host {fqdn}'  
    result = execute_command(cmd)  #outputs results from host command 
    ip =  [ ip for ip in result.splitlines() if 'has address' in ip][0] 
    marker = ip.find('has address') +  12     #find position of substring to use for splicing out the ip address
    ip_addr = ip[marker::]  #filter result of host command to show only ip addr 
    return ip_addr  


def write_data_to_directory(directory,data):
    
    with open(directory, 'w') as ink:
        ink.write(data)

    

def scan_target(intensity=0,target='google.com'):
    if 'http' in target:
        fqdn = format_domain_name(target)
        target = fqdn_to_ip(fqdn)               
        #scans target retrieving port and application version
        cmd = f"nmap -F -sV --version-intensity {intensity} {target}"        
        result = execute_command(cmd)
        write_data_to_directory(target,result)
    else:
        cmd = f"nmap -F -sV --version-intensity {intensity} {target}"
        result = execute_command(cmd)
        write_data_to_directory(target,result)
        
  
def init(network='54.242.56.0',cidr=32):     
    iplist = [ip.__str__() for ip in get_ip_range_from_cidr(network,cidr)]  #IP('x.x.x.x') use __str__() method to stringify object
     
    for ip in iplist:
        scan_target(target=ip)

init()