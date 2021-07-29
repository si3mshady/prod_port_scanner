from tld import get_tld
import argparse
import subprocess
import ipcalc
import re
# from requests.exceptions import ConnectionError




parser = argparse.ArgumentParser(description="Preform port and service scan on target(s)")
parser.add_argument('--network', type=str , help='Network notation without CIDR')
parser.add_argument('--cidr', type=int, help="network cidr")
parser.add_argument('--intensity', type=int, help='scanning intensity 0 - 9')




def test_insecure_robots_txt(data_list):

   
        for d in data_list:           
            if re.fullmatch("(Disallow:[\n\s]*)", d):
                return '\n\tInsecure robots.txt'
            else:
                  return '\n\tSecure robots.txt'
                
      
def execute_command(cmd):
    result = subprocess.Popen(cmd,stdout=subprocess.PIPE,shell=True)     
    try:
        output, _ = result.communicate(timeout=16)       
        if type(output) == type('string'):
          
            print(output)
            return output    
        else:
            
            return output.decode('utf-8')
    except Exception as e:
        print(e)


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


def write_data_to_directory(directory,nmap_data,robots_test_data):    
    with open(directory, 'a') as ink:
        ink.write(nmap_data) 
        data_list = robots_test_data.splitlines()
        test_result = test_insecure_robots_txt(data_list)
        ink.write(test_result)

def fetch_and_test_robots_txt(url,proto='http', directory='/'):
    try:
        # res = requests.get(f"{proto}://{url}/robots.txt", verify=False, timeout=8)
        cmd = f"curl --connect-timeout 4 {proto}://{url}/robots.txt"
        result = execute_command(cmd) 
        results = result.splitlines()
        return test_insecure_robots_txt(results)
       
    except Exception as e:
        try:
             fetch_and_test_robots_txt(url,proto='https')
        except Exception as e:
            print(e)

def scan_target(intensity=0,target='google.com'):
    if 'http' in target:
        fqdn = format_domain_name(target)
        print(target)
        target = fqdn_to_ip(fqdn)               
        #scans target retrieving port and application version
        cmd = f"nmap --host-timeout 1m  -sV --version-intensity {intensity} {target}"
        result = execute_command(cmd) #nmap results 
        if "Note: Host seems down" in result or result == None:
            return False
        print(target)
        
        test_results = fetch_and_test_robots_txt(url=target,directory=target)
        
        
        write_data_to_directory(directory=target,nmap_data=result,robots_test_data=test_results)
        return True
        
    else:
        cmd = f"nmap --host-timeout 1m  -sV --version-intensity {intensity} {target}"
        result = execute_command(cmd) #nmap results 
        if "Note: Host seems down" in result or result == None:
            return False
        test_results = fetch_and_test_robots_txt(url=target,directory=target)
        try:
            write_data_to_directory(directory=target,nmap_data=result,robots_test_data=test_results)
        except Exception as e:
            print(e)
        return True

  
def init(network='54.242.56.0',cidr=30):     
    iplist = [ip.__str__() for ip in get_ip_range_from_cidr(network,cidr)]  
    #IP('x.x.x.x') use __str__() method to stringify object
 
    count = 0
    while count < len(iplist):
        print(iplist[count])
        if False == scan_target(target=iplist[count]):
            iplist.remove(iplist[count])
            continue
        count += 1



if __name__ == '__main__':
    args = parser.parse_args()
    network = args.network if args.network != None else '0.0.0.0'
    cidr = args.cidr if args.cidr != None else '32'
    print(network,cidr)
    init(network=network,cidr=cidr)
   

#usage  python3  prodScanner.py --network  54.242.56.0 --cidr  32
#network scan to evaluate open ports, services and applications 
#elliott arnold 
#practice 
#7-29-21


# nmap --host-timeout 1m -F -sV --version-intensity 0 54.242.56.1
# docker run -v $(PWD):/app test --network  54.242.56.0 --cidr  32