from django.shortcuts import render
from Anomaly_Detection.forms import data_form

from django.shortcuts import render
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from django.http import HttpResponse
import pickle


def index(response):
	df = pd.read_csv("ransomware/preprocessed_data_2.csv")
	X = df.drop('attack_cat',axis=1)
	y = df.attack_cat

	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.01, random_state=6)

	filename = 'xgboost/model1.sav'
	#loaded_model = joblib.load(filename)

	loaded_model = pickle.load(open(filename, 'rb'))

	result = loaded_model.predict(X_test)

	X_test_pd = pd.DataFrame(X_test)
	dataset = pd.DataFrame(result)
	

	X_test_pd.reset_index(drop=True, inplace=True)

	#print(X_test_pd)
	#print(dataset)

	concat_final_data = pd.concat([dataset,X_test_pd], axis=1)
	#print(concat_final_data)

	#features = ['Number of announcements', 'Number of withdrawals', 'Number of announced NLRI prefixes', 'Number of withdrawn NLRI prefixes', 'Average AS-path length', 'Maximum AS-path length', 'Average unique AS-path length', 'Number of duplicate announcements', 'Number of duplicate withdrawals', 'Number of implicit withdrawals', 'Average edit distance', 'Maximum edit distance', 'Inter-arrival time', 'MED n=7', 'MED n=8', 'MED n=9', 'MED n=10', 'MED n=11', 'MED n=12', 'MED n=13', 'MED n=14', 'MED n=15', 'MED n=16', 'MED n=17',  '  AS-path length n =7', 'AS n=8', 'AS n=9', 'AS n=10', 'AS n=11', 'AS n=12', 'AS n=13', 'AS n=14', 'AS n=15', '(IGP) packets', '(EGP) packets','Incomplete packets', 'Packet size', 'Labels']
	concat_final_data.columns = ['IfAttack?','dur', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports', '3pc', 'a/n', 'aes-sp3-d', 'any', 'argus', 'aris', 'arp', 'ax.25', 'bbn-rcc', 'bna', 'br-sat-mon', 'cbt', 'cftp', 'chaos', 'compaq-peer', 'cphb', 'cpnx', 'crtp', 'crudp', 'dcn', 'ddp', 'ddx', 'dgp', 'egp', 'eigrp', 'emcon', 'encap', 'etherip', 'fc', 'fire', 'ggp', 'gmtp', 'gre', 'hmp', 'i-nlsp', 'iatp', 'ib', 'idpr', 'idpr-cmtp', 'idrp', 'ifmp', 'igmp', 'igp', 'il', 'ip', 'ipcomp', 'ipcv', 'ipip', 'iplt', 'ipnip', 'ippc', 'ipv6', 'ipv6-frag', 'ipv6-no', 'ipv6-opts', 'ipv6-route', 'ipx-n-ip', 'irtp', 'isis', 'iso-ip', 'iso-tp4', 'kryptolan', 'l2tp', 'larp', 'leaf-1', 'leaf-2', 'merit-inp', 'mfe-nsp', 'mhrp', 'micp', 'mobile', 'mtp', 'mux', 'narp', 'netblt', 'nsfnet-igp', 'nvp', 'ospf', 'pgm', 'pim', 'pipe', 'pnni', 'pri-enc', 'prm', 'ptp', 'pup', 'pvp', 'qnx', 'rdp', 'rsvp', 'rvd', 'sat-expak', 'sat-mon', 'sccopmce', 'scps', 'sctp', 'sdrp', 'secure-vmtp', 'sep', 'skip', 'sm', 'smp', 'snp', 'sprite-rpc', 'sps', 'srp', 'st2', 'stp', 'sun-nd', 'swipe', 'tcf', 'tcp', 'tlsp', 'tp++', 'trunk-1', 'trunk-2', 'ttp', 'udp', 'unas', 'uti', 'vines', 'visa', 'vmtp', 'vrrp', 'wb-expak', 'wb-mon', 'wsn', 'xnet', 'xns-idp', 'xtp', 'zero', 'Nodata', 'dhcp', 'dns', 'ftp', 'ftp0data', 'http', 'irc', 'pop3', 'radius', 'smtp', 'snmp', 'ssh', 'ssl', 'ACC', 'CLO', 'CON', 'FIN', 'INT', 'REQ', 'RST']
	concat_final_data['IfAttack?'].replace(to_replace = 0, value ='Normal', inplace=True)
	concat_final_data['IfAttack?'].replace(to_replace = 1, value ='Attack', inplace=True)

	print(concat_final_data)



	total_data_packet1 = int(len(concat_final_data.index))
	total_anomalies1 = len( [d for d in concat_final_data['IfAttack?'] if d == 'Attack'])
	total_anomalies_blocked1 = total_anomalies1
	total_passed_packet1 = len([kr for kr in concat_final_data['IfAttack?'] if kr == 'Normal'])

	return render(response, 'base.html', {'livedata' : concat_final_data, 'total_data_packet':total_data_packet1, \
	 'total_anomalies':total_anomalies1, 'total_passed_packet':total_passed_packet1 , 'total_anomalies_blocked':total_anomalies_blocked1})

def index2(response):
	return render(response,'base2.html')

def index3(response):
	return render(response,'base3.html')

def index4(response):
	return render(response,'base4.html')

def index5(response):
	return render(response,'base5.html')