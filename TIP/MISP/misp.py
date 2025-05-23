from pymisp import PyMISP
import pandas as pd
import urllib3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from dateutil.parser import parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
misp = PyMISP('https://172.16.73.90/','Your_KEy', ssl=False)
# to calculate analysis time
start_time = time.time()

# Field names for the dataset
fields_name = ['tweet_date', 'account', 'ioc_type', 'ioc_value', 'type_of_attack', 'tweet_url', 'text','misp_status','misp_first_seen', 'first_report', 'time_difference', 'time_difference(sec)']
df = pd.read_csv ('Final_IOC_13_11_2022.csv',names=fields_name, engine="python")
# To collect the values from malwarebazar and update the dataframe
def report(index):
    ioc_type=df.loc[index,'ioc_type']
    ioc = df.loc[index,'ioc_value']
    status = df.loc[index,'misp_status']
    #print(status)
    if status in ['Malicious','Clean']:
    	return
    source_date = df.loc[index, 'tweet_date']
    tweet_date=source_date[:19]
    print(tweet_date)
    # To get the api response   
    while True:
    	try:
    		attribute_details =misp.search(controller='attributes',value=ioc)
    		print(attribute_details)
    		break
    	except Exception as e:
    		print({'Error':str(e)})
    if attribute_details['Attribute']:
    	df.loc[index, 'misp_status'] = "Malicious"
    	print("Malicious")
    	first_date_misp = []
    	for t in attribute_details['Attribute']:
    		convert_time = datetime.fromtimestamp(int(t['timestamp']))
    		print(convert_time)
    		first_date_misp.append(convert_time)
    		print("yes")
    		print(first_date_misp)
    		print("no")
    	if first_date_misp != []:
    		print(min(first_date_misp))
    		min_date_misp = min(first_date_misp)
    		print("yes")
    		print(min_date_misp)
    		print("nono")
    		df.loc[index, 'misp_first_seen'] = min_date_misp
    		print("first",type(df.loc[index, 'misp_first_seen']))
    		#tweet_date = datetime.datetime.strptime(tweet_date, '%Y-%m-%d %H:%M:%S')
    		tweet_date = parse(tweet_date)
    		print("date",type(tweet_date))
    		time_diff = tweet_date-min_date_misp
    		print("diff",time_diff)
    		df.loc[index, 'time_difference'] = time_diff
    		print(df.loc[index, 'time_difference'])
    		df.loc[index, 'time_difference(sec)'] = time_diff.total_seconds()
    		print(df.loc[index, 'time_difference(sec)'])
    		if min_date_misp < tweet_date:
    			df.loc[index, 'first_report'] = "MISP"
    		else:
    			df.loc[index, 'first_report'] = "Twitter"
    		print(df.loc[index, 'first_report'] )
    else:
    	df.loc[index, 'misp_status'] = "Clean"
    	print(df.loc[index, 'misp_status'])
    print(index, ioc, df.loc[index, "misp_status"])
# To run the queries as multithreaded for faster execution rate
with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(report, range(0,len(df)))
    executor.shutdown(wait=True)
print(df)

# Writeout the database as csv for storage
df.to_csv('Final_IOC_13_11_2022.csv', na_rep='', index=None,errors='ignore')

print(f'\nTime : {time.time() - start_time : .2f}')

