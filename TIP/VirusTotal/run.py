from virustotal import VirusTotal
import time
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

# pd.options.mode.chained_assignment = None

start_time = time.time()

def report(index):

    # if df.loc[index,'vt_status'] == 'NotFound' and df.loc[index,'ioc_type'] in ['sha256']:
    #     pass
    if df.loc[index, 'vt_status'] in ['Malicious', 'Clean', 'NotFound', 'InvalidArgument']:
        return

    ioc = df.loc[index, 'ioc_value']
    ioc_type = df.loc[index, 'ioc_type']
    source_date = df.loc[index, 'tweet_date']
    source_date=source_date[:19]
    try:
        vt = VirusTotal(ioc, ioc_type, source_date, source_name='Twitter', date_format='%Y-%m-%d %H:%M:%S')

    except Exception as e:
        print(index, ioc, 'Error\n',e)
        return

    print(index, ioc, vt.status)

    df.loc[index, 'vt_status'] = vt.status
    df.loc[index, 'reference'] = vt.reference

    if vt.status == 'Malicious':
        df.loc[index, 'vt_stat'] = vt.stat
        df.loc[index, 'vt_stat_percent'] = vt.stat_percentage
        df.loc[index, 'category'] = vt.most_repeating_category
        df.loc[index, 'category_description_count'] = vt.category_count
        df.loc[index, 'category_description'] = vt.categories
        df.loc[index, 'first_submission'] = vt.first_submission_date
        df.loc[index, 'first_report'] = vt.first_submission
        df.loc[index, 'first_report_latency'] = vt.first_submission_latency
        df.loc[index, 'first_report_latency(sec)'] = vt.first_submission_latency_insec
        print(df.loc[index, 'vt_stat'])
        print(df.loc[index, 'vt_stat_percent'])
        print(df.loc[index, 'category'])
        print(df.loc[index, 'category_description_count'])
        print(df.loc[index, 'category_description'])
        print(df.loc[index, 'first_submission'])
        print(df.loc[index, 'first_report'])
        print(df.loc[index, 'first_report_latency'])
        print(df.loc[index, 'first_report_latency(sec)'])
    return

    
fields_name = ['tweet_date', 'account', 'ioc_type', 'ioc_value', 'type_of_attack', 'tweet_url', 'text', 'vt_status', 'vt_stat', 'vt_stat_percent', 'category',
               'category_description_count', 'category_description', 'first_submission', 'first_report', 'first_report_latency', 'first_report_latency(sec)', 'reference']


df = pd.read_csv("output_14_11_22.csv",names=fields_name, encoding='utf-8', low_memory=False,lineterminator='\n')

VirusTotal.API_KEY = 'Your KEY'
#cloud_data = r'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv'

#output_filename = 'VirusTotal_Output_July_1_10.csv'

# cloud_df = pd.read_csv(cloud_data, names=fields_name, encoding='utf-8', low_memory=False)

# cloud_df.sort_values(by=['t_time']).to_csv('year.csv', na_rep='', index=None, errors='ignore')


#saved_data = pd.read_csv(VT_Output.csv, encoding='utf-8', low_memory=False)

#df.update(saved_data)

#df = df.sort_values(by=['tweet_date']).reset_index(drop=True)

# df = pd.read_csv(output_filename, encoding='utf-8', low_memory=False)

print(df)

try:
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(report, range(2500,3000))
        executor.shutdown(wait=True)

except Exception as e:
    print(e)

print(df)

df.to_csv("output_14_11_22.csv", na_rep='', index=None, errors='ignore')

end_time = time.time()

print(f'\nTime : {end_time - start_time : .2f}')

