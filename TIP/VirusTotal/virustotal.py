import datetime
from re import search
import requests
import base64
import urllib.parse
import time

class Response():
    '''
    Generate VirusTotal response

    Parameters
    ----------

    api_key : str - API key generated from virustotal website

    ioc : str - the value of ioc  ** to be passed ro corresponding methods **


    Examples
    --------

    >>> r = Response('provided api key')

    >>> response = r.url('https://example.com')

    >>> response = r.ip('value of ip addres')

    >>> response = r.hash('value of hash sha1, sha256, md5 etc ')

    >>> response = r.domain('domain name[eg: google.com]')

    >>> print(response)
        {'key':'value', ..............}response from VirusTotal..............}

    Notes
    -----

    When an API request with proper data and structure is send to server the server will
    return a response, in order to get that response the class Response is used.

    Here Connection Errors and API quotas are handled properly so that further procedures 
    can be done with ease.

    Class Response has 4 methods within:
        get_response, url, ip, domain, hash

    These functions are responsible for the response generation by communicating with server
    The ioc values are passed here
    Return value will be a dict which holds the server response corresponding to the particular ioc'''

    QUOTA_EXCEEDED = False # set to true when the quota allowed by virustotal is exhausted and this is used to stop further server requests on execution

    def __init__(self, api_key) -> None:

        self.API_KEY = api_key

    '''
    This get_response is used to generate various responses from the server
        - To get responses regarding ioc
        - To submit a analysis request for an ioc
        - Retrive the analysis report

    The server request is made such a way that it only stops iteration upon the succesfull response from the server
    or the quota is exceeded

    Various errors such as QuotaExceededError,WrongCredentialsError,InvalidArgumentError,NotFoundError are handled here
    and corresponding dict response is generated'''
    def get_response(self, url, method="GET", headers=None, data=None) -> dict:

        base_url = 'https://www.virustotal.com/api/v3/'

        if headers is None:
            headers = {
                "Accept": "application/json",
                "x-apikey": self.API_KEY
            }

        while True:

            try:
                if Response.QUOTA_EXCEEDED:
                    return {'QuotaExceeded': 'Quota exceeded'}
                
                response = requests.request(method, (base_url + url), headers=headers, data=data)

                if response.status_code == 429:
                    Response.QUOTA_EXCEEDED = True
                    return {'QuotaExceeded': 'Quota exceeded'}
                break

            except requests.exceptions.RequestException as e:
                print(e)

        json_response = response.json()

        if 'error' in json_response.keys():

            error_code = json_response['error']['code']
            error_message = json_response['error']['message']

            if error_code == 'QuotaExceededError':
                Response.QUOTA_EXCEEDED = True
                return {'QuotaExceeded': error_message}
                
            elif error_code == 'WrongCredentialsError':
                print(error_message)

            elif error_code == 'InvalidArgumentError':
                return {'InvalidArgument': error_message}

            else:
                return {'NotFound': error_message}

        # print(json_response)

        return json_response

    # ip domain hash and url methods are responsible for the iocs that are under that category
    def ip(self, ip_address):

        response = self.get_response(f"ip_addresses/{ip_address}")

        return response

    def domain(self, domain_name):

        response = self.get_response(f"domains/{domain_name}")

        return response

    def hash(self, hash_value):

        response = self.get_response(f"files/{hash_value}")

        return response

    '''
    It is adviced by virustotal that the url provided should be base64encoded and is coverted in this method, 
    
    Unlike other iocs in VirusTotal we can submit a analysis of an unidentified ioc

    When the normal query returns a NotFound response, this will invoke the  'submit_url' method 
    which will recieve the url and retuns the analysis id

    Then 'url_analysis_report' will recieve that id and generates a analysis report

    This analysis report is represented as the final report generated for that url '''

    def url(self, url_address):

        url_id = base64.urlsafe_b64encode(url_address.encode()).decode().strip("=")

        response = self.get_response(f'urls/{url_id}')

        if 'NotFound' in response.keys():

            id = self.submit_url(url_address)

            if id is None:
                return {'NotFound': 'IOC not present on the database'}
            
            if id == 'QuotaExceeded':
                return {'QuotaExceeded': 'Quota exceeded'}

            response = self.url_analysis_report(id)

        return response

    # This method will recieves a url address and generates the analysis id corresponding to that ioc
    def submit_url(self, url_address):

        headers = {
            "Accept": "application/json",
            "x-apikey": self.API_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        urlencoded = urllib.parse.quote(url_address, safe='')

        payload = f"url={urlencoded}"

        response = self.get_response(
            url='urls', method="POST", headers=headers, data=payload)

        if 'NotFound' in response.keys():
            return

        if 'InvalidArgument' in response.keys():
            return
        
        if 'QuotaExceeded' in response.keys():
            return 'QuotaExceeded'

        print(response)

        id = response['data']['id']

        return id

    
    # The analysis id is passed here and the analysis report is generated
    def url_analysis_report(self, id):

        time.sleep(30)

        url = f'analyses/{id}'

        while True:

            response = self.get_response(url)

            if 'QuotaExceeded' in response.keys():
                break

            analysis_status = response['data']['attributes']['status']

            if analysis_status == 'queued':
                time.sleep(30)

            elif analysis_status == 'completed':
                break
            else:
                print(analysis_status)
                break

        return response

class VirusTotal:
    '''
    VirusTotal Report

    Parameters
    ----------

    ioc         : str - the value of ioc
    ioc_type    : str - the type of ioc mentioned
    source_date : (optional) | str - date which the ioc is reported 
    source_name : (optional) | str - name of the source
    date_format : (optional) | str - date format of the reported date eg:'%Y-%m-%d %H:%M:%S'


    Examples
    --------

    >>> vt = VirusTotal('value of ioc', 'ioc_type', 'source_date', source_name='Twitter',date_format='%Y-%m-%d %H:%M:%S')

    >>> vt2 = VirusTotal('value of ioc', 'ioc_type') # ioc and ioc type are mandatory

    >>> print(vt.status)
        Malicious

    >>> print(vt.vt_stat)
        18/59

    Notes
    -----

    The response from the Response class has to be processed inorder to get a meaningful data

    The analysis the response and data processing is done in Class VirusTotal

    The object of VirusTotal canbe created by passing ioc and ioc_type to the constructor
    source date, name and date format are optional

    When the object is created this initializes 

        status  :   which is the status of the ioc (Malicios/Clean/NotFound/Invalid..)
        
        stat    :   The number of engines that reported malicious/ Total number of engines
        
        stat_percentage :   Percentage of above mentioned stat
        
        category_count, categories  : The categories which are mentioned in the report
        
        most_repeating_category :   The most repeated category which is present in the report
        
        first_submission_date   :   first reported date in virustotal
        
        first_submission    :   who reported this ioc first (VirusTotal or the source which the ioc is passed)
        
        first_submission_latency, first_submission_latency_insec : the latency in reporting interwell
        
        reference   :   the link to which these data, which can be validated

    '''

    API_KEY : str = None

    def __init__(self, ioc, ioc_type, source_date=None, source_name='Source', date_format='%Y-%m-%d %H:%M:%S') -> None:

        self.status: str

        self.reference: str

        self.malicious: int = None

        self.total: int = None

        self.stat: str = None

        self.stat_percentage: str = None

        self.category_dict: dict = None

        self.most_repeating_category: str = None

        self.category_count: str = None

        self.categories: str = None

        self.first_submission_date: datetime = None

        self.first_submission: str = None

        self.first_submission_latency: str = None

        if not Response.QUOTA_EXCEEDED:
            self.query(ioc,ioc_type,source_date,source_name,date_format)

    # Response generation and data extracion process is initiated in this method
    def query(self, ioc, ioc_type, source_date, source_name, date_format):

        self.ioc = ioc

        obj = Response(VirusTotal.API_KEY)

        if ioc_type.lower() == 'url':
            self.response = obj.url(ioc)

        elif ioc_type.lower() == 'ip':
            self.response = obj.ip(ioc)

        elif ioc_type.lower() in ['domain', 'host']:
            self.response = obj.domain(ioc)

        elif ioc_type.lower() in ['hash', 'md5', 'sha1', 'sha256']:
            self.response = obj.hash(ioc)

        else:
            print(f'Unknown IOC Type: {ioc_type}')
            return

        self.status = self.getStatus()

        self.reference = self.getReference()

        if self.status == 'Malicious':

            self.stat = self.getStat()

            self.stat_percentage = self.getStatPercent()

            self.category_dict = self.createCategoryDict()

            self.categories = self.getCategories()

            self.most_repeating_category = self.getMostRepeatedCategory()

            self.category_count = self.getCategoriesWithCount()

            self.first_submission_date = self.getFirstSubmissionDate()

            if source_date is not None:
                self.first_submission, self.first_submission_latency, self.first_submission_latency_insec = self.getDateDifference(source_date, source_name, date_format)

    # getStat, getStatus, getStatPercent are responsibe for the status of ioc, number of reported cases and its percentages
    def getStatus(self):

        if 'NotFound' in self.response.keys():
            return "NotFound"

        if 'InvalidArgument' in self.response.keys():
            return "InvalidArgument"
        
        if 'QuotaExceeded' in self.response.keys():
            return "QuotaExceededError"

        if 'stats' in self.response['data']['attributes']:
            stat = self.response['data']['attributes']['stats']
        else:
            stat = self.response['data']['attributes']['last_analysis_stats']

        self.malicious = stat['malicious']

        if self.malicious == 0:
            return 'Clean'

        self.total = self.malicious + \
            stat['harmless'] + stat['suspicious'] + stat['undetected']

        return 'Malicious'

    def getStat(self):

        return(f'{self.malicious}/{self.total}')

    def getStatPercent(self):

        return f'{(self.malicious*100/self.total) : .2f}'

    
    # This method will process the response and returns a dict which contains the categories and its count which are mentioned in the virustotal report
    def createCategoryDict(self) -> dict:

        if 'results' in self.response['data']['attributes']:
            data = self.response['data']['attributes']['results'].values()
        else:
            data = self.response['data']['attributes']['last_analysis_results'].values()

        category_dict = {}

        for i in data:

            category = i['result']

            if category == 'clean' or category == 'unrated' or category is None:
                continue

            if category in category_dict.keys():
                category_dict[category] += 1
            else:
                category_dict[category] = 1

        return category_dict


    # Returns the most repeated category in the category_dict
    def getMostRepeatedCategory(self) -> str:

        if len(self.category_dict) > 10:
            return 'Uncertain'

        value = 0
        mostRepeating = ''

        for key, val in self.category_dict.items():
            if val == value:
                mostRepeating = mostRepeating + '#' + key
            elif val > value:
                mostRepeating = '#' + key
                value = val

        # return max(self.category_dict, key=self.category_dict.get)
        return mostRepeating

    def getCategoriesWithCount(self) -> str:

        if len(self.category_dict) > 10:
            return 'Uncertain'

        category_count = ''
        for key, val in self.category_dict.items():
            category_count += f'#{key}({val})'

        return category_count

    def getCategories(self) -> str:

        if len(self.category_dict) > 10:
            return 'Uncertain'

        categories = ''
        for i in self.category_dict:
            categories += f'#{i}'
        return categories

    
    '''
    This method will returns the first submission date for that particular ioc
    
    In certain cases the first submissiion date is not present for such the date, creation date or 
    creation date found in the 'whois' description is taken
 
    '''
    def getFirstSubmissionDate(self) -> datetime:

        if 'first_submission_date' in self.response['data']['attributes'].keys():
            time_stamp = self.response['data']['attributes']['first_submission_date']
            vt_date = datetime.datetime.utcfromtimestamp(time_stamp)
            return vt_date

        elif 'date' in self.response['data']['attributes'].keys():
            time_stamp = self.response['data']['attributes']['date']
            vt_date = datetime.datetime.utcfromtimestamp(time_stamp)
            return vt_date

        elif 'creation_date' in self.response['data']['attributes'].keys():
            time_stamp = self.response['data']['attributes']['creation_date']
            vt_date = datetime.datetime.utcfromtimestamp(time_stamp)
            return vt_date

        elif 'whois' in self.response['data']['attributes'].keys():
            pattern = 'Creation Date:\s\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
            result = search(pattern, self.response['data']['attributes']['whois'])

            if result:
                vt_date = datetime.datetime.strptime(
                    result.group()[15:], '%Y-%m-%dT%H:%M:%S')
                return vt_date

        else:
            return None

    '''
    The date difference between source date and first submission date is calculated here

    the function takes source name,date and date format as input and
    returns who submitted first, the latency in easily understandable and in seconds format '''
    def getDateDifference(self, source_date, source_name, date_format):

        if self.first_submission_date is None:
            return None, None, None
        
        try:
            source_date = datetime.datetime.strptime(source_date, date_format)
        except Exception as e:
            print(e)
            return None, None, None
            
        if source_date < self.first_submission_date:
            duration = self.first_submission_date - source_date
            return source_name,duration, duration.total_seconds()
        elif source_date > self.first_submission_date:
            duration = source_date - self.first_submission_date
            return 'VirusTotal',duration, duration.total_seconds()
        else:
            return None,None,None

    # This method will generate a url link where the credibility of the data can be checked
    def getReference(self):

        if self.status == 'QuotaExceededError':
            return

        if self.status in ['NotFound', 'InvalidArgument']:
            return 'https://www.virustotal.com/gui/search/'+self.ioc

        type = self.response['data']['type']

        if type == 'analysis':
            id = self.response['meta']['url_info']['id']
            return f"https://www.virustotal.com/gui/url/{id}"

        id = self.response['data']['id']
    
        if type in ['url', 'file', 'domain']:
            return f"https://www.virustotal.com/gui/{type}/{id}"

        if type == 'ip_address':
            return f"https://www.virustotal.com/gui/ip-address/{id}"

'''
Used for debugging purposes

This file is mainly intented to be imported and by using the object of VirusTotal, data can be retrieved


when this file is executed the main method will be invoked and a test case can be run with any given
valid apikey, ioc, ioc type.
source name,date,format are optional '''
def main(ioc,ioc_type):

    VirusTotal.API_KEY = 'Your KEY'
    vt = VirusTotal(ioc, ioc_type)

    for key, val in vt.__dict__.items():
        print(f'{key} : {val}\n\n')

if __name__ == '__main__':
    main(
        ioc = '104.168.96.6',
        ioc_type='ip'
    )
