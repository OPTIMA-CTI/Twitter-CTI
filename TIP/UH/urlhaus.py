import datetime
import requests

class Response():
    '''
    Generate URLhaus response

    Parameters
    ----------

    ioc : str - the value of ioc  ** to be passed ro corresponding methods **


    Examples
    --------

    >>> r = Response()

    >>> response = r.url('https://example.com')

    >>> response = r.hash('value of hash sha1, sha256, md5 etc ')

    >>> response = r.host('value of ip address or domain[eg: google.com]')

    >>> print(response)
        {'key':'value', ..............}response from URLhaus..............}

    Notes
    -----

    When an API request with proper data and structure is send to server the server will
    return a response, in order to get that response the class Response is used.

    Here Connection Errors and query status are handled properly so that further procedures 
    can be done with ease.

    Class Response has 4 methods within:
        get_response, url, host, hash'''

    '''
    This function is responsible for the response generation by communicating with server
    The key value and ioc values are passed here
    Return value will be a dict which holds the server response corresponding to the particular ioc'''
    
    def get_response(self, key, ioc,ioc_type):

        base_url = f'https://urlhaus-api.abuse.ch/v1/{key}/'
        if ioc_type in ['url','ip','domain']:
          data = {key: ioc}
        elif ioc_type in ['hash']:
          if len(ioc) == 64:
            key = 'sha256'
          else:
            key='md5'
          data = {key: ioc}

        # This loop will run untill the response status code is 200, which will be a proper response
        while(True):

            try:
                response = requests.post(base_url, data)
            except requests.exceptions.ConnectionError as e:
                print(e)
                continue

            if response.status_code == 200:
                json_response = response.json()
                break

        # Query status are checked and returns a corrsponding dict object
        query_status = json_response['query_status']

        if query_status == 'ok':
            return json_response

        elif query_status in ['invalid_host', 'invalid_url', 'invalid_payload']:
            return {'Invalid': query_status}

        elif query_status == 'no_results':
            return {'NotFound': query_status}

    
    '''
    URLhaus accepts 3 types of ioc, which are url, host and hashes
    Each type has its own function so that it can pass a correct key value to the get_response method
    '''

    def url(self, url_address,ioc_type):
        response = self.get_response('url', url_address,ioc_type)
        return response

    def host(self, host,ioc_type):
        response = self.get_response('host', host,ioc_type)
        return response

    def hashcheck(self, hash_value,ioc_type):
        response = self.get_response('payload', hash_value,ioc_type)
        return response


class UrlHaus:

    '''
    URLhaus Report

    Parameters
    ----------

    ioc         : str - the value of ioc
    ioc_type    : str - the type of ioc mentioned
    source_date : (optional) | str - date which the ioc is reported 
    source_name : (optional) | str - name of the source
    date_format : (optional) | str - date format of the reported date eg:'%Y-%m-%d %H:%M:%S'


    Examples
    --------

    >>> uh = UrlHaus('value of ioc', 'ioc_type', 'source_date', source_name='Twitter',date_format='%Y-%m-%d %H:%M:%S')

    >>> uh2 = UrlHaus('value of ioc', 'ioc_type') # ioc and ioc type are mandatory

    >>> print(uh.urlhaus_report)
        Malicious

    >>> print(uh.status)
        offline

    Notes
    -----

    The response from the Response class has to be processed inorder to get a meaningful data

    The analysis of the response and data processing is done in Class UrlHaus

    The object of UrlHaus canbe created by passing ioc and ioc_type to the constructor
    source date, name and date format are optional

    When the object is created this initializes 

            urlhaus_report : which is the status of the ioc (Malicios/Clean/NotFound/Invalid..)
            first_submission_date : first reported date in urlhaus
            status : the status of the ioc (Whether it is online or offline)
            first_report : who reported this ioc first (URLhaus or the source which the ioc is passed)
            first_report_latency,first_report_latency_in_sec : the latency in reporting interwell
            reference : the link to which these data, which can be validated
    '''
    # Constructor which gets and initializes required values and query that ioc
    def __init__(self, ioc, ioc_type, source_date=None, source_name='Source', date_format='%Y-%m-%d %H:%M:%S') -> None:

        self.urlhaus_report: str = None
        self.first_submission_date: str = None
        self.status: str = None
        self.first_report: str = None
        self.first_report_latency: str = None
        self.first_report_latency_in_sec: str = None
        self.reference: str = None

        self.query(ioc, ioc_type, source_date, source_name, date_format)

    # used to pass the ioc to get Response and further data processing is done here
    def query(self, ioc, ioc_type, source_date, source_name, date_format):

        r = Response()

        if ioc_type == 'url':
            response = r.url(ioc,ioc_type)

        elif ioc_type.lower() in ['hash']:
            response = r.hashcheck(ioc,ioc_type)

        elif ioc_type.lower() in ['ip', 'domain']:
            response = r.host(ioc,ioc_type)

        else:
            return

        if 'NotFound' in response.keys():
            self.urlhaus_report = 'NotFound'
            return

        elif 'Invalid' in response.keys():
            self.urlhaus_report = 'Invalid'
            return

        else:
            self.urlhaus_report = 'Malicious'

            if 'date_added' in response.keys():
                self.first_submission_date = datetime.datetime.strptime(response['date_added'], '%Y-%m-%d %H:%M:%S UTC')

            elif "firstseen" in response.keys():
                self.first_submission_date = datetime.datetime.strptime(response['firstseen'], '%Y-%m-%d %H:%M:%S UTC')

            if 'url_status' in response.keys():
                self.status = response['url_status']

            if 'urlhaus_reference' in response.keys():
                self.reference = response['urlhaus_reference']

            if source_date:
                self.first_report,self.first_report_latency,self.first_report_latency_in_sec = self.getDateDifference(source_date, source_name, date_format)

    # Functio which will calculate the time difference in the submission and returns 3 values which are first reported engine and latency in easily understandable and seconds format
    def getDateDifference(self, source_date, source_name, date_format):

        if self.first_submission_date is None:
            return None,None,None

        source_date = datetime.datetime.strptime(source_date, date_format)

        if source_date < self.first_submission_date:
            duration = self.first_submission_date - source_date
            return source_name, duration, duration.total_seconds()
        elif source_date > self.first_submission_date :
            duration = source_date - self.first_submission_date
            return 'URLhaus', duration, duration.total_seconds()
        else:
            return None,None,None


'''
Used for debugging purposes

This file is mainly intented to be imported and by using the object of UrlHaus, data can be retrieved

when this file is executed the main method will be invoked and a test case can be run with any given
ioc, ioc type.
source name,date,format are optional '''
def main(ioc,ioc_type):

    uh = UrlHaus(ioc, ioc_type)

    print(ioc,ioc_type,uh.urlhaus_report,uh.status,uh.first_submission_date,uh.reference)


if __name__ == '__main__':

    main(
        ioc='http://securecon.top/kb8xp/1806xp',
        ioc_type='url'
    )
