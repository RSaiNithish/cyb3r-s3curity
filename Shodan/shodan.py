import requests
import json

KEY = "mudRiVlGm5bduKS3CH8A63sJenPswOrm"

class Shodan_Integrations:
    class Notifier:
        def __init__(self, parent):
            self.parent = parent
        
        def list_notifiers(self):
            """List all user-created notifiers

            Returns:
                requests.Response: Returns a list of all the notifiers that the user has created.
            """
            #https://api.shodan.io/notifier?key={key}
            
            parent = self.parent
            list_notifiers = parent._session.get(f'{parent.base_url}/notifier?key={parent.api_key}')
            parent.print_json(list_notifiers.json())
            
            return list_notifiers
        
        def list_providers(self):
            """List of available notification providers

            Returns:
                requests.Response: a list of all the notification providers that are available and the parameters to submit when creating them.
            """
            #https://api.shodan.io/notifier/provider?key={key}
            
            parent = self.parent
            list_providers = parent._session.get(f'{parent.base_url}/notifier/provider?key={key}')
            parent.print_jason(list_providers.json())
            
            return list_providers
        
        def get(self, nid):
            """Get information about a notifier
            Use this method to create a new notification service endpoint that Shodan services can send notifications through.
            Args:
                nid (String): Notifier ID

            Returns:
                requests.Response: Returns information about the notifier
            """
            #https://api.shodan.io/notifier/{id}?key={key}
            
            parent = self.parent
            get = parent._session.get(f'{parent.base_url}/notifier/{nid}/key=?{parent.api_key}')
            parent.print_json(get)
            
            return get
    
    class Org:
        def __init__(self, parent):
            self.parent = parent        
        
        def info(self):
            """General Information

            Returns:
                requests.Response: Returns the information about your organization such as the list of its members, upgrades, authorized domains and more.
            """
            #https://api.shodan.io/org?key={key}
            
            parent = self.parent
            info = parent._session.get(f'{parent.base_url}/org?key={parent.api_key}')
            parent.print_json(info.json())
            
            return info
        
    class Data:
        def __init__(self, parent):
            self.parent = parent
            
        def list_datasets(self):
            """Get a list of available datasets

            Returns:
                requests.Response: Returns the  list of the datasets that are available for download
            """
            #https://api.shodan.io/shodan/data?key={key}
            
            parent = self.parent
            list_datasets = parent._session.get(f"{parent.url}/data?key={parent.api_key}")
            parent.print_json(list_datasets.json())
            
            return list_datasets
    
        def list_files(self, dataset):
            """List the files for a dataset

            Args:
                dataset (String): Name of the dataset

            Returns:
                requests.Response: Returns the list of files that are available for download from the provided dataset.
            """
            #https://api.shodan.io/shodan/data/{dataset}?key={key}
            
            parent = self.parent
            list_files = parent._session.get(f"{parent.url}/data/{dataset}?key={parent.api_key}")
            parent.print_json(list_files.json())
            
            return list_files
    class Dns:
        def __init__(self,parent):
            self.parent = parent
            
        def domain_info(self, domain, history=False, type=None, page=1):
            """Domain Information

            Args:
                domain (String): Domain name to lookup; example "cnn.com"
                history (bool, optional): True if historical DNS data should be included in the results. Defaults to False.
                type (String, optional):  DNS type, possible values are: A, AAAA, CNAME, NS, SOA, MX, TXT. Defaults to None.
                page (int, optional):  The page number to page through results 100 at a time. Defaults to 1.
            Returns:
                requests.Response: Returns all the subdomains and other DNS entries for the given domain. Uses 1 query credit per lookup.
            """
            #https://api.shodan.io/dns/domain/{domain}?key={key}
            
            parent = self.parent
            params = {}
            params['key'] = parent.api_key
            if history:
                params['history'] = history
            if type:
                params['type'] = type
            params['page'] = page
            domain_info = parent._session.get(f"{parent.base_url}/dns/domain/{domain}", params=params)
            parent.print_json(domain_info.json())
            
            return domain_info
    
        def resolve(self,hostnames):
            """DNS Lookup

            Args:
                hostnames (String):  Comma-separated list of hostnames; example "google.com,bing.com"

            Returns:
                _type_: Returns the IP address for the provided list of hostnames.
            """
            #https://api.shodan.io/dns/resolve?hostnames={hostnames}&key={key}
            
            parent = self.parent
            resolve = parent._session.get(f"{parent.base_url}/dns/resolve?hostnames={hostnames}&key={parent.api_key}")
            parent.print_json(resolve.json())
            
            return resolve
        
        def reverse(self,ips):
            """Reverse DNS Lookup

            Args:
                hostnames (String):  Comma-separated list of IP addresses; example "74.125.227.230,204.79.197.200"

            Returns:
                _type_: Returns the the hostnames that have been defined for the given list of IP addresses.
            """
            #https://api.shodan.io/dns/reverse?ips={ips}&key={key}
            
            parent = self.parent
            reverse = parent._session.get(f"{parent.base_url}/dns/reverse?ips={ips}&key={parent.api_key}")
            parent.print_json(reverse.json())
            
            return reverse
            
    def __init__(self, KEY):
        self.api_key = KEY
        self.base_url = 'https://api.shodan.io/'
        self.url= 'https://api.shodan.io/shodan'
        self.host_url = 'https://api.shodan.io/shodan/host'
        self._session = requests.Session()
        self.notifier = self.Notifier(self)
        self.org = self.Org(self)
        self.dns = self.Dns(self)
    
    def print_json(self,content):
        print(json.dumps(content, indent=2))    
        
    def host(self,IP, history=False, minify=False):
        """Returns all services that have been found on the given host IP.

        Args:
            IP (String):  Host IP address
            history (bool, optional): True if all historical banners should be returned. Defaults to False.
            minify (bool, optional): True to only return the list of ports and the general host information, no banners. Defaults to False.

        Returns:
            request.Response : Response with details of host IP
        """
        #https://api.shodan.io/shodan/host/{ip}?key={key}
        params = {}
        params['key'] = self.api_key
        if history:
            params['history'] = history
        if minify:
            params['minify'] = minify
        host = self._session.get(f'{self.host_url}/{IP}',params=params)
        self.print_json(host.json())
        
        return host
    
    
    def count(self,query, facets=None):
        """Search Shodan without Results
        This method does not return any host results, it only returns the total number of results 
        that matched the query and any facet information that was requested

        Args:
            query (String): Shodan search query. The provided string is used to search the database of banners in Shodan, \
                with the additional option to provide filters inside the search query using a "filter:value" format. \
                For example, the following search query would find Apache Web servers located in Germany: "apache country:DE".
            facets (String, optional): A comma-separated list of properties to get summary information on. Property names \
                can also be in the format of "property:count", where "count" is the number of facets that will be returned \
                for a property (i.e. "country:100" to get the top 100 countries for a search query). Defaults to None.

        Returns:
            requests.Response: Response of count method
        """
        #https://api.shodan.io/shodan/host/count?key={key}&query={query}&facets={facets}
        
        params = {}
        params['key'] = self.api_key
        params['query'] = query
        if facets:
            params['facets'] = facets
        count = self._session.get(f'{self.host_url}/count',params=params)
        self.print_json(count.json())
        
        return count
    
    
    def search(self,query, facets=None, page=1, minify=True):
        """Search Shodan using the same query syntax as the website and use facets to get summary information for different properties.
        Requirements:
        This method may use API query credits depending on usage. If any of the following criteria are met, your account will be deducted 1 query credit:

        1. The search query contains a filter.
        2. Accessing results past the 1st page using the "page". For every 100 results past the 1st page 1 query credit is deducted.
        Args:
            query (String): Shodan search query. The provided string is used to search the database of banners in Shodan, \
                with the additional option to provide filters inside the search query using a "filter:value" format. \
                For example, the following search query would find Apache Web servers located in Germany: "apache country:DE".
            facets (String, optional): A comma-separated list of properties to get summary information on. Property names \
                can also be in the format of "property:count", where "count" is the number of facets that will be returned \
                for a property (i.e. "country:100" to get the top 100 countries for a search query). Defaults to None.
            page (Integer, optional): he page number to page through results 100 at a time . Defaults to 1.
            minify (bool, optional): whether or not to truncate some of the larger fields. Defaults to True.

        Returns:
            requests.Response: Response of shodan search
        """
        #https://api.shodan.io/shodan/host/search?key={}&query={query}&facets={facets}
        
        params = {}
        params['key'] = self.api_key
        params['query'] = query
        if facets:
            params['facets'] = facets
        params['page'] = page
        if minify:
            params['minify'] = minify
        search = self._session.get(f'{self.host_url}/search',params=params)
        self.print_json(search.json())
        
        return search
    
    def search_facets(self):
        """List all search facets
        This method returns a list of facets that can be used to get a breakdown of the top values for a property.
        """
        #https://api.shodan.io/shodan/host/search/facets?key=mudRiVlGm5bduKS3CH8A63sJenPswOrm
        
        facets = self._session.get(f'{self.host_url}/search/facets?key={self.api_key}')
        self.print_json(facets.json())
        
        return facets
    
    def search_filters(self):
        """List all filters that can be used when searching
        This method returns a list of search filters that can be used in the search query.
        """
        #https://api.shodan.io/shodan/host/search/facets?key=mudRiVlGm5bduKS3CH8A63sJenPswOrm
        
        filters = self._session.get(f'{self.host_url}/search/filters?key={self.api_key}')
        self.print_json(filters.json())
        
        return filters
    
    def search_tokens(self, query):
        """Break the search query into tokens
        This method lets you determine which filters are being used by the query string and what parameters were provided to the filters.

        Args:
            query (String):Shodan search query. The provided string is used to search the database of banners in Shodan,\
                with the additional option to provide filters inside the search query using a "filter:value" format. For example, the following search query would find Apache Web servers located in Germany: "apache country:DE".

        Returns:
            requests.Response: Response of shodan token search
        """
        #https://api.shodan.io/shodan/host/search/tokens?key={key}&query={query}
        params = {}
        params['key'] = self.api_key
        params['query'] = query
        token_search = self._session.get(f"{self.host_url}/search/tokens",params=params)
        self.print_json(token_search.json())
        
        return token_search

    def ports(self):
        """List all ports that Shodan is crawling on the Internet

        Returns:
            requests.Response: This method returns a list of port numbers that the crawlers are looking for.
        """
        #https://api.shodan.io/shodan/ports?key={key}
        
        ports = self._session.get(f"{self.url}/ports?key={self.api_key}")
        self.print_json(ports.json())
        
        return ports
        
    def protocols(self):
        """List all protocols that can be used when performing on-demand Internet scans via Shodan.

        Returns:
            requests.Response: This method returns an object containing all the protocols that can be used when launching an Internet scan.
        """
        #https://api.shodan.io/shodan/protocols?key={key}
        
        protocols = self._session.get(f"{self.url}/protocols?key={self.api_key}")
        self.print_json(protocols.json())
        
        return protocols
    
    def scans(self, page=1):
        """Get list of all the created scans

        Args:
            page (int, optional): Number of pages to be displayed. Defaults to 1.

        Returns:
            requests.Response: Returns a listing of all the on-demand scans that are currently active on the account.
        """
        #https://api.shodan.io/shodan/scans?key={key}
        
        scans = self._session.get(f"{self.url}/scans?key={self.api_key}")
        self.print_json(scans.json())
        
        return json
    
    def scan_status(self, scan_id):
        """Get the status of a scan request

        Args:
            scan_id (String): The unique scan ID that was returned by /shodan/scan.
        Returns:
            requests.Response: Returns status of the scan request 
        """
        #https://api.shodan.io/shodan/scan/{id}?key={key}
        
        scan_status = self._session(f"{self.url}/scan/{id}?key={key}")
        self.print_json(scan_status.json())
        
        return scan_status
    
    def alerts(self, aid, include_expired=False):
        """Get the details for a network alert

        Args:
            aid (String: Alert ID
            include_expired (bool, optional): Include expired. Defaults to False.

        Returns:
            requests.Response: Returns the information about a specific network alert.
        """
        #https://api.shodan.io/shodan/alert/{id}/info?key={key}
        
        params = {}
        params['key'] = self.api_key
        if include_expired:
            params['include_expired'] = include_expired
        alerts = self._session.get(f"{self.url}/alert/{aid}/info", params=params)
        self.print_json(alerts.json())
        
        return alerts
    
    def alert_triggers(self):
        """Get a list of available triggers

        Returns:
            requests.Response: Returns a list of all the triggers that can be enabled on network alerts.
        """
        #https://api.shodan.io/shodan/alert/triggers?key={key}
        
        triggers = self._session.get(f"{self.url}/alert/trggers?key={self.api_key}")
        self.print_json(triggers.json())
        
        return triggers
    
    
    def queries(self, page=1, sort='timestamp', order='desc'):
        """List the saved search queries

        Args:
            page (int, optional): Page number to iterate over results; each page contains 10 items. Defaults to 1.
            sort (str, optional):  Sort the list based on a property. Possible values are: votes, timestamp. Defaults to 'timestamp'.
            order (str, optional): Whether to sort the list in ascending or descending order. Possible values are: asc, desc. Defaults to 'desc'.

        Returns:
            requests.Response: Returns a list of search queries that users have saved in Shodan.
        """
        #https://api.shodan.io/shodan/query?key={key}
        
        params = {}
        params['key'] = self.api_key
        params['page'] = page
        params['sort'] = sort
        params['order'] = order
        queries = self._session.get(f"{self.url}/query", params=params)
        self.print_json(queries.json())
        
        return queries
    
    def queries_search(self, query, page=1):
        """Search the directory of saved search queries.

        Args:
            query (String): What to search for in the directory of saved search queries.
            page (int, optional): Page number to iterate over results; each page contains 10 items. Defaults to 1.

        Returns:
            requests.Response: Returns the directory of search queries that users have saved in Shodan.
        """
        #https://api.shodan.io/shodan/query/search?key={key}
        
        params = {}
        params['key'] = self.api_key
        params['query'] = query
        params['page'] = page
        
        query_search = self._session.get(f"{self.url}/query/search", params=params)
        self.print_json(query_search.json())
        
        return query_search
    
    def queries_tags(self, size=10):
        """List the most popular tags

        Args:
            size (int, optional): The number of tags to return. Defaults to 10.

        Returns:
            requests.Response: Retuens a list of popular tags for the saved search queries in Shodan.
        """
        #https://api.shodan.io/shodan/query/tags?key={key}
        
        queries_tags = self._session.get(f"{self.url}/query/tags?key={self.api_key}")
        self.print_json(queries_tags.json())
        
        return queries_tags
    
    def account(self):
        """Account Profile

        Returns:
            requests.Response: Returns information about the Shodan account linked to this API key.
        """
        #https://api.shodan.io/account/profile?key={key}
        
        account = self._session.get(f"{self.base_url}/account/profile?key={self.api_key}")
        self.print_json(account.json())
        
        return account
    
    def info(self):
        """API Plan Information

        Returns:
            requests.Response: Returns information about the API plan belonging to the given API key.
        """
        #https://api.shodan.io/api-info?key={key}
        
        info = self._session.get(f"{self.base_url}/api-info?key={self.api_key}")
        self.print_json(info.json())
        
        return info
        
def main():
    s = Shodan_Integrations(KEY)
    #s.host('8.8.8.8',minify=True)
    #s.count(query='port:22', facets='org,os')
    #s.search(query='product:nginx', facets='country,org')
    #s.search_filters()
    #s.search_tokens(query='Raspbian port:22')
    #s.ports()
    #s.scans(page=1)
    #s.notifier.list_notifiers()
    #s.queries(page=1, sort='timestamp', order='desc')
    #s.queries_search(query='webcam', page=1)
    #s.queries_tags(size=10)
    #s.account()
    #s.info()
    #s.dns.domain_info(domain='google.com', history=False, type=None, page=1)
    
    
if __name__ == '__main__':
    main()