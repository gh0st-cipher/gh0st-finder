#!/usr/bin/env python3

"""
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝ ██║  ██║██╔═████╗██╔════╝╚══██╔══╝    ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██║  ███╗███████║██║██╔██║███████╗   ██║       █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██║   ██║██╔══██║████╔╝██║╚════██║   ██║       ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝

Gh0st-Finder: Advanced Username Discovery Tool
Find usernames across social networks and platforms
Author: gh0st-cipher | Version: 1.0.0
"""

import sys
import csv
import signal
import pandas as pd
import os
import re
import json
import secrets
from argparse import ArgumentParser, RawDescriptionHelpFormatter, ArgumentTypeError
from json import loads as json_loads
from time import monotonic
from typing import Optional
from enum import Enum
import requests
from requests_futures.sessions import FuturesSession
from colorama import init, Fore, Style
import webbrowser

__shortname__ = "Gh0st-Finder"
__longname__ = "Gh0st-Finder: Username Discovery Tool"
__version__ = "1.0.0"
__author__ = "gh0st-cipher"

default_data_url = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"
globvar = 0
class QueryStatus(Enum):
    CLAIMED = "Claimed"     
    AVAILABLE = "Available" 
    UNKNOWN = "Unknown"     
    ILLEGAL = "Illegal"
    WAF = "WAF"

    def __str__(self):
        return self.value

class QueryResult():
    def __init__(self, username, site_name, site_url_user, status,
                 query_time=None, context=None):
        self.username = username
        self.site_name = site_name
        self.site_url_user = site_url_user
        self.status = status
        self.query_time = query_time
        self.context = context

    def __str__(self):
        status = str(self.status)
        if self.context is not None:
            status += f" ({self.context})"
        return status


class QueryNotify:
    def __init__(self, result=None):
        self.result = result

    def start(self, message=None):
        pass

    def update(self, result):
        self.result = result

    def finish(self, message=None):
        pass

    def __str__(self):
        return str(self.result)


class QueryNotifyPrint(QueryNotify):
    def __init__(self, result=None, verbose=False, print_all=False, browse=False):
        super().__init__(result)
        self.verbose = verbose
        self.print_all = print_all
        self.browse = browse

    def start(self, message):
        title = "Checking username"
        print(Style.BRIGHT + Fore.GREEN + "[" +
              Fore.YELLOW + "*" +
              Fore.GREEN + f"] {title}" +
              Fore.WHITE + f" {message}" +
              Fore.GREEN + " on:")
        print('\r')

    def countResults(self):
        global globvar
        globvar += 1
        return globvar

    def update(self, result):
        self.result = result

        response_time_text = ""
        if self.result.query_time is not None and self.verbose is True:
            response_time_text = f" [{round(self.result.query_time * 1000)}ms]"

        if result.status == QueryStatus.CLAIMED:
            self.countResults()
            print(Style.BRIGHT + Fore.WHITE + "[" +
                  Fore.GREEN + "+" +
                  Fore.WHITE + "]" +
                  response_time_text +
                  Fore.GREEN +
                  f" {self.result.site_name}: " +
                  Style.RESET_ALL +
                  f"{self.result.site_url_user}")
            if self.browse:
                webbrowser.open(self.result.site_url_user, 2)

        elif result.status == QueryStatus.AVAILABLE:
            if self.print_all:
                print(Style.BRIGHT + Fore.WHITE + "[" +
                      Fore.RED + "-" +
                      Fore.WHITE + "]" +
                      response_time_text +
                      Fore.GREEN + f" {self.result.site_name}:" +
                      Fore.YELLOW + " Not Found!")

        elif result.status == QueryStatus.UNKNOWN:
            if self.print_all:
                print(Style.BRIGHT + Fore.WHITE + "[" +
                      Fore.RED + "-" +
                      Fore.WHITE + "]" +
                      Fore.GREEN + f" {self.result.site_name}:" +
                      Fore.RED + f" {self.result.context}" +
                      Fore.YELLOW + " ")

        elif result.status == QueryStatus.ILLEGAL:
            if self.print_all:
                msg = "Illegal Username Format For This Site!"
                print(Style.BRIGHT + Fore.WHITE + "[" +
                      Fore.RED + "-" +
                      Fore.WHITE + "]" +
                      Fore.GREEN + f" {self.result.site_name}:" +
                      Fore.YELLOW + f" {msg}")

        elif result.status == QueryStatus.WAF:
            if self.print_all:
                print(Style.BRIGHT + Fore.WHITE + "[" +
                      Fore.RED + "-" +
                      Fore.WHITE + "]" +
                      Fore.GREEN + f" {self.result.site_name}:" +
                      Fore.RED + " Blocked by bot detection" +
                      Fore.YELLOW + " (proxy may help)")

        else:
            raise ValueError(
                f"Unknown Query Status '{result.status}' for site '{self.result.site_name}'"
            )

    def finish(self, message="The processing has been finished."):
        NumberOfResults = self.countResults() - 1
        print(Style.BRIGHT + Fore.GREEN + "[" +
              Fore.YELLOW + "*" +
              Fore.GREEN + "] Search completed with" +
              Fore.WHITE + f" {NumberOfResults} " +
              Fore.GREEN + "results" + Style.RESET_ALL)


class SiteInformation:
    def __init__(self, name, url_home, url_username_format, username_claimed,
                 information, is_nsfw, username_unclaimed=secrets.token_urlsafe(10)):
        self.name = name
        self.url_home = url_home
        self.url_username_format = url_username_format
        self.username_claimed = username_claimed
        self.username_unclaimed = secrets.token_urlsafe(32)
        self.information = information
        self.is_nsfw = is_nsfw

    def __str__(self):
        return f"{self.name} ({self.url_home})"


class SitesInformation:
    def __init__(self, data_file_path=None):
        if not data_file_path:
            data_file_path = default_data_url

        if not data_file_path.lower().endswith(".json"):
            raise FileNotFoundError(f"Incorrect JSON file extension for data file '{data_file_path}'.")

        if data_file_path.lower().startswith("http"):
            try:
                response = requests.get(url=data_file_path)
            except Exception as error:
                raise FileNotFoundError(
                    f"Problem while attempting to access data file URL '{data_file_path}':  {error}"
                )

            if response.status_code != 200:
                raise FileNotFoundError(f"Bad response while accessing data file URL '{data_file_path}'.")
            try:
                site_data = response.json()
            except Exception as error:
                raise ValueError(f"Problem parsing json contents at '{data_file_path}':  {error}.")
        else:
            try:
                with open(data_file_path, "r", encoding="utf-8") as file:
                    try:
                        site_data = json.load(file)
                    except Exception as error:
                        raise ValueError(f"Problem parsing json contents at '{data_file_path}':  {error}.")
            except FileNotFoundError:
                raise FileNotFoundError(f"Problem while attempting to access data file '{data_file_path}'.")

        site_data.pop('$schema', None)
        self.sites = {}

        for site_name in site_data:
            try:
                self.sites[site_name] = SiteInformation(
                    site_name,
                    site_data[site_name]["urlMain"],
                    site_data[site_name]["url"],
                    site_data[site_name]["username_claimed"],
                    site_data[site_name],
                    site_data[site_name].get("isNSFW", False)
                )
            except KeyError as error:
                raise ValueError(f"Problem parsing json contents at '{data_file_path}':  Missing attribute {error}.")
            except TypeError:
                print(f"Encountered TypeError parsing json contents for target '{site_name}' at {data_file_path}\nSkipping target.\n")

    def remove_nsfw_sites(self, do_not_remove: list = []):
        sites = {}
        do_not_remove = [site.casefold() for site in do_not_remove]
        for site in self.sites:
            if self.sites[site].is_nsfw and site.casefold() not in do_not_remove:
                continue
            sites[site] = self.sites[site]
        self.sites = sites

    def site_name_list(self):
        return sorted([site.name for site in self], key=str.lower)

    def __iter__(self):
        for site_name in self.sites:
            yield self.sites[site_name]

    def __len__(self):
        return len(self.sites)


class Gh0stFuturesSession(FuturesSession):
    def request(self, method, url, hooks=None, *args, **kwargs):
        if hooks is None:
            hooks = {}
        start = monotonic()

        def response_time(resp, *args, **kwargs):
            resp.elapsed = monotonic() - start

        try:
            if isinstance(hooks["response"], list):
                hooks["response"].insert(0, response_time)
            elif isinstance(hooks["response"], tuple):
                hooks["response"] = list(hooks["response"])
                hooks["response"].insert(0, response_time)
            else:
                hooks["response"] = [response_time, hooks["response"]]
        except KeyError:
            hooks["response"] = [response_time]

        return super(Gh0stFuturesSession, self).request(
            method, url, hooks=hooks, *args, **kwargs
        )


def get_response(request_future, error_type, social_network):
    response = None
    error_context = "General Unknown Error"
    exception_text = None
    
    try:
        response = request_future.result()
        if response.status_code:
            error_context = None
    except requests.exceptions.HTTPError as errh:
        error_context = "HTTP Error"
        exception_text = str(errh)
    except requests.exceptions.ProxyError as errp:
        error_context = "Proxy Error"
        exception_text = str(errp)
    except requests.exceptions.ConnectionError as errc:
        error_context = "Error Connecting"
        exception_text = str(errc)
    except requests.exceptions.Timeout as errt:
        error_context = "Timeout Error"
        exception_text = str(errt)
    except requests.exceptions.RequestException as err:
        error_context = "Unknown Error"
        exception_text = str(err)

    return response, error_context, exception_text


def interpolate_string(input_object, username):
    if isinstance(input_object, str):
        return input_object.replace("{}", username)
    elif isinstance(input_object, dict):
        return {k: interpolate_string(v, username) for k, v in input_object.items()}
    elif isinstance(input_object, list):
        return [interpolate_string(i, username) for i in input_object]
    return input_object

def check_for_parameter(username):
    return "{?}" in username

def multiple_usernames(username):
    checksymbols = ["_", "-", "."]
    allUsernames = []
    for i in checksymbols:
        allUsernames.append(username.replace("{?}", i))
    return allUsernames

def gh0st_search(
    username: str,
    site_data: dict,
    query_notify: QueryNotify,
    tor: bool = False,
    unique_tor: bool = False,
    dump_response: bool = False,
    proxy: Optional[str] = None,
    timeout: int = 60,
):

    query_notify.start(username) 
    if tor or unique_tor:
        try:
            from torrequest import TorRequest
        except ImportError:
            print("Notice!")
            print("> --tor and --unique-tor require torrequest package.")
            print("> Install it with: pip install torrequest")
            sys.exit(query_notify.finish())

        print("Notice!")
        print("> Using Tor for enhanced privacy and anonymity.")
        try:
            underlying_request = TorRequest()
        except OSError:
            print("Tor not found in system path. Unable to continue.\n")
            sys.exit(query_notify.finish())

        underlying_session = underlying_request.session
    else:
        underlying_session = requests.session()
        underlying_request = requests.Request()
    if len(site_data) >= 20:
        max_workers = 20
    else:
        max_workers = len(site_data)

    session = Gh0stFuturesSession(max_workers=max_workers, session=underlying_session)
    results_total = {}
    for social_network, net_info in site_data.items():
        results_site = {"url_main": net_info.get("urlMain")}

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
        }

        if "headers" in net_info:
            headers.update(net_info["headers"])

        url = interpolate_string(net_info["url"], username.replace(' ', '%20'))

        # Don't make request if username is invalid for the site
        regex_check = net_info.get("regexCheck")
        if regex_check and re.search(regex_check, username) is None:
            results_site["status"] = QueryResult(
                username, social_network, url, QueryStatus.ILLEGAL
            )
            results_site["url_user"] = ""
            results_site["http_status"] = ""
            results_site["response_text"] = ""
            query_notify.update(results_site["status"])
        else:
            results_site["url_user"] = url
            url_probe = net_info.get("urlProbe")
            request_method = net_info.get("request_method")
            request_payload = net_info.get("request_payload")
            request = None

            if request_method is not None:
                if request_method == "GET":
                    request = session.get
                elif request_method == "HEAD":
                    request = session.head
                elif request_method == "POST":
                    request = session.post
                elif request_method == "PUT":
                    request = session.put
                else:
                    raise RuntimeError(f"Unsupported request_method for {url}")
            if request_payload is not None:
                request_payload = interpolate_string(request_payload, username)
            if url_probe is None:
                url_probe = url
            else:
                url_probe = interpolate_string(url_probe, username)
            if request is None:
                if net_info["errorType"] == "status_code":
                    request = session.head
                else:
                    request = session.get
            if net_info["errorType"] == "response_url":
                allow_redirects = False
            else:
                allow_redirects = True
            if proxy is not None:
                proxies = {"http": proxy, "https": proxy}
                future = request(
                    url=url_probe,
                    headers=headers,
                    proxies=proxies,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                    json=request_payload,
                )
            else:
                future = request(
                    url=url_probe,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                    json=request_payload,
                )
            net_info["request_future"] = future
            if unique_tor:
                underlying_request.reset_identity()

        results_total[social_network] = results_site
    for social_network, net_info in site_data.items():
        results_site = results_total.get(social_network)
        url = results_site.get("url_user")
        status = results_site.get("status")
        
        if status is not None:
            continue

        error_type = net_info["errorType"]
        future = net_info["request_future"]
        r, error_text, exception_text = get_response(
            request_future=future, error_type=error_type, social_network=social_network
        )
        try:
            response_time = r.elapsed
        except AttributeError:
            response_time = None

        try:
            http_status = r.status_code
        except Exception:
            http_status = "?"
        try:
            response_text = r.text.encode(r.encoding or "UTF-8")
        except Exception:
            response_text = ""

        query_status = QueryStatus.UNKNOWN
        error_context = None

        WAFHitMsgs = [
            r'.loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}body.dark{background-color:#222;color:#d9d9d9}body.dark a{color:#fff}body.dark a:hover{color:#ee730a;text-decoration:underline}body.dark .lds-ring div{border-color:#999 transparent transparent}body.dark .font-red{color:#b20f03}body.dark',
            r'<span id="challenge-error-text">',
            r'AwsWafIntegration.forceRefreshToken',
            r'{return l.onPageView}}),Object.defineProperty(r,"perimeterxIdentifiers",{enumerable:'
        ]

        if error_text is not None:
            error_context = error_text
        elif any(hitMsg in r.text for hitMsg in WAFHitMsgs):
            query_status = QueryStatus.WAF
        elif error_type == "message":
            error_flag = True
            errors = net_info.get("errorMsg")
            
            if isinstance(errors, str):
                if errors in r.text:
                    error_flag = False
            else:
                for error in errors:
                    if error in r.text:
                        error_flag = False
                        break
            
            if error_flag:
                query_status = QueryStatus.CLAIMED
            else:
                query_status = QueryStatus.AVAILABLE
                
        elif error_type == "status_code":
            error_codes = net_info.get("errorCode")
            query_status = QueryStatus.CLAIMED

            if isinstance(error_codes, int):
                error_codes = [error_codes]

            if error_codes is not None and r.status_code in error_codes:
                query_status = QueryStatus.AVAILABLE
            elif r.status_code >= 300 or r.status_code < 200:
                query_status = QueryStatus.AVAILABLE
                
        elif error_type == "response_url":
            if 200 <= r.status_code < 300:
                query_status = QueryStatus.CLAIMED
            else:
                query_status = QueryStatus.AVAILABLE
        else:
            raise ValueError(f"Unknown Error Type '{error_type}' for site '{social_network}'")

        if dump_response:
            print("+++++++++++++++++++++")
            print(f"TARGET NAME   : {social_network}")
            print(f"USERNAME      : {username}")
            print(f"TARGET URL    : {url}")
            print(f"TEST METHOD   : {error_type}")
            try:
                print(f"STATUS CODES  : {net_info['errorCode']}")
            except KeyError:
                pass
            print("Results...")
            try:
                print(f"RESPONSE CODE : {r.status_code}")
            except Exception:
                pass
            try:
                print(f"ERROR TEXT    : {net_info['errorMsg']}")
            except KeyError:
                pass
            print(">>>>> BEGIN RESPONSE TEXT")
            try:
                print(r.text)
            except Exception:
                pass
            print("<<<<< END RESPONSE TEXT")
            print("VERDICT       : " + str(query_status))
            print("+++++++++++++++++++++")

        result = QueryResult(
            username=username,
            site_name=social_network,
            site_url_user=url,
            status=query_status,
            query_time=response_time,
            context=error_context,
        )
        query_notify.update(result)

        results_site["status"] = result
        results_site["http_status"] = http_status
        results_site["response_text"] = response_text
        results_total[social_network] = results_site

    return results_total
def timeout_check(value):
    float_value = float(value)
    if float_value <= 0:
        raise ArgumentTypeError(f"Invalid timeout value: {value}. Timeout must be a positive number.")
    return float_value

def handler(signal_received, frame):
    sys.exit(0)

def print_banner():
    banner = f"""
{Fore.CYAN}
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝ ██║  ██║██╔═████╗██╔════╝╚══██╔══╝    ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██║  ███╗███████║██║██╔██║███████╗   ██║       █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██║   ██║██╔══██║████╔╝██║╚════██║   ██║       ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.GREEN}┌─────────────────────────────────────────────────────────────────────────────────────┐
│ {Fore.YELLOW}Gh0st-Finder v{__version__}{' ' * (15 - len(__version__))} - Advanced Username Discovery Tool{' ' * 15} {Fore.GREEN}│
│ {Fore.WHITE}Author: {__author__}{' ' * (20 - len(__author__))} │ Find usernames across social networks{' ' * 15} {Fore.GREEN}│
│ {Fore.MAGENTA}Termux Compatible{' ' * 12} │ Fast • Reliable • Comprehensive{' ' * 21} {Fore.GREEN}│
└─────────────────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}
"""
    print(banner)

def main():
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=f"{__longname__} (Version {__version__})",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__shortname__} v{__version__}",
        help="Display version information and dependencies.",
    )
    parser.add_argument(
        "--verbose", "-v", "-d", "--debug",
        action="store_true",
        dest="verbose",
        default=False,
        help="Display extra debugging information and metrics.",
    )
    parser.add_argument(
        "--folderoutput", "-fo",
        dest="folderoutput",
        help="If using multiple usernames, the output of the results will be saved to this folder.",
    )
    parser.add_argument(
        "--output", "-o",
        dest="output",
        help="If using single username, the output of the result will be saved to this file.",
    )
    parser.add_argument(
        "--tor", "-t",
        action="store_true",
        dest="tor",
        default=False,
        help="Make requests over Tor; increases runtime; requires Tor to be installed and in system path.",
    )
    parser.add_argument(
        "--unique-tor", "-u",
        action="store_true",
        dest="unique_tor",
        default=False,
        help="Make requests over Tor with new Tor circuit after each request; increases runtime; requires Tor to be installed and in system path.",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        dest="csv",
        default=False,
        help="Create Comma-Separated Values (CSV) File.",
    )
    parser.add_argument(
        "--xlsx",
        action="store_true",
        dest="xlsx",
        default=False,
        help="Create the standard file for the modern Microsoft Excel spreadsheet (xlsx).",
    )
    parser.add_argument(
        "--site",
        action="append",
        metavar="SITE_NAME",
        dest="site_list",
        default=[],
        help="Limit analysis to just the listed sites. Add multiple options to specify more than one site.",
    )
    parser.add_argument(
        "--proxy", "-p",
        metavar="PROXY_URL",
        action="store",
        dest="proxy",
        default=None,
        help="Make requests over a proxy. e.g. socks5://127.0.0.1:1080",
    )
    parser.add_argument(
        "--dump-response",
        action="store_true",
        dest="dump_response",
        default=False,
        help="Dump the HTTP response to stdout for targeted debugging.",
    )
    parser.add_argument(
        "--json", "-j",
        metavar="JSON_FILE",
        dest="json_file",
        default=None,
        help="Load data from a custom JSON file or an online JSON file URL.",
    )
    parser.add_argument(
        "--timeout",
        action="store",
        metavar="TIMEOUT",
        dest="timeout",
        type=timeout_check,
        default=60,
        help="Time (in seconds) to wait for response to requests (Default: 60)",
    )
    parser.add_argument(
        "--print-all",
        action="store_true",
        dest="print_all",
        default=False,
        help="Output sites where the username was not found.",
    )
    parser.add_argument(
        "--print-found",
        action="store_true",
        dest="print_found",
        default=True,
        help="Output sites where the username was found (also if exported as file).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        default=False,
        help="Don't color terminal output",
    )
    parser.add_argument(
        "username",
        nargs="+",
        metavar="USERNAMES",
        action="store",
        help="One or more usernames to check with social networks. Check similar usernames using {?} (replace to '_', '-', '.').",
    )
    parser.add_argument(
        "--browse", "-b",
        action="store_true",
        dest="browse",
        default=False,
        help="Browse to all results on default browser.",
    )
    parser.add_argument(
        "--local", "-l",
        action="store_true",
        default=False,
        help="Force the use of the local data.json file.",
    )
    parser.add_argument(
        "--nsfw",
        action="store_true",
        default=False,
        help="Include checking of NSFW sites from default list.",
    )
    parser.add_argument(
        "--no-txt",
        action="store_true",
        dest="no_txt",
        default=False,
        help="Disable creation of a txt file",
    )

    args = parser.parse_args()

    signal.signal(signal.SIGINT, handler)
    print_banner()
    if args.tor and (args.proxy is not None):
        raise Exception("Tor and Proxy cannot be set at the same time.")

    if args.proxy is not None:
        print("Using the proxy: " + args.proxy)

    if args.tor or args.unique_tor:
        print("Using Tor to make requests")
        print("Warning: some websites might refuse connecting over Tor, so note that using this option might increase connection errors.")

    if args.no_color:
        init(strip=True, convert=False)
    else:
        init(autoreset=True)

    if args.output is not None and args.folderoutput is not None:
        print("You can only use one of the output methods.")
        sys.exit(1)

    if args.output is not None and len(args.username) != 1:
        print("You can only use --output with a single username")
        sys.exit(1)
    try:
        if args.local:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            local_data_path = os.path.join(script_dir, "data.json")
            sites = SitesInformation(local_data_path)
        else:
            json_file_location = args.json_file
            sites = SitesInformation(json_file_location)
    except Exception as error:
        print(f"ERROR:  {error}")
        sys.exit(1)

    if not args.nsfw:
        sites.remove_nsfw_sites(do_not_remove=args.site_list)
    site_data_all = {site.name: site.information for site in sites}
    
    if args.site_list == []:
        site_data = site_data_all
    else:
        site_data = {}
        site_missing = []
        for site in args.site_list:
            counter = 0
            for existing_site in site_data_all:
                if site.lower() == existing_site.lower():
                    site_data[existing_site] = site_data_all[existing_site]
                    counter += 1
            if counter == 0:
                site_missing.append(f"'{site}'")
        if site_missing:
            print(f"Error: Desired sites not found: {', '.join(site_missing)}.")

        if not site_data:
            sys.exit(1)
    query_notify = QueryNotifyPrint(
        result=None, verbose=args.verbose, print_all=args.print_all, browse=args.browse
    )
    all_usernames = []
    for username in args.username:
        if check_for_parameter(username):
            for name in multiple_usernames(username):
                all_usernames.append(name)
        else:
            all_usernames.append(username)
    for username in all_usernames:
        results = gh0st_search(
            username,
            site_data,
            query_notify,
            tor=args.tor,
            unique_tor=args.unique_tor,
            dump_response=args.dump_response,
            proxy=args.proxy,
            timeout=args.timeout,
        )
        if args.output:
            result_file = args.output
        elif args.folderoutput:
            os.makedirs(args.folderoutput, exist_ok=True)
            result_file = os.path.join(args.folderoutput, f"{username}.txt")
        else:
            result_file = f"{username}.txt"
        if not args.no_txt:
            with open(result_file, "w", encoding="utf-8") as file:
                exists_counter = 0
                for website_name in results:
                    dictionary = results[website_name]
                    if dictionary.get("status").status == QueryStatus.CLAIMED:
                        exists_counter += 1
                        file.write(dictionary["url_user"] + "\n")
                file.write(f"Total Websites Username Detected On : {exists_counter}\n")
        if args.csv:
            result_file = f"{username}.csv"
            if args.folderoutput:
                os.makedirs(args.folderoutput, exist_ok=True)
                result_file = os.path.join(args.folderoutput, result_file)

            with open(result_file, "w", newline="", encoding="utf-8") as csv_report:
                writer = csv.writer(csv_report)
                writer.writerow([
                    "username", "name", "url_main", "url_user", "exists", "http_status", "response_time_s"
                ])
                for site in results:
                    if (args.print_found and not args.print_all and 
                        results[site]["status"].status != QueryStatus.CLAIMED):
                        continue
                    response_time_s = results[site]["status"].query_time
                    if response_time_s is None:
                        response_time_s = ""
                    writer.writerow([
                        username,
                        site,
                        results[site]["url_main"],
                        results[site]["url_user"],
                        str(results[site]["status"].status),
                        results[site]["http_status"],
                        response_time_s,
                    ])
        if args.xlsx:
            usernames = []
            names = []
            url_main = []
            url_user = []
            exists = []
            http_status = []
            response_time_s = []
            for site in results:
                if (args.print_found and not args.print_all and 
                    results[site]["status"].status != QueryStatus.CLAIMED):
                    continue

                response_time_val = results[site]["status"].query_time
                if response_time_val is None:
                    response_time_s.append("")
                else:
                    response_time_s.append(response_time_val)
                    
                usernames.append(username)
                names.append(site)
                url_main.append(results[site]["url_main"])
                url_user.append(results[site]["url_user"])
                exists.append(str(results[site]["status"].status))
                http_status.append(results[site]["http_status"])
            DataFrame = pd.DataFrame({
                "username": usernames,
                "name": names,
                "url_main": url_main,
                "url_user": url_user,
                "exists": exists,
                "http_status": http_status,
                "response_time_s": response_time_s,
            })
            DataFrame.to_excel(f"{username}.xlsx", sheet_name="sheet1", index=False)

        print()
    query_notify.finish()
    
if __name__ == "__main__":
    main()

