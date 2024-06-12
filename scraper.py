from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from pathlib import Path
import argparse
import requests
import json
import csv



class Scraper:
    def __init__(self, args):
        self.__BASE_URL = "https://workbench.cisecurity.org/benchmarks"
        self.__BASE_URL_API = "https://workbench.cisecurity.org/api/v1/benchmarks"
        self.__USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        self.__CREDENTIAL_FILE = Path(args.credential_file)
        if not self.__CREDENTIAL_FILE.is_file():
            print("Unable to locate the credential file! Exiting...")
            exit(1)
        with open(self.__CREDENTIAL_FILE, "r") as f:
            credential_data = json.loads(f.read())
            self.__XSRF_TOKEN = credential_data["xsrf_token"]
            self.__WORKBENCH_SESSION = credential_data["workbench_session"]
        self.__SESSION = requests.Session()
        self.__SESSION.headers.update({
            "Cookie": f"XSRF-TOKEN={self.__XSRF_TOKEN}; workbench_session={self.__WORKBENCH_SESSION}",
            "User-Agent": self.__USER_AGENT
        })
        self.__BENCHMARK_ID = args.id
        self.__NUM_THREADS = args.threads
        self.__FORMAT = args.format
        self.__OUTPUT = self.__create_path(Path("output") if not args.output_path else args.output_path)
        self.__BENCHMARK_TITLE, self.__BENCHMARK_VERSION = self.__get_title_and_version()
        self.__BENCHMARK_DATA = {"title": f"{self.__BENCHMARK_TITLE}", "controls": {}, "total": None}
        self.__OUTPUT_FILENAME = f"{self.__BENCHMARK_TITLE.replace(' ', '_')}"  # TODO: Implement custom output filename

    @staticmethod
    def __create_path(path_to_create):
        _path = Path(path_to_create)
        if not _path.is_dir():
            _path.mkdir()
        return _path
    
    @staticmethod
    def __create_soup(html):
        return BeautifulSoup(html, "html.parser")

    def __get_title_and_version(self):
        print("[*] Scraping benchmark title and version")
        _soup = self.__create_soup(self.__SESSION.get(f"{self.__BASE_URL}/{self.__BENCHMARK_ID}").text)
        _title = _soup.find("wb-benchmark-title")["title"].split(" ")
        version = _title.pop(-1)
        title = " ".join(i for i in _title)
        print(f"[*] Found: {title} - {version}")
        return title, version

    def __parse_text(self, text):
        _text = text.strip()
        if not _text:
            return ""
        return _text

    def __extract_subsections(self, subsection, navtree_list):
        if "subsections_for_nav_tree" in subsection:
            for sub in subsection["subsections_for_nav_tree"]:
                self.__extract_subsections(sub, navtree_list)
        if "recommendations_for_nav_tree" in subsection:
            for rec in subsection["recommendations_for_nav_tree"]:
                self.__extract_subsections(rec, navtree_list)
        if not ("recommendations_for_nav_tree" and "subsections_for_nav_tree" in subsection):
            navtree_list.append({
                "id": subsection["id"],
                "title": subsection["title"],
                "key": f"{subsection['view_level']} {subsection['title']}",
                "url": f"https://workbench.cisecurity.org/sections/{subsection['section_id']}/recommendations/{subsection['id']}"
            })

    def __fetch_control(self, control):
        _soup = self.__create_soup(self.__SESSION.get(control["url"]).text)
        return {
            "id": control["id"],
            "key": control["key"],
            "title": control["title"],
            "assessment_status": self.__parse_text(_soup.find("span", {"id": "automated_scoring-recomendtation-data"}).text),
            "description": self.__parse_text(_soup.find("div", {"id": "description-recomendtation-data"}).text),
            "rationale": self.__parse_text(_soup.find("div", {"id": "rationale_statement-recomendtation-data"}).text),
            "impact": self.__parse_text(_soup.find("div", {"id": "impact_statement-recomendtation-data"}).text),
            "audit": self.__parse_text(_soup.find("div", {"id": "audit_procedure-recomendtation-data"}).text),
            "remediation": self.__parse_text(_soup.find("div", {"id": "remediation_procedure-recomendtation-data"}).text),
            "default_value": self.__parse_text(_soup.find("div", {"id": "default_value-recomendtation-data"}).text),
            "references": self.__parse_text(_soup.find("div", {"id": "references-recomendtation-data"}).text),
        }

    def __parse_navtree(self):
        print("[*] Parsing navigation tree")
        navigation_tree = self.__SESSION.get(f"{self.__BASE_URL_API}/{self.__BENCHMARK_ID}/navtree").json()["navtree"]
        navtree_data = []
        for item in navigation_tree:
             self.__extract_subsections(item, navtree_data)
        print("[*] Parsing completed")
        return navtree_data

    def main(self):
        navtree_parsed = self.__parse_navtree()
        with ThreadPoolExecutor(max_workers=self.__NUM_THREADS) as executor:
            futures = {executor.submit(self.__fetch_control, control): control for control in navtree_parsed}
            for index_control, future in enumerate(as_completed(futures)):
                control_id = futures[future]["id"]
                try:
                    data = future.result()
                    self.__BENCHMARK_DATA["controls"][control_id] = data
                    print(f"Scraping {index_control+1}/{len(navtree_parsed)} controls...", end="\r")
                except Exception as e:
                    print(f"Error scraping control {control_id}: {e}")    
                    exit(1)
        self.__BENCHMARK_DATA["total"] = len(self.__BENCHMARK_DATA["controls"])
        output_file = Path(self.__OUTPUT, f"{self.__OUTPUT_FILENAME}.{self.__FORMAT}")
        print(f"[*] Done! Saving to \"{output_file}\"")
        with open(output_file, "w") as f:
            if self.__FORMAT == "json":
                json.dump(self.__BENCHMARK_DATA, f, indent=4)
            elif self.__FORMAT == "csv":
                csv_writer = csv.writer(f)
                csv_writer.writerow(["id", "key", "title", "assessment_status", "description", "rationale", "impact", "audit", "remediation", "default_value", "references"])
                for controls in self.__BENCHMARK_DATA["controls"].values():
                    csv_writer.writerow(controls.values())



if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog = "CIS Workbench Scraper")
    parser.add_argument("-id", help="Benchmark ID.", required=True)
    parser.add_argument("-o", "--output_path", help="Path to save the benchmark.", required=False)
    parser.add_argument("-f", "--format", help="Format to save.", choices=["csv", "json"], default="json")
    parser.add_argument("-t", "--threads", help="Number of threads to use to scrape controls.", type=int, default=10)
    parser.add_argument("-c", "--credential_file", help="File that stores the credentials.", required=True)
    args = parser.parse_args()
    Scraper(args).main()