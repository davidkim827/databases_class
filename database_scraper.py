import random
import json
from datetime import datetime

import requests
from bs4 import BeautifulSoup


def convert_input_to_date_obj(date_str):
    date_str = "/".join([date_str[0:2], date_str[2:4], date_str[4:]])
    date_str = datetime.strptime(date_str, "%m/%d/%Y")
    print(datetime.strftime(date_str, "%Y-%m-%d"))
    return date_str


def get_cve_dict(cve, os):
    def get_rating(score):
        if score in (None, 0, "", "NULL"):
            return "Informational"
        score *= 10
        if score < 20:
            return "Informational"
        elif score < 40:
            return "Low"
        elif score < 60:
            return "Moderate"
        elif score < 90:
            return "High"
        else:
            return "Critical"

    cve_base_url = "http://cve.circl.lu/api/cve/"
    cve_dict = requests.get(cve_base_url + cve)
    if cve_dict.text == "null":
        return "null"
    try:
        cve_dict = cve_dict.json()
    except json.JSONDecodeError:
        return "null"

    try:
        cvss = cve_dict.get("cvss")
    except:
        cvss = "null"
    try:
        published = cve_dict.get("Published")[:10]
    except:
        published = "NULL"
    return_dict = {
        "cveID": cve,
        "severity": cvss,
        "rating": get_rating(cvss),
        "published": published,
        "summary": cve_dict.get("summary"),
        "os": os,
    }
    return return_dict


def get_all_redhat_adv_dict(before_date, after_date):
    return_list = []
    redhat_base_url = "https://access.redhat.com/hydra/rest/securitydata"
    before_date = datetime.strftime(before_date, "%Y-%m-%d")
    after_date = datetime.strftime(after_date, "%Y-%m-%d")

    cve_data_uri = (
        redhat_base_url
        + f"/cvrf.json?before={after_date}&after={before_date}&per_page=25&severity=critical"
    )
    return_json = requests.get(cve_data_uri).json()
    for i in requests.get(cve_data_uri).json():
        return_json.append(i)

    cve_data_uri = (
        redhat_base_url
        + f"/cvrf.json?before={after_date}&after={before_date}&per_page=25&severity=moderate"
    )
    for i in requests.get(cve_data_uri).json():
        return_json.append(i)

    for adv in return_json:
        resource_url = requests.get(adv.get("resource_url")).json().get("cvrfdoc")
        title = resource_url.get("document_title")

        try:
            branch = resource_url.get("product_tree").get("branch")
            products = [
                product.get("full_product_name")
                for product in [branch_2 for branch_2 in branch][0].get("branch")
            ]
        except Exception as e:
            print(e)
            products = []

        return_dict = {
            "advID": adv.get("RHSA"),
            "cves": adv.get("CVEs"),
            "title": title,
            "severity": adv.get("severity"),
            "published": adv.get("released_on")[:10],
            "affected_products": products,
        }
        return_list.append(return_dict)
        if len(return_list) == 25:
            return return_list


def convert_datetime_to_mysqldatetime_str(datetime_obj):
    return datetime.strftime(datetime_obj, "%Y-%m-%d")


# before_date, after_date


def get_all_suse_dict(before_date, after_date):
    suse_base_url = "https://www.suse.com"
    page = requests.get("https://www.suse.com/support/update/").text
    soup = BeautifulSoup(page, "html.parser").find("table", {"id": "dataTable"})
    all_data = [data.text for data in soup.find_all("td")]
    all_links = [data["href"] for data in soup.find_all("a")]

    count = 0
    return_list = []
    for i in range(0, len(all_data) // 5, 5):
        row = all_data[i : i + 5] + [all_links[count]]
        if row[0].lower() != "security":
            count += 1
            continue
        if row[1].lower() not in ("moderate", "critical"):
            count += 1
            continue
        if before_date > datetime.strptime(row[4], "%b %d, %Y") > after_date:
            count += 1
            continue
        page = requests.get(suse_base_url + row[-1]).text
        soup = BeautifulSoup(page, "html.parser")
        first_table = soup.find("table")
        table_rows = first_table.find_all("tr")

        for table_row in table_rows:
            references = table_row.text.strip().splitlines()
            if "cross" in references[0].lower():
                cves = references[-1].split(" ")
                row.append(cves)
            elif "affected" in references[0].lower():
                products = [product for product in references[1:] if product != ""]
                row.append(products)
            else:
                continue
        if "cve" not in row[6][0].lower():
            count += 1
            continue
        count += 1
        suse_dict = {
            "advID": row[2],
            "title": row[3],
            "severity": row[1],
            "cves": row[6],
            "affected_products": row[7],
            "published": convert_datetime_to_mysqldatetime_str(
                datetime.strptime(row[4], "%b %d, %Y")
            ),
        }
        return_list.append(suse_dict)
        if len(return_list) == 25:
            return return_list


def write_to_file(table, tuple):
    with open(f".\\sqlfiles\\{table}.txt", "a", encoding="utf-8", newline="") as file:
        file.write(f"{tuple}\n")


def create_sql_query(os_obj, os):
    for adv in os_obj:
        tuple_os = f"insert into {os} values ({adv.get('advID')}, {adv.get('title')}, {adv.get('severity')}, {adv.get('published')})"
        print(tuple_os)
        write_to_file(f"{os}_table", tuple_os)
        for product in adv.get("affected_products"):
            tuple_product = (
                f"insert into Products values ({adv.get('advID')}, {product})"
            )
            write_to_file("Products", tuple_product)
            print(tuple_product)
        for cve in adv.get("cves"):
            cve_dict = get_cve_dict(cve, os)
            if cve_dict == "null":
                continue
            tuple_cve_table = f"insert into CVE values ({cve_dict.get('cveID')}, {cve_dict.get('severity')}, {cve_dict.get('rating')}, {cve_dict.get('published')}, {cve_dict.get('summary')}, {cve_dict.get('os')})"
            tuple_cve = f"insert into Advisory_CVEs values ({adv.get('advID')}, {cve})"
            print(tuple_cve_table)
            print(tuple_cve)
            write_to_file("cve_table", tuple_cve_table)
            write_to_file("cve", tuple_cve)


before_date = input("Before date: MMDDYYYY:\n")
after_date = input("After date: MMDDYYYY:\n")
while 1:
    if after_date.lower() == "today" or (
        (before_date and after_date)
        and (before_date.isdigit and after_date.isdigit)
        and (len(before_date) == 8 and len(after_date) == 8)
    ):
        if after_date.lower() == "today":
            after_date = datetime.today()
            before_date = convert_input_to_date_obj(before_date)
        else:
            after_date = convert_input_to_date_obj(after_date)
            before_date = convert_input_to_date_obj(before_date)
        break
    else:
        print("please input a proper date")
        before_date = input("Before date: MMDDYYYY:\n")
        after_date = input("After date: MMDDYYYY:\n")


create_sql_query(get_all_redhat_adv_dict(before_date, after_date), "RedHat")
create_sql_query(get_all_suse_dict(before_date, after_date), "SUSE")


def get_words_list():
    word_site = "http://svnweb.freebsd.org/csrg/share/dict/words?view=co&content-type=text/plain"

    response = requests.get(word_site)
    WORDS = response.content.splitlines()

    try:
        with open("words.txt", "r") as file:
            WORDS = file.read().splitlines()
    except:
        word_site = "http://svnweb.freebsd.org/csrg/share/dict/words?view=co&content-type=text/plain"
        response = requests.get(word_site)
        WORDS = response.content.splitlines()
        with open("words.txt", "w") as file:
            for word in WORDS:
                file.write(f"{word.decode('utf-8')}\n")
        with open("words.txt", "r") as file:
            WORDS = file.read().splitlines()
    return WORDS


def create_inventory():
    words = get_words_list()

    def create_fqdn():
        word = words[random.randint(0, len(words))]
        word = "".join([word[random.randint(0, len(word) - 1)] for letter in word])
        fqdn = f"{word}.fakeFQDN.us.dk"
        return fqdn

    def create_mac():
        all_num_chars = [chr(num) for num in list(range(48, 57)) + list(range(97, 102))]
        rand_chars = [
            all_num_chars[random.randint(0, len(all_num_chars) - 1)]
            for num in range(12)
        ]
        mac_address = ":".join(
            [r1 + r2 for r1, r2 in zip(rand_chars[::2], rand_chars[1::2])]
        )
        print(mac_address)
        return mac_address

    def create_products():
        with open(".\\sqlfiles\\Products.txt", "r") as file:
            all_lines = file.read().splitlines()
            all_products = [line.split(", ")[-1][:-1] for line in all_lines]
        product = all_products[random.randint(0, len(all_products) - 1)]
        return product

    def create_computer_type(product):
        if "server" in product.lower():
            return "Server"
        elif "desktop" in product.lower() or "workstation" in product.lower():
            return "Desktop"
        else:
            return "IOT"

    def create_os(product):
        if "redhat" in product.lower() or "red hat" in product.lower():
            return "RedHat"
        else:
            return "SUSE"

    with open(".\\sqlfiles\\Inventory.txt", "a") as file:
        for count in range(0, random.randint(15, 30)):
            product = create_products()
            tuple = f"insert into Inventory values ({create_mac()}, {create_fqdn()}, {create_os(product)}, {create_computer_type(product)}, {product})\n"
            file.write(tuple)
            print(tuple)
