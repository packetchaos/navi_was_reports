from flask import Flask, render_template, request
from dbconfig import insert_apps, create_apps_table, new_db_connection, drop_tables, create_keys_table, create_plugins_table, insert_plugins
import requests
import dateutil.parser
import sys

app = Flask(__name__)


def grab_headers():
    header_db = r"navi.db"
    h_conn = new_db_connection(header_db)
    with h_conn:
        h_cur = h_conn.cursor()
        h_cur.execute("SELECT * from keys;")
        rows = h_cur.fetchall()
        for row in rows:
            access_key = row[0]
            secret_key = row[1]
    return {'Content-type': 'application/json', 'user-agent': 'Navi-WAS-Reporter', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


def request_data(method, url_mod, **kwargs):

    # set the Base URL
    url = "https://cloud.tenable.com"

    # check for params and set to None if not found
    try:
        params = kwargs['params']
    except KeyError:
        params = None

    # check for a payload and set to None if not found
    try:
        payload = kwargs['payload']
    except KeyError:
        payload = None

    # Retry the request three times
    for x in range(1, 3):
        try:
            r = requests.request(method, url + url_mod, headers=grab_headers(), params=params, json=payload, verify=True)
            if r.status_code == 200:
                return r.json()
            else:
                print("Something went wrong...Don't be trying to hack me now {}".format(r))
                break
        except ConnectionError:
            print("Check your connection...You got a connection error. Retying")
            continue


def plugin_parser(plugin_output):
    tech_list = []
    # Split the plugin information on '-'
    plugin_tuple = plugin_output.split('-')
    # Ignore the item in the tuple and add all others to a list
    for x in range(len(plugin_tuple) - 1):
        tech_list.append(str(plugin_tuple[x + 1]))
    return tech_list


def get_was_stats(scan_id):
    params = {"limit": "200", "offset": "0"}
    was_data = request_data("POST", "/was/v2/scans/{}/vulnerabilities/search".format(scan_id), params=params)
    stat_dict = {}

    for finding in was_data['items']:
        if str(finding['plugin_id']) == '98000':

            scan_meta_data = finding['details']['output']

            new_data = str(scan_meta_data).split()

            stat_dict['eng_version'] = "0"#new_data[2]
            stat_dict['start_time'] = "0"#"{} {} {}".format(new_data[11], new_data[12],new_data[13])
            stat_dict['duration'] = "0"#new_data[15]

            stat_dict['requests_made'] = "0"#new_data[17]
            stat_dict['crawler_requests'] = "0"#new_data[20]
            stat_dict['requests_per_sec'] = "0"#new_data[22]
            stat_dict['mean_response_time'] = "0"#new_data[26]

            stat_dict['data_target'] = "0"#"{} {}".format(new_data[33], new_data[34])
            stat_dict['target_to_data'] = "0"#"{} {}".format(new_data[39], new_data[40])

            stat_dict['network_timeouts'] = "0"#new_data[45]
            stat_dict['browser_timeouts'] = "0"#new_data[48]
            stat_dict['browser_respawns'] = "0"#new_data[51]

            return stat_dict


def download_data(uuid):
    database = r"navi.db"
    app_conn = new_db_connection(database)
    app_conn.execute('pragma journal_mode=wal;')
    with app_conn:
        apps_table_list = []
        report = request_data('GET', '/was/v2/scans/{}/report'.format(uuid))
        #scan_metadata = get_was_stats(uuid)

        config_id = report['config']['config_id']

        # Ignore all scans that have not completed
        if report['scan']['status'] == 'completed':
            scan_name = report['config']['name']

            scan_completed_time = report['scan']['finalized_at']
            try:
                requests_made = 0#scan_metadata['requests_made']
            except KeyError:
                requests_made = 0

            try:
                pages_crawled = 0#scan_metadata['crawler_requests']
            except KeyError:
                pages_crawled = 0

            critical = []
            high = []
            medium = []
            low = []
            info = []
            critical_summary = []
            high_summary = []
            medium_summary = []
            low_summary = []
            info_summary = []
            tech_list = ['Nothing Found']
            owasp_list = []
            owasp_dict = {}
            try:
                notes = report['config']['notes']
            except KeyError:
                notes = "No Scan Notes"

            try:
                target = report['scan']['target']
            except KeyError:
                target = report['config']['settings']['target']

            # Count for-loop
            plugin_list = []

            for finding in report['findings']:
                plugin_list.append(finding['plugin_id'])
                for xref in finding['xrefs']:
                    # Grab multiples values here
                    if xref['xref_name'] == 'OWASP':
                        if '2021' in xref['xref_value']:
                            owasp_clean = str(xref['xref_value']).split('-')[1]
                            owasp_list.append(owasp_clean)

            def occurances(number, number_list):
                return number_list.count(number)

            for owasp in range(1, 11):
                owasp_dict["A{}".format(owasp)] = occurances("A{}".format(owasp), owasp_list)

            for finding in report['findings']:
                finding_list = []
                risk = finding['risk_factor']
                plugin_id = finding['plugin_id']
                plugin_name = finding['name']
                family = finding['family']
                cves = finding['cves']
                description = finding['description']
                output = finding['output']
                owasp = finding['owasp']
                payload = finding['payload']
                plugin_mod_date = finding['plugin_modification_date']
                plugin_pub_date = finding['plugin_publication_date']
                proof = finding['proof']
                request_headers = finding['request_headers']
                response_headers = finding['response_headers']
                solution = finding['solution']
                url = finding['uri']
                xrefs = finding['xrefs']
                see_also = finding['see_also']

                finding_list.append(str(uuid))
                finding_list.append(str(plugin_name))
                finding_list.append(str(cves))
                finding_list.append(str(description))
                finding_list.append(str(family))
                finding_list.append(str(output))
                finding_list.append(str(owasp))
                finding_list.append(str(payload))
                finding_list.append(str(plugin_id))
                finding_list.append(str(plugin_mod_date))
                finding_list.append(str(plugin_pub_date))
                finding_list.append(str(proof))
                finding_list.append(str(request_headers))
                finding_list.append(str(response_headers))
                finding_list.append(str(risk))
                finding_list.append(str(solution))
                finding_list.append(str(url))
                finding_list.append(str(xrefs))
                finding_list.append(str(see_also))

                insert_plugins(app_conn, finding_list)

                if str(plugin_id) == '98059':
                    tech_list = plugin_parser(finding['output'])

                vuln_count = occurances(finding['plugin_id'], plugin_list)
                vuln_list = [risk, plugin_id, plugin_name, family, vuln_count]
                if risk == 'high':
                    high.append(plugin_id)
                    if vuln_list not in high_summary:
                        high_summary.append(vuln_list)
                elif risk == 'medium':
                    medium.append(plugin_id)
                    if vuln_list not in medium_summary:
                        medium_summary.append(vuln_list)
                elif risk == 'low':
                    low.append(plugin_id)
                    if vuln_list not in low_summary:
                        low_summary.append(vuln_list)
                elif risk == 'critical':
                    critical.append(plugin_id)
                    if vuln_list not in critical_summary:
                        critical_summary.append(vuln_list)
                else:
                    info.append(plugin_id)
                    if vuln_list not in info_summary:
                        info_summary.append(vuln_list)

            apps_table_list.append(scan_name)
            apps_table_list.append(uuid)
            apps_table_list.append(target)
            apps_table_list.append(scan_completed_time)
            apps_table_list.append(pages_crawled)
            apps_table_list.append(requests_made)
            apps_table_list.append(len(critical))
            apps_table_list.append(len(high))
            apps_table_list.append(len(medium))
            apps_table_list.append(len(low))
            apps_table_list.append(len(info))
            apps_table_list.append(str(owasp_dict))
            apps_table_list.append(str(tech_list))
            apps_table_list.append(config_id)
            apps_table_list.append(str(notes))

            insert_apps(app_conn, apps_table_list)

    return


def grab_scans():
    database = r"navi.db"
    app_conn = new_db_connection(database)
    app_conn.execute('pragma journal_mode=wal;')

    drop_tables(app_conn, 'apps')
    create_apps_table()
    create_plugins_table()

    data = request_data('POST', '/was/v2/configs/search?limit=200&offset=0')

    for scanids in data['items']:
        if scanids['last_scan']:
            was_scan_id = scanids['last_scan']['scan_id']
            status = scanids['last_scan']['status']
            # Ignore all scans that have not completed
            if status == 'completed':
                download_data(was_scan_id)

    return


@app.route('/report')
def scan_report():
    scan_uuid = request.args.get('scan_uuid')
    database = r"navi.db"
    conn = new_db_connection(database)
    app_data = {}
    with conn:
        cur = conn.cursor()
        cur2 = conn.cursor()
        cur.execute("SELECT * from plugins where scan_uuid =='{}';".format(scan_uuid))
        cur2.execute("SELECT * from apps where uuid=='{}';".format(scan_uuid))
        plugin_data = cur.fetchall()
        data2 = cur2.fetchall()

        critical_summary = []
        high_summary = []
        medium_summary = []
        low_summary = []
        info_summary = []
        tech_list = []
        owasp_list = []

        critical = []
        high = []
        medium = []
        low = []
        info = []

        scan_name = data2[0][0]
        scan_completed_time = data2[0][3]
        requests_made = data2[0][5]
        pages_crawled = data2[0][4]
        target = data2[0][2]
        notes = data2[0][14]
        plugin_list = []
        instance_dict = {}
        sitemap = 'No Sitemap Found'
        plugin_info_list = {}

        for finding in plugin_data:
            owasp_dict = []
            plugin_id = finding[8]

            # This list is to count plugins
            plugin_list.append(plugin_id)

            instance_dict.setdefault(plugin_id, []).append(finding[16])

            def occurances(number, number_list):
                return number_list.count(number)

            if str(plugin_id) == '98059':
                tech_list = plugin_parser(finding[5])

            if str(plugin_id) == '98009':
                sitemap = finding[5]

            plugin_name = finding[1]
            family = finding[4]
            description = finding[3]
            see_also = finding[18]
            solution = finding[15]
            owasp_list = finding[6]
            risk = finding[14]

            for year in eval(owasp_list):
                if year['year'] == '2021':
                    owasp_dict.append(year['category'])

            vuln_count = occurances(plugin_id, plugin_list)

            vuln_list = [risk, plugin_id, plugin_name, family, owasp_dict, vuln_count]

            if plugin_id not in plugin_info_list:
                plugin_info_list[plugin_id] = [risk, family, description, see_also, solution]#, instance_dict[plugin_id]]

            if risk == 'high':
                high.append(plugin_id)
                if vuln_list not in high_summary:
                    high_summary.append(vuln_list)
            elif risk == 'medium':
                medium.append(plugin_id)
                if vuln_list not in medium_summary:
                    medium_summary.append(vuln_list)
            elif risk == 'low':
                low.append(plugin_id)
                if vuln_list not in low_summary:
                    low_summary.append(vuln_list)
            elif risk == 'critical':
                critical.append(plugin_id)
                if vuln_list not in critical_summary:
                    critical_summary.append(vuln_list)
            else:
                info.append(plugin_id)
                if vuln_list not in info_summary:
                    info_summary.append(vuln_list)

        return render_template('was_report.html', scan_name=scan_name, scan_completed_time=scan_completed_time,
                               requests_made=requests_made, pages_crawled=pages_crawled,
                               critical=len(critical), high=len(high), target=target, low=len(low), medium=len(medium),
                               name=scan_name, scan_uuid=scan_uuid, info=len(info), high_summary=high_summary,
                               medium_summary=medium_summary, low_summary=low_summary, info_summary=info_summary,
                               critical_summary=critical_summary, tech_list=tech_list, notes=notes,
                               owasp_dict=owasp_dict,
                               sitemap=sitemap[:-116], plugin_info_list=plugin_info_list)


@app.route('/')
def consolidated():
    config_id = request.args.get('config_id')
    scan_summaries = []

    data = request_data('POST', '/was/v2/configs/search?limit=200&offset=0')
    for scan_data in data['items']:
        if scan_data['last_scan']:
            was_scan_id = scan_data['last_scan']['scan_id']
            status = scan_data['last_scan']['status']
            # Ignore all scans that have not completed
            if status == 'completed':
                scan_summary = []
                summary_start = scan_data['last_scan']['started_at']
                finish = scan_data['last_scan']['finalized_at']
                application = scan_data['last_scan']['application_uri']
                scan_summary.append(application)
                scan_summary.append(was_scan_id)
                scan_summary.append(summary_start)
                scan_summary.append(finish)
                scan_summaries.append(scan_summary)

    # grab data from the Database
    critical_total, high_total, medium_total, low_total, info_total, crawled_total, request_total, \
    app_data, value_dict, technology_list = grab_was_consolidated_data(config_id)

    # Send the data to the Web Page
    return render_template('was_consolidated_report.html', scan_summaries=scan_summaries, crawled_total=crawled_total,
                           critical_total=critical_total,
                           high_total=high_total, medium_total=medium_total, low_total=low_total,
                           request_total=request_total, info_total=info_total, app_data=app_data, value_dict=value_dict,
                           technology_list=technology_list)


def grab_was_consolidated_data(config_id):
    database = r"navi.db"
    conn = new_db_connection(database)
    app_data = {}
    with conn:
        cur = conn.cursor()
        if config_id:
            print("hello")
            cur.execute("SELECT critical_count, high_count, medium_count, low_count, info_count,"
                        "pages_crawled, requests_made, target, uuid, name, owasp, tech_list, scan_completed_time, config_id from apps where config_id='{}';".format(config_id))
        else:
            cur.execute("SELECT critical_count, high_count, medium_count, low_count, info_count,"
                        "pages_crawled, requests_made, target, uuid, name, owasp, tech_list, scan_completed_time, config_id from apps;")

        data = cur.fetchall()

        # Set baselines for calculating totals
        critical_total = 0
        high_total = 0
        medium_total = 0
        low_total = 0
        info_total = 0
        crawled_total = 0
        request_total = 0
        owasp_list = []
        values_per_key = {}
        value_dict = {}
        technology_list = []

        for apps in data:
            scan_completed_time_raw = apps[12]
            scan_completed_time_formatted = dateutil.parser.parse(scan_completed_time_raw)
            scan_completed_time = scan_completed_time_formatted.strftime("%A, %b %-d %Y")


            # Totals
            critical_total = critical_total + int(apps[0])
            high_total = high_total + int(apps[1])
            medium_total = medium_total + int(apps[2])
            low_total = low_total + int(apps[3])
            info_total = info_total + int(apps[4])
            crawled_total = crawled_total + int(apps[5])
            request_total = request_total + int(apps[6])

            # Values
            critical = apps[0]
            high = apps[1]
            medium = apps[2]
            low = apps[3]
            info = apps[4]
            pages_crawled = apps[5]
            requests_made = apps[6]
            target = apps[7]
            scan_uuid = apps[8]
            scan_name = apps[9]
            owasp_dictionary = apps[10]
            tech_dictionary = apps[11]
            scan_config = apps[13]

            app_data[apps[9]] = [critical, high, medium, low, info,
                                 pages_crawled, requests_made, target, scan_name, eval(owasp_dictionary),
                                 eval(tech_dictionary), scan_completed_time, scan_uuid, scan_config]

            # owasp info is saved a json format as a string. Turn it into a dict using eval
            owasp_dict = eval(apps[10])

            # Create a list of owasp dicts for display iteration and calculations
            owasp_list.append(owasp_dict)

            # turn the tech list string into a list, cycle through each tech in the list.
            for tech in eval(apps[11]):

                # check to see if the current tech is a duplicate, before adding it to the global list
                if tech not in technology_list:
                    technology_list.append(tech)

        # This code counts the values of every dict and uses that information to create a new dictionary.
        for instance in owasp_list:
            for risk, value in instance.items():
                # Group each value with its corresponding Key
                values_per_key.setdefault(risk, []).append(value)
                # Cycle through each key and add them up
                for owasp_risk, risk_value in values_per_key.items():
                    total = 0  # Set the value to zero
                    for val in risk_value:
                        total = total + val
                        value_dict[owasp_risk] = total

        return critical_total, high_total, medium_total, low_total, info_total, crawled_total, request_total, app_data, value_dict, technology_list


def run_app():
    app.run(host="0.0.0.0", port=5004)


if __name__ == '__main__':
    print("\n This is going to take a few minutes.\n Downloading all of your completed scans\n")
    create_keys_table()
    init_access_key = sys.argv[1]
    init_secret_key = sys.argv[2]
    key_dict = (init_access_key, init_secret_key)
    navi_database = r"navi.db"
    init_conn = new_db_connection(navi_database)
    with init_conn:
        sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
        cur = init_conn.cursor()
        cur.execute(sql, key_dict)
        drop_tables(init_conn, 'apps')
        drop_tables(init_conn, 'plugins')
    grab_scans()
    run_app()

