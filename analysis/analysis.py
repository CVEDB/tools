"""
Initial file to run the CVEDB Analysis
"""

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as plticker
import json
import time
from tqdm import tqdm
from dateutil import parser
from genson import SchemaBuilder

"""Replace with local cvedb-database clone if running from an IDE (e.g., PyCharm)"""
local_cvedb = f"../cvedb-database/"
github_advisory_db = "../advisory-database/"


def get_cvedb_list(local_cvedb):
    """
    Returns a dataframe of all the CVEDB entries.
    :param file: Known file from previous run so you don't have to parse the CVEDB database again
    :param saveFile: Save file on an initial run
    :return: A dataframe of all the CVEDB entries and cvedb_update_time
    """

    """Get the NVD Update Time from the txt file in CVEDB"""
    temp_cvedb_update_time = open(f'{local_cvedb}nvd_updated_time.txt', 'r').readlines()[0].split(":")[:-1]
    temp_cvedb_update_time = parser.parse("".join(temp_cvedb_update_time))

    """Create a filename to save list of all CVEDB entries"""
    cvedb_entry_filename = f"./data/cvedb_entries_{str(temp_cvedb_update_time).split(' ')[0].replace('-', '')}.csv"

    """Check if file exists so we don't have to reload data"""
    if os.path.exists(cvedb_entry_filename):
        print(f"Using preexisting CVEDB Entry List: {cvedb_entry_filename}\n")
        temp_cvedb_list = pd.read_csv(cvedb_entry_filename)
    else:
        print(f"Scanning the cvedb-database for potential CVEDB entries.\n")
        """Get list of available years within CVEDB"""
        cvedb_years = [name for name in os.listdir(local_cvedb) if os.path.isdir(os.path.join(local_cvedb, name))]
        cvedb_years = [name for name in cvedb_years if "." not in name]
        cvedb_years.sort()

        """Base DF to hold data"""
        temp_cvedb_list = pd.DataFrame(columns=["path"])

        """Walk through the cvedb-database and obtain the CVEDB json files"""
        for r, d, f in os.walk(local_cvedb):
            if r.split("/")[-2] in cvedb_years:
                temp_cvedb_file = [f"{r}/{cvedb}" for cvedb in f]
                temp_cvedb = pd.DataFrame(temp_cvedb_file, columns=["path"])
                temp_cvedb_list = pd.concat([temp_cvedb_list, temp_cvedb])

        """Set the year/group_id/cvedb value for the DF"""
        temp_cvedb_list["year"] = temp_cvedb_list.apply(lambda row: row["path"].split("/")[-3], axis=1)
        temp_cvedb_list["group_id"] = temp_cvedb_list.apply(lambda row: row["path"].split("/")[-2], axis=1)
        temp_cvedb_list["cvedb"] = temp_cvedb_list.apply(lambda row: row["path"].split("/")[-1], axis=1)

        temp_cvedb_list["api"] = temp_cvedb_list.apply(
            lambda x: f"https://raw.globalsecuritydatabase.org/{x['path'].split('/')[-1].strip('.json')}",
            axis=1)

        """Reset the index"""
        temp_cvedb_list = temp_cvedb_list.reset_index(drop=True)

        print(f"Saving CVEDB entries CSV to: {cvedb_entry_filename}")
        """Save file if desired"""
        temp_cvedb_list.to_csv(cvedb_entry_filename, encoding='utf-8', index=False)

    print(f"Total CVEDB Entries: {len(temp_cvedb_list):,}.\n"
          f"CVEDB Timestamp: {temp_cvedb_update_time}\n")

    return temp_cvedb_list, temp_cvedb_update_time


def get_github_advisory_db_list():
    """
    Gets the list of available Github reviewed advisories from a locally cloned github.com/github/advisory-database
    :param file:
    :return:
    """
    """Base DF to hold data"""
    temp_advisories_list = pd.DataFrame(columns=["path"])
    """Walk through the cvedb-database and obtain the CVEDB json files"""
    for r, d, f in os.walk(f"{github_advisory_db}advisories/github-reviewed/"):
        temp_advisories_file = [f"{r}/{cvedb}" for cvedb in f]
        temp_advisories = pd.DataFrame(temp_advisories_file, columns=["path"])
        temp_advisories_list = pd.concat([temp_advisories_list, temp_advisories])

    temp_advisories_list["year"] = temp_advisories_list.apply(lambda x: x['path'].split('/')[-4], axis=1)
    temp_advisories_list["ghsa"] = temp_advisories_list.apply(lambda x: x['path'].split('/')[-2], axis=1)

    return temp_advisories_list


def visualize_cvedb(cvedb_items, cvedb_counts, analysis_date):
    """
    Create a figure of the CVEDB item counts by year
    :param cvedb_items: Dataframe of CVEDB entries
    :param cvedb_items: Dataframe of CVEDB counts for each objects
    :param analysis_date: Date of CVEDB NVD update time
    :return: None
    """

    cvedb_counts["year"] = cvedb_counts.apply(lambda x: int(x['path'].split("/")[2]), axis=1)

    """Count by year"""
    cvedb_year_counts = cvedb_items["year"].value_counts().rename_axis('year').reset_index(name='counts').sort_values(
        'year')
    cve_year_counts = cvedb_counts[cvedb_counts["cve.org"] == 1]["year"].value_counts().rename_axis('year').reset_index(
        name='cve_counts').sort_values('year')
    nvd_year_counts = cvedb_counts[cvedb_counts["nvd.nist.gov"] == 1]["year"].value_counts().rename_axis(
        'year').reset_index(
        name='nvd_counts').sort_values('year')
    gitlab_year_counts = cvedb_counts[cvedb_counts["gitlab.com"] == 1]["year"].value_counts().rename_axis(
        'year').reset_index(
        name='gitlab_counts').sort_values('year')
    osv_year_counts = cvedb_counts[cvedb_counts["OSV"] == 1]["year"].value_counts().rename_axis('year').reset_index(
        name='osv_counts').sort_values('year')
    cisa_year_counts = cvedb_counts[cvedb_counts["cisa.gov"] == 1]["year"].value_counts().rename_axis('year').reset_index(
        name='cisa_counts').sort_values('year')

    """Combine each object type to a single DF"""
    total_counts = pd.merge(cvedb_year_counts, osv_year_counts,
                            on="year",
                            how="outer")

    total_counts = total_counts.merge(cisa_year_counts, on="year", how="outer")
    total_counts = total_counts.merge(cve_year_counts, on="year", how="outer")
    total_counts = total_counts.merge(gitlab_year_counts, on="year", how="outer")
    total_counts = total_counts.merge(nvd_year_counts, on="year", how="outer")

    """Fill any empty columns"""
    total_counts = total_counts.fillna(0)

    """Create a figure of the size of CVEDB by year"""
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot([], [], ' ', label=f"CVEDB Timestamp: {analysis_date}")
    ax.plot(total_counts["year"], total_counts["counts"], label=f"Total: {int(total_counts['counts'].sum()):,}")
    ax.plot(total_counts["year"], total_counts["cve_counts"],
            label=f"CVE.ORG: {int(total_counts['cve_counts'].sum()):,}")
    ax.plot(total_counts["year"], total_counts["nvd_counts"], label=f"NVD: {int(total_counts['nvd_counts'].sum()):,}")
    ax.plot(total_counts["year"], total_counts["gitlab_counts"],
            label=f"GitLab: {int(total_counts['gitlab_counts'].sum()):,}")
    ax.plot(total_counts["year"], total_counts["osv_counts"], label=f"OSV: {int(total_counts['osv_counts'].sum()):,}")
    ax.plot(total_counts["year"], total_counts["cisa_counts"],
            label=f"CISA: {int(total_counts['cisa_counts'].sum()):,}")

    """Set some labels"""
    ax.set_xlim(cvedb_year_counts["year"].min(), cvedb_year_counts["year"].max())
    ax.set_ylim(0)
    plt.xticks(rotation=75)
    loc = plticker.MultipleLocator(base=1.0)  # this locator puts ticks at regular intervals
    ax.xaxis.set_major_locator(loc)
    plt.yticks(np.arange(0, cvedb_year_counts["counts"].max() + 5000, 5000))
    ax.get_yaxis().set_major_formatter(plticker.FuncFormatter(lambda x, p: format(int(x), ',')))
    ax.set_ylabel('Count')
    ax.set_title(f'Count of CVEDB Entries by Year')
    plt.grid(color='gray', linestyle='-', linewidth=0.2)
    plt.legend(loc='upper left')

    # """Add a box with some key values"""
    # textstr = f"CVEDB Timestamp = {analysis_date}"
    # props = dict(boxstyle='round', facecolor='white', edgecolor='gray', alpha=0.9)
    # # place a text box in middle left
    # ax.text(0.50, 0.98, textstr, transform=ax.transAxes, fontsize=8,
    #         verticalalignment='top', bbox=props)

    """Save Fig"""
    plt.savefig("./data/figs/cvedb_total_count.png", bbox_inches="tight")


def generate_complete_cvedb_schema(cvedb_items_complete, analysis_date):
    """
    Generates a complete CVEDB schema for all possible data entries
    :param cvedb_items_complete: Dataframe of CVEDB entries
    :param analysis_date: Timestamp from CVEDB database locally cloned repo
    :return: CVEDB schema and checklist of various counts
    """
    """Create a filename to save counts entries"""
    cvedb_counts_filename = f"./data/cvedb_counts_{str(analysis_date).split(' ')[0].replace('-', '')}.csv"

    # Check if schema and master_checklist already exists so we don't have to re-run
    if os.path.exists(f"./data/schemas/cvedb_complete_schema.json") and os.path.exists(cvedb_counts_filename):
        print(f"Using preexisting schema (./data/schemas/cvedb_complete_schema.json) and counts ({cvedb_counts_filename}) "
              f"files.")
        with open(f"./data/schemas/cvedb_complete_schema.json", 'r') as f:
            schema = json.load(f)
            f.close()
        master_checklist = pd.read_csv(cvedb_counts_filename)
    else:
        print(f"Parsing each CVEDB ({len(cvedb_items_complete):,}) to build a schema and generate a general counts file:")
        """"Hold the complete schema"""
        builder = SchemaBuilder()

        """Holds various counts of the various object types in the CVEDB"""
        master_checklist = pd.DataFrame()

        """Use tqdm to create a nice progress bar instead of printing the index of each JSON"""
        with tqdm(total=len(cvedb_items_complete)) as pbar:
            """Loop through each CVEDB entry, loads the JSON, adding object to Genson Schema, 
            creating a master dataframe"""
            for index, cvedb in cvedb_items_complete.iterrows():
                # print(f"{index}/{len(cvedb_items_complete)}")
                with open(cvedb["path"], 'r') as f:
                    data = json.load(f)

                    builder.add_object(data)

                    temp_check_values = pd.DataFrame([cvedb["path"]], columns=["path"])

                    """Identify any JSONs without a CVEDB object"""
                    if '\'CVEDB\':' not in str(data):
                        temp_check_values["missingCVEDB"] = 1
                    else:
                        temp_check_values["missingCVEDB"] = 0

                    """Identify any JSONs with a CVEDB object"""
                    if '\'CVEDB\':' in str(data):
                        temp_check_values["CVEDB"] = 1
                        try:
                            temp_check_values["CVEDB_alias"] = data["CVEDB"]["alias"]
                        except:
                            temp_check_values["CVEDB_alias"] = "Missing"
                    else:
                        temp_check_values["CVEDB"] = 0
                        temp_check_values["CVEDB_alias"] = None

                    """Identify any JSONs with a OSV object"""
                    if '\'OSV\':' in str(data):
                        temp_check_values["OSV"] = 1
                    else:
                        temp_check_values["OSV"] = 0

                    """Identify any JSONs with a overlay object"""
                    if '\'overlay\':' in str(data):
                        temp_check_values["overlay"] = 1
                    else:
                        temp_check_values["overlay"] = 0

                    """Identify any JSONs with a cve.org object"""
                    if '\'cve.org\':' in str(data):
                        temp_check_values["cve.org"] = 1
                        try:
                            temp_check_values["cve_org_id"] = data["namespaces"]["cve.org"]["CVE_data_meta"]["ID"]
                        except:
                            temp_check_values["cve_org_id"] = None
                    else:
                        temp_check_values["cve.org"] = 0
                        temp_check_values["cve_org_id"] = None

                    """Identify any JSONs with a nvd.nist.gov object"""
                    if '\'nvd.nist.gov\':' in str(data):
                        temp_check_values["nvd.nist.gov"] = 1
                        try:
                            temp_check_values["nvd_id"] = data["namespaces"]["nvd.nist.gov"]["cve"]["CVE_data_meta"]["ID"]
                        except:
                            temp_check_values["nvd_id"] = None
                    else:
                        temp_check_values["nvd.nist.gov"] = 0
                        temp_check_values["nvd_id"] = None

                    """Identify any JSONs with a cisa object"""
                    if '\'cisa.gov\':' in str(data):
                        temp_check_values["cisa.gov"] = 1
                        try:
                            temp_check_values["cisa_id"] = data["namespaces"]["cisa.gov"]["cveID"]
                        except:
                            temp_check_values["cisa_id"] = None
                    else:
                        temp_check_values["cisa.gov"] = 0
                        temp_check_values["cisa_id"] = None

                    """Identify any JSONs with a gitlab.com object"""
                    if '\'gitlab.com\':' in str(data):
                        temp_check_values["gitlab.com"] = 1
                        try:
                            temp_check_values["gitlab_id"] = data["namespaces"]["gitlab.com"]["advisories"][0]["identifier"]
                        except:
                            temp_check_values["gitlab_id"] = None
                    else:
                        temp_check_values["gitlab.com"] = 0
                        temp_check_values["gitlab_id"] = None

                    """Checking for CVEDB JSONs with the following key"""
                    if "github.com/kurtseifried:582211" in str(data):
                        temp_check_values["github.com/kurtseifried:582211"] = 1
                    else:
                        temp_check_values["github.com/kurtseifried:582211"] = 0

                    master_checklist = pd.concat([master_checklist, temp_check_values])

                    f.close()

                    """Updated the progress bar by 1"""
                    pbar.update(1)
        """Close the progress bar"""
        pbar.close()

        schema = builder.to_schema()["properties"]

        """Save complete schema"""
        with open("./data/schemas/cvedb_complete_schema.json", "w") as schema_file:
            json.dump(schema, schema_file, indent=4, sort_keys=True)

        master_checklist["api"] = master_checklist.apply(
            lambda x: f"https://raw.globalsecuritydatabase.org/{x['path'].split('/')[-1].strip('.json')}",
            axis=1)

        master_checklist.to_csv(cvedb_counts_filename, encoding='utf-8', index=False)

    return schema, master_checklist


if __name__ == '__main__':
    start = time.time()

    """Check for passed arguments"""
    try:
        local_cvedb = sys.argv[1]
    except:
        print(f"No local database provided. Using default {local_cvedb}\n")

    """Get CVEDB Entries & the CVEDB timestamp"""
    cvedb_list, cvedb_update_time = get_cvedb_list(local_cvedb)

    """Get Github Advisories DB"""
    # github_advisories = get_github_advisory_db_list()

    """Generate Schemas for CVEDB"""
    complete_schema, cvedb_df = generate_complete_cvedb_schema(cvedb_list, cvedb_update_time)

    """Figure for CVEDB Entries by Year"""
    visualize_cvedb(cvedb_list, cvedb_df, cvedb_update_time)

    """============================================================================================================"""
    """============================================================================================================"""
    print("Running some general analysis: \n")

    """Checking for CVEDB alias duplicates"""
    cvedb_alias_cve = cvedb_df["CVEDB_alias"].value_counts().rename_axis('cve').reset_index(name='count')
    cvedb_alias_cve = cvedb_alias_cve[(cvedb_alias_cve["count"] > 1) & (cvedb_alias_cve['cve'] != "Missing")]
    duplicates = pd.merge(cvedb_df, cvedb_alias_cve,
                          left_on="CVEDB_alias",
                          right_on="cve",
                          how="inner")
    print(f"Duplicate CVEs with differing CVEDB entries: {len(duplicates)}")
    for each in duplicates[["cve", "api"]].values.tolist():
        print(f"{each[0]}: {each[1]}")

    """Checking when CVEDB alias != cve.org CVE"""
    cvedb_df["cvedb_vs_cve_org"] = cvedb_df.apply(lambda x: 1 if x['CVEDB_alias'] == x['cve_org_id'] else 0, axis=1)
    cvedb_mismatch = cvedb_df[(cvedb_df["cvedb_vs_cve_org"] == 0)
                          & (cvedb_df['cve.org'] == 1)
                          & (cvedb_df['CVEDB_alias'] != "Missing")]

    """Checking when CVEDB alias != nvd CVE"""
    cvedb_df["cvedb_vs_nvd"] = cvedb_df.apply(lambda x: 1 if x['CVEDB_alias'] == x['nvd_id'] else 0, axis=1)
    cvedb_nvd_mismatch = cvedb_df[(cvedb_df["cvedb_vs_nvd"] == 0)
                              & (cvedb_df['nvd.nist.gov'] == 1)
                              & (cvedb_df['CVEDB_alias'] != "Missing")]

    """Checking when cve.org != nvd CVE"""
    cvedb_df["cve_vs_nvd"] = cvedb_df.apply(lambda x: 1 if x['cve_org_id'] == x['nvd_id'] else 0, axis=1)
    cve_nvd_mismatch = cvedb_df[(cvedb_df["cve_vs_nvd"] == 0)
                              & (cvedb_df['nvd.nist.gov'] == 1)
                              & (cvedb_df['cve.org'] == 1)]

    nvd_cve = cvedb_df["cve_org_id"].value_counts().rename_axis('cve').reset_index(name='count')
    nvd_cve = nvd_cve[nvd_cve["count"] > 1]
    """============================================================================================================"""
    """============================================================================================================"""

    print("Saving individual schemas to ./data/schemas/\n")

    """CVEDB SCHEMA"""
    schema_cvedb = complete_schema["CVEDB"]

    # Save CVEDB Schema
    with open("./data/schemas/schema_cvedb_object.json", "w") as write_file:
        json.dump(schema_cvedb, write_file, indent=4, sort_keys=True)

    # Find instances when the CVEDB object is missing
    example_missing_cvedb = cvedb_df[cvedb_df["missingCVEDB"] == 1].sort_values("path")
    print(f"Missing a CVEDB object. Total: {len(example_missing_cvedb)} | {example_missing_cvedb['api'].values.tolist()}\n")

    # Find instances when entries only contain a CVEDB object
    example_only_cvedb = cvedb_df[(cvedb_df["CVEDB"] == 1) &
                              (cvedb_df["cisa.gov"] == 0) &
                              (cvedb_df["github.com/kurtseifried:582211"] == 0) &
                              (cvedb_df["gitlab.com"] == 0) &
                              (cvedb_df["nvd.nist.gov"] == 0) &
                              (cvedb_df["cve.org"] == 0) &
                              (cvedb_df["OSV"] == 0)].sort_values("path")
    print(f"Only contains a CVEDB object. Total: {len(example_only_cvedb)} | {example_only_cvedb['api'].values.tolist()}\n")

    """============================================================================================================"""
    """============================================================================================================"""

    """OSV SCHEMA"""
    schema_osv = complete_schema["OSV"]

    # Save OSV Schema
    with open("./data/schemas/schema_osv.json", "w") as write_file:
        json.dump(schema_osv, write_file, indent=4, sort_keys=True)

    # OSV examples
    example_osv = cvedb_df[cvedb_df["OSV"] == 1]
    # print two random OSV examples
    print(f"OSV object examples: {example_osv['api'].sample(2).values.tolist()}\n")

    """============================================================================================================"""
    """============================================================================================================"""

    """cisa.gov SCHEMA"""
    schema_cisa = complete_schema["namespaces"]["properties"]["cisa.gov"]

    # Save CISA Schema
    with open("./data/schemas/schema_cisa.json", "w") as write_file:
        json.dump(schema_cisa, write_file, indent=4, sort_keys=True)

    # CISA examples
    example_cisa = cvedb_df[cvedb_df["cisa.gov"] == 1]
    # print two random CISA examples
    print(f"cisa.gov examples: {example_cisa['api'].sample(2).values.tolist()}\n")

    """============================================================================================================"""
    """============================================================================================================"""

    """cve.org SCHEMA"""
    schema_cve_org = complete_schema["namespaces"]["properties"]["cve.org"]

    # Save CISA Schema
    with open("./data/schemas/schema_cve_org.json", "w") as write_file:
        json.dump(schema_cve_org, write_file, indent=4, sort_keys=True)

    # CVE.org examples
    example_cve_org = cvedb_df[cvedb_df["cve.org"] == 1]
    # print two random CISA examples
    print(f"cve.org examples: {example_cve_org['api'].sample(2).values.tolist()}\n")

    """============================================================================================================"""
    """============================================================================================================"""

    """kurt SCHEMA"""
    schema_kurt = complete_schema["namespaces"]["properties"]["github.com/kurtseifried:582211"]
    example_kurt = cvedb_df[cvedb_df["github.com/kurtseifried:582211"] == 1].sort_values("path")
    print(f"github.com/kurtseifried:582211 object. Total: "
          f"{len(example_kurt)} | {example_kurt['api'].values.tolist()}\n")

    """============================================================================================================"""
    """============================================================================================================"""

    """gitlab.com SCHEMA"""
    schema_gitlab = complete_schema["namespaces"]["properties"]["gitlab.com"]

    # Save gitlab.com Schema
    with open("./data/schemas/schema_gitlab.json", "w") as write_file:
        json.dump(schema_gitlab, write_file, indent=4, sort_keys=True)

    # gitlab examples
    example_gitlab = cvedb_df[cvedb_df["gitlab.com"] == 1]
    # print two random CISA examples
    print(f"gitlab.com examples: {example_gitlab['api'].sample(2).values.tolist()}\n")

    """============================================================================================================"""
    """============================================================================================================"""

    """nvd.nist.gov SCHEMA"""
    schema_nvd = complete_schema["namespaces"]["properties"]["nvd.nist.gov"]

    # Save gitlab.com Schema
    with open("./data/schemas/schema_nvd.json", "w") as write_file:
        json.dump(schema_nvd, write_file, indent=4, sort_keys=True)

    # nvd examples
    example_nvd = cvedb_df[cvedb_df["nvd.nist.gov"] == 1]
    # print two random NVD examples
    print(f"nvd.nist.gov examples: {example_nvd['api'].sample(2).values.tolist()}\n")

    """============================================================================================================"""
    """============================================================================================================"""

    """overlay SCHEMA"""
    schema_overlay = complete_schema["overlay"]
    example_overlay = cvedb_df[cvedb_df["overlay"] == 1].sort_values("path")
    print(f"overlay examples: {example_overlay['api'].values.tolist()}")

    print(f"Total Time: {time.time() - start}")
