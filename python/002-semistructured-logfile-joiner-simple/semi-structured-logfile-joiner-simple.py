import json
import re
import sys
from datetime import datetime
from typing import Dict


def print_error(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def convert_headers(log_line: Dict) -> Dict:
    # template for our requestHeaders dictionary
    request_headers_template = {"Accept-Encoding": [], "Host": [], "Connection": [], "User-Agent": []}
    # now we iterate over each key defined in our template
    for key in request_headers_template.keys():
        # first we correct all lowercase keys in the header to match our definition
        cleaned_header = str(log_line.get("headers")).replace(key.lower(), key)
        # then we use a regex to match the desired part of the header value
        # f.e. Accept-Encoding:(.+?)(\n|[^\n].*$)
        result = re.search(key + ":(.+?)(\n|[^\n].*$)", cleaned_header)
        try:
            # get the first group
            request_headers_template[key] = [result.group(1)]
        except AttributeError:
            # if key is not existing we throw an error, but continue with processing the file
            print_error("Error when processing key: " + key + " of request id: " + log_line["requestId"])
            request_headers_template[key] = "Error when parsing"
    log_line["requestHeaders"] = request_headers_template
    return log_line


def main():
    # this is our structure for storing the read log lines
    # we use our identifier on which we will join the entries from the different log files as key and
    # the log entry itself as value. json.loads returns a Dict therefore we use a Dict of str and Dict
    forensics_log: Dict[str, Dict] = {}
    # we open the file containing the json lines with specifying the encoding

    with open("../001-semistructured-logfile-joiner/forensics.json", encoding="UTF-8") as forensics_log_file:
        for line in forensics_log_file:
            dict_from_line: Dict = json.loads(line)
            # as mentioned above we get the requestId from the entry and use it as a key and the dict as value
            forensics_log[dict_from_line["requestId"]] = convert_headers(dict_from_line)
    print(forensics_log["XoKkgH8AAAEAAGciTDAAAACI"])

    with open("../001-semistructured-logfile-joiner/access.log", mode="r", encoding="UTF-8") as access_log_file, \
            open("output.json", mode="w", encoding="UTF-8") as output_file:

        # actually this is not necessary, a simple {} would suffice, but
        output_template = {"requestId": "", "remoteAddress": "", "timestamp": "",
                           "method": "", "url": "", "version": "", "responseCode": 0,
                           "responseSize": 0, "requestHeaders": {}}

        for line in access_log_file:
            try:
                # in order to be able to split by whitespace more comfortably, we remove them from the timestamps
                line = line.replace(" +", "+")
                # removes the newline
                line = line.replace("\n", "")
                # here we get a list of strings by splitting the line on each whitespace character
                parts = line.split(" ")
                # now we assign the values to our output template
                output_template["requestId"] = parts[0]
                output_template["remoteAddress"] = parts[1]
                # no need to preprocess our timestamp string, we can adjust the format accordingly to parse it including
                # square brackets
                output_template["timestamp"] = datetime.strptime(parts[4], "[%d/%m/%Y:%H:%M:%S%z]")
                # we need to replace quotation marks
                output_template["method"] = parts[5].replace("\"", "")
                # we need to replace quotation marks
                output_template["url"] = parts[6].replace("\"", "")
                # we need to replace quotation marks
                output_template["version"] = parts[7].replace("\"", "")
                # we need to cast our string to an integer
                output_template["responseCode"] = int(parts[8])
                # we need to cast our string to an integer, but handle the occasional "-" values first
                output_template["responseSize"] = int(parts[9].replace("-", "0"))
                # now we look up the requestHeaders dictionary from our previously ingested forensics json
                output_template["requestHeaders"] = forensics_log[parts[0]]["requestHeaders"]
            except KeyError:
                print_error("No entry found in forensics log for key: " + parts[0])
                output_template["requestHeaders"] = {"Error": "Key not found"}
            finally:
                output_file.write(json.dumps(output_template, indent=4, default=str))


if __name__ == "__main__":
    main()
