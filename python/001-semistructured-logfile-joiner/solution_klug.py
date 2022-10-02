import json
import re
import string
import sys
import uuid
import codecs
from enum import Enum
from string import Template
from datetime import datetime
from typing import List, Dict


def print_error(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class Refiner:
    input_1: Dict[str, Dict]
    input_2: List[Dict]

    def __init__(self, input_1: Dict[str, Dict], input_2: Dict[str, Dict]):
        self.input_1 = input_1
        self.input_2 = input_2

    def refine(self) -> Dict[str, Dict]:
        refined_log = []
        for request in self.input_1:
            header_dict = {}
            try:
                if len(self.input_2[request]['headers']) < 1:
                    header_dict = {}
                else:
                    for param in self.input_2[request]['headers'].split("\n"):
                        if param.split(":")[0] not in header_dict:
                            header_dict[param.split(":")[0]] = [param.split(":")[1]]
                        else:
                            header_dict.get(param.split(":")[0]).append(param.split(":")[1])
            except KeyError:
                header_dict['Error'] = 'No Entry for this key'
                print_error("No header entry found for key: " + request)

            refined_entry = {'requestId': self.input_1[request]['requestId'],
                             'remoteAddress': self.input_1[request]['remoteIP'],
                             'timestamp': self.input_1[request]['timestamp'],
                             'method': self.input_1[request]['request'].split(" ")[0],
                             'url': self.input_1[request]['request'].split(" ")[1],
                             'version': self.input_1[request]['request'].split(" ")[2],
                             'responseCode': self.input_1[request]['responseCode'],
                             'responseSize': self.input_1[request]['responseSize'],
                             'requestHeaders': header_dict
                             }
            refined_log.append(refined_entry)
        return refined_log


class LogFieldType(Enum):
    STRING = 1
    TIMESTAMP = 2
    IP = 3
    INTEGER = 4


class ParserType(Enum):
    DELIMITED = 1
    JSON = 2


class LogField:
    name: string
    type: LogFieldType
    format: string
    fieldStartDelimiter: string
    fieldEndDelimiter: string
    isUniqueId: bool

    def __init__(self, name: string = None, field_type=LogFieldType.STRING, format_str: string = None,
                 field_start_delimiter: string = None,
                 field_end_delimiter: string = None, is_unique_id: bool = False):
        self.type = field_type
        if name is None:
            name = str(uuid.uuid1())
        self.name = name
        self.format = format_str
        self.type = field_type
        self.fieldStartDelimiter = field_start_delimiter
        self.fieldEndDelimiter = field_end_delimiter
        self.isUniqueId = is_unique_id


class LogParser:
    # Fist placeholder is for the delimiter, second placeholder is for the distinct field delimiters
    # f.e [^\;"|\*|\[|\]]+ where ; is the delimiter and *, [, ], " are the field delimiters
    PATTERN_NEGATE_TEMPLATE: string = "[^$delimiter$field_delimiter]+$single_pattern$dual_pattern"
    SINGLE_DELIMITER_TEMPLATE: string = "|\\$sd[^\\$sd]*\\$sd"
    DUAL_DELIMITER_TEMPLATE: string = "|\\$sd[^\\$sd|\\$ed]*\\$ed"

    type: ParserType
    delimiter: string
    fields: List[LogField]
    logPath: string
    processed_log: Dict[str, Dict]

    pkSet: bool = False

    def __init__(self, parser_type: ParserType, log_path: string, delimiter: string = None,
                 fields: List[LogField] = None):
        self.type = parser_type
        if len(log_path) == 0:
            raise Exception("Path to log file is not present")
        self.logPath = log_path
        if parser_type == ParserType.DELIMITED:
            if len(delimiter) == 0:
                raise Exception("Delimiter must be set")
            if fields is None:
                fields = []
            self.delimiter = delimiter
            self.fields = fields

    def add_field(self, field: LogField):
        if type == ParserType.JSON:
            raise Exception("No implicit setting of fields in parser of type JSON")
        else:
            if field.isUniqueId:
                if self.pkSet:
                    raise Exception("Multiple unique id fields set, there should be one check config")
                self.pkSet = True
            self.fields.append(field)

    def process_log(self) -> Dict[str, Dict]:
        proc_log = {}
        if self.type == ParserType.DELIMITED:
            proc_log = self.process_delimited_log()
        elif self.type == ParserType.JSON:
            proc_log = self.process_json_log()
        return proc_log

    def process_delimited_log(self) -> Dict[str, Dict]:
        regex = self.create_pattern()
        expected_number_of_values = len(self.fields)
        error_counter = 0
        processed_log = {}

        pk_field_name: string = None
        for field in self.fields:
            if field.isUniqueId:
                pk_field_name = field.name

        with codecs.open(self.logPath, encoding="UTF-8") as logfile:
            for line in logfile:
                # Yes shame on me, I ll try to fix this in the pattern creator itself, in order to be more generic
                line = str(line).replace('\\"', '§§§')
                groups = regex.findall(line)
                log_line = {}
                if len(groups) == expected_number_of_values:
                    for x in range(len(groups)):
                        val = str(groups[x]).replace('§§§', '\\"')
                        log_line[self.fields[x].name] = self.convert_value(x, val)
                    processed_log[log_line[pk_field_name]] = log_line
                else:
                    error_counter += 1
                    print_error("Malformed log line or erroneous parser configuration: " + line)
                    if error_counter > 100:
                        raise Exception("Too many parsing errors")

        self.processed_log = processed_log
        return processed_log

    def process_json_log(self) -> Dict[str, Dict]:
        processed_log = {}

        with codecs.open(self.logPath, encoding="UTF-8") as logfile:
            for line in logfile:
                log_line = json.loads(line)
                processed_log[log_line['requestId']] = log_line

        return processed_log

    def convert_value(self, index: int, value):
        field = self.fields[index]
        conversion = None
        if field.fieldStartDelimiter is not None:
            value = value[1:-1]
        if field.type == LogFieldType.TIMESTAMP:
            if field.format is not None:
                conversion = datetime.strptime(value, field.format)
        elif field.type == LogFieldType.STRING:
            conversion = str(value)
        elif field.type == LogFieldType.INTEGER:
            conversion = int(value)
        return conversion

    """
    *   Creates a regular expression pattern for splitting the string 
    *
    """

    def create_pattern(self) -> re.Pattern:
        single_delimiter = []
        dual_delimiter = []
        for field in self.fields:
            if field.fieldStartDelimiter is not None and field.fieldEndDelimiter is None:
                single_delimiter.append(field.fieldStartDelimiter)
            elif field.fieldStartDelimiter is not None and field.fieldEndDelimiter is not None:
                dual_delimiter.append([field.fieldStartDelimiter, field.fieldEndDelimiter])
        field_delimiter: string = ""
        single_delimiter_pattern: string = ""
        dual_delimiter_pattern: string = ""

        for sd in single_delimiter:
            field_delimiter += ("\\" + sd + "|")
            pat = Template(self.SINGLE_DELIMITER_TEMPLATE).substitute(sd=sd)
            single_delimiter_pattern += pat

        for dd in dual_delimiter:
            field_delimiter += ("\\" + dd[0] + "|" + "\\" + dd[1] + "|")
            pat = Template(self.DUAL_DELIMITER_TEMPLATE).substitute(sd=dd[0], ed=dd[1])
            dual_delimiter_pattern += pat
        field_delimiter = field_delimiter[:-1]

        pattern = Template(self.PATTERN_NEGATE_TEMPLATE).substitute(delimiter=self.delimiter,
                                                                    field_delimiter=field_delimiter,
                                                                    single_pattern=single_delimiter_pattern,
                                                                    dual_pattern=dual_delimiter_pattern)
        print("Using pattern " + pattern + " for line splitting")
        return re.compile(pattern)


def run():
    delimited_parser = LogParser(parser_type=ParserType.DELIMITED, log_path="access.log", delimiter="\\s")
    delimited_parser.add_field(LogField(name="requestId", field_type=LogFieldType.STRING, is_unique_id=True))
    delimited_parser.add_field(LogField(name="remoteIP", field_type=LogFieldType.IP))
    delimited_parser.add_field(LogField(name="remoteLogName", field_type=LogFieldType.STRING))
    delimited_parser.add_field(LogField(name="httpUsername", field_type=LogFieldType.STRING))
    delimited_parser.add_field(
        LogField(name="timestamp", field_type=LogFieldType.TIMESTAMP, format_str="%d/%m/%Y:%H:%M:%S %z",
                 field_start_delimiter="[", field_end_delimiter="]"))
    delimited_parser.add_field(LogField(name="request", field_type=LogFieldType.STRING, field_start_delimiter="\""))
    delimited_parser.add_field(LogField(name="responseCode", field_type=LogFieldType.INTEGER))
    delimited_parser.add_field(LogField(name="responseSize", field_type=LogFieldType.STRING))
    access_log = delimited_parser.process_log()

    json_parser = LogParser(parser_type=ParserType.JSON, log_path="forensics.json")
    json_log = json_parser.process_json_log()
    refiner = Refiner(access_log, json_log)

    with open('output.json', 'w') as file:
        file.write(json.dumps(refiner.refine(), indent=4, default=str))


run()
