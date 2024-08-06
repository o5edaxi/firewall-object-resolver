"""Takes a list of policies as csv as well as csv files for address, address group, service, and service
 group definitions, and outputs a list of policies containing raw IPs, protocols, and port numbers"""

import sys
import csv
import argparse
import logging


def resolve_groups(obj, dictionary):
    """Checks if a firewall object is a group or group of groups and recursively flattens it into its constituent
    member objects"""
    if obj not in dictionary:
        return [obj]
    output = []
    for sub_obj in dictionary[obj]:
        output += resolve_groups(sub_obj, dictionary)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Takes a list of policies as csv as well as csv files for address, '
                                                 'address group, service, and service group definitions, and outputs a '
                                                 'list of policies containing raw IPs, protocols, and port numbers. The'
                                                 'additional csv files for address objects, service objects, and their'
                                                 'groups are simple lookup tables in which the first column is the '
                                                 'name of the object or group, and the second column is the value of '
                                                 'the IP or group members separated by the --address-separator. For '
                                                 'services, the first column is the name of the service, the second is'
                                                 ' the protocol, and the third is the port. A service can contain '
                                                 'multiple protocols and ports separated by the --address-separator. '
                                                 'Example:'
                                                 ''
                                                 'service,protocol,port'
                                                 'RADIUS,6;17,1812;1813')
    parser.add_argument('input_policies', type=str, help='Input csv containing the firewall policies')
    parser.add_argument('input_addresses', type=str, help='Input csv containing the firewall address objects')
    parser.add_argument('input_address_groups', type=str, help='Input csv containing the firewall address groups')
    parser.add_argument('input_services', type=str, help='Input csv containing the firewall service objects')
    parser.add_argument('input_service_groups', type=str, help='Input csv containing the firewall service groups')
    parser.add_argument('-o', '--output-file', type=str, default='output.csv', help='The name of the output file '
                                                                                    'containing the policy list. '
                                                                                    'Default: output.csv')
    parser.add_argument('-e', '--allow-unknown', action='store_true', default=False, help='Do not exit the script when '
                                                                                          'a value in policy is not '
                                                                                          'found in the respective csv '
                                                                                          'lookup. Default: False')
    parser.add_argument('-d', '--deduplicate', action='store_true', default=False, help='Deduplicate results. Default: '
                                                                                        'False')
    parser.add_argument('-1', '--source-column', type=str, default='source', help='The column header in the csv '
                                                                                  'corresponding to the source address '
                                                                                  'column. Default: source')
    parser.add_argument('-2', '--destination-column', type=str, default='destination', help='The column header in the '
                                                                                            'csv corresponding to the '
                                                                                            'destination address '
                                                                                            'column. Default: '
                                                                                            'destination')
    parser.add_argument('-3', '--service-column', type=str, default='service', help='The column header in the csv '
                                                                                    'corresponding to the service '
                                                                                    'column. Default: service')
    parser.add_argument('-c', '--csv-separator', type=str, default=',', help='CSV separator. Default: ","')
    parser.add_argument('-r', '--address-separator', type=str, default=';', help='CSV separator. Default: ";"')
    parser.add_argument('-x', '--debug-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        default='WARNING', help='Logging message verbosity. Default: WARNING')
    args = parser.parse_args()
    logging.basicConfig(level=args.debug_level, format='%(asctime)s [%(levelname)s] %(message)s')
    logging.debug('Starting with args %s', args)
    logging.info('Opening file %s', args.input_policies)
    with open(args.input_policies, 'r', encoding='utf-8') as f:
        parsed_policies = list(csv.reader(f, delimiter=args.csv_separator))
        logging.debug('%s', parsed_policies)
    try:
        missing_column = args.source_column
        logging.info('Looking for source column %s', args.source_column)
        SRC_INDEX = parsed_policies[0].index(args.source_column)
        logging.info('Found source column')
        missing_column = args.destination_column
        logging.info('Looking for destination column %s', args.destination_column)
        DEST_INDEX = parsed_policies[0].index(args.destination_column)
        logging.info('Found destination column')
        missing_column = args.service_column
        logging.info('Looking for service column %s', args.service_column)
        SVC_INDEX = parsed_policies[0].index(args.service_column)
        logging.info('Found service column')
    except ValueError:
        logging.critical('Column %s not present in the file. Exiting...', missing_column)
        sys.exit(1)
    address_dict = {}
    address_group_dict = {}
    service_dict = {}
    service_group_dict = {}
    with open(args.input_addresses, 'r', encoding='utf-8') as f:
        parsed_addresses = list(csv.reader(f, delimiter=args.csv_separator))
        logging.debug('%s', parsed_addresses)
    try:
        for line in parsed_addresses:
            address_dict[line[0]] = line[1].split(args.address_separator)
    except IndexError:
        logging.critical('Missing columns in address file. Exiting...')
        sys.exit(1)
    with open(args.input_address_groups, 'r', encoding='utf-8') as f:
        parsed_address_groups = list(csv.reader(f, delimiter=args.csv_separator))
        logging.debug('%s', parsed_address_groups)
    try:
        for line in parsed_address_groups:
            address_group_dict[line[0]] = line[1].split(args.address_separator)
    except IndexError:
        logging.critical('Missing columns in address group file. Exiting...')
        sys.exit(1)
    with open(args.input_services, 'r', encoding='utf-8') as f:
        parsed_services = list(csv.reader(f, delimiter=args.csv_separator))
        logging.debug('%s', parsed_services)
    try:
        for line in parsed_services:
            service_dict[line[0]] = (line[1].split(args.address_separator), line[2].split(args.address_separator))
    except IndexError:
        logging.critical('Missing columns in service file. Exiting...')
        sys.exit(1)
    with open(args.input_service_groups, 'r', encoding='utf-8') as f:
        parsed_service_groups = list(csv.reader(f, delimiter=args.csv_separator))
        logging.debug('%s', parsed_service_groups)
    try:
        for line in parsed_service_groups:
            service_group_dict[line[0]] = line[1].split(args.address_separator)
    except IndexError:
        logging.critical('Missing columns in service group file. Exiting...')
        sys.exit(1)
    output_csv = [parsed_policies[0]]
    output_csv[0][SVC_INDEX] = 'protocol_number'
    output_csv[0].append('port_number')
    for idx, line in enumerate(parsed_policies[1:], start=1):
        output_line = line
        results = []
        try:
            for member in line[SRC_INDEX].split(args.address_separator):
                logging.debug('Checking source address %s in policy at line %d', member, idx)
                groups_done = resolve_groups(member, address_group_dict)
                for addr_obj in groups_done:
                    results += address_dict[addr_obj]
        except KeyError:
            if not args.allow_unknown:
                logging.critical('ERROR: source address %s in policy at line %d not found in lookups. Run with -e flag '
                                 'to continue anyway. Exiting...', member, idx)
                sys.exit(1)
            logging.error('ERROR: source address %s in policy at line %d not found in lookups. Continuing anyway '
                          'due to -e flag', member, idx)
        if args.deduplicate:
            logging.info('Deduplicating sources')
            results = list(set(results))
        output_line[SRC_INDEX] = args.address_separator.join(results)
        results = []
        try:
            for member in line[DEST_INDEX].split(args.address_separator):
                logging.debug('Checking destination address %s in policy at line %d', member, idx)
                groups_done = resolve_groups(member, address_group_dict)
                for addr_obj in groups_done:
                    results += address_dict[addr_obj]
        except KeyError:
            if not args.allow_unknown:
                logging.critical('ERROR: destination address %s in policy at line %d not found in lookups. Run with -e '
                                 'flag to continue anyway. Exiting...', member, idx)
                sys.exit(1)
            logging.error(
                'ERROR: destination address %s in policy at line %d not found in lookups. Continuing anyway due to -e '
                'flag', member, idx)
        if args.deduplicate:
            logging.info('Deduplicating destinations')
            results = list(set(results))
        output_line[DEST_INDEX] = args.address_separator.join(results)
        results = []
        results_port = []
        try:
            for member in line[SVC_INDEX].split(args.address_separator):
                logging.debug('Checking service %s in policy at line %d', member, idx)
                groups_done = resolve_groups(member, service_group_dict)
                for svc_obj in groups_done:
                    results += service_dict[svc_obj][0]
                    results_port += service_dict[svc_obj][1]
        except KeyError:
            if not args.allow_unknown:
                logging.critical('ERROR: service %s in policy at line %d not found in lookups. Run with -e flag to '
                                 'continue anyway. Exiting...', member, idx)
                sys.exit(1)
            logging.error('ERROR: service %s in policy at line %d not found in lookups. Continuing anyway due to -e '
                          'flag', member, idx)
        if args.deduplicate:
            logging.info('Deduplicating services')
            results = list(set(results))
            results_port = list(set(results_port))
        output_line[SVC_INDEX] = args.address_separator.join(results)  # Protocol
        output_line.append(args.address_separator.join(results_port))  # Port
        output_csv.append(output_line)
    logging.info('Writing csv to file %s', args.output_file)
    with open(args.output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=args.csv_separator)
        writer.writerows(output_csv)
