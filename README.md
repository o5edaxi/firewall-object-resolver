# Firewall Address, Service, and Group Resolver

This script takes a list of firewall policies or access control lists in csv format, and replaces any named address, address group, service, or service group alias with their actual values. For example:

```
source_ip,destination_ip,service,action
Private_Networks,Host_198.51.100.1,DNS;NTP,Allow
```

Becomes:

```
source_ip,destination_ip,protocol_number,action,port_number
192.168.0.0/16;10.0.0.0/8;172.16.0.0/12,198.51.100.1,6;17,Allow,53;123
```

The contents of the named objects must be provided as separate csv files in the form:

```
NAME,CONTENTS
Host_198.51.100.1,198.51.100.1
```

for addresses and groups, and

```
NAME,PROTOCOL,PORT
DNS,6;17,53
```

for services.


### Usage

```
usage: firewall_object_resolver.py [-h] [-o OUTPUT_FILE] [-e] [-d] [-1 SOURCE_COLUMN] [-2 DESTINATION_COLUMN] [-3 SERVICE_COLUMN] [-c CSV_SEPARATOR]
                                   [-r ADDRESS_SEPARATOR] [-x {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                   input_policies input_addresses input_address_groups input_services input_service_groups

positional arguments:
  input_policies        Input csv containing the firewall policies
  input_addresses       Input csv containing the firewall address objects
  input_address_groups  Input csv containing the firewall address groups
  input_services        Input csv containing the firewall service objects
  input_service_groups  Input csv containing the firewall service groups

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        The name of the output file containing the policy list. Default: output.csv
  -e, --allow-unknown   Do not exit the script when a value in policy is not found in the respective csv lookup. Default: False
  -d, --deduplicate     Deduplicate results. Default: False
  -1 SOURCE_COLUMN, --source-column SOURCE_COLUMN
                        The column header in the csv corresponding to the source address column. Default: source
  -2 DESTINATION_COLUMN, --destination-column DESTINATION_COLUMN
                        The column header in the csv corresponding to the destination address column. Default: destination
  -3 SERVICE_COLUMN, --service-column SERVICE_COLUMN
                        The column header in the csv corresponding to the service column. Default: service
  -c CSV_SEPARATOR, --csv-separator CSV_SEPARATOR
                        CSV separator. Default: ","
  -r ADDRESS_SEPARATOR, --address-separator ADDRESS_SEPARATOR
                        CSV separator. Default: ";"
  -x {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --debug-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Logging message verbosity. Default: WARNING
```
```
Example:

  $ python3 firewall_object_resolver.py -d -e -1 src -2 dst -3 svc policies.csv addresses.csv addgrps.csv services.csv svcgrps.csv
```

### License

This project is licensed under the [Apache-2.0 license](LICENSE).
