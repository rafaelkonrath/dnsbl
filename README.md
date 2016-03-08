# dnsbl
This program runs a query against the ProofPoint and DNSBL blocked database to
check whther the MTA list servers are listed and send alerts to VictorOps

## Usage
check_dnsbl.py [options]

  Options:
      
      -h --help         Prints this
      
      -s --standalone   Disable VictorOps Notification
      
      -v --verbose      Execute in verbose mode
