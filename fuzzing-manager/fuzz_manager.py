
"""

Fuzzing manager.  Run by Kubernetes cron job periodically. 
Assumes we have already run fuzzing_init.py

Takes one argument, the param file

"""


# Get campaign parameters 
yf = yaml.load(open(campaign_param_file)
ct = yf.campaign_type

# Check on state of fuzzing campaign
fm.assess_fuzzing_campaign()

# Figure out what to do (launch one or more Kub jobs)
fm.do_something()
