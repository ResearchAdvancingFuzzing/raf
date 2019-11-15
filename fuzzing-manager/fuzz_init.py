
"""

Fuzzing campaign initializer.  Run once at the beginning of a fuzzing
campaign to create database tables and register (if that's the word)
the correct invocation of fuzzing_manager.py to be run periodically to
monitor and manage the campaign.

Usage: fuzzing_init.py fuzz_campaign,json

"""
import sys
import yaml
from fuzz_campaign_params import FuzzCampaignParams
from fuzz_database import initialize_fuzzing_database
from util.util import progress


campaign_param_file = sys.argv[1]
command = sys.argv[2]

assert (command is "start" or "stop")

# Get campaign parameters 
yf = yaml.load(open(campaign_param_file)
ct = yf.campagin_type

progress("fuzzing manager type is [%s]" % ct)

FuzzCampaignParams = __import__("params.%sFuzzCampaignParams" % ct)

#fc_params = FuzzCampaignParams(campaign_param_file)

if command is "start":
    # Create fuzzing database for this campaign
    initialize_fuzzing_database(fc_params)
    
    # Register fuzzing manager for this campagin to run periodically
    register_fuzzing_manager(fc_params)

else:
    # unregister fuzzing manager
    unregister_fuzzing_manager(fc_params)
    # should we archive db tables?


