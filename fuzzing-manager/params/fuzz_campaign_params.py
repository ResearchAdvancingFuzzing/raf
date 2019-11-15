
"""

All of the parameters for this fuzzing campaign live in this object.

"""

import yaml
from util.prompt import yes

class FuzzCampaignParams:

    def __init__(self, yamlfile):
        with open(yamlfile, 'r') as yf:
            self.param = yaml.load(yf)
        assert(type(self.param is dict))
        # promote all those keys in yaml dict to member variables
        for param_name in self.param.keys():
            settattr(self, param_name, self.param[param_name])
        try:
            self.validate_params(host)
        except AssertionError as e:
            print("Your campaign json file did not validate")
            raise
        # are we fuzzing using code that's actually been committed?
        output = sp.check_output(["git", "status", "-s"])
        if output != "":
            warn("You are fuzzing using code that may not have been checked in.  You sure?")
            assert (yes() == True)
        # get git commit hash 
        # XXX Do we need to try to ensure that this is happening inside the repo?
        # that is: what happens if someone runs script from /home/you? 
        self.gitcommit = sp.check_output(["git", "log", "--pretty=format:'%H'", "-n", "1"])
        
        
                



    def validate(self):
        # some minimal validation -- every fuzzing params should have these
        assert "name" in self.param
        assert "num_rounds" in self.param
        # ... others

