
"""

All of the parameters for this fuzzing campaign live in this object.

"""

class FuzzCampaignParams:

    def __init__(self, json_filename):
        with open(json_filename, 'r') as jf:
            self.param = json.load(jf)
            # pick out a few that we want to have at top level
            self.name = self.param.name
            self.num_rounds = self.param.num_rounds
            # ... others

        try:
            self.validate_params(host)
        except AssertionError as e:
            print("Your campaign json file did not validate")
            raise

    def validate(self):
        assert "name" in self.param
        assert "num_rounds" in self.param
        # ... others

