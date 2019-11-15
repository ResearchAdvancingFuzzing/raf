

"""

All of the parameters for this spitfire fuzzing campaign

"""


class SpitfileFuzzCampaignParams(FuzzCampaignParams):

    def __init__(self, yamlfile):
        
        super.__init__(yamlfile)

    def validate(self):
        super.validate()
        # also check to see that we have specified a taint analysis
        assert "taint_analysis" in self.param
        # note that the taint analysis will have its own params
        # and we will have to validate that those are present 
        # but that will be left to the taint analysis itself
