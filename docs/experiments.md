Goal: We want to run multiple experiments/campaigns at once.

What we need: 
- Different parameters for the config
- Different versions of tools
- Different driver scripts 
- Anything else?

How to do this: 
- Each experiment needs to be self contained; we can use different branches for different experiments and checkout the branch that holds everything for that experiment. 
- We need to have a unique number or identifier for the experiment that will be then used to parametrize start and stop scripts and things like the init job, fuzzing manager, persistent volumes claims, knowledge base, since these things will need to be unique per campaign and currently would not be.
- Docker files will need to be parametrized for version numbers of things and anything else that we want to be configurable if we don’t want to have to go in and find and change these things manually. 
- Everything inside config/expt<num> can be changed to suit that experiment manually? 
