# Heather's notes

## Goal: We want to run multiple experiments/campaigns at once.

### What we need: 
- Different parameters for the config
- Different versions of tools
- Different driver scripts 
- Anything else?

### How to do this: 
- Each experiment needs to be self contained; we can use different branches for different experiments and checkout the branch that holds everything for that experiment. 
- We need to have a unique number or identifier for the experiment that will be then used to parametrize start and stop scripts and things like the init job, fuzzing manager, persistent volumes claims, knowledge base, since these things will need to be unique per campaign and currently would not be.
- Docker files will need to be parametrized for version numbers of things and anything else that we want to be configurable if we don’t want to have to go in and find and change these things manually. 
- Everything inside config/expt<num> can be changed to suit that experiment manually? 


---

# Tim's ideas for how expts could work.

Here is some of the experimental support I'd like in RAF.

## Starting from scratch, i.e. clone the repo and build docker containers

    % cd ~
    % git clone https://github.com/ResearchAdvancingFuzzing/raf
    ...
    % cd raf
    % run
    ...
    [raf]%

Note that our prompt is [raf].  More on that later.

## Get a listing of the available experiments checked in and labeled in
the repo

    [raf]% cd ~/raf
    [raf]% raf-list-expts
    RAF listing available experiments.
    Label	Comment			Creation Date		Creator		Git commit
    expt1      	[Initial experiment...]	07-12-2020 10:12:12	hpreslier	ec0c395698a0e46881c6ddd24a245b9ee0ff6fdc
    e-3-covg	[3-edges test to se...]	07-13-2020 09:18:01	tleek		a1f34a148e7e15678112f1673126f2b6b820d242
    tcn1	[taint computute nu...] 08-12-2020 14:45:21	hpreslier	589be92e13038f3aa192ea6e0fde5a77f89be8ff
    ...
    [raf]% raf-list-expt e-3-covg
    RAF listing experiment details.
    Comment: 		   3-edges test to see if collecting more state (bb1->bb2->bb3 here) helps
    Creation date: 	   07-13-2020 09:18:01
    Git commit: 	   a1f34a148e7e15678112f1673126f2b6b820d242
    ...
    

## Reproduce someone else's (or your) experiment that is checked in to
the raf repo.

First, we have to "check out" that experiment meaning get all code and config for that.

    [raf]% cd ~/raf
    [raf]% raf-checkout tcn1    
    RAF checking out code and config for experiment tcn1.
    tcn1 corresponds to git checkout 589be92e13038f3aa192ea6e0fde5a77f89be8ff
    Docker containers exist so no need to build.
    ...
    Current raf experiment is tcn1.
    [raf-tcn1]% 

Note that this switch to a different experiment would be expensive if we have
to rebuild docker containers. So we should cache them. If an experiment is
checked in to git and labeled, then, *by definition* it need only be built once.       

Also note that raf should have a notion of the current experiment. Perhaps
this is just in standard place like ~/.raf/current-expt?
When we first cloned raf there was no current experiment.
Thus, the prompt was
just [raf]. When we checked out tcn1, the prompt changed to indicate the
current experiment.

Now that we have the experiment checked out, we can run the current experiment.

    [raf-tcn1]% raf-run
    RAF kicking off 1 run of experiment tcn1.
    Run id: 5473efce5d2e8c94fffff1ffc5a79c91                 
    %

Note that this returns shell prompt almost immediately. Campaign will
run for a potentially long time. There will be raf commands that can
be used to monitor progress and also to summarize and analyze results.
And thus to *verify* reproducibility (compare my results to yours, my
results to my old results, etc). See later in this doc.

Note that we get a run id. This is what is used to identify the knowledge
base associated with this run, in which details and results accumulate. 


3. Run the current experiment again, creating new run and thus new KB
and results.

    % raf-run 
    RAF kicking off 1 run of experiment tcn1.
    Run id: 57c447ca2c84dc14d71ab174dd35bd9f
    %

Note that we will want to run same expt many times to determine if and
how results vary. Thus, we will need ways to compute statistics for a bunch
of such runs. See later in this doc.

Perhaps we want a shortcut here.

    % raf-run 5
    RAF kicking off 5 runs of experiment tcn1.
    Run id: 57c447ca2c84dc14d71ab174dd35bd9f
    Run id: 0bee89b07a248e27c83fc3d5951213c1
    Run id: f5ac8127b3b6b85cdc13f237c6005d80
    Run id: 9b9af6945c95f1aa302a61acf75c9bd6
    Run id: 5ab557c937e38f15291c04b7e99544ad
    Run id: d42300f85175d86d779716d2174628ef
    Run id: 1c2212dad8894fdd10c65af6eef06a45
    %



4. List all runs currently available for monitoring or analysis.
Note: each has an associated KB (identified by the run id).

    % cd ~/raf
    % raf-list
    RAF listing active or completed runs.
    Run Id					Start Time		End Time
    5473efce5d2e8c94fffff1ffc5a79c91	07-15-2020 09:31:02	07-20-2020 18:22:41	
    57c447ca2c84dc14d71ab174dd35bd9f	07-21-2020 11:30:34	in progress
    %


5. Clone an experiment, in preparation for changing it.

    % cd ~/raf
    % raf-clone expt1
    RAF cloning experiment expt1.
    Created new experiment expt71
    %

After tinkering with config or code for expt71 which starts out *identical* to expt1, we can
run the new one.

    % cd ~/raf
    % raf-run expt71
    RAF kicking off run of experiment expt1.
    Run id: 61d60a8f0be9cd5687da0a1b50ee6678 
    %

A good initial test of this machinery would be to run expt1 10 times
(10 run ids). And then clone it to create, say, expt71.  Then run that 10
times. Then compute summary stats or do analysis on the results for expt1
and expt71. Should be same.


6. Misc.  We'll need a few things like the ability to clean up by discarding
KB for a run. Note: all the info for a run in is its KB, right?

% raf-rm 61d60a8f0be9cd5687da0a1b50ee6678
RAF deleting run 61d60a8f0be9cd5687da0a1b50ee6678.
%


7. Status.  We'll need the ability to get status of a run.  

# monitor status of a run -- snapshot of what it has done, how long
# it has been running etc.  
% raf-status 5473efce5d2e8c94fffff1ffc5a79c91
...

# continuously updated version of the previous, kinda like
# afl's panel
% raf-status -c 5473efce5d2e8c94fffff1ffc5a79c91 
...


8. Analysis.  What are our needs?  We want plots to look at with detail.
But we also want robust statistical comparisons that allow us to answer
questions like

I have N runs of expt12 and N runs of expt13. Are they different?

This question can be answered maybe in the following way. Generate summary
graphs for expt12 and expt13 in which the N runs give us a mean and standard
deviation (or similar). Now divide timeline for each into M cells and, for
each, determine if expt12 is better or worse than expt13, or if the difference
is not statistically significant. Then summarize: expt12 better 7 times.
No difference 8 times. expt13 better 2 times.

This could work with covg over time. Or unique crashes.  