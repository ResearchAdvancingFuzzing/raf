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

## Starting from scratch, clone the repo and build docker containers

    % cd ~
    % git clone https://github.com/ResearchAdvancingFuzzing/raf
    ...
    % cd raf
    % run
    ...
    [raf]%

Note that our prompt is now `[raf]`.  More on that later.

## Get a listing of the available experiments checked in and labeled in the repo

    [raf]% cd ~/raf
    [raf]% raf-list-expts
    RAF listing available experiments.
    Label       Comment			Creation Date		Creator		Git commit
    expt1       [Initial experiment...]	07-12-2020 10:12:12	hpreslier	ec0c395698a0e46881c6ddd24a245b9ee0ff6fdc
    e-3-covg    [3-edges test to se...]	07-13-2020 09:18:01	tleek		a1f34a148e7e15678112f1673126f2b6b820d242
    tcn1        [taint computute nu...]	08-12-2020 14:45:21	hpreslier	589be92e13038f3aa192ea6e0fde5a77f89be8ff
    ...
    [raf]% raf-list-expt e-3-covg
    RAF listing experiment details.
    Comment:       3-edges test to see if collecting more state (bb1->bb2->bb3 here) helps
    Creation date: 07-13-2020 09:18:01
    Git commit:    a1f34a148e7e15678112f1673126f2b6b820d242
    ...
    

## Reproduce someone else's (or your) experiment that is checked in to the raf repo.

First, we have to "check out" that experiment, meaning get all code and config for it.

    [raf]% cd ~/raf
    [raf]% raf-checkout tcn1    
    RAF checking out code and config for experiment 'tcn1'.
    tcn1 corresponds to git checkout 589be92e13038f3aa192ea6e0fde5a77f89be8ff
    Docker containers exist so no need to build.
    ...
    Current raf experiment is tcn1.
    [raf-tcn1]% 

Note that this switch to a different experiment would be expensive if
we have to rebuild docker containers. So we should cache them or just
look for them, which means they need to be tagged by git hash or expt
label. If an experiment is checked in to git and labeled, then, by
definition, it need only be built once, right?

Also note that raf should have a notion of the current
experiment. Perhaps this is just in standard place like
~/.raf/current-expt?  When we first cloned raf there was no current
experiment.  Thus, the prompt was just [raf]. When we checked out
tcn1, the prompt changed to indicate the current experiment.

Now that we have the experiment checked out, we can run it.

    [raf-tcn1]% raf-run
    RAF kicking off 1 run of experiment tcn1.
    Run id: 5473efce5d2e8c94fffff1ffc5a79c91                 
    [raf-tcn1]%

Note that this returns shell prompt almost immediately. Campaign will
run for a potentially long time. There will be raf commands that can
be used to monitor progress and also to summarize and analyze results.
And thus to *verify* reproducibility (compare my results to yours, my
results to my old results, etc). See later in this doc.

Note that we get a run id. This is what is used to identify the knowledge
base associated with this run, in which details and results accumulate. 


## Run the current experiment again, creating new run and thus new KB and results.

    [raf-tcn1]% raf-run 
    RAF kicking off 1 run of experiment tcn1.
    Run id: 57c447ca2c84dc14d71ab174dd35bd9f
    [raf-tcn1]%

Note that we will want to run same expt many times to determine if and
how results vary. Thus, we will need ways to compute statistics for a bunch
of such runs. See later in this doc.

Perhaps we want a shortcut here, to be able to kick of lots of runs at once.

    [raf-tcn1]% raf-run 5 tcn1-5-runs
    RAF kicking off 5 runs of experiment tcn1.
    Run id: 57c447ca2c84dc14d71ab174dd35bd9f
    Run id: 0bee89b07a248e27c83fc3d5951213c1
    Run id: f5ac8127b3b6b85cdc13f237c6005d80
    Run id: 9b9af6945c95f1aa302a61acf75c9bd6
    Run id: 5ab557c937e38f15291c04b7e99544ad
    Run id: d42300f85175d86d779716d2174628ef
    Run id: 1c2212dad8894fdd10c65af6eef06a45
    Run group label: tcn1-5-runs 
    [raf-tcn1]%

Note that we can optionally give the set of runs a label so they can be
considered as a group (for statistics, etc).  If we dont give it a label,
raf will assign a random string of words to it.

    [raf-tcn1%]
    Run group label: babble-dove-bash
    


## List all runs currently available for monitoring or analysis.

Note: each has an associated KB (identified by the run id).

    [raf-tcn1]% cd ~/raf
    [raf-tcn1]% raf-list-runs
    RAF listing active or completed runs.
    Run Id                            Start Time           End Time
    5473efce5d2e8c94fffff1ffc5a79c91  07-15-2020 09:31:02  07-20-2020 18:22:41	
    57c447ca2c84dc14d71ab174dd35bd9f  07-21-2020 11:30:34  in progress
    [raf-tcn1]%

List run groups too?

    [raf-tcn1]% raf-list-run-groups
    Run Group Label	Number of runs
    tcn1-5-runs		5
    babble-dove-bash	5
    ...    


## Clone an experiment, in preparation for changing it.

    [raf-tcn1]% cd ~/raf
    [raf-tcn1]% raf-clone tcn1 tcn2
    RAF cloning experiment tcn2 into new experiment tcn2.
    Current raf experiment is tcn2.
    [raf-tcn2*]%

Note that cloning implicitly changes current experiment.  Note also that
raf-tcn2 hasn't been checked in so it gets a *.

After tinkering with config or code for tcn2 which starts out
*identical* to tcn1, we can run the new one.

    [raf-tcn2*]% cd ~/raf
    [raf-tcn2*]% raf-run
    RAF kicking off run of experiment tcn2.
    Run id: 61d60a8f0be9cd5687da0a1b50ee6678 
    [raf-tcn2*]%

And we'll have to check-in the current experiment for the label to be
in the repo.

    [raf-tcn2*]% raf-commit -m "Slight modification of tcn1 with different combination of labels when ..."
    RAF committed experiment tcn2 to the repository.
    [raf-tcn2]

Which removes the star from the prompt.


A good initial test of this machinery would be to run tcn1 10 times
(10 run ids). And then also run tcn2 which is a clone of tcn1 but
hasn't been changed at all. Then compute summary stats or do analysis
on the results for expt1 and expt71. Should be same.

    [raf-tcn2]% raf-checkout tcn1
    RAF checking out code and config for experiment 'tcn1'.
    tcn1 corresponds to git checkout 589be92e13038f3aa192ea6e0fde5a77f89be8ff
    Docker containers exist so no need to build.
    ...
    Current raf experiment is tcn1.
    [raf-tcn1]% raf-run 10 tcn1-runs
    Run id: b026324c6904b2a9cb4b88d6d61c81d1
    Run id: 26ab0db90d72e28ad0ba1e22ee510510 
    Run id: 6d7fce9fee471194aa8b5b6e47267f03 
    Run id: 48a24b70a0b376535542b996af517398 
    Run id: 1dcca23355272056f04fe8bf20edfce0 
    Run id: 9ae0ea9e3c9c6e1b9b6252c8395efdc1 
    Run id: 84bc3da1b3e33a18e8d5e1bdd7a18d7a 
    Run id: c30f7472766d25af1dc80b3ffc9a58c7 
    Run id: 7c5aba41f53293b712fd86d08ed5b36e 
    Run id: 31d30eea8d0968d6458e0ad0027c9f80 
    Run group label: tcn1-runs
    [raf-tcn1]% raf-checkout tcn2
    RAF checking out code and config for experiment 'tcn1'.
    tcn2 corresponds to git checkout 63cbff2b7dfb3668d32d586ed9ca44a32a709a01
    Docker containers exist so no need to build.
    ...
    Current raf experiment is tcn2.
    [raf-tcn2]% raf-run 10 tcn2-runs 
    Run id: 31d30eea8d0968d6458e0ad0027c9f80
    Run id: 166d77ac1b46a1ec38aa35ab7e628ab5
    Run id: 2737b49252e2a4c0fe4c342e92b13285
    Run id: aa6ed9e0f26a6eba784aae8267df1951
    Run id: 367764329430db34be92fd14a7a770ee
    Run id: 8c9eb686bf3eb5bd83d9373eadf6504b
    Run id: 5b6b41ed9b343fed9cd05a66d36650f0
    Run id: 4d095eeac8ed659b1ce69dcef32ed0dc
    Run id: cf4278314ef8e4b996e1b798d8eb92cf
    Run id: 3bb50ff8eeb7ad116724b56a820139fa
    Run id: dbbf8220893d497d403bb9cdf49db7a4
    Run group label: tcn2-runs
    [raf-tcn2]%

Note the new idea of run group labels. This means we can have a raf command
try to compare two run groups.

    [raf-tcn2] raf-compare tcn1-runs tcn2-runs


## Misc

We'll need a few things like the ability to clean up by discarding
KB for a run. Note: all the info for a run in is its KB, right?

    [raf-tcn2]% raf-rm 61d60a8f0be9cd5687da0a1b50ee6678
    RAF deleting run 61d60a8f0be9cd5687da0a1b50ee6678 of experiment tcn2.
    Confirm? Y
    RAF deleted run 61d60a8f0be9cd5687da0a1b50ee6678.
    [raf-tcn2]%

And, unprompted.

    [raf-tcn2]% raf-rm -f 61d60a8f0be9cd5687da0a1b50ee6678
    RAF deleted run 61d60a8f0be9cd5687da0a1b50ee6678 of experiment tcn2.
    [raf-tcn2]%


## Status.

We'll need the ability to get status of a run.  

Monitor status of a run -- snapshot of what it has done, how long
it has been running etc.  

    [raf-tcn2]% raf-status 5473efce5d2e8c94fffff1ffc5a79c91
    RAF status for run id 5473efce5d2e8c94fffff1ffc5a79c91
    ...
    

Continuously updated version of the previous, kinda like
afl's panel?

    [raf-tcn2]% raf-status -c 5473efce5d2e8c94fffff1ffc5a79c91 
    curses mode live updated panel...


## Analysis

What are our needs?  We want plots to look at with detail.
But we also want robust statistical comparisons that allow us to answer
questions like

I have N runs of expt12 and N runs of expt13. Are they different?

This question can be answered maybe in the following way. Generate summary
graphs for expt12 and expt13 in which the N runs give us a mean and standard
deviation (or similar). Now divide timeline for each into M cells and, for
each, determine if expt12 is better or worse than expt13, or if the difference
is not statistically significant. Then summarize: expt12 better 7 times.
No difference 8 times. expt13 better 2 times.

This could work with covg over time. Or unique crashes.  And will make use
of the notion of run group labels (see above).