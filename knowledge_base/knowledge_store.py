
from abc import ABC


class KnowledgeStore(ABC):


    # Retrieve canonical representation for this program from the store
    # Add if not yet present.
    # 
    # program object required fields:
    # 'name', 'filepath', and 'git_hash'
    # NB: filepath should be accessible to the kb
    @abstractmethod
    def get_program(self, program):
        raise NotImplementedError
       
    # Retrieve canonical representation for this input from the store
    # Add if not yet present.
    #
    # inp object required fileds:
    # 'filepath'
    # NB: filepath should be accessible to the kb
    @abstractmethod
    def get_input(self, inp):
        raise NotImplementedError

    # Retrieve canonical representation for this corpus from the store
    # Add if not yet present.
    #
    # corp object required fields:    
    # 'name' and 'input'
    # input should be an array
    @abstractmethod
    def get_corpus(self, corp):
        raise NotImplementedError

    # Retrieve canonical representation for this experiment from the store
    # Add if not yet present.
    #
    # experiment required fields:
    # 'start', 'end', 'description', 'program', 'seed_corpus', 'prng_seed'
    @abstractmethod
    def get_experiment(self, experiment):
        raise NotImplementedError


    # Retrieve canonical representation for this taint engine from the store
    # Add if not yet present.
    #
    # taint_engine required fields:
    # 'name', 'install_string'    
    @abstractmethod   
    def get_taint_engine(self, taint_engine):
        raise NotImplementedError
        
