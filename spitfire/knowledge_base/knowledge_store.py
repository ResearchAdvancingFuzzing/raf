


from abc import ABC


class KnowledgeStore(ABC):

    # Determine if item is already in the knowledge store
    # All of these return KnowledgeBaseResult with success=True to indicate
    # that the item exists in the kb. success=False otherwise
    @abstractmethod
    def program_exists(self, program):
        raise NotImplementedError

    @abstractmethod
    def input_exists(self, input)
        raise NotImplementedError

    @abstractmethod
    def input_exists(self, input)
        raise NotImplementedError

    @abstractmethod
    def corpus_exists(self, corpus)
        raise NotImplementedError

    @abstractmethod
    def experiment_exists(self, experiment)
        raise NotImplementedError

    @abstractmethod
    def taint_engine_exists(self, taint_engine)
        raise NotImplementedError

    @abstractmethod
    def taint_analysis_exists(self, taint_analysis)
        raise NotImplementedError


    # Obtain canonical message for each of these, with
    # uuid filled in.  If item not in kb, it will be added first

    @abstractmethod
    def add_program(self, program):
        raise NotImplementedError
       
    @abstractmethod
    def add_input(self, inp):
        raise NotImplementedError

    @abstractmethod
    def add_corpus(self, corp):
        raise NotImplementedError

    @abstractmethod
    def add_experiment(self, experiment):
        raise NotImplementedError

    @abstractmethod   
    def add_taint_engine(self, taint_engine):
        raise NotImplementedError

    @abstractmethod   
    def add_taint_analysis(self, taint_analysis):
        raise NotImplementedError



    # Obtain canonical message for each of these, with
    # uuid filled in.  If item not in kb, it will be added first

    @abstractmethod
    def get_program(self, program):
        raise NotImplementedError
       
    @abstractmethod
    def get_input(self, inp):
        raise NotImplementedError

    @abstractmethod
    def get_corpus(self, corp):
        raise NotImplementedError

    @abstractmethod
    def get_experiment(self, experiment):
        raise NotImplementedError

    @abstractmethod   
    def get_taint_engine(self, taint_engine):
        raise NotImplementedError

    @abstractmethod   
    def get_taint_analysis(self, taint_analysis):
        raise NotImplementedError

    @abstractmethod   
    def add_fuzzable_byte_set(self, fbs):
        raise NotImplementedError

    @abstractmethod   
    def add_tainted_instruction(self, ti):
        raise NotImplementedError

    @abstractmethod   
    def add_taint_mapping(self, tm):
        raise NotImplementedError

    @abstractmethod   
    def get_tainted_instructions(self):
        raise NotImplementedError

    @abstractmethod   
    def get_taint_inputs(self):
        raise NotImplementedError

    # iterator over inputs that tait this instruction
    def get_taint_inputs_for_tainted_instruction(self, ti):
        raise NotImplementedError

    # iterator over fuzzable byte sets for this input
    def get_fuzzable_byte_sets_for_taint_input(self, inp):
        raise NotImplementedError

    # iterator over tainted instructions for this input
    def get_tainted_instructions_for_taint_input(self, inp):
        raise NotImplementedError

    # iterator over taint mappings for this inp-fbs/instr key
    def get_taint_mappings(self, tmk):
        raise NotImplementedError





    
