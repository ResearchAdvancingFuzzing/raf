FROM raf:latest

RUN apt-get install -y git 
RUN git clone https://github.com/google/AFL.git
WORKDIR AFL/
RUN make

WORKDIR /
ENV SOURCE_DIR spitfire/fuzzing_manager
COPY $SOURCE_DIR/aflfast.py ./
COPY infinite ./
CMD python3.6 aflfast.py 
