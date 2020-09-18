FROM raf:latest

WORKDIR /
ENV SOURCE_DIR spitfire/fuzzing_manager
COPY $SOURCE_DIR/spitfire.py ./
COPY infinite ./
CMD python3.6 spitfire.py 
