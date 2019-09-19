/*
database tables for RAF
*/


/* Kind of job */
CREATE TYPE job_kind AS ENUM ('dumbfuzzing', 'taint', 'symbolicexec');

/* Current status of job */
CREATE TYPE job_status AS ENUM ('dispatched', 'succeeded', 'failed');

/* Kind of file */
CREATE TYPE file_kind AS ENUM ('original', 'fuzzed');

/* Kind of attack point */
CREATE TYPE ap_kind AS ENUM (
  load_ptr,                   /* address used in a load tainted */ 
  store_ptr,                  /* address used in store tainted */
  store_val,                  /* value being stored tainted */
  condition,                  /* condition is tainted */
  jump                        /* indirect jump or call address tainted */
);   

/* Table for a fuzzing campaign */
CREATE TABLE campaign (
  id             BIGSERIAL NOT NULL PRIMARY KEY,
  
);


/* Table for every job created by the FM (Fuzzing Manager */
CREATE TABLE job (
  id             BIGSERIAL NOT NULL PRIMARY KEY,
  job_kind       job_kind NOT NULL,              
  docker_image   TEXT NOT NULL,                  /* name of docker image to use */
  cmdline        TEXT NOT NULL,                  /* text of cmdline for docker run */
  status         job_status NOT NULL,            
  exit_code      INTEGER NOT NULL.               /* exit code of the cmdline program that ran in the container */
  input_filename TEXT NOT NULL,                  /* a job runs on an input */
  start_time     TIMESTAMP NOT NULL,             /* dispatch time for this job (presumably close to actual start?) */
  end_time       TIMESTAMP NOT NULL,             /* end time for this job */
);


/* Table for every input file (original, fuzzed, etc) */
CREATE TABLE input_file (
  id             BIGSERIAL NOT NULL PRIMARY KEY,
  filename       TEXT NOT NULL,                  /* filename of input this is part of */
  file_kind      file_kind NOT NULL
  parent (job_id ?)  
);


/* Table for parts of inputs to fuzz as a unit. 
   These are contiguous byte ranges (extents) seen to taint some important internal program quantity, 
   as a result of a taint query. */
CREATE TABLE input_extent (
  id             BIGSERIAL NOT NULL PRIMARY KEY,
  input_id       BIGSERIAL NOT NULL,
  start_offset   INTEGER NOT NULL,               /* start byte of extent in input  */
  end_offset     INTEGER NOT NULL,               /* end byte */
  val            BYTEA NOT NULL,                 /* the original bytes in that range for that input */
  FOREIGN KEY (input_id) REFERENCES input(id)
);

// checksums?
// A+B  where A and B are in differnt parts

/* Table for parts of the program that can be fuzzed bc they are tainted 
   Note that we keep track of count so we can choose to fuzz attack points
   that we have not yet tried to fuzz. */
CREATE TABLE attack_point (
  id             BIGSERIAL NOT NULL PRIMARY KEY,
  ap_kind        ap_kind NOT NULL,                        
  pc             NUMERIC NOT NULL,               /* program counter of this attack_point */
  count          NUMERIC NOT NULL,               /* The number of times this attack_point has been fuzzed */
);


/* Table recording taint relationship between input_extents and attack_points 
   Really this is a bi-partite graph, since each input_extent can taint one or more 
   attack points, and an attack point can be tainted by more than one input extent 
   (different files). */
CREATE TABLE taint (
  id                      BIGSERIAL NOT NULL PRIMARY KEY,  
  input_extent_id         BIGSERIAL NOT NULL,
  attack_point_id         BIGSERIAL NOT NULL,
  taint_compute_numbers   INTEGER[] NOT NULL,        /* the taint compute numbers for each of the bytes in the extent (INT_MAX if not tainted?) */
  controlled_bits         INTEGER[] NOT NULL,        /* controlled bits for each of the bytes in the extent (0 if not tainted *) */   
  FOREIGN KEY (input_extent_id) REFERENCES input_extent(id),
  FOREIGN KEY (attack_point_id) REFERENCES attack_point(id)
);


/* Table to keep track of each of the taint-based fuzzings we have tried.
   A fuzzing is one or more input extent we decided to fuzz at once. */
CREATE TABLE fuzzing (
  id                      BIGSERIAL NOT NULL PRIMARY KEY,  
  input_extent1_id        BIGSERIAL NOT NULL,                 /* one of the input_extents we fuzz */
  input_extent2_id        BIGSERIAL,                          /* another (optional) input_extents we fuzz */
  input_extent3_id        BIGSERIAL,                          /* another (optional) input_extents we fuzz */
  input_extent4_id        BIGSERIAL,                          /* another (optional) input_extents we fuzz */
  FOREIGN KEY (input_extent1_id) REFERENCES input_extent(id),
  FOREIGN KEY (input_extent1_id) REFERENCES input_extent(id),
  FOREIGN KEY (input_extent1_id) REFERENCES input_extent(id),
  FOREIGN KEY (input_extent1_id) REFERENCES input_extent(id),
);



