import enum

from sqlalchemy import Table
from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import create_engine
from sqlalchemy.types import Text
from sqlalchemy.types import Float
from sqlalchemy.types import Integer
from sqlalchemy.types import Boolean
from sqlalchemy.types import BigInteger
from sqlalchemy.types import DateTime
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.expression import func
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class JobKind(enum.Enum):
    dumbfuzzing = 1
    taint = 2
    symbolicexec = 3
    magic = 4


class JobStatus(enum.Enum):
    dispatched = 1
    succeeded = 2
    failed = 3


class fileKind(enum.Enum):
    loadPtr = 1
    storePtr = 2
    storeVal = 3
    condition = 4
    jump = 5


class Campaign(Base):
    __tablename__ = 'campaign'

    id = Column(Integer, primary_key=True)
    name = Column(Text)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    num_jobs = Column(Integer)


class Coverage(Base):
    __tablename__ = 'coverage'

    id = Column(Integer, primary_key=True)
    hash = Column(Text)


class Job(Base):
    __tablename__ = 'job'

    id = Column(Integer, primary_key=True)
    campaign = Column(Integer, ForeignKey('campaign.id'))
    job_kind = Column(enum.Enum(JobKind))
    docker_image = Column(Text)
    cmdline = Column(Text)
    status = Column(enum.Enum(JobStatus))
    exit_code = Column(Integer)
    input_filename = Column(Text)
    start_time = Column(DateTime)
    end_time = Column(DateTime)


class Input(Base):
    __tablename__ = 'input'

    id = Column(Integer, primary_key=True)



class SourceLval(Base):
    __tablename__ = 'sourcelval'

    id = Column(Integer, primary_key=True)
    loc = ASTLoc.composite('loc')
    ast_name = Column(Text)

    def __str__(self):
        return 'Lval[{}](loc={}:{}, ast="{}")'.format(
            self.id, self.loc.filename, self.loc.begin.line, self.ast_name
        )
