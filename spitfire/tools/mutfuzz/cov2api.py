import drcov
import sys
import os
import os.path

if __name__ == "__main__":
    argc = len(sys.argv)
    argv = sys.argv

    # base usage
    if argc < 2:
        print "usage: %s <coverage filename>" % os.path.basename(sys.argv[0])
        sys.exit()

    # attempt file parse
    x = drcov.DrcovData(argv[1])
    for bb in x.basic_blocks:
        print "0x%08x\t%s @ 0x%08x" % (bb.start, x.modules[bb.mod_id].filename, x.modules[bb.mod_id].base)
