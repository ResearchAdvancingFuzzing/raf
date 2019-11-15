

import inspect

# prompt for answer to yes/no question
# and return true if it seem like answer was yes
def yes():
    inp = input()
    if inp == "Y" or inp == "y" or inp == "yes" or inp == "YES":
        return True
    return False


def progress(msg):
    print('')
    callername = inspect.currentframe().f_back.f_globals['__name__']
    print(Fore.GREEN + '[' + callername + '] ' + Fore.RESET +
          Style.BRIGHT + msg + Style.RESET_ALL)

