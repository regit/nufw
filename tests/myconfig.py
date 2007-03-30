from ConfigParser import RawConfigParser as ParentConfigParser, \
    NoOptionError, ParsingError, DEFAULTSECT

class ConfigParser(ParentConfigParser):
    def __init__(self, defaults=None):
        self._sections = {}
        self._defaults = {}
        if defaults:
            for key, value in defaults.iteritems():
                if isinstance(value, dict):
                    for subkey, value in value.iteritems():
                        key = "%s:%s" % (key, subkey)
                        self._defaults[self.optionxform(key)] = value
                else:
                    self._defaults[self.optionxform(key)] = value

    def get(self, section, option):
        opt = self.optionxform(option)
        if opt in self._sections[section]:
            return self._sections[section][opt].strip()

        if section not in self._sections:
            if section != DEFAULTSECT:
                raise NoSectionError(section)
        try:
            return self._defaults["%s:%s" % (section, opt)]
        except KeyError:
            pass
        try:
            return self._defaults[opt]
        except KeyError:
            raise NoOptionError(option, section)

if __name__ == "__main__":
    import doctest
    doctest.testmod()

