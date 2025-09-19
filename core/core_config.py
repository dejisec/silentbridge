import configparser


class CoreConfig(object):

    def __init__(self, input_path, output_path):

        self.path = input_path
        self.hostapd_conf_path = output_path

        self.config = configparser.ConfigParser()
        self.config.read(self.path)

    def sections(self):

        return self.config.sections()

    def items(self, section=None):

        if section is not None:

            for item in self.config.items(section):
                yield item
            return

        for sec in self.sections():
            yield from self.items(section=sec)

    def get(self, section, setting):
        return self.config.get(section, setting)

    def update(self, section, setting, value):

        self.config.set(section, setting, value)

        with open(self.path, "w", encoding="utf-8") as fd:
            self.config.write(fd)

    def write(self):

        with open(self.hostapd_conf_path, "w", encoding="utf-8") as fd:
            for key, value in self.items():
                fd.write(f"{key}={value}\n")

    def delete(self, section, setting=None):

        if setting is not None:
            self.config.remove_option(section, setting)
        else:
            for key, _ in self.items(section):
                self.config.remove_option(section, key)

        with open(self.path, "w", encoding="utf-8") as fd:
            self.config.write(fd)


if __name__ == "__main__":
    pass
