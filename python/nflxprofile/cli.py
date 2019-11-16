import json
import argparse

from nflxprofile.convert.v8_cpuprofile import parse as v8_parse
from nflxprofile.convert.linux_perf import parse as linux_perf_parse


def main():
    parser = argparse.ArgumentParser(prog="nflxprofile", description='Parse common profile/tracing formats into nflxprofile')
    parser.add_argument('--output')
    parser.add_argument('--force', action="store_true")
    parser.add_argument('--extra-options', type=json.loads)
    parser.add_argument('input', nargs="+")

    args = parser.parse_args()

    filenames = args.input
    extra_options = args.extra_options or {}
    out = args.output
    if not out:
        out = 'profile.nflxprofile'

    profile = None
    if len(filenames) >= 1 and filenames[0].endswith(".cpuprofile"):
        profiles = []
        for filename in filenames:
            with open(filename, 'r') as f:
                profiles.append(json.loads(f.read()))
        profile = v8_parse(profiles, **extra_options)
    else:
        filename = filenames[0]
        with open(filename, 'r') as f:
            profile = linux_perf_parse(f.readlines())


    with open(out, 'wb') as f:
        f.write(profile.SerializeToString())
