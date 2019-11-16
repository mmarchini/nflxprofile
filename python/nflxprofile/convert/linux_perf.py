import re
import os
import logging
import hashlib
from nflxprofile import nflxprofile_pb2

event_regexp = re.compile(r" +([0-9.]+): .+?:")
frame_regexp = re.compile(r"^[\t ]*[0-9a-fA-F]+ (.+) \((.*?)\)$")


idle_stack = [
    "cpuidle",
    "cpu_idle",
    "cpu_bringup_and_idle",
    "native_safe_halt",
    "xen_hypercall_sched_op",
    "xen_hypercall_vcpu_op",
    "mwait_idle",
]

LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO')

logger = logging.getLogger()
logger.setLevel(getattr(logging, LOGLEVEL))

# inverted cache for nodes
node_id_cache = None


def is_idle_stack(stack, comm):
    if comm != "swapper":
        return False
    for pair in stack:
        for idle_frame in idle_stack:
            if idle_frame in pair.function_name:
                return True
    return False


def find_node_id(stack_hash):
    global node_id_cache
    try:
        return node_id_cache[stack_hash]
    except KeyError: # stack hash not found in cache
        return None


def add_to_node_id_cache(stack_hash, node_id):
    global node_id_cache
    node_id_cache[stack_hash] = node_id


def get_stack_hash(comm, stack):
    stack_hash = hashlib.sha1()
    stack_hash.update(comm.encode('utf-8'))
    for frame in stack:
        stack_hash.update(frame.function_name.encode('utf-8'))
    return stack_hash.hexdigest()


def library2type(library):
    if library == "":
        return ""
    if library.startswith("/tmp/perf-"):
        return "jit"
    if library.startswith("["):
        return "kernel"
    if library.find("vmlinux") > 0:
        return "kernel"
    return "user"


def parse_process_line(line):
    """Parse the process line, return comm, pid and cpu.

    Process line format can be one of the following:

      - "comm pid [cpu] ..."
      - "comm pid/tid [cpu] ..."
    """

    comm = pid = tid = cpu = ""

    splitted_line = line.rsplit(None, 5)

    comm, pid, cpu = splitted_line[:3]
    if "/" in pid:
        pid, tid = pid.split("/")
    else:
        tid = pid

    #  if cpu[0] != "[" or cpu[-1] != "]":
    #      logger.error("Can't parse comm: {}; cpu field has invalid format: {}".format(line, cpu))
    #      return "[unknown]", "0", "0", "0"

    #  cpu = cpu.strip("[]")

    if not (pid.isdigit() or tid.isdigit() or cpu.isdigit):
        logger.error("Can't parse comm: {}; pid: {}; tid: {}; cpu: {}".format(line, pid, tid, cpu))
        return "[unknown]", "0", "0", "0"

    return comm, pid, tid, cpu


def parse(data, **extra_options):
    # initializing inverted cache
    global node_id_cache
    node_id_cache = {}

    # creating the new protobuf profile and initializing with root
    profile = nflxprofile_pb2.Profile()
    profile.nodes[0].function_name = 'root'
    profile.nodes[0].hit_count = 0
    profile.params['has_parent'] = 'false'
    profile.params['has_children'] = 'false'
    profile.params['has_node_stack'] = 'true'
    profile.params['has_node_cpu'] = 'false'
    profile.params['has_node_pid'] = 'true'
    profile.params['has_node_tid'] = 'true'
    profile.params['has_samples_cpu'] = 'true'
    profile.params['has_samples_pid'] = 'true'
    profile.params['has_samples_tid'] = 'true'

    # global count for node ids
    id_count = 1

    # sample timestamp store for delta calculation
    previous_ts = None

    # temporary stack array for current sample
    stack = []

    # comm for previous sample
    comm = None

    # pid for previous sample
    pid = None

    # cpu for previous sample
    cpu = None

    # tid for previous sample
    tid = None

    # ts for the previous sample
    ts = None

    for line in data:
        # utf-8
        if type(line) != str:
            line = line.decode('utf-8')

        # skip comments and empty lines
        if not line or line[0] == '#':
            continue

        # As a performance optimization, skip an event regexp search if the
        # line looks like a stack trace based on starting with '\t'. This
        # makes a big difference.
        r = None

        if (line[0] != '\t'):
            r = event_regexp.search(line)
        if (r):  # TODO: or after last line
            if (stack):
                if not (is_idle_stack(stack, comm)):
                    stack_hash = get_stack_hash(comm, stack)
                    node_id = find_node_id(stack_hash)
                    if node_id:
                        # increment hit count
                        profile.nodes[node_id].hit_count += 1
                    else:
                        node_id = id_count
                        profile.nodes[node_id].function_name = comm
                        profile.nodes[node_id].hit_count = 1
                        #  profile.nodes[node_id].cpu = int(cpu)
                        profile.nodes[node_id].pid = int(pid)
                        profile.nodes[node_id].tid = int(tid)
                        add_to_node_id_cache(stack_hash, node_id) # adding new node to node id cache
                        profile.nodes[node_id].stack.extend(stack)
                        id_count = id_count + 1 # incrementing next id
                    profile.samples.append(node_id)
                    profile.samples_pid.append(int(pid))
                    #  profile.samples_cpu.append(int(cpu))
                    profile.samples_tid.append(int(tid))
                    if ts:
                        if not previous_ts:
                            profile.time_deltas.append(0)
                            profile.start_time = ts
                        else:
                            profile.time_deltas.append(ts - previous_ts)
                        previous_ts = ts
                        profile.end_time = ts
                    else:
                        logger.error("Missing timestamp.")
                        exit(1)
                stack = []
                comm = None
                pid = None
                #  cpu = None
                tid = None
            ts = float(r.group(1))
            comm, pid, tid, cpu = parse_process_line(line)
        else:
            r = frame_regexp.search(line)
            if (r):
                # Split inlined frames. "->" is used by software such as java
                # perf-map-agent. For example, "a->b->c" means c() is inlined in b(),
                # and b() is inlined in a(). This code will identify b() and c() as
                # the "inlined" library type, and a() as whatever the library says
                # it is.
                names = r.group(1).split('->')
                n = 0
                for name in reversed(names):
                    # strip instruction offset (+0xfe200...)
                    c = name.find("+")
                    if (c > 0):
                        name = name[:c]
                    # strip leading "L" from java symbols (only reason we need comm):
                    if (comm and comm == "java" and name.startswith("L")):
                        name = name[1:]
                    libtype = library2type(r.group(2)) if n == 0 else "inlined"
                    stack_frame = nflxprofile_pb2.StackFrame()
                    stack_frame.function_name = name
                    stack_frame.libtype = libtype
                    stack.insert(0, stack_frame)
                    n += 1
    logger.debug("Processed {} ids.".format(str(id_count)))
    return profile

