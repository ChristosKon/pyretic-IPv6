from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
from extratopos import *
import subprocess, shlex, time, signal, os, sys
from threading import Timer
import argparse

################################################################################
#### Test-case-specific functions
################################################################################

# First, common functions which call the test-case-specific functions:
def setup_network(test, params):
    """ A function that returns a 3-tuple (network, hosts, switches), based on
    the test case that's being run.
    """
    if test == "tm":
        return setup_tm_network(params)
    elif test == "waypoint":
        return setup_waypoint_network(params)
    else:
        print "Unknown test case topology!"
        sys.exit(0)

def setup_full_traffic_measurement(test, params, switches):
    if test == "tm":
        return setup_tm_full_traffic_measurement(params, switches)
    elif test == "waypoint":
        return setup_waypoint_full_traffic_measurement(params, switches)
    else:
        print "Unknown test case traffic measurement call!"
        sys.exit(0)

def setup_workload(test, params, hosts):
    if test == "tm":
        return setup_tm_workload(params, hosts)
    elif test == "waypoint":
        return setup_waypoint_workload(params, hosts)
    else:
        print "Unknown test case for workload setup!"
        sys.exit(0)

### Helper functions for getting hosts and switches from a network
def get_hosts(net, num_hosts):
    """ Get a list of host objects from the network object """
    hosts = []
    for i in range(1, num_hosts+1):
        hosts.append(net.getNodeByName('h' + str(i)))
    return hosts

def get_switches(net, num_switches):
    switches = []
    for i in range(1, num_switches+1):
        switches.append(net.getNodeByName('s' + str(i)))
    return switches

def get_default_net_hosts_switches(topo, listen_port, num_hosts, num_switches):
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=listen_port)
    net.start()
    hosts = get_hosts(net, num_hosts)
    switches = get_switches(net, num_switches)
    return (net, hosts, switches)

### Test 1: traffic matrix
def setup_tm_network(params):
    """ Set up a cycle topology of num_hosts. """
    num_hosts = params.num_hosts
    listen_port = params.listen_port
    topo = CycleTopo(num_hosts, num_hosts)
    return get_default_net_hosts_switches(topo, listen_port, num_hosts,
                                          num_hosts)

def setup_tm_workload(params, hosts):
    hosts_src = hosts
    hosts_dst = hosts[1:] + [hosts[0]]
    per_flow_bw = ["8M"] * len(hosts)
    return (hosts_src, hosts_dst, per_flow_bw)

def setup_tm_full_traffic_measurement(params, switches):
    """ Setup tshark collectors and statistics for the 'total' traffic in the
    network.
    """
    adjust_path = get_adjust_path(params)
    total_traffic_prefix = adjust_path(params.total_traffic_prefix)
    test_duration_sec = params.test_duration_sec
    slack = params.slack_factor
    # setup internal and external interfaces
    internal_ints = reduce(lambda r, sw: r + [sw.name + '-eth1',
                                              sw.name + '-eth2'],
                           switches, [])
    external_ints = reduce(lambda r, sw: r + [sw.name + '-eth3'], switches, [])
    return run_tshark_full_traffic_measurement(internal_ints, external_ints,
                                               test_duration_sec,
                                               total_traffic_prefix, slack)

### Test 2. Detecting violations of waypoint constraints
class WaypointTopo(Topo):
    """ A simple topology to check waypoint specifications in the routing."""
    def __init__(self):
        Topo.__init__(self)
        # Switches
        for i in range(1,5):
            self.addSwitch('s' + str(i))
        self.addLink('s1', 's2')
        self.addLink('s2', 's3')
        self.addLink('s3', 's4')
        self.addLink('s4', 's1')
        # Hosts.
        for i in range(1,5):
            self.addHost('h' + str(i))
        self.addLink('h1', 's1')
        self.addLink('h2', 's3')
        self.addLink('h3', 's1')
        self.addLink('h4', 's3')

def setup_waypoint_network(params):
    listen_port = params.listen_port
    topo = WaypointTopo()
    return get_default_net_hosts_switches(topo, listen_port, 4, 4)

def setup_waypoint_workload(params, hosts):
    frac = params.violating_frac
    total_bw = params.total_bw

    hosts_src = [hosts[0], hosts[2]]
    hosts_dst = [hosts[1], hosts[3]]
    per_flow_bw = [str(int(frac*total_bw)), str(int((1-frac)*total_bw))]
    return (hosts_src, hosts_dst, per_flow_bw)

def setup_waypoint_full_traffic_measurement(params,
                                            switches):
    adjust_path = get_adjust_path(params)
    total_traffic_prefix = adjust_path(params.total_traffic_prefix)
    test_duration_sec = params.test_duration_sec
    slack = params.slack_factor
    # setup internal and external interfaces
    internal_ints = reduce(lambda r, sw: r + [sw.name + '-eth1',
                                              sw.name + '-eth2'],
                           switches, [])
    external_ints = reduce(lambda r, sw: r + [sw.name + '-eth3',
                                              sw.name + '-eth4'],
                           [switches[0], switches[2]], [])
    return run_tshark_full_traffic_measurement(internal_ints, external_ints,
                                               test_duration_sec,
                                               total_traffic_prefix, slack)

################################################################################
#### Diagnostics
################################################################################

def ping_flow_pairs(net, hosts_src, hosts_dst):
    """ Test connectivity between flow sources and destinations """
    assert len(hosts_src) == len(hosts_dst)
    for i in range(0, len(hosts_src)):
        result = hosts_src[i].cmd('ping -c1 %s' % (hosts_dst[i].IP()))
        sent, received = net._parsePing(result)
        print ('%d ' % i) if received else 'X '

################################################################################
### Essentials test setup functions on all test cases
################################################################################

def pyretic_controller(test, testwise_params, c_out, c_err, pythonpath):
    c_outfile = open(c_out, 'w')
    c_errfile = open(c_err, 'w')
    # Hackety hack. I don't know of any other way to supply the PYTHONPATH
    # variable for the pyretic controller!
    py_env = os.environ.copy()
    if not "PYTHONPATH" in py_env:
        py_env["PYTHONPATH"] = pythonpath

    cmd = ("pyretic.py -m p0 pyretic.evaluations.eval_path --test=" + test +
           reduce(lambda r, k: r + ("--" + k + "=" + testwise_params[k] + " "),
                  testwise_params.keys(), " "))
    c = subprocess.Popen(shlex.split(cmd), stdout=c_outfile, stderr=c_errfile,
                         env=py_env)
    return ([c], [c_outfile, c_errfile])

def wait_switch_rules_installed(switches):
    """This function waits for switch rule installation to stabilize on all
    switches before running tests.
    """
    print "Waiting for switch rule installation to complete..."
    not_fully_installed = True
    num_rules = {}
    num_iterations = 0
    per_iter_timeout = 3
    while not_fully_installed:
        num_iterations += 1
        not_fully_installed = False
        for s in switches:
            if not s in num_rules:
                num_rules[s] = 0
            rules = s.cmd("dpctl dump-flows tcp:localhost:6634 | grep -v \
                           'stats_reply' | grep -v cookie=0 | wc -l")
            rules = int(rules)
            if not (rules == num_rules[s] and rules > 2): # not converged!
                not_fully_installed = True
                print '.'
            num_rules[s] = rules
        time.sleep(per_iter_timeout)
    print
    time_waited = per_iter_timeout * num_iterations
    print "Rules fully installed after waiting", time_waited, "seconds"

def run_iperf_test(net, hosts_src, hosts_dst, test_duration_sec,
                   per_transfer_bandwidth, client_prefix, server_prefix):
    """Run UDP iperf transfers between hosts_src and hosts_dst pairs for
    test_duration_sec seconds, with a targeted bandwidth of
    per_transfer_bandwidth.
    """
    # start iperf servers
    for dst in hosts_dst:
        dst_server_file = server_prefix + '-' + dst.name + '.txt'
        dst.cmd("iperf -fK -u -s -p 5002 -i 5 2>&1 > " + dst_server_file + " &")
    print "Finished starting up iperf servers..."

    # start iperf client transfers
    for i in range(0, len(hosts_src)):
        src = hosts_src[i]
        src_client_file = client_prefix + '-' + src.name + '.txt'
        src.cmd("iperf -fK -t " + str(test_duration_sec) + " -c " +
                hosts_dst[i].IP() + " -u -p 5002 -i 5 -b " +
                per_transfer_bandwidth[i] + " 2>&1 > " + src_client_file + "&")
    print "Client transfers initiated."

def setup_overhead_statistics(overheads_file, test_duration_sec, slack):
    cmd = ("tshark -q -i lo -z io,stat," + str(slack * test_duration_sec) +
           ",'of.pktin||of.stats_flow_byte_count' -f 'tcp port 6633'")
    f = open(overheads_file, "w")
    p = subprocess.Popen(shlex.split(cmd), stdout=f, stderr=subprocess.STDOUT)
    print "Started tshark process"
    return ([p], [f])

def run_tshark_full_traffic_measurement(internal_ints, external_ints,
                                        test_duration_sec, total_traffic_prefix,
                                        slack):
    """Given a list of "internal" and "external"-facing interfaces in the
    network, set up tshark captures to count the number of total packets on all
    the links in the network (separate traffic counted once and twice for later
    merging). This function is generic across test cases.
    """
    def get_interfaces(intr_list):
        """ Get tshark interface argument for a switch sw, whose interfaces in
        interface_list must be captured. """
        return reduce(lambda r, intr: r + "-i " + intr + " ", intr_list, ' ')

    def get_tshark_cmd_file(interfaces, file_suffix):
        cmd = ("tshark -q " + get_interfaces(interfaces) +
               " -z io,stat," + str(slack * test_duration_sec))
        fname = total_traffic_prefix + file_suffix
        return (cmd, fname)

    def get_fds_processes(cmds, files):
        out_fds = []
        processes = []
        assert len(cmds) == len(files)
        for i in range(0, len(cmds)):
            f = files[i]
            cmd = cmds[i]
            out_fds.append(open(f, 'w'))
            processes.append(subprocess.Popen(shlex.split(cmd),
                                              stdout=out_fds[-1],
                                              stderr=subprocess.STDOUT))
        return processes, out_fds

    (cmd_once,  file_once)  = get_tshark_cmd_file(external_ints,  '-once.txt')
    (cmd_twice, file_twice) = get_tshark_cmd_file(internal_ints, '-twice.txt')
    return get_fds_processes([cmd_once, cmd_twice], [file_once, file_twice])

################################################################################
### The main function.
################################################################################

def query_test():
    """ Main """
    # Configuring the experiment.
    args = parseArgs()

    # Get path adjustment function
    adjust_path = get_adjust_path(args)

    # Global parameters used by specific tests as well
    listen_port = args.listen_port
    test_duration_sec = args.test_duration_sec
    slack_factor = args.slack_factor
    controller_debug_mode = args.controller_debug_mode
    test = args.test

    # Global parameters not used elsewhere outside this function
    overheads_file = adjust_path("tshark_output.txt")
    c_out = adjust_path("pyretic-stdout.txt")
    c_err = adjust_path("pyretic-stderr.txt")
    iperf_client_prefix = adjust_path("client-udp")
    iperf_server_prefix = adjust_path("server-udp")
    params_file = adjust_path("params.txt")

    # Explicit spelling-out of testwise parameters for pyretic controller
    testwise_params = get_testwise_params(test, args)

    # Hack to set pythonpath.
    pypath = "/home/mininet/pyretic:/home/mininet/mininet:/home/mininet/pox"

    # Actual experiment setup.
    mn_cleanup()

    ctlr = None
    if not controller_debug_mode:
        print "Starting pyretic controller"
        ctlr = pyretic_controller(test, testwise_params, c_out, c_err, pypath)

    print "Setting up topology"
    (net, hosts, switches) = setup_network(test, args)

    print "Setting up overhead statistics measurements"
    tshark = setup_overhead_statistics(overheads_file, test_duration_sec,
                                       slack_factor)

    print "Setting up collectors for total traffic"
    switch_stats = setup_full_traffic_measurement(test, args, switches)

    print "Setting up handlers for graceful experiment abort"
    signal.signal(signal.SIGINT, get_abort_handler(controller_debug_mode, ctlr,
                                                   tshark, switch_stats, net))

    print "Setting up workload configuration"
    (hosts_src, hosts_dst, per_flow_bw) = setup_workload(test, args, hosts)

    print "Setting up switch rules"
    if controller_debug_mode:
        print "*** YOU must start the controller separately for this to work!"
    wait_switch_rules_installed(switches)

    # print "Testing network connectivity"
    # ping_flow_pairs(net, hosts_src, hosts_dst)

    print "Starting iperf tests"
    run_iperf_test(net, hosts_src, hosts_dst, test_duration_sec, per_flow_bw,
                   iperf_client_prefix, iperf_server_prefix)

    print ("Running iperf transfer tests. This may take a while (" +
           str(test_duration_sec) + " seconds)...")
    time.sleep(test_duration_sec)
    print "Experiment done!"

    # Wrapping up and cleaning up
    print "Writing down experiment parameters for successful completion"
    write_expt_settings(args, params_file)

    finish_up(controller_debug_mode, ctlr, tshark, switch_stats, net)

    if controller_debug_mode:
        CLI(net)
        net.stop()

################################################################################
### Cleanup-related functions
################################################################################

def mn_cleanup():
    subprocess.call("sudo mn -c", shell=True)

def write_expt_settings(params, params_file):
    f = open(params_file, 'w')
    params_dict = vars(params)
    for k in params_dict.keys():
        f.write(k + " " + str(params_dict[k]))
    f.close()

def finish_up(controller_debug_mode, ctlr, tshark, switch_stats, net):
    def close_fds(fds, fd_str):
        for fd in fds:
            fd.close()
        print "Closed", fd_str, "file descriptors"

    print "--- Cleaning up after experiment ---"
    # controller
    if not controller_debug_mode:
        ([p], fds) = ctlr
        kill_process(p, "controller")
        close_fds(fds, "controller")
    # overhead statistics tshark
    ([p], fds) = tshark
    kill_process(p, "tshark overhead statistics collection")
    close_fds(fds, "overhead statistics")
    # switch statistics
    (procs, fds) = switch_stats
    for p in procs:
        kill_process(p, "tshark switch statistics collection")
    close_fds(fds, "switch statistics")
    # mininet network
    if not controller_debug_mode:
        net.stop()
        print "Killed mininet network"

def get_abort_handler(controller_debug_mode, ctlr, tshark, switch_stats, net):
    def abort_handler(signum, frame):
        finish_up(controller_debug_mode, ctlr, tshark, switch_stats, net)
    return abort_handler

def kill_process(p, process_str):
    print "Signaling", process_str, "for experiment completion"
    p.send_signal(signal.SIGINT)

################################################################################
### Argument parsing
################################################################################

def parseArgs():
    parser = argparse.ArgumentParser(description="Run tests for query evaluations")
    parser.add_argument("--test_duration_sec", type=int,
                        help="Duration for running data transfers",
                        default=30)
    parser.add_argument("-d", "--controller_debug_mode", action="store_true",
                        help="Run controller separately for debugging")
    parser.add_argument("-t", "--test", default="waypoint",
                        choices=['tm', 'waypoint'], help="Test case to run")
    parser.add_argument("-l", "--listen_port", default=6634, type=int,
                        help="Starting port for OVS switches to listen on")
    parser.add_argument("--total_traffic_prefix", default="total-traffic",
                        help="Naming prefix for total traffic measurement")
    parser.add_argument("--slack_factor", default=5.0, type=float,
                        help="Slack multiple of duration for tshark interval")
    parser.add_argument("-r", "--results_folder",
                        default="./pyretic/evaluations/results/",
                        help="Folder to put the raw results data into")

    # Test-case-specific options

    # traffic matrix
    parser.add_argument("-n", "--num_hosts", default=5, type=int,
                        help="Number of hosts")
    parser.add_argument("--query_duration_sec", default=180, type=int,
                        help="Duration after which no stat queries issued")
    parser.add_argument("--query_period_sec", default=10, type=int,
                        help="Polling frequency for switch statistics")

    # waypoint
    parser.add_argument("-v", "--violating_frac", default=0.10, type=float,
                        help="Traffic fraction violating waypoint constraints")
    parser.add_argument("-b", "--total_bw", type=int, default=1800000,
                        help="Total traffic injected into the network per sec")

    args = parser.parse_args()
    return args

def get_testwise_params(test, args):
    params = {}
    if test == "tm":
        params['n'] = str(args.num_hosts)
        params['poll'] = str(args.query_period_sec)
        params['test_duration'] = str(args.query_duration_sec)
    elif test == "waypoint":
        params['violating_frac'] = str(args.violating_frac)
        params['total_bw'] = str(args.total_bw)
    else:
        print "Error! Requesting test-wise-args for unknown test", test
        sys.exit(1)
    return params

def get_adjust_path(args):
    """ Return a function that adjusts the path of all file outputs into the
    results folder provided in the arguments.
    """
    results_folder = args.results_folder
    def adjust_path(rel_path):
        return os.path.join(results_folder, rel_path)
    return adjust_path

################################################################################
### Call to main function
################################################################################
if __name__ == "__main__":
    setLogLevel('info')
    query_test()
