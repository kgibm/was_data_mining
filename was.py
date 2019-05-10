#!/usr/bin/env python3
# was.py: Process various WAS-related logs
# usage: was.py file1 ... fileN
#
# Expert usage (use at your own risk when understanding caveats of all options):
#   was.py --filter-to-well-known-threads
#
# Author: Kevin Grigorenko (kevin.grigorenko@us.ibm.com)
#
# Notes:
#   * Prerequisites: pip3 install numpy pandas matplotlib pytz xlsxwriter
#   * Run from REPL:
#     >>> exec(open("was.py").read())
#     >>> data = process_files(["file1", "file2", ...])
#
#   Tips:
#     >>> To access data after processing: df = pandas.read_pickle("file.pkl")
#     >>> data.describe() # To print statistics of numeric columns
#     >>> pandas.set_option("display.expand_frame_repr", False) # To print all columns when printing DataFrames
#     >>> pandas.set_option("display.max_rows", 10) # Change print(data) # of rows. Set to None to print everything
#     >>> data.info() # Count number of NaNs

import os
import re
import sys
import enum
import math
import pytz
import numpy
import pandas
import pprint
import shutil
import numbers
import argparse
import datetime
import matplotlib

def file_head(file, options, lines=20):
  result = ""
  with open(file, encoding=options.encoding) as f:
    for line in f:
      result += line + os.linesep
      lines -= 1
      if lines == 0:
        break
  return result

def ensure_data(dict, keys):
  current_dict = dict
  for key in keys:
    data = current_dict.get(key)
    if data is None:
      data = {}
      current_dict[key] = data
    current_dict = data
  return data

def create_multi_index2(dict, cols):
  if len(dict) > 0:
    reform = {(firstKey, secondKey): values for firstKey, secondDict in dict.items() for secondKey, values in secondDict.items()}
    return pandas.DataFrame.from_dict(reform, orient="index").rename_axis(cols).sort_index()
  else:
    return None

def create_multi_index3(dict, cols):
  if len(dict) > 0:
    reform = {(firstKey, secondKey, thirdKey): values for firstKey, secondDict in dict.items() for secondKey, thirdDict in secondDict.items() for thirdKey, values in thirdDict.items()}
    return pandas.DataFrame.from_dict(reform, orient="index").rename_axis(cols).sort_index()
  else:
    return None

def find_files(options, dir=None):
  result = []
  if dir is None:
    dir = os.getcwd()

  # Some files in directory are related and need to be parsed in a particular
  # order, so we sort them if needed

  find_files_process_directory(dir, os.listdir(dir), result, options.recurse)

  return result

def find_files_process_directory(dirpath, pathnames, result, recurse):
  for pathname in sorted(pathnames, key=sortcmp):
    pathname.replace("$", "\\$")
    if "was_data_mining" not in dirpath and "was_data_mining" not in pathname:
      if os.path.isfile(os.path.join(dirpath, pathname)):
        result.append(os.path.join(dirpath, pathname))
      elif recurse:
        find_files_process_directory(os.path.join(dirpath, pathname), os.listdir(os.path.join(dirpath, pathname)), result, recurse)

def sortcmp(pathname):

  if pathname.endswith("/"):
    pathname = pathname[:-1]

  # Performance MustGather
  if pathname == "uname.out" or pathname == "lparstat-i.out":
    return 0
  elif pathname == "screen.out":
    return 1

  # WAS Configuration Visualizer
  if pathname == "Cell":
    return 0
  elif pathname == "Node":
    return 1
  elif pathname == "Cluster":
    return 2
  elif pathname == "Application server":
    return 3

  return 999

def should_skip_file(file, file_extension):
  global file_extension_numbers
  if file_extension is not None:
    match = file_extension_numbers.search(file_extension)
    if match is not None:
      file_extension = match.group(1)
    valid_extensions = [".txt", ".log", ".out", ".xml"]
    if file_extension.lower() not in valid_extensions:
      return True
  return False

bytes = re.compile(r"([\d,\.]+)([bBkKmMgGtTpPeE])")
posix_date_time = re.compile(r"\w+\s+(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+([^ ]+)\s+(\d+)")

def parseBytes(str):
  global bytes
  match = bytes.search(str)
  if match is not None:
    result = float(match.group(1))
    bytes_type = match.group(2).lower()
    if bytes_type == "k":
      result *= 1024
    elif bytes_type == "m":
      result *= 1048576
    elif bytes_type == "g":
      result *= 1073741824
    elif bytes_type == "t":
      result *= 1099511627776
    elif bytes_type == "p":
      result *= 1125899906842624
    elif bytes_type == "e":
      result *= 1.152921504606847e18
    return result
  else:
    raise ValueError("Value {} does not seem to be in a bytes format".format(str))

def should_skip_stack_frame(frame):
  if frame.startswith(("java/", "sun/", "com/ibm/io/", "com/ibm/ejs")):
    return True
  return False

def trim_stack_frame(frame):
  i = frame.find("(")
  if i != -1:
    frame = frame[:i]
  i = frame.rfind("/")
  if i != -1:
    frame = frame[i+1:]
  else:
    frame1 = frame[0:frame.rindex('.')]
    frame1a = frame1[frame1.rindex('.') + 1:] 
    frame2 = frame[frame.rindex('.'):]
    frame = frame1a + frame2
  return frame

def should_filter_thread(name):
  if name.startswith(("WebContainer", "Default Executor", "server.startup", "ORB.thread.pool", "SIB", "WMQ")):
    return False
  return True

FileType = enum.Enum(
  "FileType", [
    "Unknown",
    "IBMJavacore",
    "TraditionalWASSystemOutLog",
    "TraditionalWASSystemErrLog",
    "TraditionalWASTrace",
    "WASFFDCSummary",
    "WASFFDCIncident",
    "ProcessStdout",
    "ProcessStderr",
    "WASLibertyMessages",
    "AccessLog",
    "WASPerformanceMustGatherScreenOut",
    "UnameOut",
    "Vmstat",
    "Mpstat",
    "LparstatDashi",
    "XML",
    "VerboseGC",
  ]
)

def should_skip_inferred_type(file_type, skip, only):
  if skip is not None and len(skip) > 0:
    for s in skip:
      if s == file_type.name:
        return True
  if only is not None and len(only) > 0:
    for s in only:
      if s == file_type.name:
        return False
    return True
  return False

def is_compressed(name):
  if name.endswith("zip"):
    return True
  elif name.endswith("gz"):
    return True
  elif name.endswith("tar"):
    return True
  elif name.endswith("Z"):
    return True
  elif name.endswith("rar"):
    return True
  elif name.endswith("7z"):
    return True
  elif name.endswith("bz2"):
    return True
  elif name.endswith("xz"):
    return True
  return False

def infer_file_type(name, path, filename, file_extension):
  if not is_compressed(name):
    if "javacore" in name:
      return FileType.IBMJavacore
    elif "SystemOut" in name:
      return FileType.TraditionalWASSystemOutLog
    elif "SystemErr" in name:
      return FileType.TraditionalWASSystemErrLog
    elif "trace" in name:
      return FileType.TraditionalWASTrace
    elif "ffdc" in path:
      if "_exception.log" in name:
        return FileType.WASFFDCSummary
      else:
        return FileType.WASFFDCIncident
    elif "native_stdout" in name:
      return FileType.ProcessStdout
    elif "native_stderr" in name:
      return FileType.ProcessStderr
    elif "messages" in name:
      return FileType.WASLibertyMessages
    elif "proxy" in name:
      return FileType.AccessLog
    elif name == "uname.out":
      return FileType.UnameOut
    elif name == "screen.out":
      return FileType.WASPerformanceMustGatherScreenOut
    elif name == "vmstat.out":
      return FileType.Vmstat
    elif name == "mpstat.out":
      return FileType.Mpstat
    elif name == "lparstat-i.out":
      return FileType.LparstatDashi
    elif name.endswith(".xml"):
      return FileType.XML
    elif "gc.log" in name:
      return FileType.VerboseGC
  return FileType.Unknown

timezones_cache = {}

def get_tz(tz_str):
  global timezones_cache

  tz = timezones_cache.get(tz_str)
  if tz is None:
    if tz_str.startswith("GMT+") or tz_str.startswith("GMT-"):
      tz_str = tz_str[3:]
    if tz_str.startswith("-") or tz_str.startswith("+"):
      if len(tz_str) == 3:
        minutes = (int(tz_str[1:3])*60)
      elif len(tz_str) == 5:
        minutes = (int(tz_str[1:3])*60)+(int(tz_str[3:]))
      else:
        minutes = (int(tz_str[1:3])*60)+(int(tz_str[4:]))
      if tz_str[0] == "-":
        minutes *= -1
      tz = pytz.FixedOffset(minutes)
    else:
      # https://stackoverflow.com/questions/10913986/
      # https://stackoverflow.com/questions/17976063/
      # https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
      if "CEST" == tz_str:
        tz = pytz.FixedOffset(120)
      elif "CET" == tz_str:
        tz = pytz.FixedOffset(60)
      elif "JST" == tz_str:
        tz = pytz.timezone("Asia/Tokyo")
      elif "EST" == tz_str or "EDT" == tz_str:
        tz = pytz.timezone("America/New_York")
      elif "CST" == tz_str or "CDT" == tz_str:
        tz = pytz.timezone("America/Chicago")
      elif "MST" == tz_str or "MDT" == tz_str:
        tz = pytz.timezone("America/Denver")
      elif "PST" == tz_str or "PDT" == tz_str:
        tz = pytz.timezone("America/Los_Angeles")
      elif "TRT" == tz_str:
        tz = pytz.timezone("Europe/Istanbul")
      elif "EET" == tz_str or "EEST" == tz_str:
        tz = pytz.timezone("Europe/Istanbul")
      else:
        tz = pytz.timezone(tz_str)
    timezones_cache[tz_str] = tz
  return tz

printed_warnings = {}
all_warnings = []

def print_warning(message, first_only=None, remember=True):
  global printed_warnings, all_warnings
  if first_only is not None:
    if printed_warnings.get(first_only) is not None:
      return False
    printed_warnings[first_only] = True

  print("")
  print("!!!!!!!!!!!")
  print("! WARNING !")
  print("!!!!!!!!!!!")
  print(message)
  print("")
  if remember:
    all_warnings.append(message)
  return True

def print_all_warnings():
  global all_warnings
  for warning in all_warnings:
    print_warning(warning, remember=False)

def month_short_name_to_num_start1(month):
  return datetime.datetime.strptime(month, "%b").month

file_extension_numbers = re.compile(r"^(.*)\.\d+$")

def get_meaningful_file_extension(pathname):
  global file_extension_numbers
  filename, file_extension = os.path.splitext(pathname)
  match = file_extension_numbers.search(file_extension)
  if match is not None:
    keep = file_extension
    filename, file_extension = os.path.splitext(filename)
    file_extension = file_extension + keep
  return (filename, file_extension)

def process_files(args):
  global timezones_cache

  parser = argparse.ArgumentParser()

  parser.add_argument("file", help="path to a file", nargs="*")
  parser.add_argument("--available-only", help="Print available only options", action="store_true", default=False)
  parser.add_argument("--available-skip", help="Print available skip options", action="store_true", default=False)
  parser.add_argument("-c", "--clean-output-directory", help="Clean the output directory before starting", dest="clean_output_directory", action="store_true")
  parser.add_argument("--create-csvs", help="Create CSVs", dest="create_csvs", action="store_true")
  parser.add_argument("--create-excels", help="Create Excels", dest="create_excels", action="store_true")
  parser.add_argument("--create-pickles", help="Create Pickles", dest="create_pickles", action="store_true")
  parser.add_argument("--create-texts", help="Create txt files", dest="create_texts", action="store_true")
  parser.add_argument("--do-not-create-csvs", help="Don't create CSVs", dest="create_csvs", action="store_false")
  parser.add_argument("--do-not-create-excels", help="Don't create Excels", dest="create_excels", action="store_false")
  parser.add_argument("--do-not-create-pickles", help="Don't create Pickles", dest="create_pickles", action="store_false")
  parser.add_argument("--do-not-create-texts", help="Don't create txt files", dest="create_texts", action="store_false")
  parser.add_argument("--do-not-trim-stack-frames", help="Don't trim stack frames", dest="trim_stack_frames", action="store_false")
  parser.add_argument("--do-not-print-full", help="Do not print full data summary", dest="print_full", action="store_false")
  parser.add_argument("--do-not-print-top-messages", help="Do not print top messages", dest="print_top_messages", action="store_false")
  parser.add_argument("--do-not-recurse", help="Do not recurse", dest="recurse", action="store_false")
  parser.add_argument("--do-not-skip-well-known-stack-frames", help="Don't skip well known stack frames", dest="skip_well_known_stack_frames", action="store_false")
  parser.add_argument("--encoding", help="File encoding. For example, --encoding 'ISO-8859-1'", default="utf-8")
  parser.add_argument("--end-date", help="Filter any time-series data before 'YYYY-MM-DD( HH:MM:SS)?'", default=None)
  parser.add_argument("--filter-to-well-known-threads", help="Filter to well known threads", dest="filter_to_well_known_threads", action="store_true")
  parser.add_argument("--important-messages", help="Important messages to search for", default="CWOBJ7852W,DCSV0004W,HMGR0152W,TRAS0017I,TRAS0018I,UTLS0008W,UTLS0009W,WSVR0001I,WSVR0024I,WSVR0605W,WSVR0606W")
  parser.add_argument("--keep-raw-timestamps", help="Keep raw timestamp and raw TZ columns", dest="remove_raw_timestamps", action="store_false")
  parser.add_argument("-o", "--output-directory", help="Output directory", default="was_data_mining")
  parser.add_argument("--only", help="Only process certain types of files", action="append")
  parser.add_argument("--print-full", help="Print full data summary", dest="print_full", action="store_true")
  parser.add_argument("--print-stdout", help="Print tables to stdout", dest="print_stdout", action="store_true")
  parser.add_argument("--recurse", help="Recurse", dest="recurse", action="store_true")
  parser.add_argument("--show-plots", help="Show each plot interactively", dest="show_plots", action="store_true")
  parser.add_argument("--skip", help="Skip certain types of files", action="append")
  parser.add_argument("--start-date", help="Filter any time-series data after 'YYYY-MM-DD( HH:MM:SS)?'", default=None)
  parser.add_argument("-t", "--tz", help="Output timezone (olson format). Example: -t America/New_York")
  parser.add_argument("--time-grouping", help="See https://pandas.pydata.org/pandas-docs/stable/user_guide/timeseries.html#offset-aliases", default="1s")
  parser.add_argument("--top-hitters", help="top X items to process for top hitters plots", type=int, default=10)

  parser.set_defaults(
    clean_output_directory=False,
    create_csvs=False,
    create_excels=True,
    create_pickles=False,
    create_texts=False,
    filter_to_well_known_threads=False,
    print_full=True,
    print_stdout=False,
    print_summaries=False,
    print_top_messages=True,
    recurse=True,
    remove_raw_timestamps=True,
    show_plots=False,
    skip_well_known_stack_frames=True,
    trim_stack_frames=True,
  )

  options = parser.parse_args(args)

  if options.available_skip:
    print("Available --skip options:")
    for name, member in FileType.__members__.items():
      print("--skip {} ".format(name), end="", flush=True)
    print("\n")
    parser.print_help()
    sys.exit(1)

  if options.available_only:
    print("Available --only options:")
    for name, member in FileType.__members__.items():
      print("--only {} ".format(name), end="", flush=True)
    print("\n")
    parser.print_help()
    sys.exit(1)

  # If the user doesn't change the output directory, then it should be safe to clean
  clean = options.clean_output_directory
  if options.output_directory == "was_data_mining":
    clean = True

  if clean and os.path.exists(options.output_directory):
    for entry in os.listdir(options.output_directory):
      entrypath = os.path.join(options.output_directory, entry)
      if os.path.isfile(entrypath):
        os.unlink(entrypath)
      else:
        shutil.rmtree(entrypath)

  if not os.path.exists(options.output_directory):
    os.makedirs(options.output_directory)

  # Suppress scientific notation and trim trailing zeros
  pandas.options.display.float_format = lambda x: "{:.2f}".format(x).rstrip("0").rstrip(".")

  iso8601_date_time = re.compile(r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d")
  iso8601_date_time_short = re.compile(r"\d\d\d\d-\d\d-\d\d")

  parsed_start_date = None
  parsed_end_date = None
  if options.start_date is not None:
    match = iso8601_date_time.search(options.start_date)
    if match is not None:
      parsed_start_date = pandas.to_datetime(match.group(0), format="%Y-%m-%d %H:%M:%S")
    else:
      match = iso8601_date_time_short.search(options.start_date)
      if match is not None:
        parsed_start_date = pandas.to_datetime(match.group(0), format="%Y-%m-%d %H:%M:%S")
  if options.end_date is not None:
    match = iso8601_date_time.search(options.end_date)
    if match is not None:
      parsed_end_date = pandas.to_datetime(match.group(0), format="%Y-%m-%d %H:%M:%S")
    else:
      match = iso8601_date_time_short.search(options.end_date)
      if match is not None:
        parsed_end_date = pandas.to_datetime(match.group(0), format="%Y-%m-%d %H:%M:%S")

  print(parsed_start_date)

  thread_dumps = None
  thread_dumps_data = {}
  thread_dumps_thread_data = {}

  javacore_name = re.compile(r"javacore\.\d+\.\d+\.(\d+)\.(\d+)")
  javacore_time = re.compile(r"1TIDATETIME\s+Date:\s+(\d{4,})/(\d{2,})/(\d{2,}) at (\d{2,}):(\d{2,}):(\d{2,})(:\d+)?")
  javacore_cpus = re.compile(r"3XHNUMCPUS\s+How Many\s+: (\d+)")
  javacore_option = re.compile(r"2CIUSERARG\s+(.*)")
  javacore_vsz = re.compile(r"MEMUSER[\s|+\-]+([^:]+): ([\d,]+) bytes")
  javacore_cpu_all = re.compile(r"1XMTHDCATEGORY.*All JVM attached threads: ([\d.]+) secs")
  javacore_cpu_jvm = re.compile(r"2XMTHDCATEGORY.*System-JVM: ([\d.]+) secs")
  javacore_cpu_gc = re.compile(r"3XMTHDCATEGORY.*GC: ([\d.]+) secs")
  javacore_cpu_jit = re.compile(r"3XMTHDCATEGORY.*JIT: ([\d.]+) secs")
  javacore_cpu_app = re.compile(r"2XMTHDCATEGORY.*Application: ([\d.]+) secs")
  javacore_heap_total = re.compile(r"1STHEAPTOTAL\s+Total memory:\s+(\d+)")
  javacore_heap_used = re.compile(r"1STHEAPINUSE\s+Total memory in use:\s+(\d+)")
  javacore_heap_free = re.compile(r"1STHEAPFREE\s+Total memory free:\s+(\d+)")
  javacore_monitors = re.compile(r"2LKPOOLTOTAL\s+Current total number of monitors: (\d+)")
  javacore_threads = re.compile(r"2XMPOOLTOTAL\s+Current total number of pooled threads: (\d+)")
  javacore_scc_size = re.compile(r"2SCLTEXTCSZ\s+Cache size\s+= (\d+)")
  javacore_scc_free = re.compile(r"2SCLTEXTFRB\s+Free bytes\s+= (\d+)")
  javacore_classloader = re.compile(r"2CLTEXTCLLOAD\s+Loader (.*)")
  javacore_class = re.compile(r"3CLTEXTCLASS\s+(.*)")
  javacore_stack_frame = re.compile(r"4XESTACKTRACE\s+at (.*)")
  javacore_thread_info1 = re.compile(r"3XMTHREADINFO\s+\"([^\"]+)\" J9VMThread:0x[0-9a-fA-F]+, .*thread_t:0x[0-9a-fA-F]+, java/lang/Thread:0x[0-9a-fA-F]+, state:(\w+), prio=\d+")
  javacore_thread_bytes = re.compile(r"3XMHEAPALLOC\s+Heap bytes allocated since last GC cycle=(\d+)")

  twas_log_entries = None
  liberty_messages_entries = None
  access_log_entries = None
  vmstat_entries = None
  host_cpus = None
  was_servers = None
  was_jdbc = None

  twas_was_version = re.compile(r"WebSphere Platform (\S+) .* running with process name [^\\]+\\[^\\]+\\(\S+) and process id (\d+)")

  access_log1 = re.compile(r"(\S+)\s(\S+)\s(\S+)\s\[([^/]+)/([^/]+)/([^:]+):([^:]+):([^:]+):([^:]+) ([\-\+]\d+)\]\s\"([^\"]+) (HTTP/[\d\.]+)\"\s(\S+)\s(\S+)")

  hotspot_thread = re.compile(r"\"([^\"]+)\"( daemon)? prio=(\d+) tid=0x([0-9a-f]+) nid=0x([0-9a-f]+) ([^\[]+)\[0x([0-9a-f]+)\]")

  files = options.file
  if len(files) == 0:
    files = find_files(options)
  else:
    new_files = []
    for pathname in sorted(files, key=sortcmp):
      if os.path.isdir(pathname):
        new_files = new_files + find_files(options, pathname)
      else:
        new_files.append(pathname)
    files = new_files

  last_script_time = None
  last_script_tz = None
  last_script_tz_str = None
  last_hostname = None
  last_vmstat_interval = None
  last_cellname = None

  for file in files:

    filename, file_extension = get_meaningful_file_extension(file)
    if should_skip_file(file, file_extension):
      continue

    file_type = infer_file_type(os.path.basename(file), file, filename, file_extension)
    fileabspath = os.path.abspath(file)

    if should_skip_inferred_type(file_type, options.skip, options.only):
      continue

    print("Processing {} as {}".format(file, file_type))

    if file_type == FileType.IBMJavacore:
      head = file_head(file, options)
      match = javacore_time.search(head)
      if match.group(7) is not None:
        current_time = pandas.to_datetime("{}-{}-{} {}:{}:{}{}".format(match.group(1), match.group(2), match.group(3), match.group(4), match.group(5), match.group(6), match.group(7)), format="%Y-%m-%d %H:%M:%S:%f")
      else:
        current_time = pandas.to_datetime("{}-{}-{} {}:{}:{}".format(match.group(1), match.group(2), match.group(3), match.group(4), match.group(5), match.group(6)), format="%Y-%m-%d %H:%M:%S")
      match = javacore_name.search(file)
      # or 1CIPROCESSID\s+Process ID: \d+ (
      pid = int(match.group(1))
      artifact = int(match.group(2))

      pid_data = ensure_data(thread_dumps_data, [current_time, pid])
      pid_data["File"] = fileabspath

      cpu_all = 0
      cpu_jvm = 0
      heap_size = 0
      current_thread = None
      threads_data = None
      thread_filtered = False
      line_number = 0

      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          lineplus1 = line
          if len(lineplus1) > 0:
            lineplus1 = lineplus1[1:]

          if lineplus1.startswith("MEMUSER"):
            match = javacore_vsz.search(line)
            if match is not None:
              name = match.group(1)
              bytes = int(match.group(2).replace(",", ""))
              if name == "JRE":
                pid_data["JVMVirtualSize"] = bytes
              elif name == "Classes":
                pid_data["NativeClasses"] = bytes
              elif name == "Threads":
                pid_data["NativeThreads"] = bytes
              elif name == "JIT":
                pid_data["NativeJIT"] = bytes
              elif name == "Direct Byte Buffers":
                pid_data["NativeDirectByteBuffers"] = bytes
              elif name == "Unused <32bit allocation regions":
                pid_data["NativeFreePooledUnder4GB"] = bytes
          elif line.startswith("3XHNUMCPUS"):
            match = javacore_cpus.search(line)
            if match is not None:
              pid_data["CPUs"] = int(match.group(1))
          elif line.startswith("1STHEAPTOTAL"):
            match = javacore_heap_total.search(line)
            if match is not None:
              heap_size = int(match.group(1))
              pid_data["JavaHeapSize"] = heap_size
          elif line.startswith("1STHEAPINUSE"):
            match = javacore_heap_used.search(line)
            if match is not None:
              pid_data["JavaHeapUsed"] = int(match.group(1))
              pid_data["JavaHeapUsedPercent"] = int(match.group(1)) / heap_size
          elif line.startswith("1STHEAPFREE"):
            match = javacore_heap_free.search(line)
            if match is not None:
              pid_data["JavaHeapFree"] = int(match.group(1))
          elif line.startswith("2CIUSERARG"):
            match = javacore_option.search(line)
            if match is not None:
              option = match.group(1)
              if option.startswith("-Xmx"):
                pid_data["MaxJavaHeap"] = parseBytes(option)
              elif option.startswith("-Xmn"):
                pid_data["MaxNursery"] = parseBytes(option)
              elif option.startswith("-Xms"):
                pid_data["MinJavaHeap"] = parseBytes(option)
          elif line.startswith("2LKPOOLTOTAL"):
            match = javacore_monitors.search(line)
            if match is not None:
              pid_data["Monitors"] = int(match.group(1))
          elif line.startswith("2XMPOOLTOTAL"):
            match = javacore_threads.search(line)
            if match is not None:
              pid_data["Threads"] = int(match.group(1))
          elif line.startswith("1XMTHDCATEGORY") or line.startswith("2XMTHDCATEGORY") or line.startswith("3XMTHDCATEGORY"):
            # https://www.ibm.com/support/knowledgecenter/SSYKE2_8.0.0/com.ibm.java.api.80.doc/com.ibm.lang.management/com/ibm/lang/management/JvmCpuMonitorInfo.html
            match = javacore_cpu_all.search(line)
            if match is not None:
              cpu_all = float(match.group(1))
            match = javacore_cpu_jvm.search(line)
            if match is not None:
              cpu_jvm = float(match.group(1))
              pid_data["CPUProportionApp"] = (cpu_all - cpu_jvm) / cpu_all
              pid_data["CPUProportionJVM"] = cpu_jvm / cpu_all
            match = javacore_cpu_gc.search(line)
            if match is not None:
              cpu_gc = float(match.group(1))
              pid_data["CPUProportionGC"] = cpu_gc / cpu_all
            match = javacore_cpu_jit.search(line)
            if match is not None:
              cpu_jit = float(match.group(1))
              pid_data["CPUProportionJIT"] = cpu_jit / cpu_all
          elif line.startswith("3XMTHREADINFO "):
            match = javacore_thread_info1.search(line)
            if match is not None:
              current_thread = match.group(1)
              thread_filtered = False
              if options.filter_to_well_known_threads:
                thread_filtered = should_filter_thread(current_thread)
              if not thread_filtered:
                threads_data = ensure_data(thread_dumps_thread_data, [current_time, pid, current_thread])
                threads_data["State"] = match.group(2)
          elif line.startswith("3XMHEAPALLOC") and not thread_filtered:
            match = javacore_thread_bytes.search(line)
            if match is not None:
              threads_data["JavaHeapSinceLastGC"] = int(match.group(1))
          elif line.startswith("4XESTACKTRACE") and not thread_filtered:
            match = javacore_stack_frame.search(line)
            if match is not None:
              frame = match.group(1)
              if threads_data.get("TopStackFrame") is None and options.skip_well_known_stack_frames and not should_skip_stack_frame(frame):
                if options.trim_stack_frames:
                  frame = trim_stack_frame(frame)
                threads_data["TopStackFrame"] = frame
          elif line.startswith("2SCLTEXTCSZ"):
            match = javacore_scc_size.search(line)
            if match is not None:
              pid_data["SharedClassCacheSize"] = int(match.group(1))
          elif line.startswith("2SCLTEXTFRB"):
            match = javacore_scc_free.search(line)
            if match is not None:
              pid_data["SharedClassCacheFree"] = int(match.group(1))
          elif line.startswith("2CLTEXTCLLOAD"):
            pid_data["Classloaders"] = pid_data.get("Classloaders", 0) + 1
          elif line.startswith("3CLTEXTCLASS"):
            pid_data["Classes"] = pid_data.get("Classes", 0) + 1
    elif file_type == FileType.TraditionalWASSystemOutLog or file_type == FileType.ProcessStdout or file_type == FileType.TraditionalWASTrace:
      process = "UnknownProcess"
      pid = -1
      version = "Unknown"

      rows = []
      line_number = 0
      durations = {}
      previous_line = None

      hotspot_threaddump_time = None
      hotspot_thread_name = None
      hotspot_thread_daemon = None
      hotspot_thread_priority = None
      hotspot_thread_tid = None
      hotspot_thread_nid = None
      hotspot_thread_state = None
      hotspot_thread_extra = None

      pid_data = {}
      threads_data = {}

      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          if line.startswith("["):
            process_logline(line, rows, process, pid, fileabspath, line_number, file_type, durations, parsed_start_date, parsed_end_date)
          elif line.startswith("WebSphere Platform"):
            match = twas_was_version.search(line)
            if match is not None:
              version = match.group(1)
              process = match.group(2)
              pid = int(match.group(3))
              if version != "Unknown":
                process = "{} ({})".format(process, version)
          elif line.startswith("Full thread dump"):
            match = iso8601_date_time.search(previous_line)
            if match is not None:
              hotspot_threaddump_time = pandas.to_datetime(match.group(0), format="%Y-%m-%d %H:%M:%S")
              pid_data = ensure_data(thread_dumps_data, [hotspot_threaddump_time, pid])
              pid_data["File"] = fileabspath
          elif hotspot_threaddump_time is not None:
            if line.startswith("\""):
              match = hotspot_thread.search(line)
              if match is not None:
                hotspot_thread_name = match.group(1)
                hotspot_thread_daemon = match.group(2) is not None
                hotspot_thread_priority = int(match.group(3))
                hotspot_thread_tid = int(match.group(4), 16)
                hotspot_thread_nid = int(match.group(5), 16)
                hotspot_thread_state = match.group(6).strip()
                threads_data = ensure_data(thread_dumps_thread_data, [hotspot_threaddump_time, pid, hotspot_thread_name])
                threads_data["State"] = hotspot_thread_state
            elif line.startswith("   java.lang.Thread.State: "):
              threads_data["State2"] = line[27:].strip()
            elif line.startswith("	at "):
              hotspot_method = line[4:]
              if threads_data.get("TopStackFrame") is None and options.skip_well_known_stack_frames and not should_skip_stack_frame(hotspot_method):
                if options.trim_stack_frames:
                  hotspot_method = trim_stack_frame(hotspot_method)
                threads_data["TopStackFrame"] = hotspot_method
            elif line.startswith("	- locked "):
              hotspot_locked = line[10:]

          previous_line = line

      twas_log_entries = process_logline_rows(rows, twas_log_entries)

    elif file_type == FileType.WASLibertyMessages:
      process = "UnknownProcess"
      pid = -1
      version = "Unknown"

      rows = []
      line_number = 0
      durations = {}

      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          if line.startswith("["):
            process_logline(line, rows, process, pid, fileabspath, line_number, file_type, durations, parsed_start_date, parsed_end_date)
          elif line.startswith("product = "):
            version = line[10:]
          elif line.startswith("process = "):
            process = pid = line[10:]
            if "@" in pid:
              pid = pid[0:pid.find("@")]
            if version != "Unknown":
              process = "{} ({})".format(process, version)

      liberty_messages_entries = process_logline_rows(rows, liberty_messages_entries)

    elif file_type == FileType.AccessLog:
      process = "UnknownProcess"

      rows = []
      line_number = 0

      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          match = access_log1.search(line)
          if match is not None:

            # HttpProxyLogImpl
            tz = get_tz(match.group(10))
            t_datetime = datetime.datetime(int(match.group(6)), month_short_name_to_num_start1(match.group(5)), int(match.group(4)), int(match.group(7)), int(match.group(8)), int(match.group(9)))
            t = pandas.to_datetime(t_datetime)

            first_line = match.group(11)
            method = first_line[0:first_line.index(" ")]
            uri = first_line[first_line.index(" ")+1:]

            response_code = int(match.group(13))
            response_bytes = int(match.group(14))
            rows.append([process, t, match.group(10), tz, method, uri, response_code, response_bytes, fileabspath, line_number, str(file_type)])
    
      if len(rows) > 0:
        df = pandas.DataFrame(rows, columns=["Process", "RawTimestamp", "RawTZ", "TZ", "Method", "URI", "ResponseCode", "ResponseBytes", "File", "Line Number", "FileType"])
        df.set_index(["Process"], inplace=True)
        if access_log_entries is None:
          access_log_entries = df
        else:
          access_log_entries = pandas.concat([access_log_entries, df], sort=False)
          
    elif file_type == FileType.UnameOut:
      line_number = 0
      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          if line_number == 1:
            if line.startswith("SunOS"):
              last_hostname = line[line.index(" ")+1:]
              last_hostname = last_hostname[0:last_hostname.index(" ")]

    elif file_type == FileType.LparstatDashi:
      line_number = 0
      lparstati_name = re.compile(r"Node Name\s+: (\w+)")
      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          match = lparstati_name.search(line)
          if match is not None:
            last_hostname = match.group(1)

    elif file_type == FileType.WASPerformanceMustGatherScreenOut:
      line_number = 0
      looking_for_date = True
      vmstat_interval_re = re.compile(r"VMSTAT_INTERVAL = (\d+)")
      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          if looking_for_date:
            if len(line.strip()) > 0:
              (last_script_time, last_script_tz_str, last_script_tz) = parse_unix_date_time(line, file)
              looking_for_date = False
          else:
            match = vmstat_interval_re.search(line)
            if match is not None:
              last_vmstat_interval = int(match.group(1))

    elif file_type == FileType.Vmstat:
      line_number = 0
      rows = []

      first_stats = True
      last_time = None
      last_tz_str = None
      last_tz = None

      # kthr      memory            page            disk          faults      cpu
      # r b w   swap  free  re  mf pi po fr de sr vc vc -- --   in   sy   cs us sy id
      # 0 0 0 85614096 31518776 3880 23598 821 359 357 0 0 19 118 0 0 43714 154790 58251 8 3 89
      vmstat_solaris_re = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")

      # kthr    memory              page              faults              cpu          
      # ----- ----------- ------------------------ ------------ -----------------------
      # r  b   avm   fre  re  pi  po  fr   sr  cy  in   sy  cs us sy id wa    pc    ec
      # 16  1 9401598 6555123   0   0   0   0    0   0 216 270940 16504 36 12 52  0  2.42  80.8
      vmstat_aix_re = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d\.]+)\s+([\d\.]+)\s*$")

      interval = pandas.Timedelta(seconds=last_vmstat_interval)

      looking_for_date = True

      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          if looking_for_date:
            if len(line.strip()) > 0:
              match = posix_date_time.search(line)
              if match is not None:
                (last_time, last_tz_str, last_tz) = parse_unix_date_time(line, file)
              else:
                print_warning(f"vmstat.out unknown date format '{line.strip()}' in {file}")
              looking_for_date = False
          else:
            match = vmstat_solaris_re.search(line)
            if match is not None:
              # Skip first line on Solaris: https://publib.boulder.ibm.com/httpserv/cookbook/Operating_Systems-Solaris.html#Operating_Systems-Solaris-Central_Processing_Unit_CPU-vmstat
              if first_stats:
                first_stats = False
              else:
                last_time = last_time + interval
                total_cpu = 100 - int(match.group(22))
                rows.append([last_hostname, last_time, last_tz_str, last_tz, total_cpu, fileabspath, line_number, str(file_type)])

            match = vmstat_aix_re.search(line)
            if match is not None:
              last_time = last_time + interval
              total_cpu = 100 - int(match.group(16))
              rows.append([last_hostname, last_time, last_tz_str, last_tz, total_cpu, fileabspath, line_number, str(file_type)])

      if len(rows) > 0:
        df = pandas.DataFrame(rows, columns=["Host", "RawTimestamp", "RawTZ", "TZ", "CPU%", "File", "Line Number", "FileType"])
        df.set_index(["Host"], inplace=True)
        if vmstat_entries is None:
          vmstat_entries = df
        else:
          vmstat_entries = pandas.concat([vmstat_entries, df], sort=False)

    elif file_type == FileType.Mpstat:
      line_number = 0
      rows = []
      numcpus = 0
      state = 0

      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          if state == 0:
            if line.startswith("CPU"):
              state = 1
          elif state == 1:
            if line.startswith("CPU"):
              state = 2
            else:
              numcpus = numcpus + 1

      rows.append([last_hostname, last_script_time, last_script_tz_str, last_script_tz, numcpus, fileabspath, 1, str(file_type)])

      if len(rows) > 0:
        df = pandas.DataFrame(rows, columns=["Host", "RawTimestamp", "RawTZ", "TZ", "CPUs", "File", "Line Number", "FileType"])
        df.set_index(["Host"], inplace=True)
        if host_cpus is None:
          host_cpus = df
        else:
          host_cpus = pandas.concat([host_cpus, df], sort=False)

    elif file_type == FileType.XML:
      line_number = 0
      state = 0
      serverrow = None
      jdbcrows = []

      jvmlogs = re.compile(r"maxNumberOfBackupFiles=\"(\d+)\".*rolloverSize=\"(\d+)\"")
      cellname = re.compile(r"<Name>([^<]+)")
      nodenamere = re.compile(r"<Node>([^<]+)")
      clusternamere = re.compile(r"<ClusterName>([^<]+)")
      genericjvmargs = re.compile(r"genericJvmArguments=\"(.*)\"\s+hprofArguments.*initialHeapSize=\"(\d+)\"\s+maximumHeapSize=\"(\d+)\".*verboseModeGarbageCollection=\"([^\"]+)\"")
      genericjvmargs2 = re.compile(r"genericJvmArguments=\"(.*)\"\s+hprofArguments.*verboseModeGarbageCollection=\"([^\"]+)\"")
      xmsre = re.compile(r"-Xms(\d+\w)")
      xmxre = re.compile(r"-Xmx(\d+\w)")
      xmnre = re.compile(r"-Xmn(\d+\w)")
      gcpolicyre = re.compile(r"-Xgcpolicy:(\w+)")
      threadpoolsre = re.compile(r"<ThreadPool.*name=\"([^\"]+)\".*maximumSize=\"(\d+)\"\s+minimumSize=\"(\d+)\"")
      sessionsre = re.compile(r"<SessionManager.*enable=\"([^\"]+)\".*sessionPersistenceMode=\"([^\"]+)\"")
      sessionsre2 = re.compile(r"<TuningParams allowOverflow=\"([^\"]+)\"\s+invalidationTimeout=\"(\d+)\"\s+maxInMemorySessionCount=\"(\d+)\"\s+scheduleInvalidation=\"([^\"]+)\"\s+usingMultiRowSchema=\"([^\"]+)\"\s+writeContents=\"([^\"]+)\"\s+writeFrequency=\"([^\"]+)\"\s+writeInterval=\"(\d+)\"")
      datasourcere = re.compile(r"<JNDI_DataSources jndiName=\"([^\"]+)\"\s+jndiScope=\"([^\"]+)\"")
      connpoolre = re.compile(r"<ConnectionPools.*maxConnections=\"(\d+)\"\s+minConnections=\"(\d+)\"")

      nodename = None
      clustername = None
      servername = None
      sysout_maxmb = None
      syserr_maxmb = None
      trace_maxmb = None
      xms = None
      xmx = None
      xmn = None
      verbosegc = None
      gcpolicy = None
      disableexplicitgc = False
      jvmargs = None
      xmnpercent = None
      tp_min_wc = None
      tp_max_wc = None
      tp_min_def = None
      tp_max_def = None
      tp_min_orb = None
      tp_max_orb = None
      tp_min_sib = None
      tp_max_sib = None
      tp_min_mq = None
      tp_max_mq = None
      tp_min_ml = None
      tp_max_ml = None
      sessions_enabled = None
      sessions_mode = None
      sessions_count = None
      sessions_overflow = None
      jndiscope = None
      datasource = None

      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1

          # WAS Config Visualizer -z zip output
          if line_number == 2:
            if line.startswith("<ApplicationServer>"):
              state = 1
              servername = os.path.basename(filename)
              if servername.startswith("nodeagent."):
                servername = servername[:9]
            elif line.startswith("<Cell>"):
              state = 2
            elif line.startswith("<Database>"):
              state = 3

          if state == 1:
            if line.startswith("  <Node>"):
              match = nodenamere.search(line)
              if match is not None:
                nodename = match.group(1)
            elif line.startswith("  <ClusterName>"):
              match = clusternamere.search(line)
              if match is not None:
                clustername = match.group(1)
            elif line.startswith("  <JVMLogs"):
              if "rolloverType=\"SIZE\"" in line:
                match = jvmlogs.search(line)
                if match is not None:
                  maxNumberOfBackupFiles = int(match.group(1))
                  rolloverSize = int(match.group(2))
                  if "name=\"Output\"" in line:
                    sysout_maxmb = maxNumberOfBackupFiles * rolloverSize
                  else:
                    syserr_maxmb = maxNumberOfBackupFiles * rolloverSize
            elif line.startswith("  <Trace"):
              if "traceOutputType=\"SPECIFIED_FILE\"" in line:
                match = jvmlogs.search(line)
                if match is not None:
                  maxNumberOfBackupFiles = int(match.group(1))
                  rolloverSize = int(match.group(2))
                  trace_maxmb = maxNumberOfBackupFiles * rolloverSize
            elif line.startswith("    <JavaVirtualMachine"):
              match = genericjvmargs.search(line)
              if match is not None:
                jvmargs = match.group(1).strip()
                xms = int(match.group(2))
                xmx = int(match.group(3))
                verbosegc = (match.group(4) == "true")
              else:
                match = genericjvmargs2.search(line)
                if match is not None:
                  jvmargs = match.group(1).strip()
                  verbosegc = (match.group(2) == "true")

              if jvmargs is not None:
                if "-verbosegc" in jvmargs or "-verbose:gc" in jvmargs or "-Xverbosegclog" in jvmargs or "-Xloggc" in jvmargs:
                  verbosegc = True
                
                match = xmsre.search(jvmargs)
                if match is not None:
                  xms = parseBytes(match.group(1)) / 1048576

                match = xmxre.search(jvmargs)
                if match is not None:
                  xmx = parseBytes(match.group(1)) / 1048576

                match = xmnre.search(jvmargs)
                if match is not None:
                  xmn = parseBytes(match.group(1)) / 1048576

                match = gcpolicyre.search(jvmargs)
                if match is not None:
                  gcpolicy = match.group(1)

                if "-XX:+UseConcMarkSweepGC" in jvmargs:
                  gcpolicy = "CMS"

                if "-XX:+UseParallelOldGC" in jvmargs:
                  gcpolicy = "ParallelOld"

                if "-XX:+UseG1GC" in jvmargs:
                  gcpolicy = "G1"

                if "-Xdisableexplicitgc" in jvmargs or "-XX:+DisableExplicitGC" in jvmargs:
                  disableexplicitgc = True

                if xmn is not None and xmx is not None:
                  xmnpercent = (xmn / xmx) * 100
            elif "<ThreadPool" in line:
              match = threadpoolsre.search(line)
              if match is not None:
                threadpoolname = match.group(1)
                threadpoolmin = int(match.group(3))
                threadpoolmax = int(match.group(2))
                if threadpoolname == "WebContainer":
                  tp_min_wc = threadpoolmin
                  tp_max_wc = threadpoolmax
                elif threadpoolname == "Default":
                  tp_min_def = threadpoolmin
                  tp_max_def = threadpoolmax
                elif threadpoolname == "ORB.thread.pool":
                  tp_min_orb = threadpoolmin
                  tp_max_orb = threadpoolmax
                elif threadpoolname == "SIBJMSRAThreadPool":
                  tp_min_sib = threadpoolmin
                  tp_max_sib = threadpoolmax
                elif threadpoolname == "WMQJCAResourceAdapter":
                  tp_min_mq = threadpoolmin
                  tp_max_mq = threadpoolmax
                elif threadpoolname == "Message.Listener.Pool":
                  tp_min_ml = threadpoolmin
                  tp_max_ml = threadpoolmax
            elif line.startswith("    <SessionManager"):
              match = sessionsre.search(line)
              if match is not None:
                sessions_enabled = (match.group(1) == "true")
                sessions_mode = match.group(2)
            elif line.startswith("      <TuningParams"):
              match = sessionsre2.search(line)
              if match is not None:
                sessions_overflow = (match.group(1) == "true")
                sessions_count = int(match.group(3))
          elif state == 2:
            if line.startswith("  <Name>"):
              match = cellname.search(line)
              if match is not None:
                last_cellname = match.group(1)
          elif state == 3:
            if line.startswith("  <JNDI_DataSources"):
              match = datasourcere.search(line)
              if match is not None:
                datasource = match.group(1)
                jndiscope = match.group(2)
            elif line.startswith("    <ConnectionPools"):
              match = connpoolre.search(line)
              if match is not None:
                connpoolmax = int(match.group(1))
                connpoolmin = int(match.group(2))
                jdbcrows.append([jndiscope, datasource, connpoolmin, connpoolmax, fileabspath, line_number, str(file_type)])

      if servername is not None:
        serverrow = [servername, nodename, last_cellname, f"{last_cellname}/{nodename}/{servername}", clustername, sysout_maxmb, syserr_maxmb, trace_maxmb, xms, xms, xmn, xmnpercent, verbosegc, gcpolicy, disableexplicitgc, tp_min_wc, tp_max_wc, tp_min_orb, tp_max_orb, tp_min_def, tp_max_def, tp_min_sib, tp_max_sib, tp_min_mq, tp_max_mq, tp_min_ml, tp_max_ml, sessions_enabled, sessions_mode, sessions_count, sessions_overflow, jvmargs, fileabspath, 1, str(file_type)]

      if serverrow is not None:
        df = pandas.DataFrame([serverrow], columns=["Server", "Node", "Cell", "QualifiedServer", "Cluster", "SystemOutMaxMB", "SystemErrMaxMB", "TraceMaxMB", "XmsMB", "XmxMB", "XmnMB", "XmnPercentOfXmx", "Verbosegc", "GCPolicy", "DisableExplicitGC", "ThreadPoolMinWebContainer", "ThreadPoolMaxWebContainer", "ThreadPoolMinEJB", "ThreadPoolMaxEJB", "ThreadPoolMinDefault", "ThreadPoolMaxDefault", "ThreadPoolMinSIB", "ThreadPoolMaxSIB", "ThreadPoolMinMQ", "ThreadPoolMaxMQ", "ThreadPoolMinMessageListener", "ThreadPoolMaxMessageListener", "SessionsEnabled", "SessionsMode", "SessionsCount", "SessionsOverflow", "JVMArgs", "File", "Line Number", "FileType"])
        df.set_index(["QualifiedServer"], inplace=True)
        if was_servers is None:
          was_servers = df
        else:
          was_servers = pandas.concat([was_servers, df], sort=False)

      if len(jdbcrows) > 0:
        df = pandas.DataFrame(jdbcrows, columns=["Scope", "Name", "ConnectionPoolMin", "ConnectionPoolMax", "File", "Line Number", "FileType"])
        df.set_index(["Scope"], inplace=True)
        if was_jdbc is None:
          was_jdbc = df
        else:
          was_jdbc = pandas.concat([was_jdbc, df], sort=False)
    elif file_type == FileType.VerboseGC:
      line_number = 0
      rows = []

      hotspot_verbosegc_re = re.compile(r"^(\d\d\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)\.(\d\d\d)([-+]\d\d\d\d): (.*)")

      with open(file, encoding=options.encoding) as f:
        for line in f:
          line_number += 1
          if line.startswith("2") and ": " in line:
            match = hotspot_verbosegc_re.search(line)
            if match is not None:
              tz_str = match.group(8)
              tz = get_tz(tz_str)
              t_datetime = datetime.datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4)), int(match.group(5)), int(match.group(6)), int(match.group(7)))
              pandas_datetime = pandas.to_datetime(t_datetime)
              #print(pandas_datetime)

  print("Post-processing...")

  # Get number of unique timezones found
  unique_tzs = {}
  for k, v in timezones_cache.items():
    unique_tzs[v] = None

  output_tz = pytz.utc
  if options.tz is not None:
    output_tz = pytz.timezone(options.tz)
  elif len(unique_tzs) == 1:
    output_tz = list(timezones_cache.values())[0]
  elif len(unique_tzs) > 1:
    print_warning(f"Multiple time zones {len(unique_tzs)} were found in the data, so all times will be converted to UTC. Use --tz TZ to convert to another. Use --keep-raw-timestamps to keep columns with the raw timestamps. Timezones found: {list(timezones_cache.values())}")

  twas_log_entries = complete_loglines(twas_log_entries, output_tz, options)
  liberty_messages_entries = complete_loglines(liberty_messages_entries, output_tz, options)
  access_log_entries = complete_loglines(access_log_entries, output_tz, options)
  vmstat_entries = complete_loglines(vmstat_entries, output_tz, options)
  host_cpus = complete_loglines(host_cpus, output_tz, options)

  if was_servers is not None:
    was_servers.sort_index(inplace=True)

  if was_jdbc is not None:
    was_jdbc.sort_index(inplace=True)

  print("Finished creating timestamps and sorting")

  print_all_warnings()

  return {
    "Options": options,
    "OutputTZ": output_tz,
    "ThreadDumpInfo": create_multi_index2(thread_dumps_data, ["Time", "PID"]),
    "Threads": create_multi_index3(thread_dumps_thread_data, ["Time", "PID", "Thread"]),
    "TraditionalWASLogEntries": filter_timestamps(twas_log_entries, options, output_tz),
    "WASLibertyMessagesEntries": filter_timestamps(liberty_messages_entries, options, output_tz),
    "AccessLogEntries": filter_timestamps(access_log_entries, options, output_tz),
    "VmstatEntries": filter_timestamps(vmstat_entries, options, output_tz),
    "HostCPUs": filter_timestamps(host_cpus, options, output_tz),
    "WASServers": was_servers,
    "WASJDBC": was_jdbc,
  }

log_line = re.compile(r"\[(\d+)/(\d+)/(\d+) (\d+):(\d+):(\d+):(\d+) ([^\]]+)\] (\S+) (\S+)\s+(\S)\s+(.*)")
log_line_message_code = re.compile(r"^([A-Z][A-Z0-9]+[IAEOW]): (.*)")
log_line_message_code2 = re.compile(r"(.*) ([A-Z][A-Z][A-Z][A-Z0-9]+[IAEOW]): (.*)")
log_line_message_code3 = re.compile(r"^([A-Z][A-Z][A-Z][A-Z0-9]+[IAEOW]) (.*)")

def parse_unix_date_time(line, file):
  global posix_date_time

  line = line.strip()
  match = posix_date_time.search(line)
  if match is not None:
    month = match.group(1)
    day = int(match.group(2))
    hour = int(match.group(3))
    minute = int(match.group(4))
    second = int(match.group(5))
    year = int(match.group(7))
    tz_str = match.group(6)
    tz = get_tz(tz_str)
    t_datetime = datetime.datetime(year, month_short_name_to_num_start1(month), day, hour, minute, second)
    pandas_datetime = pandas.to_datetime(t_datetime)
    return (pandas_datetime, tz_str, tz)
  else:
    print_warning(f"Unknown date format '{line}' in {file}")
    raise ValueError(f"Unknown date format '{line}' in {file}")

def process_logline(line, rows, process, pid, fileabspath, line_number, file_type, durations, parsed_start_date, parsed_end_date):
  global log_line, log_line_message_code, log_line_message_code2, log_line_message_code3

  match = log_line.search(line)
  if match is not None:

    tz_str = match.group(8)
    tz = get_tz(tz_str)

    year_first = False
    if tz.zone == "Asia/Tokyo":
      year_first = True

    year = int(match.group(1 if year_first else 3))
    if year < 70:
      year += 2000
    elif year < 100:
      year += 1900

    microseconds = 0
    if len(match.group(7)) == 3:
      microseconds = int(match.group(7)) * 1000
    elif len(match.group(7)) == 6:
      microseconds = int(match.group(7))
    elif len(match.group(7)) == 9:
      microseconds = int(match.group(7)) / 1000
    else:
      raise ValueError("Cannot infer microseconds from {}".format(match.group(7)))

    t_datetime = datetime.datetime(year, int(match.group(2 if year_first else 1)), int(match.group(3 if year_first else 2)), int(match.group(4)), int(match.group(5)), int(match.group(6)), microseconds)

    t = pandas.to_datetime(t_datetime)

    if parsed_start_date is not None and t < parsed_start_date:
      return

    message = match.group(12)
    message_code = None

    if len(message) > 5:
      firstchar = ord(message[0])
      secondchar = ord(message[0])
      msgmatch = log_line_message_code.search(message)
      if msgmatch is not None:
        message_code = msgmatch.group(1)
      if message_code is None:
        msgmatch = log_line_message_code2.search(message)
        if msgmatch is not None:
          message_code = msgmatch.group(2)
      if message_code is None:
        if message.startswith("CWWIM"):
          msgmatch = log_line_message_code3.search(message)
          if msgmatch is not None:
            message_code = msgmatch.group(1)

    duration = pandas.NaT
    thread = int(match.group(9), 16)
    component = match.group(10)
    level = match.group(11)

    if message_code is not None and (message_code[-1] == 'E' or message_code[-1] == 'W'):
      level = message_code[-1]

    if isInterestingExecutionStart(component, level, message):
      durations[thread] = t
    elif isInterestingExecutionEnd(component, level, message):
      previous = durations.get(thread)
      if previous is not None:
        duration = t - previous

    rows.append([process, pid, t, tz_str, tz, thread, component, level, message_code, message, duration, fileabspath, line_number, str(file_type)])

def isInterestingExecutionStart(component, level, message):
  # *=info:com.ibm.ws.rsadapter.jdbc.WSJdbcPreparedStatement=all
  # https://www-01.ibm.com/support/docview.wss?uid=swg21496047
  return component == "WSJdbcPrepare" and level == ">" and message == "executeQuery Entry"

def isInterestingExecutionEnd(component, level, message):
  return component == "WSJdbcPrepare" and level == "<" and message == "executeQuery Exit"

def process_logline_rows(rows, combined):
  if len(rows) > 0:
    df = pandas.DataFrame(rows, columns=["Process", "PID", "RawTimestamp", "RawTZ", "TZ", "Thread", "Component", "Level", "MessageCode", "MessageFirstLine", "Duration", "File", "Line Number", "FileType"])
    df.set_index(["Process", "PID"], inplace=True)
    if combined is None:
      combined = df
    else:
      combined = pandas.concat([combined, df], sort=False)
  return combined

def get_timestamp_column(output_tz):
  if isinstance(output_tz, pytz._FixedOffset):
    mins = output_tz._minutes
    hours = mins / 60.0
    inthours = int(hours)
    remaining = int((hours - inthours) * 60)
    header = "{:02d}{:02d}".format(abs(inthours), remaining)
    if mins < 0:
      header = "-" + header
  else:
    header = output_tz.zone
    if "/" in header:
      header = header[header.index("/")+1:]
  return "Timestamp ({})".format(header)

# Add a column which is a timezone-aware timestamp
# Remove the TZ column
# Remove the RawTimestamp and RawTZ columns
# Sort byt the timezone-aware timestamp
def complete_loglines(loglines, output_tz, options):
  if loglines is not None:
    loglines[get_timestamp_column(output_tz)] = loglines.apply(lambda row: pandas.to_datetime(row["TZ"].localize(row["RawTimestamp"]).astimezone(output_tz)), axis="columns")

    remove_duration = False
    if "Duration" in loglines.columns:
      if loglines["Duration"].isnull().all():
        remove_duration = True
      else:
        loglines["Duration (s)"] = loglines["Duration"].apply(lambda d: d.total_seconds())

    final_columns = loglines.columns.values.tolist()
    if remove_duration:
      final_columns.remove("Duration")
    final_columns.remove("TZ")
    if options.remove_raw_timestamps:
      final_columns.remove("RawTimestamp")
      final_columns.remove("RawTZ")
    final_columns.remove(get_timestamp_column(output_tz))
    final_columns.insert(0, get_timestamp_column(output_tz))
    loglines = loglines[final_columns]
    loglines = loglines.sort_values(get_timestamp_column(output_tz))
  return loglines

def final_processing(df, title, prefix, save_image=True, large_numbers=False, options=None, kind="line", stacked=False):
  if not df.empty:
    cleaned_title = clean_name(title)
    axes = df.plot(title=title, kind=kind, stacked=stacked)
    axes.get_yaxis().get_major_formatter().set_scientific(False)
    axes.legend(bbox_to_anchor=(1,1), shadow=True)
    #axes.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), shadow=True, ncol=2)
    if large_numbers:
      axes.get_yaxis().set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, p: format(int(x), ',')))
    fig = matplotlib.pyplot.gcf()
    fig.autofmt_xdate(bottom=0.2, rotation=30, ha="right", which="both")
    fig.set_size_inches(10, 5)
    matplotlib.pyplot.tight_layout()
    image_name = "{}_{}.png".format(prefix, cleaned_title)
    matplotlib.pyplot.savefig(os.path.join(options.output_directory, image_name), dpi=100)
    print_data_frame(df, options, title, prefix)
    if options is not None and options.show_plots:
      matplotlib.pyplot.show()

def find_columns(df, columns):
  result = []
  for column in columns:
    if column in df.columns:
      result.append(column)
  return result

def filter_timestamps(data, options, output_tz, column=None):
  if column is None:
    column = get_timestamp_column(output_tz)
  if data is not None and data.empty is False:
    start_date = options.start_date
    end_date = options.end_date
    if start_date is not None and end_date is not None:
      data = data[(data[column] >= start_date) & (data[column] <= end_date)]
    elif start_date is not None:
      data = data[data[column] >= start_date]
    elif end_date is not None:
      data = data[data[column] <= end_date]
  return data

def combine_tuple(t):
  return "/".join(map(str, list(filter(None, t))))

def max_str_length(x):
  if isinstance(x, tuple):
    return len(combine_tuple(x))
  else:
    return len(str(x))

def print_data_frame(df, options, name, prefix=None):
  if df is not None and df.empty is False:
    print("")
    print("== {} ==".format(name))
    file_name = clean_name(name)
    if prefix is not None:
      file_name = prefix + "_" + file_name
    if options.print_stdout:
      if options.print_full:
        print_all_columns(df)
      else:
        print(df)
    if options.create_texts:
      print("Writing " + file_name + ".txt ... ", end="", flush=True)
      df2 = df.reset_index()
      columns = df2.columns.values
      formats = list(map(lambda x: "%-" + str(max(df2[x].map(lambda y: len(str(y))).max(), max_str_length(x))) + "s", columns))
      header = ""
      for i in range(0, len(columns)):
        if isinstance(columns[i], tuple):
          header += (formats[i] % combine_tuple(columns[i])) + " "
        else:
          header += (formats[i] % columns[i]) + " "
      numpy.savetxt(os.path.join(options.output_directory, file_name + ".txt"), df2.values, fmt=formats, header=header, comments="")
      print("Done")
    if options.create_csvs:
      print("Writing " + file_name + ".csv ... ", end="", flush=True)
      df.to_csv(os.path.join(options.output_directory, file_name + ".csv"))
      print("Done")
    if options.create_excels:
      print("Writing " + file_name + ".xlsx ... ", end="", flush=True)
      writer = pandas.ExcelWriter(
        os.path.join(options.output_directory, file_name + ".xlsx"),
        engine="xlsxwriter",
        datetime_format="YYYY-MM-DD HH:MM:SS.000", # Testing suggests Excels does not support any more precision (or errors were caused by some datasets not having such precision)
        options={"remove_timezone": True}
      )
      df.to_excel(writer, sheet_name=name[:31], freeze_panes=(df.columns.nlevels, df.index.nlevels))
      writer.save()
      print("Done")
    if options.create_pickles:
      print("Writing " + file_name + ".pkl ... ", end="", flush=True)
      df.to_pickle(os.path.join(options.output_directory, file_name + ".pkl"))
      print("Done")

def clean_name(name):
  return name.replace(" ", "_").replace("(", "").replace(")", "").replace("[", "").replace("]", "").replace("'", "").replace("\"", "").replace("&", "_")

def post_process(data):

  options = data["Options"]
  output_tz = data["OutputTZ"]

  thread_dumps = data["ThreadDumpInfo"]
  if thread_dumps is not None:
    final_processing(thread_dumps[find_columns(thread_dumps, ["CPUs"])].unstack(), "CPUs", "thread_dumps", options=options)
    final_processing(thread_dumps[find_columns(thread_dumps, ["JVMVirtualSize", "NativeClasses", "NativeThreads", "NativeJIT", "NativeDirectByteBuffers", "NativeFreePooledUnder4GB"])].unstack(), "JVM Virtual Native Memory", "thread_dumps", large_numbers=True, options=options)
    final_processing(thread_dumps[find_columns(thread_dumps, ["JavaHeapSize", "JavaHeapUsed", "MaxJavaHeap", "MinJavaHeap", "MaxNursery"])].unstack(), "Java Heap", "thread_dumps", large_numbers=True, options=options)
    final_processing(thread_dumps[find_columns(thread_dumps, ["Monitors"])].unstack(), "Monitors", "thread_dumps", options=options)
    final_processing(thread_dumps[find_columns(thread_dumps, ["Threads"])].unstack(), "Threads", "thread_dumps", options=options)
    final_processing(thread_dumps[find_columns(thread_dumps, ["CPUProportionApp", "CPUProportionJVM", "CPUProportionGC", "CPUProportionJIT"])].unstack(), "CPU Proportions", "thread_dumps", options=options)
    final_processing(thread_dumps[find_columns(thread_dumps, ["SharedClassCacheSize", "SharedClassCacheFree"])].unstack(), "Shared Class Cache", "thread_dumps", options=options)
    final_processing(thread_dumps[find_columns(thread_dumps, ["Classloaders"])].unstack(), "Classloaders", "thread_dumps", options=options)
    final_processing(thread_dumps[find_columns(thread_dumps, ["Classes"])].unstack(), "Classes", "thread_dumps", options=options)

  threads = data["Threads"]
  if threads is not None:
    if "JavaHeapSinceLastGC" in threads.columns:
      # Get the top X "Java heap allocated since last GC" and then plot those values for those threads over time
      top_heap_alloc_threads = numpy.unique(threads["JavaHeapSinceLastGC"].groupby("Thread").agg("max").sort_values(ascending=False).head(options.top_hitters).index.values)

      # Filter to only the threads in the above list and unstack the thread name into columns
      top_allocating_threads = threads["JavaHeapSinceLastGC"][threads.index.get_level_values("Thread").isin(top_heap_alloc_threads)].unstack()

      final_processing(top_allocating_threads, "Top Java heap allocated since last GC by Thread", "thread_dumps", large_numbers=True, options=options)

    # Get stats on thread states
    thread_states = threads[["State"]].groupby(["Time", "PID", "State"]).size().unstack().unstack()
    final_processing(thread_states, "Thread States", "thread_dumps", options=options)

    if "State2" in threads.columns:
      thread_states = threads[["State2"]].groupby(["Time", "PID", "State2"]).size().unstack().unstack()
      final_processing(thread_states, "Thread States 2", "thread_dumps", options=options)

    if "TopStackFrame" in threads.columns:
      # Find the top hitters for top stack frames and then plot those stack frame counts over time
      top_stack_frames = threads.groupby("TopStackFrame").size().sort_values(ascending=False).head(options.top_hitters)

      top_thread_stack_frames = threads[threads.TopStackFrame.isin(top_stack_frames.index.values)].groupby(["Time", "PID", "TopStackFrame"]).size().unstack().unstack()
      final_processing(top_thread_stack_frames, "Top Stack Frame Counts", "thread_dumps", options=options)

  post_process_loglines(data["TraditionalWASLogEntries"], "twas", options, output_tz)
  post_process_loglines(data["WASLibertyMessagesEntries"], "liberty", options, output_tz)

  access_log_entries = data["AccessLogEntries"]
  if access_log_entries is not None:
    x = access_log_entries.groupby([pandas.Grouper(key=get_timestamp_column(output_tz), freq=options.time_grouping), "Process"]).size().unstack()
    final_processing(x, "Responses per {}".format(options.time_grouping), "accesslog", options=options, kind="area", stacked=True)

  vmstat_entries = data["VmstatEntries"]
  if vmstat_entries is not None:
    x = vmstat_entries.groupby([get_timestamp_column(output_tz), "Host"]).aggregate({"CPU%": "mean" }).unstack()
    final_processing(x, f"Average CPU per {options.time_grouping}", "vmstat", options=options)

  host_cpus = data["HostCPUs"]
  if host_cpus is not None:
    x = host_cpus.groupby([pandas.Grouper(key=get_timestamp_column(output_tz), freq=options.time_grouping), "Host"]).aggregate({"CPUs": "max" }).unstack()
    final_processing(x, f"CPUs", "hostcpus", options=options, kind="bar")

def post_process_loglines(loglines, context, options, output_tz):
  if loglines is not None and loglines.empty is False:

    x = loglines.groupby([pandas.Grouper(key=get_timestamp_column(output_tz), freq=options.time_grouping), "Process"]).size().unstack()
    final_processing(x, "Log Entries per {}".format(options.time_grouping), context, options=options)

    x = loglines.groupby([pandas.Grouper(key=get_timestamp_column(output_tz), freq=options.time_grouping), "Level", "Process"]).size().unstack().unstack()
    final_processing(x, "Log Entries by Level per {}".format(options.time_grouping), context, options=options)

    if options.print_top_messages:
      print_data_frame(loglines.groupby(["Process", "MessageCode"]).size().sort_values(ascending=False).head(options.top_hitters).reset_index(name="Count"), options, "Top messages")
      print_data_frame(loglines[(loglines.Level != "I") & (loglines.Level != "A")].groupby(["Process", "MessageCode"]).size().sort_values(ascending=False).head(options.top_hitters).reset_index(name="Count"), options, "Top non-informational messages")
      print_data_frame(loglines[loglines.MessageCode.isin(options.important_messages.split(","))], options, "Important messages")
    
    if "Duration (s)" in loglines.columns:

      df = loglines[pandas.notnull(loglines["Duration (s)"])]
      df["Method"] = df["Component"] + "." + df["MessageFirstLine"]

      x = df.groupby([pandas.Grouper(key=get_timestamp_column(output_tz), freq=options.time_grouping), "Method"]).aggregate({"Duration (s)": "mean" }).unstack()
      final_processing(x, f"Execution Durations (Average) per {options.time_grouping}", context, options=options)

      x = df.groupby([pandas.Grouper(key=get_timestamp_column(output_tz), freq=options.time_grouping), "Method"]).aggregate({"Duration (s)": "max" }).unstack()
      final_processing(x, f"Execution Durations (Max) per {options.time_grouping}", context, options=options)

      x = df.groupby([pandas.Grouper(key=get_timestamp_column(output_tz), freq=options.time_grouping), "Method"]).aggregate({"Duration (s)": "sum" }).unstack()
      final_processing(x, f"Execution Durations (Sum) per {options.time_grouping}", context, options=options)

      x = df.groupby([pandas.Grouper(key=get_timestamp_column(output_tz), freq=options.time_grouping), "Method"]).aggregate({"Duration (s)": "count" }).unstack()
      final_processing(x, f"Execution Durations (Count) per {options.time_grouping}", context, options=options)

def print_all_columns(df):
  with pandas.option_context("display.max_columns", None):
    with pandas.option_context("display.max_colwidth", sys.maxsize):
      print(df)

if __name__ == "__main__":

  data = process_files(sys.argv[1:])

  options = data["Options"]

  for name, df in data.items():
    if isinstance(df, pandas.DataFrame):
      print_data_frame(df, options, name)
    else:
      print("== {} ==".format(name))
      print(df)
  print("")

  post_process(data)

  print_all_warnings()
