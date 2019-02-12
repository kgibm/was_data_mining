# was.py: Process various WAS-related logs
# usage: python was.py file1 ... fileN
#
# Author: Kevin Grigorenko (kevin.grigorenko@us.ibm.com)
#
# Notes:
#   * Designed for Python3, so might require using python3/pip3 commands.
#   * Install: pip install numpy pandas matplotlib
#   * Run from REPL:
#     >>> exec(open("was.py").read())
#     >>> data = process_files(["file1", "file2", ...])
#
#   Tips:
#     >>> data.describe() # To print statistics of numeric columns
#     >>> pandas.set_option("display.expand_frame_repr", False) # To print all columns when printing DataFrames
#     >>> pandas.set_option("display.max_rows", 10) # Change print(data) rows. Set to None to print everything
#     >>> data.info() # Count number of NaNs

import os
import re
import sys
import math
import numpy
import pandas
import pprint
import numbers
import argparse
import matplotlib

def file_head(file, lines=20):
  result = ""
  with open(file) as f:
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

def find_files():
  result = []
  for root, subdirs, files in os.walk(os.getcwd()):
    for file in files:
      result.append(os.path.join(root, file))
  return result

def should_skip_file(file, file_extension):
  if file_extension is not None:
    valid_extensions = [".txt", ".log"]
    if file_extension.lower() not in valid_extensions:
      return True
  return False

bytes = re.compile(r"([\d,\.]+)([bBkKmMgGtTpPeE])")

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
  if frame.startswith("java/") or frame.startswith("sun/") or frame.startswith("com/ibm/io/") or frame.startswith("com/ibm/ejs"):
    return True
  return False

def trim_stack_frame(frame):
  i = frame.index("(")
  if i is not None:
    frame = frame[:i]
  i = frame.rindex("/")
  if i is not None:
    frame = frame[i+1:]
  return frame

def should_filter_thread(name):
  if name.startswith("WebContainer") or name.startswith("Default Executor") or name.startswith("server.startup") or name.startswith("ORB.thread.pool") or name.startswith("SIB") or name.startswith("WMQ"):
    return False
  return True

def process_files(args):
  parser = argparse.ArgumentParser()
  parser.add_argument("file", help="path to a file", nargs="*")
  parser.add_argument("-t", "--top-hitters", help="top X items to process for top hitters plots", type=int, default=10)
  parser.add_argument("--do-not-trim-stack-frames", help="Don't trim stack frames", dest="trim_stack_frames", action="store_false")
  parser.add_argument("--do-not-skip-well-known-stack-frames", help="Don't skip well known stack frames", dest="skip_well_known_stack_frames", action="store_false")
  parser.add_argument("--filter-to-well-known-threads", help="Filter to well known threads", dest="filter_to_well_known_threads", action="store_true")
  parser.set_defaults(
    trim_stack_frames=True,
    skip_well_known_stack_frames=True,
    filter_to_well_known_threads=False
  )
  options = parser.parse_args(args)

  # Suppress scientific notation and trim trailing zeros
  pandas.options.display.float_format = lambda x: "{:.2f}".format(x).rstrip("0").rstrip(".")

  javacores = None
  javacore_data = {}
  javacore_thread_data = {}

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

  javacore_thread_info1 = re.compile(r"3XMTHREADINFO\s+\"([^\"]+)\" J9VMThread:0x[0-9a-fA-F]+, j9thread_t:0x[0-9a-fA-F]+, java/lang/Thread:0x[0-9a-fA-F]+, state:(\w+), prio=\d+")
  javacore_thread_bytes = re.compile(r"3XMHEAPALLOC\s+Heap bytes allocated since last GC cycle=(\d+)")

  files = options.file
  if len(files) == 0:
    files = find_files()

  for file in files:

    filename, file_extension = os.path.splitext(file)
    if should_skip_file(file, file_extension):
      continue

    print("Processing {}".format(file))

    head = file_head(file)

    if "0SECTION" in head:
      match = javacore_time.search(head)
      if match.group(7) is not None:
        current_time = pandas.to_datetime("{}-{}-{} {}:{}:{}{}".format(match.group(1), match.group(2), match.group(3), match.group(4), match.group(5), match.group(6), match.group(7)), format="%Y-%m-%d %H:%M:%S:%f")
      else:
        current_time = pandas.to_datetime("{}-{}-{} {}:{}:{}".format(match.group(1), match.group(2), match.group(3), match.group(4), match.group(5), match.group(6)), format="%Y-%m-%d %H:%M:%S")
      match = javacore_name.search(file)
      # or 1CIPROCESSID\s+Process ID: \d+ (
      pid = int(match.group(1))
      artifact = int(match.group(2))

      pid_data = ensure_data(javacore_data, [current_time, pid])

      cpu_all = 0
      cpu_jvm = 0
      heap_size = 0
      current_thread = None
      threads_data = None
      thread_filtered = False

      with open(file) as f:
        for line in f:

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
                threads_data = ensure_data(javacore_thread_data, [current_time, pid, current_thread])
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

  return {
    "Options": options,
    "JavacoreInfo": create_multi_index2(javacore_data, ["Time", "PID"]),
    "JavacoreThreads": create_multi_index3(javacore_thread_data, ["Time", "PID", "Thread"]),
  }

def final_processing(df, title, prefix="was", save_image=True, show_plot=False, large_numbers=False):
  if not df.empty:
    cleaned_title = title.replace(" ", "_").replace("(", "").replace(")", "")
    df.to_csv("{}_{}.csv".format(prefix, cleaned_title))
    axes = df.plot(title=title)
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
    matplotlib.pyplot.savefig(image_name, dpi=100)
    print("Created {}".format(image_name))
    if show_plot:
      matplotlib.pyplot.show()

def find_columns(df, columns):
  result = []
  for column in columns:
    if column in df.columns:
      result.append(column)
  return result

def post_process(data):

  options = data["Options"]

  javacores = data["JavacoreInfo"]
  if javacores is not None:
    final_processing(javacores[find_columns(javacores, ["CPUs"])].unstack(), "CPUs")
    final_processing(javacores[find_columns(javacores, ["JVMVirtualSize", "NativeClasses", "NativeThreads", "NativeJIT", "NativeDirectByteBuffers", "NativeFreePooledUnder4GB"])].unstack(), "JVM Virtual Native Memory", large_numbers=True)
    final_processing(javacores[find_columns(javacores, ["JavaHeapSize", "JavaHeapUsed", "MaxJavaHeap", "MinJavaHeap", "MaxNursery"])].unstack(), "Java Heap", large_numbers=True)
    final_processing(javacores[find_columns(javacores, ["Monitors"])].unstack(), "Monitors")
    final_processing(javacores[find_columns(javacores, ["Threads"])].unstack(), "Threads")
    final_processing(javacores[find_columns(javacores, ["CPUProportionApp", "CPUProportionJVM", "CPUProportionGC", "CPUProportionJIT"])].unstack(), "CPU Proportions")
    final_processing(javacores[find_columns(javacores, ["SharedClassCacheSize", "SharedClassCacheFree"])].unstack(), "Shared Class Cache")
    final_processing(javacores[find_columns(javacores, ["Classloaders", "Classes"])].unstack(), "Classloaders and Classes")

  threads = data["JavacoreThreads"]
  if threads is not None:
    # Get the top X "Java heap allocated since last GC" and then plot those values for those threads over time
    top_heap_alloc_threads = numpy.unique(threads["JavaHeapSinceLastGC"].groupby("Thread").agg("max").sort_values(ascending=False).head(options.top_hitters).index.values)

    # Filter to only the threads in the above list and unstack the thread name into columns
    top_allocating_threads = threads["JavaHeapSinceLastGC"][threads.index.get_level_values("Thread").isin(top_heap_alloc_threads)].unstack()

    final_processing(top_allocating_threads, "Top Java heap allocated since last GC by Thread", large_numbers=True)

    # Get stats on thread states
    thread_states = threads[["State"]].groupby(["Time", "PID", "State"]).size().unstack().unstack()
    final_processing(thread_states, "Thread States")

    # Find the top hitters for top stack frames and then plot those stack frame counts over time
    top_stack_frames = threads.groupby("TopStackFrame").size().sort_values(ascending=False).head(options.top_hitters)

    top_thread_stack_frames = threads[threads.TopStackFrame.isin(top_stack_frames.index.values)].groupby(["Time", "PID", "TopStackFrame"]).size().unstack().unstack()
    final_processing(top_thread_stack_frames, "Top Stack Frame Counts")

# https://stackoverflow.com/a/53873661/1293660
def print_wrapped_head(x, nrow = 5, ncol = 4):
  with pandas.option_context("display.expand_frame_repr", False):
    seq = numpy.arange(0, len(x.columns), 4)
    for i in seq:
      print(x.loc[range(0,nrow), x.columns[range(i,min(i+ncol, len(x.columns)))]])

if __name__ == "__main__":

  data = process_files(sys.argv[1:])

  for name, df in data.items():
    print("")
    print("== {} ==".format(name))
    print(df)
  print("")

  post_process(data)
