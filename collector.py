import logging
import os
import shutil
import socket
import time
from time import sleep
from multiprocessing import Process
import pandas as pd
import psutil
import re
from filelock import FileLock
from nfstream import NFStreamer

TMP_TOKEN = 0
FILE_SIZE = 500 * 1024 * 1024  # 500MB

# Auxiliar function used to write a several flows to a file;
def writeListToFile(filePath, header, flows):
    auxheader = ['id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'src2dst_packets', 'dst2src_packets', 'src2dst_max_ps', 'src2dst_min_ps', 'src2dst_mean_ps', 'src2dst_stddev_ps', 'dst2src_max_ps', 'dst2src_min_ps', 'dst2src_mean_ps', 'dst2src_stddev_ps', 'src2dst_mean_piat_ms', 'src2dst_stddev_piat_ms', 'src2dst_max_piat_ms', 'src2dst_min_piat_ms', 'dst2src_mean_piat_ms', 'dst2src_stddev_piat_ms', 'dst2src_max_piat_ms', 'dst2src_min_piat_ms', 'src2dst_psh_packets', 'dst2src_psh_packets', 'src2dst_urg_packets', 'dst2src_urg_packets', 'bidirectional_packets']
    df = pd.DataFrame(flows,columns=auxheader)
    if header == []:
        header = auxheader
        df.to_csv(filePath,header=header,index=False, sep=',', mode='a',encoding="utf-8")
    else:
        df.to_csv(filePath,header=False,index=False, sep=',', mode='a',encoding="utf-8")
    return header

# Main function where the retrieval of flows and their saving are compilated;
def flowStreamer():
    global TMP_TOKEN
    interfaces = psutil.net_if_addrs()
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    auxBPF = "not src net " + IPAddr +" and "+os.environ.get("BPF_FILTER") #type:ignore
    logging.info("The interface being analysed is: "+str(list(interfaces.keys())[1]))  # type:ignore
    # Initialize flow analyser;
    streamer = NFStreamer(source=list(interfaces.keys())[1],  # type: ignore
                          decode_tunnels=False,
                          bpf_filter= auxBPF,
                          snapshot_length=68,
                          idle_timeout=1,
                          active_timeout=30,
                          n_dissections=0,
                          statistical_analysis=True,
                          )

    # Timestamp to use aas identifier for the main flow file;
    timestr = time.strftime("%Y%m%d-%H%M%S")

    # File Initialization;
    header = []
    headerTmp = []
    aux = open("flow_"+timestr+".csv", "w")
    aux.close()
    aux = open("Temp/tmp"+str(TMP_TOKEN)+".csv", "w")
    aux.close()
    flowList=[]

    # File Locking Mechanism to not allow for concurrent reading/writing errors;
    lock = FileLock("flow.csv.lock")
    lockTmp = FileLock("tmp.csv.lock")
    timeStamp = time.time()

    for flow in streamer:
        features = [
            flow.id,
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol,
            flow.src2dst_packets,
            flow.dst2src_packets,
            flow.src2dst_max_ps,
            flow.src2dst_min_ps,
            flow.src2dst_mean_ps,
            flow.src2dst_stddev_ps,
            flow.dst2src_max_ps,
            flow.dst2src_min_ps,
            flow.dst2src_mean_ps,
            flow.dst2src_stddev_ps,
            flow.src2dst_mean_piat_ms,
            flow.src2dst_stddev_piat_ms,
            flow.src2dst_max_piat_ms,
            flow.src2dst_min_piat_ms,
            flow.dst2src_mean_piat_ms,
            flow.dst2src_stddev_piat_ms,
            flow.dst2src_max_piat_ms,
            flow.dst2src_min_piat_ms,
            flow.src2dst_psh_packets,
            flow.dst2src_psh_packets,
            flow.src2dst_urg_packets,
            flow.dst2src_urg_packets,
            flow.bidirectional_packets
        ]
        
        currentStamp = time.time()
        flowList.append(features)
        # Write every 30 seconds
        if(currentStamp-timeStamp>=30):
            with lockTmp:
                if os.path.getsize("Temp/tmp"+str(TMP_TOKEN)+".csv") > FILE_SIZE:
                    TMP_TOKEN += 1
                    aux = open("Temp/tmp"+str(TMP_TOKEN)+".csv", "w")
                    aux.close()
                headerTmp = writeListToFile(
                    "Temp/tmp"+str(TMP_TOKEN)+".csv", headerTmp, flowList)
            with lock:
                header = writeListToFile("flow_"+timestr+".csv", header, flowList)
            flowList=[]
    return streamer

def init_variables():
    if bool(re.search(r'\d', str(os.environ.get("FILE_SAVE"))))==False:
        os.environ["FILE_SAVE"] = "60"
    else:
        logging.debug("FILE_SAVE already exists as an environment variable")

    if bool(re.search(r'\d', str(os.environ.get("BPF_FILTER"))))==False:
        os.environ["BPF_FILTER"] = "not src net 10.96.0.10"
    else:
        logging.debug("BPF_FILTER already exists as an environment variable")

# Main function
if __name__ == "__main__":
    if not os.path.exists("Temp"):
        os.mkdir("Temp")

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    init_variables()

    logging.info('Flow File saves in an interval of ' + os.environ.get("FILE_SAVE")+" minute(s).")
    logging.info("BPF Filter set to: "+str(os.environ.get("BPF_FILTER")))

    # Run the streamer for a certain amount of time (FILE_SAVE), then restart and create a new file;
    while True:
        process = Process(target=flowStreamer)
        process.start()
        sleep(int(os.environ.get("FILE_SAVE"))*60)
        process.terminate()
        process.join()
        logging.info("Reset of flow file.")
