import pyshark
from yaml import safe_load
from mesh_class import MeshClass
import copy
from threading import Event, Thread
import time
import os
from datetime import datetime
import matplotlib.pyplot as plt

class Mesh_Tester():

    def __init__(self):
        with open("./mesh_ip.yml") as f:
            self.yaml_data = safe_load(f)
        self.mesh = MeshClass(self.yaml_data["ip_address"])

        self.data = {}
        self.rsus = {}
        self.cur_time : int

        self.cap_folder_name = "Packet_Captures/" + datetime.now().strftime("%b-%d-%H:%M:%S")
        self.res_folder_name = "Results/" + datetime.now().strftime("%b-%d-%H:%M:%S")

        #See if we need to create a new folder and csv file for today for today
        for newpath in [self.cap_folder_name, self.res_folder_name]:
            if not os.path.exists(newpath):
                os.makedirs(newpath)

    def call_repeatedly(self, interval, func, *args):
        stopped = Event()
        def loop():
            while not stopped.wait(interval): # the first call is in `interval` secs
                func(*args)
        Thread(target=loop).start()    
        return stopped.set

    def display_data(self):
        global cur_time
        cur_time += 1
        print("\r    Time: %d // " % cur_time, end='')
        for rsu in self.data.keys():
            print(rsu + " ≈ " + str(self.data[rsu]) + " // ", end='')

    def clear_data(self):
        global cur_time
        cur_time = 0
        for name in self.rsus.keys():
            self.data[name] = 0

    def handle_paket(self, block):
        #print("Got something!")
        i = 0
        for rsu in self.rsus.keys():
            if (hasattr(block, 'ip')  
                    and str(block['ip'].src) == self.rsus[rsu]['ip']                 # RSU IP Address
                    and str(block['ip'].proto) == '17'                          # UDP Protocol number
                and hasattr(block, 'udp')
                    and str(block['udp'].dstport) == str(self.rsus[rsu]['dst_port']) # This UDP reception port
                and hasattr(block, 'DATA')
            ):
                # If we got in here, then this packet is a forwarded C-V2X packet from the specified RSU
                self.data[rsu] += 1
                #print ("Packet received: ", rsu)

    def uniquify(self, path):
        filename, extension = os.path.splitext(path)
        counter = 1

        while os.path.exists(path):
            path = filename + "(" + str(counter) + ")" + extension
            counter += 1

        return path

    def midway(self, bottom, top):
        return int(((top - bottom) / 2) + bottom)



    def mesh_run_test(self, mesh_rsu_info: dict, tx_port: str):
        self.rsus = mesh_rsu_info.copy()

        bottom_att = 80 #yaml_data["att_low"]
        top_att = 130 #yaml_data["att_high"]
        attenuation = bottom_att

        critical_safety_limit = 0.9

        knee_finders = {}
        for rsu in self.rsus:
            knee_finders[rsu] = {"bottom": bottom_att, "top": top_att, "knee_found": False}

        # This set of numbers lets us make sure that we find knees iteratively, focusing on one and then the other
        num_knees_found = 0
        num_rsus = len(self.rsus)

        results = {}

        while num_knees_found < num_rsus:
            # Clear the data and declare the start of the trial
            self.clear_data()
            print("\x1B[32mSetting up trial on attenuation value\x1B[35m %d\x1B[32m db for\x1B[35m %d\x1B[32m seconds...\x1B[37m" 
                % (attenuation, self.yaml_data["trial_length"]))

            cap_file_name = self.uniquify(self.cap_folder_name + "/attenuation_%d.pcap" % attenuation)

            cap = pyshark.LiveCapture(interface=self.yaml_data["wireshark_interface"], 
                bpf_filter="udp and not src host %s" % self.yaml_data['host_ip'],
                output_file=cap_file_name)

            

            # Go through and set all the attenuation values we need
            for rsu in self.rsus.keys():
                rx_port = self.rsus[rsu]["mesh_port"]
                partial_att = self.rsus[rsu]["att_offset"]
                diff_att = attenuation - partial_att
                diff_att = round(diff_att * 4) / 4 # needs a multiple of 0.25

                #print('dbg: mesh.set_att(%s, %s, %f)' % (tx_port, rx_port, diff_att))
                self.mesh.set_att(tx_port, rx_port, diff_att)

            time.sleep(10) # Delay to allow new setup to settle
            print("Starting trial:")

            # Start the repeating timer
            end_timer = self.call_repeatedly(1, self.display_data)

            # Start the packet capture
            try:
                cap.apply_on_packets(self.handle_paket, timeout=int(self.yaml_data["trial_length"]))

            except Exception as e:
                if e is TimeoutError:
                    # This just means that a packet was caught mid-exit; not fatal to the experiment
                    pass
            finally:
                end_timer()
            #timer.cancel()
            print()
            print("\x1B[32mEnding trial for\x1B[35m %d\x1B[32m db\x1B[37m" % attenuation, end="\n")
            
            print("Saving data from trial...")
            # Save the results in their own files
            cap.close()

            results[attenuation] = {}
            
            for rsu in self.rsus:
                
                
                total_time_gap = self.yaml_data["trial_length"]
                num_packets = self.data[rsu]

                estimated_num_spaced = int(total_time_gap * 10)
                percent_reception = float(float(num_packets) / float(estimated_num_spaced))

                summaries_file_name = '%s/summaries_%s.txt' % (self.res_folder_name, rsu)

                print("Saving %s data in %s" % (rsu, summaries_file_name))

                print(file=open(summaries_file_name, 'a'))
                print("Attenuation ", attenuation, file=open(summaries_file_name, 'a'))
                print("Number of packets: ", num_packets, file=open(summaries_file_name, 'a'))
                print('Total time gap: ', total_time_gap, file=open(summaries_file_name, 'a'))
                print('Total expected packets: ', estimated_num_spaced, file=open(summaries_file_name, 'a'))
                print("Calculated missed packets: ", estimated_num_spaced - num_packets, file=open(summaries_file_name, 'a'))
                print("Percent reception: ", percent_reception, file=open(summaries_file_name, 'a'))

                # Now we focus on taking the current recpetion rate and trying to find the knee
                if percent_reception > critical_safety_limit:
                    if attenuation > knee_finders[rsu]["bottom"]:
                        knee_finders[rsu]["bottom"] = attenuation
                else:
                    # Crucially, we don't want to record a slightly low value if a higher attenuation, for 
                    #  whatever reason, gives us a better recpetion rate. 
                    if attenuation < knee_finders[rsu]["top"] and attenuation > knee_finders[rsu]["bottom"]:
                        knee_finders[rsu]["top"] = attenuation

                results[attenuation][rsu] = percent_reception


            
            print("Data saved 👍\n")
            # Here, we reset each knee as needed
            for rsu in list(self.rsus)[num_knees_found:]:
                if knee_finders[rsu]["top"] - knee_finders[rsu]["bottom"] == 1:
                    knee_finders[rsu]["knee_found"] = True
                    num_knees_found += 1
                else:
                    if knee_finders[rsu]["top"] - knee_finders[rsu]["bottom"] < 0:
                        # Error, top and bottom are switched, move top back
                        knee_finders[rsu]["top"] = top_att
                    # No matter what, if the current index doesn't check out, break
                    break

            # Here, we need to set the "attenuation" variable for the next loop
            if num_knees_found < num_rsus:
                nkf = list(knee_finders)[num_knees_found]
                attenuation = self.midway(knee_finders[nkf]["bottom"], knee_finders[nkf]["top"])
                
                print("New attenuation: %d" % attenuation)

        ##############################################################################################
        # At this point, all attenuations have been gathered, and we are ready to display the results.
        ##############################################################################################
        for rsu in self.rsus:

            values = []

            num_vals = 0
            att = 0
            rec = 0.0

            for attenuation in results:
                values.append((attenuation, results[attenuation][rsu]))
            values.sort()

            attenuations = []
            reception_rates = []
            for i in values:
                attenuations.append(i[0])
                reception_rates.append(i[1] * 100.0)

            self.data['att'] = attenuations
            self.data[rsu] = {}
            self.data[rsu]['rate'] = reception_rates


            plt.plot(attenuations, reception_rates, marker = 'o')
            plt.xlabel("Attenuations (dB)")
            plt.ylabel("Packet Reception Rate (%)")
            plt.title("Reception Rate per Attenuation (%s)" % rsu)
            plt.ylim(-4, 104)
            plt.axhline(y=90, color='red', linestyle='--', label='Critical Safety Limit: 90%')
            plt.show()
            plt.savefig(self.res_folder_name + '/Attenuations-%s.png' % rsu)
            plt.clf()

        for rsu in self.rsus:
            plt.plot(self.data['att'], self.data[rsu]['rate'], label=rsu, marker = 'o')

        plt.xlabel("Attenuation (db)")
        plt.ylabel("Packet Reception Rate (%)")
        plt.ylim(-4, 104)
        plt.title("Reception Rate per Attenuation (All RSU Comparison)")
        plt.axhline(y=90, color='red', linestyle='--', label='Critical Safety Limit: 90%')
        plt.legend()
        plt.savefig(self.res_folder_name + '/Comparison-Attenuations.png')
        plt.show()
        plt.clf()
