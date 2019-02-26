/*
   Copyright 2012 Google Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   Author: peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "main_processes.h"
#include "rpc_handler.h"
#include "../jsoncpp/json/json.h"
#include <fstream>
#include <dirent.h>
#include <sys/time.h>
extern "C" {
  #include "../headerspace/array.h"
}

using namespace net_plumber;
using namespace std;

list<long> load_netplumber_from_dir(string json_file_path, NetPlumber * N, array_t *filter) {
  struct timeval start, end;
  int rule_counter = 0;
  ifstream jsfile;
  Json::Value root;
  Json::Reader reader;
  list<long> t_list;
  long total_run_time = 0;

  // read topology
  string file_name = json_file_path + "/" + "topology.json";
  jsfile.open (file_name.c_str());
  if (!jsfile.good()) {
    printf("Error opening the file %s\n",file_name.c_str());
    return t_list;
  }
  reader.parse(jsfile,root,false);
  Json::Value topology = root["topology"];
  for (unsigned i = 0; i < topology.size(); i++) {
    N->add_link(topology[i]["src"].asInt(),topology[i]["dst"].asInt());
  }
  N->print_topology();
  jsfile.close();

  //read every json file.
  struct dirent *ent;
  DIR *dir = opendir(json_file_path.c_str());
  if (dir != NULL) {
    while ((ent = readdir(dir)) != NULL ) {
      file_name = string(ent->d_name);
      if (file_name.find(".rules.json") != string::npos ||
          file_name.find(".tf.json") != string::npos) {
        // open the json file
        file_name = json_file_path + "/" + file_name;
        printf("=== Loading rule file %s to NetPlumber ===\n",file_name.c_str());
        jsfile.open (file_name.c_str());
        reader.parse(jsfile,root,false);

        // get the table id, ports and rules
        uint32_t table_id = root["id"].asInt();
        Json::Value ports = root["ports"];
        Json::Value rules = root["rules"];

        // create the table
        N->add_table(table_id,val_to_list(ports));

        // add the rules
        for (unsigned i = 0; i < rules.size(); i++) {
          long run_time = 0;
          rule_counter++;
          string action = rules[i]["action"].asString();
          if (action == "fwd" || action == "rw" /*|| action == "encap"*/) {
            array_t *match = val_to_array(rules[i]["match"]);
            if (filter && !array_isect(match,filter,N->get_length(),match)) {
              run_time = 0;
            } else {
              gettimeofday(&start, NULL);
              N->add_rule(table_id,
                          0,
                          val_to_list(rules[i]["in_ports"]),
                          val_to_list(rules[i]["out_ports"]),
                          match,
                          val_to_array(rules[i]["mask"]),
                          val_to_array(rules[i]["rewrite"]));
              gettimeofday(&end, NULL);
              run_time = end.tv_usec - start.tv_usec;
              if (run_time < 0) {
                run_time = 1000000 * (end.tv_sec - start.tv_sec);
              }
              total_run_time += run_time;
            }
            t_list.push_back(run_time);
          } else if (action == "multipath") {
            Json::Value mp_rules = rules[i]["rules"];
            uint64_t group = 0;
            for (unsigned i = 0; i < mp_rules.size(); i++) {
              string action = mp_rules[i]["action"].asString();
              if (action == "fwd" || action == "rw" /*|| action == "encap"*/) {
                uint64_t id = N->add_rule_to_group(
                                table_id,
                                0,
                                val_to_list(mp_rules[i]["in_ports"]),
                                val_to_list(mp_rules[i]["out_ports"]),
                                val_to_array(mp_rules[i]["match"]),
                                val_to_array(mp_rules[i]["mask"]),
                                val_to_array(mp_rules[i]["rewrite"]),
                                group);
                if (i == 0) group = id;
              }
            }
          }
        }

        // clean up
        jsfile.close();
      }
    }
    //N->print_plumbing_network();
  }
  printf("total run time is %ld us. rules: %d average: %ld us\n",total_run_time,rule_counter,total_run_time/rule_counter);
  closedir(dir);
  return t_list;
}

void load_policy_file(string json_policy_file, NetPlumber *N, array_t *filter) {
  printf("Loading policy file %s\n",json_policy_file.c_str());
  time_t start, end;
  ifstream jsfile;
  Json::Value root;
  Json::Reader reader;

  // read topology
  jsfile.open (json_policy_file.c_str());
  if (!jsfile.good()) {
    printf("Error opening the file %s\n",json_policy_file.c_str());
    return;
  }
  reader.parse(jsfile,root,false);
  Json::Value commands = root["commands"];
  start = clock();
  for (int i = 0; i < commands.size(); i++) {
    string type = commands[i]["method"].asString();
    if (type == "add_source") {
      // count_hs_isect_arr = 0;
      // struct timeval start_in, end_in;
      time_t start_in, end_in;
      hs *tmp = val_to_hs(commands[i]["params"]["hs"], N->get_length());
      hs *h;
      if (filter) {
        h = hs_create(N->get_length());
        hs_isect_arr(h,tmp,filter);
        hs_free(tmp);
      } else {
        h = tmp;
      }
      List_t ports = val_to_list(commands[i]["params"]["ports"]);
      // gettimeofday(&start_in, NULL);
      start_in = clock();
      N->add_source(h,ports);
      end_in = clock();
      // gettimeofday(&end_in, NULL);
      // printf("Add source %d need %ld ms to be completed.\n", commands[i]["id"].asUInt(), ((end_in.tv_usec - start_in.tv_usec)/1000));
      printf("Add source %d need %2lf ms to be completed.\n", commands[i]["id"].asUInt(), (double(end_in - start_in) / (CLOCKS_PER_SEC/1000)));

    } else if (type == "add_source_probe") {
      List_t ports = val_to_list(commands[i]["params"]["ports"]);
      PROBE_MODE mode = !strcasecmp(commands[i]["params"]["mode"].asCString(), "universal")
          ? UNIVERSAL : EXISTENTIAL;
      Condition *filter = val_to_cond(commands[i]["params"]["filter"], N->get_length());
      Condition *test = val_to_cond(commands[i]["params"]["test"], N->get_length());
      N->add_source_probe(ports, mode, filter, test, NULL, NULL);
    } else if (type == "add_link") {
      time_t start_in, end_in;
      // struct timeval start_in, end_in;
      uint32_t from_port = commands[i]["params"]["from_port"].asUInt();
      uint32_t to_port = commands[i]["params"]["to_port"].asUInt();
      // gettimeofday(&start_in, NULL);
      start_in = clock();
      N->add_link(from_port,to_port);
      end_in = clock();

      printf("Add link %d - %d need %2lf ms to be completed.\n", from_port, to_port, (double(end_in - start_in) / (CLOCKS_PER_SEC/1000)));
      // gettimeofday(&end_in, NULL);
      // printf("Add link %d - %d need %ld ms to be completed.\n", from_port, to_port, (end_in.tv_usec - start_in.tv_usec)/1000);
    } else if (type == "remove_link") {
      time_t start_in, end_in;
      // struct timeval start_in, end_in;
      uint32_t from_port = commands[i]["params"]["from_port"].asUInt();
      uint32_t to_port = commands[i]["params"]["to_port"].asUInt();
      // gettimeofday(&start_in, NULL);
      start_in = clock();
      N->remove_link(from_port,to_port);
      end_in = clock();

      // gettimeofday(&end_in, NULL);
      printf("Remove link %d - %d need %2lf ms to be completed.\n", from_port, to_port, (double(end_in - start_in) / (CLOCKS_PER_SEC/1000)));
      // printf("Remove link %d - %d need %ld ms to be completed.\n", from_port, to_port, (end_in.tv_usec - start_in.tv_usec)/1000);
    } 
    else if (type == "re_add_rule") {
      // time_t start_in, end_in;
      struct timeval start_in, end_in;
      long run_time = 0;
      // struct timeval start_in, end_in;
      uint32_t table = commands[i]["params"]["table"].asUInt();
      uint32_t id = commands[i]["params"]["id"].asUInt();

      // long run_time = 0;
      uint64_t rule_id = (uint64_t)id + ((uint64_t)table << 32) ;
      RuleNode *r = N->get_rule(rule_id);


      printf("Get rule %d - %d successed.\n", table, id);
      cout << r->rule_to_str()<< endl;
      List_t in_ports = r->copy_in_ports();
      List_t out_ports = r->copy_out_ports();
      array_t *match = r->copy_match();
      array_t *mask = r->copy_mask();
      array_t *rewrite = r->copy_rewrite();

      // if (table == 31 && id == 8){
      //   match = array_from_str("11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,00000000,00000000");
      //   mask = array_from_str("11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,00000000,00000000");
      //   rewrite = array_from_str("00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,11001111");
      // }

      // cout << "Match: " << array_to_str(match,16,false) << endl;
      // if (mask)
      //   cout << ", Mask: " << array_to_str(mask,16,false) << ", Rewrite: " << array_to_str(rewrite,16,false) << endl;

      // cout << ", iPorts: " << list_to_string(in_ports) << ", oPorts: " << list_to_string(out_ports) << endl;

      // N->remove_rule(rule_id);
      N->remove_rule_frtable(rule_id);
      
      printf("Remove rule %d - %d successed.\n", table, id);

      gettimeofday(&start_in, NULL);
      N->add_rule(table,
                  0,
                  in_ports,
                  out_ports,
                  match,
                  mask,
                  rewrite);

      // N->re_add_rule(table, id);
      gettimeofday(&end_in, NULL);
      run_time = end_in.tv_usec - start_in.tv_usec;
      run_time = 1000000 * (end_in.tv_sec - start_in.tv_sec) + end_in.tv_usec - start_in.tv_usec;
      printf("Add rule %d - %d need %ld us to be completed.\n", table, id, run_time);
    }else if (type == "re_add_table") {
      // time_t start_in, end_in;
      struct timeval start_in, end_in;
      long run_time = 0;
      // struct timeval start_in, end_in;
      uint32_t table = commands[i]["params"]["table"].asUInt();
      uint32_t nrules = commands[i]["params"]["nrules"].asUInt();


      printf("re_add_table\n");
      // long run_time = 0;
      for (int j = 1; j < nrules; j++) {

      
        uint64_t rule_id = (uint64_t)j + ((uint64_t)table << 32) ;
        RuleNode *r = N->get_rule(rule_id);


        printf("Get rule %d - %d ;", table, j);
        // cout << r->rule_to_str()<< endl;
        List_t in_ports = r->copy_in_ports();
        List_t out_ports = r->copy_out_ports();
        array_t *match = r->copy_match();
        array_t *mask = r->copy_mask();
        array_t *rewrite = r->copy_rewrite();

        // if (table == 31 && id == 8){
        //   match = array_from_str("11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,00000000,00000000");
        //   mask = array_from_str("11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,11111111,00000000,00000000");
        //   rewrite = array_from_str("00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,11001111");
        // }

        // cout << "Match: " << array_to_str(match,16,false) << endl;
        // if (mask)
        //   cout << ", Mask: " << array_to_str(mask,16,false) << ", Rewrite: " << array_to_str(rewrite,16,false) << endl;

        // cout << ", iPorts: " << list_to_string(in_ports) << ", oPorts: " << list_to_string(out_ports) << endl;

        // N->remove_rule(rule_id);
        N->remove_rule_frtable(rule_id);
        
        // printf("Remove rule %d - %d successed.\n", table, id);
        
        gettimeofday(&start_in, NULL);
        N->add_rule(table,
                    j,
                    in_ports,
                    out_ports,
                    match,
                    mask,
                    rewrite);

        // N->re_add_rule(table, id);
        gettimeofday(&end_in, NULL);
        run_time = end_in.tv_usec - start_in.tv_usec;
        run_time = 1000000 * (end_in.tv_sec - start_in.tv_sec) + end_in.tv_usec - start_in.tv_usec;
        printf(" need %ld us to be completed.\n", run_time);
      }
    } else if (type == "add_rule") {
      struct timeval start_in, end_in;
      long run_time = 0;
      uint32_t table = commands[i]["params"]["table"].asUInt();
      gettimeofday(&start_in, NULL);
      N->add_rule(table,
                  0,
                  val_to_list(commands[i]["params"]["in_ports"]),
                  val_to_list(commands[i]["params"]["out_ports"]),
                  val_to_array(commands[i]["params"]["match"]),
                  val_to_array(commands[i]["params"]["mask"]),
                  val_to_array(commands[i]["params"]["rewrite"]));
      gettimeofday(&end_in, NULL);
      run_time = end_in.tv_usec - start_in.tv_usec;
      run_time = 1000000 * (end_in.tv_sec - start_in.tv_sec) + end_in.tv_usec - start_in.tv_usec;
      printf("Add rule %d need %ld us to be completed.\n", table, run_time);

    }
    
  }
  end = clock();
  printf("Loaded policy file in %2lf seconds\n",(double(end - start) / CLOCKS_PER_SEC));
  jsfile.close();
}



