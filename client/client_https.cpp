#include "client_https.hpp"

//Added for the json-example
#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/replace.hpp>


//Added for the default_resource example
#include <fstream>
#include <boost/filesystem.hpp>
#include <array>
#include <algorithm>

#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <stdlib.h>

#include <iostream>
#include <sstream>
#include <iomanip>

extern "C" {
#include "anon.h"
}

using namespace std;
//Added for the json-example:
using namespace boost::property_tree;

typedef SimpleWeb::Client<SimpleWeb::HTTPS> HttpsClient;

void pretty(const char* str, const char* title) {
    printf("%s:\n",title);
    const char *p = str;
    do {
        const char *l = strchr(p, '\n');
        if (l) {
            printf("         %.*s\n", (int)(l-p),p);
            p = l+1;
        } else { 
            printf("         %s\n", p);
            p = l;
        }
    } while (p);
}

template <typename T>
std::vector<T> as_vector(ptree const& pt, ptree::key_type const& key)
{
    std::vector<T> r;
    for (auto& item : pt.get_child(key))
        r.push_back(item.second.get_value<T>());
    return r;
}

int main(int argc, char *argv[]) { 
    string host = "localhost";
    if(argc == 2){
        host = argv[1];
    }
    else
    if(argc > 2){
        cout << "Too many arguments. Format ./client_https <host ip>" << endl;
        return 1;
    }


    initAnonize();
    cout<<"initAnonize()"<<endl;
    string uid;
    //Client examples
    //Second Client() parameter set to false: no certificate verification
    HttpsClient client(host+":8080", false);
    cout << "Register your UserName: ";
    // cin >> uid;
    cin >> uid;
    // auto r1=client.request("GET", "/match/123");
    // cout << r1->content.rdbuf() << endl;


    stringstream ss;
    auto r1=client.request("POST", "/registerUser", uid);
    ss << r1->content.rdbuf();
    string RAVK=ss.str();

    const char* precred = makeCred(uid.c_str());
    string reg1 = registerUserMessage(precred, RAVK.c_str());

    stringstream ss2;
    string json_string="{\"uid\": \"" + uid + "\",\"reg\": \"" + reg1 + "\"}";
    auto r2=client.request("POST", "/registerServerResponse", json_string);
    ss2 << r2->content.rdbuf();
    string reg2=ss2.str();

    const char* cred = registerUserFinal(uid.c_str(), reg2.c_str(), precred, RAVK.c_str());

    auto cred_json =client.request("POST", "/surveyCred", uid);


    ptree pt;
    read_json(cred_json->content, pt);

    string uidsig = pt.get<string>("uidsig");
    string vid = pt.get<string>("vid");
    string vk = pt.get<string>("vk");

    cout << "uidsig: " << uidsig << endl;
    cout << "vid   : " << vid << endl;
    cout << "vk    : " << vk << endl;

    string msg = "[", finalmsg;

    auto survey_json =client.request("GET", "/survey");
    ptree survey;
    read_json(survey_json->content, survey);

    string answer;
    cin.ignore();
    for (auto i : as_vector<string>(survey, "questions")) {
        cout << i << "\n";
        getline(cin, answer);
        msg = msg + "\"" + answer + "\",";
    }

    msg[msg.length()-1] = ' ';
    msg+="]";

    cout << "\nmsg : " << msg << endl;

    // msg = "reeaeeeeeeeeeeeeeeeeeeeeeeeeeeeallylongmessagethatwillbelong";

    finalmsg = submitMessage(msg.c_str(), cred, RAVK.c_str(), uidsig.c_str(), vid.c_str(), vk.c_str());
    boost::replace_all(finalmsg, "\n", "~");

    cout << "finalmessage: \n" << finalmsg << endl;

    cout << "\n\nlength: " << finalmsg.length() << endl;
    cout << "size: " << finalmsg.size() << endl;

    auto submit_response =client.request("POST", "/submit", finalmsg);
    cout << "Submit Response : " << submit_response->content.rdbuf() << endl;

    return 0;
}
