#include "server_https.hpp"

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
#include <boost/algorithm/string.hpp>

#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <stdlib.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <sqlite3.h>

extern "C" {
#include "anon.h"
}

using namespace std;
//Added for the json-example:
using namespace boost::property_tree;

typedef SimpleWeb::Server<SimpleWeb::HTTPS> HttpsServer;

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

const char* getUidsig(const char* uid, const char* sigs){
    const char* s = sigs;
    do{
        const char *l = strchr(s, '\n');
        if(l){
            if(strncmp(uid,s, strlen(uid)) == 0)
            {
                if((int)(strchr(s, ',')-s) == strlen(uid)){
                    char *ret = new char[(int)(l-s)+1];             
                    strncpy(ret, s, (int)(l-s));
                    ret[(int)(l-s)] = '\0';

                    return ret + strlen(uid) + 1;
                }
            } 
            s = l+1;
        } else {
            s = l;
        }

    } while(s);

    return NULL;
}

int verifyUID(const char* uid, const char *authorized){
    const char* auth = authorized;
    do{
        const char *l = strchr(auth, '\n');
        if(l){
            if(strncmp(uid,auth, strlen(uid)) == 0)
                return 1; 

            auth = l+1;
        } else {
            if(strncmp(uid,auth, strlen(uid)) == 0)
                return 1;

            auth = l;
        }

    } while(auth);

    return 0;
}

string getQuestions(){
    ifstream infile;
    infile.open("server/q.dat");
    string question, json_string = "{\"questions\" : [";

    while(!infile.eof()){
        getline(infile, question);
        json_string = json_string + "\"" + question + "\"";
        if (infile.peek()!=EOF)
            json_string = json_string + ","; 
    }

    infile.ignore();

    json_string = json_string + "]}";

    return json_string;
}

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
   int i;
   for(i=0; i<argc; i++){
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   return 0;
}


int main() {
   
   static sqlite3 *db;
   char *zErrMsg = 0;
   int  rc;
   char *sql;

   bool init = false;
   bool vinit = false;

   /* Open database */
   rc = sqlite3_open("RA.db", &db);
   if( rc ){
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      exit(0);
   }else{
      fprintf(stdout, "Opened database successfully\n");
   }

   /* Create SQL statement */
   sql = "CREATE TABLE CLIENTS("  \
         "UID CHAR(30) PRIMARY KEY     NOT NULL," \
         "REQUESTED INT," \
         "SIG CHAR(1024)," \
         "SID INT);";

   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   if( rc != SQLITE_OK ){
   fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }else{
      fprintf(stdout, "CLIENTS Table created successfully\n");
   }


    sql = "CREATE TABLE RESPONSES("  \
         "TOKEN TEXT NOT NULL," \
         "INCIDENTS INT," \
         "DEVICES INT," \
         "INDUSTRY CHAR(30) NOT NULL);";
         
   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   if( rc != SQLITE_OK ){
   fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }else{
      fprintf(stdout, " RESPONSE Table created successfully\n");
   }

   sql = "CREATE TABLE RA("  \
         "ID INT PRIMARY KEY NOT NULL," \
         "RAVK CHAR(2048) NOT NULL," \
         "RASK CHAR(2048) NOT NULL);";
         
   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        if(strcmp(zErrMsg,"table RA already exists "))
            init = true;
        sqlite3_free(zErrMsg);
   }else{
      fprintf(stdout, "RA Table created successfully\n");
   }

    sql = "CREATE TABLE VA("  \
         "ID INT PRIMARY KEY NOT NULL," \
         "VID CHAR(1024) NOT NULL," \
         "VAVK CHAR(2048) NOT NULL," \
         "VASK CHAR(2048) NOT NULL," \
         "COUNT INT NOT NULL);";
         
   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        if(strcmp(zErrMsg,"table VA already exists "))
            vinit = true;
        sqlite3_free(zErrMsg);
   }else{
      fprintf(stdout, "VA Table created successfully\n");
   }



    initAnonize();
    cout<<"initAnonize()"<<endl;

   static char RAVK[2048], RASK[2048];
   if(!init){
        if (!makeKey(RAVK,RASK)) {
            fprintf(stderr, "!!!! error making keys.");
            exit(1);
        }
        string in = "INSERT INTO RA (ID,RAVK,RASK) " \
                    "VALUES (1, \'" + string(RAVK) + "\', \'" + string(RASK) + "\');";
       rc = sqlite3_exec(db, in.c_str(), callback, 0, &zErrMsg);
       if( rc != SQLITE_OK ){
          fprintf(stderr, "SQL error: %s\n", zErrMsg);
          sqlite3_free(zErrMsg);
       }else{
          fprintf(stdout, "KEYS saved successfully\n");
       }
    } else{

        /* Execute SQL statement */
        sqlite3_stmt * stmt;
        sqlite3_prepare_v2( db, "SELECT * from RA WHERE ID =1;", -1, &stmt, NULL );
        sqlite3_step(stmt);
        strcpy(RAVK, (char *)sqlite3_column_text( stmt, 1 ));
       //printf("RAVK : %s\n\n", sqlite3_column_text( stmt, 1 ));

        //printf("RASK : %s\n\n", sqlite3_column_text( stmt, 2 ));
        strcpy(RASK,(char *)sqlite3_column_text( stmt, 2 ));

        pretty(RAVK,"RAVK");
        pretty(RASK,"RASK");
        sqlite3_finalize(stmt);
    }

    static string auth_uids = "";


    // const char* emails2 = "efwefwe\nbdfsdfwew\nalfwew2ice\nAn2ita\nsdfsDfsdf\nedfsdfwewwueh";
    static survey s;
    
    printf(" ******************************************** \n\n");

    if(!vinit){
        if (createSurvey(&s) != 1) {
            fprintf(stderr, "!!!! ERROR CREATING Survey!\n");
            exit(1);        
        }

        //pretty(s.sigs,"SIGS");

       string in = "INSERT INTO VA (ID,VID,VAVK,VASK,COUNT) " \
                    "VALUES (1, \'" + string(s.vid) + "\', \'" + string(s.vavk) + "\', \'" + string(s.vask) + "\', "+ to_string(s.cnt) + ");";
       rc = sqlite3_exec(db, in.c_str(), callback, 0, &zErrMsg);
       if( rc != SQLITE_OK ){
          fprintf(stderr, "SQL error: %s\n", zErrMsg);
          sqlite3_free(zErrMsg);
       }else{
          fprintf(stdout, "Survey saved successfully\n");
       }

    } else{

        sqlite3_stmt * stmt;
        sqlite3_prepare_v2( db, "SELECT * from VA WHERE ID =1;", -1, &stmt, NULL );
        sqlite3_step(stmt);

        static string vid((char *)sqlite3_column_text( stmt, 1 ));
        static string vk((char *)sqlite3_column_text( stmt, 2 ));
        static string sk((char *)sqlite3_column_text( stmt, 3 ));

        s.vid = vid.c_str();
        s.vavk = vk.c_str();
        s.vask = sk.c_str();

        s.cnt = sqlite3_column_int( stmt, 4 );
        s.sigs = NULL;
        sqlite3_finalize(stmt);
    }

        pretty(s.vavk,"VAVK1");
        pretty(s.vask,"VASK1");
        pretty(s.vid, "VID1");
        cout <<"CNT1: "<< s.cnt <<endl;
        //pretty(s.sigs, "SIGS1");

    // if (extendSurvey(emails2, &s) != 6) {
    //  fprintf(stderr, "!!!! ERROR extending Survey!\n");
    //  exit(1);        
    // }


    //HTTPS-server at port 8080 using 4 threads
    HttpsServer server(8080, 4, "server/server.crt", "server/server.key");
    
    //Add resources using path-regex and method-string, and an anonymous function
    //POST-example for the path /string, responds the posted string

    server.resource["^/registerUser$"]["POST"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {
        
        //add uid to list of authorized uids
        string uid = request->content.string();
        auth_uids+=uid;

        sqlite3_stmt * stmt;
        string sql = "SELECT COUNT(*),REQUESTED from CLIENTS WHERE UID=\'" + uid +"\';";
        sqlite3_prepare_v2( db, sql.c_str(), -1, &stmt, NULL );
        sqlite3_step(stmt);
        int client = sqlite3_column_int(stmt, 0);
        int req = sqlite3_column_int(stmt, 1);
        sqlite3_finalize(stmt);

        cout << "uid: " << uid << endl<<"req: " << req << endl<<"client: " << client << endl;



        if(client != 0){
            if(req == 0){
                if (extendSurvey(uid.c_str(), &s) != 1) {

                    string  err = "There was a problem extending the survey to your UID";
                    response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << err.length() << "\r\n\r\n" << err;
                    fprintf(stderr, "UID: %s  !!!! ERROR extending Survey!\n", uid.c_str());
                }

                cout <<"sigs: "<< s.sigs << endl;
                
                char *zErrMsg = 0;
                int  rc;
               string in = "UPDATE CLIENTS SET SIG= \'" + string(getUidsig(uid.c_str(), s.sigs)) + "\', REQUESTED="+ to_string(++req) +" WHERE UID=\'" +uid+"\' AND SID=1;";
               rc = sqlite3_exec(db, in.c_str(), callback, 0, &zErrMsg);
               if( rc != SQLITE_OK ){
                  fprintf(stderr, "SQL error: %s\n", zErrMsg);
                  sqlite3_free(zErrMsg);
               }else{
                  fprintf(stdout, "SIG updated successfully\n");
               }
               printf("Registered User: %s\n\n", uid.c_str());
               response << "HTTP/1.1 200 OK\r\nContent-Length: " << (unsigned) strlen(RAVK) << "\r\n\r\n" << RAVK;
            }
        } else {
                string  err = "There was a problem.";
                response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << err.length() << "\r\n\r\n" << err;
        }

       //printf("RAVK : %s\n\n", sqlite3_column_text( stmt, 1 ));

        
        //delimited by new lines
        //auth_uids+="";

        


        
    };


    server.resource["^/registerServerResponse$"]["POST"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {
        //Retrieve string:
        try {
            ptree pt;
            read_json(request->content, pt);

            string uid = pt.get<string>("uid");
            string reg = pt.get<string>("reg");

            string reg2 = registerServerResponse(uid.c_str(), reg.c_str(), RASK);

            //request->content.string() is a convenience function for:
            //stringstream ss;
            //ss << request->content.rdbuf();
            //string content=ss.str();
            
            response << "HTTP/1.1 200 OK\r\nContent-Length: " << reg2.length() << "\r\n\r\n" << reg2;
            
        }
        catch(exception& e) {
            cout << "registerServerResponse error" << endl;
            response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n" << e.what();
        }
    };

    server.resource["^/surveyCred$"]["POST"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {
        
        //add uid to list of authorized uids
        string uid = request->content.string();
        
        string uidsig = getUidsig(uid.c_str(), s.sigs);

        cout << uid << " SIG: " << uidsig << endl;

        string json_string="{\"uidsig\": \"" + uidsig + "\",\"vid\": \"" + s.vid + "\",\"vk\": \"" + s.vavk + "\"}";

        response << "HTTP/1.1 200 OK\r\nContent-Length: " << json_string.length() << "\r\n\r\n" << json_string;

    };

    server.resource["^/submit$"]["POST"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {
        cout << "submite called" << endl;
        //add uid to list of authorized uids
        string msg = request->content.string();

        boost::replace_all(msg, "~", "\n");

        
        survey_response sr;
        string result;
        int r = verifyMessage(msg.c_str(), RAVK, s.vid, s.vavk, &sr);
        if (!r) {
            result = "\n\nMessage failed to Verify\n\n";
            cout << result << endl;
        } else {
            result = "\n\nSuccessful verification\n\n";
            printf(" === SUCCEED ===\n");
        }

        vector<string> strs;
        boost::split(strs, sr.msg, boost::is_any_of(","));
        


        char *zErrMsg = 0;
        int  rc;

        sqlite3_stmt * stmt;
        string sql = "SELECT COUNT(*) from RESPONSES WHERE TOKEN=\'" + string(sr.token) +"\';";
        sqlite3_prepare_v2( db, sql.c_str(), -1, &stmt, NULL );
        sqlite3_step(stmt);
        int exists = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);

        cout << "token" << string(sr.token)<<endl;

        if(!exists){       
           string in = "INSERT INTO RESPONSES(TOKEN, INCIDENTS, DEVICES, INDUSTRY) VALUES(\'"+ string(sr.token) + "\'," + strs[0] + "," + strs[1] + ",\'" + strs[2] + "\');"; 
           rc = sqlite3_exec(db, in.c_str(), callback, 0, &zErrMsg);
           if( rc != SQLITE_OK ){
              fprintf(stderr, "SQL error: %s\n", zErrMsg);
              sqlite3_free(zErrMsg);
           }else{
              fprintf(stdout, "Responses inserted\n");
           }
           result = "Submitted";
        } else{
            result = "Responded";
        }

        cout << sr.token <<": " << sr.msg << endl;
        freeSurveyResponse(&sr);

        response << "HTTP/1.1 200 OK\r\nContent-Length: " << result.length() << "\r\n\r\n" << result;

    };

    server.resource["^/survey$"]["GET"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {

        string json_string = getQuestions();

        response << "HTTP/1.1 200 OK\r\nContent-Length: " << json_string.length() << "\r\n\r\n" << json_string;

    };

    server.resource["^/report"]["GET"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {

        string json_string;

        response << "HTTP/1.1 200 OK\r\nContent-Length: " << json_string.length() << "\r\n\r\n" << json_string;

    };

    

    //POST-example for the path /json, responds firstName+" "+lastName from the posted json
    //Responds with an appropriate error message if the posted json is not valid, or if firstName or lastName is missing
    //Example posted json:
    //{
    //  "firstName": "John",
    //  "lastName": "Smith",
    //  "age": 25
    //}
    server.resource["^/json$"]["POST"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {
        try {
            ptree pt;
            read_json(request->content, pt);

            string name=pt.get<string>("firstName")+" "+pt.get<string>("lastName");
            
            response << "HTTP/1.1 200 OK\r\nContent-Length: " << name.length() << "\r\n\r\n" << name;
        }
        catch(exception& e) {
            response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n" << e.what();
        }
    };
    
    //GET-example for the path /info
    //Responds with request-information
    server.resource["^/info$"]["GET"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {
        stringstream content_stream;
        content_stream << "<h1>Request from " << request->remote_endpoint_address << " (" << request->remote_endpoint_port << ")</h1>";
        content_stream << request->method << " " << request->path << " HTTP/" << request->http_version << "<br>";
        for(auto& header: request->header) {
            content_stream << header.first << ": " << header.second << "<br>";
        }
        
        //find length of content_stream (length received using content_stream.tellp())
        content_stream.seekp(0, ios::end);
        
        response <<  "HTTP/1.1 200 OK\r\nContent-Length: " << content_stream.tellp() << "\r\n\r\n" << content_stream.rdbuf();
    };


    server.resource["^/surveyCred$"]["GET"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {
        response << "HTTP/1.1 200 OK\r\nContent-Length: " << (unsigned) strlen(RAVK) << "\r\n\r\n" << RAVK;
    };
    
    //GET-example for the path /match/[number], responds with the matched string in path (number)
    //For instance a request GET /match/123 will receive: 123
    server.resource["^/match/([0-9]+)$"]["GET"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {
        string number=request->path_match[1];
        response << "HTTP/1.1 200 OK\r\nContent-Length: " << number.length() << "\r\n\r\n" << number;
    };
    
    //Default GET-example. If no other matches, this anonymous function will be called. 
    //Will respond with content in the web/-directory, and its subdirectories.
    //Default file: index.html
    //Can for instance be used to retrieve an HTML 5 client that uses REST-resources on this server
    server.default_resource["GET"]=[](HttpsServer::Response& response, shared_ptr<HttpsServer::Request> request) {
        const auto web_root_path=boost::filesystem::canonical("web");
        boost::filesystem::path path=web_root_path;
        path/=request->path;
        if(boost::filesystem::exists(path)) {
            path=boost::filesystem::canonical(path);
            //Check if path is within web_root_path
            if(distance(web_root_path.begin(), web_root_path.end())<=distance(path.begin(), path.end()) &&
               equal(web_root_path.begin(), web_root_path.end(), path.begin())) {
                if(boost::filesystem::is_directory(path))
                    path/="index.html";
                if(boost::filesystem::exists(path) && boost::filesystem::is_regular_file(path)) {
                    ifstream ifs;
                    ifs.open(path.string(), ifstream::in | ios::binary);
                    
                    if(ifs) {
                        ifs.seekg(0, ios::end);
                        size_t length=ifs.tellg();
                        
                        ifs.seekg(0, ios::beg);
                        
                        response << "HTTP/1.1 200 OK\r\nContent-Length: " << length << "\r\n\r\n";
                        
                        //read and send 128 KB at a time
                        const size_t buffer_size=131072;
                        array<char, buffer_size> buffer;
                        size_t read_length;
                        try {
                            while((read_length=ifs.read(&buffer[0], buffer_size).gcount())>0) {
                                response.write(&buffer[0], read_length);
                                response.flush();
                            }
                        }
                        catch(const exception &e) {
                            cerr << "Connection interrupted, closing file" << endl;
                        }
        
                        ifs.close();
                        return;
                    }
                }
            }
        }
        string content="Could not open path "+request->path;
        response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << content.length() << "\r\n\r\n" << content;
    };

    
    thread server_thread([&server](){
        //Start server
        server.start();
    });
    
    // //Wait for server to start so that the client can connect
    // this_thread::sleep_for(chrono::seconds(1));
    
    // //Client examples
    // //Second Client() parameter set to false: no certificate verification
    // HttpsClient client("localhost:8080", false);
    // auto r1=client.request("GET", "/match/123");
    // cout << r1->content.rdbuf() << endl;

    // const char* precred = makeCred(uid);
    // string reg1 = registerUserMessage(precred, RAVK);
    // auto r2=client.request("POST", "/register", reg1);
    // stringstream ss;
    // ss << r2->content.rdbuf();
    // string reg2=ss.str();
    // // cout << reg2->content.rdbuf() << endl;
    // const char* cred = registerUserFinal(uid, reg2.c_str(), precred, RAVK);

    // pretty(cred,"cred");


    
    // // auto r3=client.request("POST", "/json", json_string);
    // // cout << r3->content.rdbuf() << endl;
    
    server_thread.join();
    sqlite3_close(db);
    return 0;
}