#include "analyzer.hpp"
#include "base64.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

static void help(){
 std::cout<<"Digital Archaeologist v1.2.0\n\n"
 <<"Usage: archaeologist [options] <file>\n\n"
 <<"Core:\n  archaeologist <file>       Analyze by bytes, not extension\n  -u, --unknown <file>       Unknown-format research profile\n  -L, --linux <file>         Linux/filesystem profile\n  -M, --macos <file>         macOS/filesystem profile\n  -W, --windows <file>       Windows/filesystem profile\n  -p, --password <file>      Encryption/recovery metadata profile\n\n"
 <<"Transport:\n  --transport-encode <file>  Base64 encode exact bytes to stdout\n  --transport-decode <file>  Decode Base64 text file to <file>.decoded\n\n"
 <<"Other:\n  -h, --help                 Show help\n  --help unknown             Explain unknown research mode\n  --help password             Explain authorized recovery mode\n  --version                  Show version\n\n"
 <<"Safety: analysis is read-only. No disk mounting, kernel-driver installation, or\n"
 <<"unattended password cracking is performed by this prototype.\n";
}
static std::vector<unsigned char> read_bytes(const std::string&p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("cannot open input");f.seekg(0,std::ios::end);auto n=f.tellg();f.seekg(0);std::vector<unsigned char>d((size_t)n);if(n>0)f.read((char*)d.data(),n);return d;}
int main(int argc,char**argv){
 try{
  if(argc<2){help();return 2;}
  std::string a=argv[1];
  if(a=="-h"||a=="--help"){help();return 0;}
  if(a=="--version"){std::cout<<"1.2.0\n";return 0;}
  if(a=="--help"&&argc>2){help();return 0;}
  if(a=="--transport-encode"){
   if(argc<3)throw std::runtime_error("missing file"); std::cout<<da::base64_encode(read_bytes(argv[2]))<<"\n";return 0;
  }
  if(a=="--transport-decode"){
   if(argc<3)throw std::runtime_error("missing Base64 text file");std::ifstream f(argv[2]);std::stringstream s;s<<f.rdbuf();auto d=da::base64_decode(s.str());std::string out=std::string(argv[2])+".decoded";std::ofstream o(out,std::ios::binary);o.write((char*)d.data(),d.size());std::cout<<"Decoded "<<d.size()<<" bytes to "<<out<<"\n";return 0;
  }
  std::string mode="general", path=a;
  if(a=="-u"||a=="--unknown"||a=="-L"||a=="--linux"||a=="-M"||a=="--macos"||a=="-W"||a=="--windows"||a=="-p"||a=="--password"){
   if(argc<3)throw std::runtime_error("missing file"); path=argv[2];mode=a;
  }
  auto r=da::analyze(path); std::cout<<"Profile: "<<mode<<"\n"; da::print_report(r);
  if(mode=="-p"||mode=="--password")std::cout<<"\nRecovery policy: provide known/authorized credentials manually; this v1 prototype does not brute-force or bypass encryption.\n";
  if(mode=="-u"||mode=="--unknown")std::cout<<"\nResearch profile: no known signature is treated as failure. Next-stage structural inference belongs to the v1.x research engine.\n";
  return 0;
 }catch(const std::exception&e){std::cerr<<"Error: "<<e.what()<<"\n";return 1;}
}
