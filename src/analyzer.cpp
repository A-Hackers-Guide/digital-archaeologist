#include "analyzer.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <array>

namespace da {
namespace {
using U=std::uint32_t;
U R(U x,int n){return (x>>n)|(x<<(32-n));}
std::string sha256(const std::vector<unsigned char>& in){
 static const U K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 U h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 std::vector<unsigned char> d=in; std::uint64_t bits=(std::uint64_t)d.size()*8; d.push_back(0x80); while(d.size()%64!=56)d.push_back(0); for(int i=7;i>=0;i--)d.push_back((unsigned char)(bits>>(i*8)));
 for(size_t off=0;off<d.size();off+=64){ U w[64]{}; for(int i=0;i<16;i++)for(int j=0;j<4;j++)w[i]=(w[i]<<8)|d[off+i*4+j]; for(int i=16;i<64;i++){U s0=R(w[i-15],7)^R(w[i-15],18)^(w[i-15]>>3);U s1=R(w[i-2],17)^R(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;} U a=h[0],b=h[1],c=h[2],e=h[4],f=h[5],g=h[6],hh=h[7],dd=h[3]; for(int i=0;i<64;i++){U S1=R(e,6)^R(e,11)^R(e,25);U ch=(e&f)^((~e)&g);U t1=hh+S1+ch+K[i]+w[i];U S0=R(a,2)^R(a,13)^R(a,22);U maj=(a&b)^(a&c)^(b&c);U t2=S0+maj;hh=g;g=f;f=e;e=dd+t1;dd=c;c=b;b=a;a=t1+t2;} h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=dd;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh; }
 std::ostringstream x; x<<std::hex<<std::setfill('0'); for(U v:h)x<<std::setw(8)<<v; return x.str();
}
bool eq(const std::vector<unsigned char>&d,std::initializer_list<unsigned char> s,size_t p=0){return p+s.size()<=d.size()&&std::equal(s.begin(),s.end(),d.begin()+p);}
void add(std::vector<Detection>& out,std::string c,std::string f,int conf,std::initializer_list<Evidence> e){out.push_back({std::move(c),std::move(f),conf,std::vector<Evidence>(e)});}
}
Report analyze(const std::filesystem::path& p){
 Report r; r.path=p; std::ifstream f(p,std::ios::binary); if(!f)throw std::runtime_error("cannot open input"); f.seekg(0,std::ios::end); r.size=(std::uintmax_t)f.tellg(); f.seekg(0); std::vector<unsigned char>d((size_t)r.size); if(!d.empty())f.read((char*)d.data(),(std::streamsize)d.size());
 r.sha256=sha256(d); std::map<unsigned,int> cnt; for(unsigned char c:d)cnt[c]++; if(!d.empty())for(auto [c,n]:cnt){double q=(double)n/d.size();r.entropy-=q*std::log2(q);}
 auto A=[&](std::string c,std::string fmt,int conf,std::initializer_list<Evidence> e){add(r.detections,c,fmt,conf,e);};
 if(eq(d,{0x4d,0x5a}))A("executable","Windows PE/DOS MZ",100,{{"signature","MZ header",100}});
 if(eq(d,{0x7f,'E','L','F'}))A("executable","ELF",100,{{"signature","ELF magic",100}});
 if(eq(d,{0xfe,0xed,0xfa,0xce})||eq(d,{0xce,0xfa,0xed,0xfe})||eq(d,{0xfe,0xed,0xfa,0xcf})||eq(d,{0xcf,0xfa,0xed,0xfe})||eq(d,{0xca,0xfe,0xba,0xbe})||eq(d,{0xbe,0xba,0xfe,0xca}))A("executable","Mach-O / universal binary",100,{{"signature","Apple executable magic",100}});
 if(eq(d,{0x25,0x50,0x44,0x46,0x2d}))A("document","PDF",100,{{"signature","%PDF-",100}});
 if(eq(d,{0x89,'P','N','G',0x0d,0x0a,0x1a,0x0a}))A("image","PNG",100,{{"signature","PNG magic",100}});
 if(eq(d,{0xff,0xd8,0xff}))A("image","JPEG",100,{{"signature","JPEG SOI",100}});
 if(eq(d,{'G','I','F','8'}))A("image","GIF",100,{{"signature","GIF header",100}});
 if(eq(d,{'P','K',0x03,0x04})||eq(d,{'P','K',0x05,0x06})||eq(d,{'P','K',0x07,0x08}))A("container","ZIP",100,{{"signature","PK ZIP signature",100}});
 if(eq(d,{0x1f,0x8b}))A("container","GZIP",100,{{"signature","gzip magic",100}});
 if(eq(d,{'7','z',0xbc,0xaf,0x27,0x1c}))A("container","7-Zip",100,{{"signature","7z magic",100}});
 if(eq(d,{'R','a','r','!',0x1a,0x07}))A("container","RAR",100,{{"signature","RAR marker",100}});
 if(eq(d,{'S','Q','L','i','t','e',' ','f','o','r','m','a','t',' ','3',0}))A("database","SQLite 3",100,{{"signature","SQLite header",100}});
 if(d.size()>=0x8006 && std::string(d.begin()+0x8001,d.begin()+0x8006)=="CD001")A("filesystem","ISO 9660",100,{{"signature","Primary Volume Descriptor",100}});
 if(d.size()>=512 && d[510]==0x55&&d[511]==0xaa)A("partition","MBR-compatible boot sector",90,{{"signature","0x55AA at sector 0",60},{"structure","possible partition table",30}});
 if(d.size()>=520 && eq(d,{'E','F','I',' ','P','A','R','T'},512))A("partition","GPT protective/EFI header",100,{{"signature","EFI PART at LBA1",100}});
 if(d.size()>=11 && std::string(d.begin()+3,d.begin()+11)=="NTFS    ")A("filesystem","NTFS",100,{{"signature","NTFS OEM ID",100}});
 if(d.size()>=90 && std::string(d.begin()+3,d.begin()+11)=="EXFAT   ")A("filesystem","exFAT",100,{{"signature","EXFAT OEM ID",100}});
 if(d.size()>=8 && (std::string(d.begin()+3,d.begin()+8)=="FAT12"||std::string(d.begin()+3,d.begin()+8)=="FAT16"))A("filesystem","FAT12/FAT16",95,{{"signature","FAT OEM label",80},{"structure","boot-sector geometry",15}});
 if(d.size()>=90 && std::string(d.begin()+54,d.begin()+62)=="FAT32   ")A("filesystem","FAT32",100,{{"signature","FAT32 label",100}});
 if(d.size()>=0x43a && d[0x438]==0x53&&d[0x439]==0xef)A("filesystem","ext2/ext3/ext4",100,{{"signature","superblock magic 0xEF53",100}});
 if(d.size()>=0x48 && std::string(d.begin()+0x40,d.begin()+0x48)=="NXSB\0\0\0\0")A("filesystem","APFS",100,{{"signature","NXSB container superblock",100}});
 if(d.size()>=0x400 && std::string(d.begin()+0x400,d.begin()+0x404)=="H+\0\0")A("filesystem","HFS+ (heuristic)",85,{{"signature","HFS+ signature location",70},{"structure","volume header position",15}});
 if(d.size()>=4 && eq(d,{'h','s','q','s'}))A("filesystem","SquashFS",100,{{"signature","hsqs superblock",100}});
 if(r.entropy>7.5)r.notes.push_back("High entropy: data may be compressed, encrypted, packed, or otherwise binary-dense.");
 else if(r.entropy<2.0)r.notes.push_back("Very low entropy: data is highly repetitive or sparse.");
 if(r.detections.empty())r.notes.push_back("No known signature matched. This is not proof that the format is unknown; inspect structure, entropy, strings, and offsets next.");
 return r;
}
void print_report(const Report&r){
 std::cout<<"DIGITAL ARCHAEOLOGIST v1.0.0-pre1\n"<<"Input: "<<r.path.string()<<"\nSize: "<<r.size<<" bytes\nSHA-256: "<<r.sha256<<"\nEntropy: "<<std::fixed<<std::setprecision(4)<<r.entropy<<" bits/byte\n\n";
 if(r.detections.empty())std::cout<<"Detection: UNKNOWN / UNRESOLVED\n"; else for(const auto&d:r.detections){std::cout<<"Detection: "<<d.format<<" ["<<d.confidence<<"%] ("<<d.category<<")\n";for(const auto&e:d.evidence)std::cout<<"  + "<<e.label<<": "<<e.detail<<" ("<<e.weight<<")\n";}
 for(const auto&n:r.notes)std::cout<<"Note: "<<n<<"\n";
 if(!r.detections.empty()&&r.detections.front().confidence==100)std::cout<<"\nCOMPLETE ANSWER FOUND (for the matched signature; structural completeness is not guaranteed).\n";
}
}

