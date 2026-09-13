#include "base64.hpp"
#include <array>
namespace da {
static constexpr char T[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string base64_encode(const std::vector<unsigned char>& d){
 std::string o; o.reserve(((d.size()+2)/3)*4);
 for(size_t i=0;i<d.size();i+=3){ unsigned v=d[i]<<16; if(i+1<d.size())v|=d[i+1]<<8; if(i+2<d.size())v|=d[i+2]; o+=T[(v>>18)&63]; o+=T[(v>>12)&63]; o+=(i+1<d.size()?T[(v>>6)&63]:'='); o+=(i+2<d.size()?T[v&63]:'='); }
 return o;
}
std::vector<unsigned char> base64_decode(const std::string& s){
 std::array<int,256> m{}; m.fill(-1); for(int i=0;i<64;i++)m[(unsigned char)T[i]]=i;
 std::vector<unsigned char> o; int v=0,b=-8; for(unsigned char c:s){ if(c=='='||m[c]<0)continue; v=(v<<6)|m[c]; b+=6; if(b>=0){o.push_back((unsigned char)((v>>b)&255));b-=8;} } return o;
}
}
