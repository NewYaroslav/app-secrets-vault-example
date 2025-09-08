#include <cassert>
#include <string>
#include <vector>
#include <array>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <chrono>

#include <aes_cpp/aes_utils.hpp>
#include <hmac_cpp/hmac_utils.hpp>
#include <hmac_cpp/encoding.hpp>
#include <hmac_cpp/secret_string.hpp>
#include <obfy/obfy_str.hpp>

#include "json.hpp"
using json = nlohmann::json;

using namespace aes_cpp;
using namespace hmac_cpp;

static std::string pepper() { return std::string(OBFY_STR("demo_pepper")); }

static std::vector<uint8_t> to_bytes(const std::string& s){
    return std::vector<uint8_t>(s.begin(), s.end());
}

static std::string b64enc(const std::vector<uint8_t>& v){
    return hmac_cpp::base64_encode(v);
}
static std::vector<uint8_t> b64dec(const std::string& s){
    std::vector<uint8_t> out; if(!hmac_cpp::base64_decode(s,out)) throw std::runtime_error("b64"); return out; }

static std::array<uint8_t,32> derive_key(const std::string& password,
                                         const std::vector<uint8_t>& salt,
                                         uint32_t iters) {
    auto pw = to_bytes(password);
    auto pep = to_bytes(pepper());
    auto vec = pbkdf2_with_pepper(pw, salt, pep, iters, 32);
    std::array<uint8_t,32> key{};
    std::copy(vec.begin(), vec.end(), key.begin());
    return key;
}

static void test_simple() {
    const std::string master = "m";
    const std::string payload = "a:b";
    const uint32_t iters = 1000;
    const std::string aad = "t";

    auto salt = random_bytes(16);
    auto key  = derive_key(master, salt, iters);
    std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
    auto enc = utils::encrypt_gcm(payload, key, aad_bytes);
    std::string serialized = std::to_string(iters) + ":" +
       b64enc(salt) + ":" +
       b64enc(std::vector<uint8_t>(enc.iv.begin(), enc.iv.end())) + ":" +
       b64enc(std::vector<uint8_t>(enc.tag.begin(), enc.tag.end())) + ":" +
       b64enc(enc.ciphertext);
    std::vector<std::string> parts; std::stringstream ss(serialized); std::string item;
    while (std::getline(ss, item, ':')) parts.push_back(item);
    assert(parts.size()==5);
    uint32_t iters2 = static_cast<uint32_t>(std::stoul(parts[0]));
    auto salt2 = b64dec(parts[1]);
    auto iv2 = b64dec(parts[2]);
    auto tag2 = b64dec(parts[3]);
    auto ct2 = b64dec(parts[4]);
    auto key2 = derive_key(master, salt2, iters2);
    utils::GcmEncryptedData packet;
    std::copy(iv2.begin(), iv2.end(), packet.iv.begin());
    packet.ciphertext = ct2;
    std::copy(tag2.begin(), tag2.end(), packet.tag.begin());
    auto plain = utils::decrypt_gcm_to_string(packet, key2, aad_bytes);
    assert(plain == payload);
}

struct VaultFile {
    uint32_t v = 1;
    uint32_t iters;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ct;
    std::string aad;
};

static std::string serialize_vault(const VaultFile& vf) {
    json j;
    j["v"] = vf.v;
    j["kdf"] = {{"name","PBKDF2-HMAC-SHA256"},{"iters",vf.iters},{"salt",b64enc(vf.salt)},{"dkLen",32}};
    j["aead"] = {{"alg","AES-256-GCM"},{"iv",b64enc(vf.iv)},{"tag",b64enc(vf.tag)}};
    j["ciphertext"] = b64enc(vf.ct);
    if(!vf.aad.empty()) j["aad"]=vf.aad;
    return j.dump();
}
static VaultFile parse_vault(const std::string& s) {
    auto j = json::parse(s);
    VaultFile vf; vf.v=j.at("v").get<uint32_t>();
    auto jk=j.at("kdf"); vf.iters=jk.at("iters").get<uint32_t>(); vf.salt=b64dec(jk.at("salt").get<std::string>());
    auto ja=j.at("aead"); vf.iv=b64dec(ja.at("iv").get<std::string>()); vf.tag=b64dec(ja.at("tag").get<std::string>());
    vf.ct=b64dec(j.at("ciphertext").get<std::string>());
    vf.aad=j.value("aad","");
    return vf;
}
static VaultFile create_vault(const std::string& master,const std::string& email,const std::string& password,uint32_t iters,const std::string& aad){
    VaultFile vf; vf.v=1; vf.iters=iters; vf.salt=random_bytes(16); auto key=derive_key(master,vf.salt,iters); json payload={{"email",email},{"password",password}}; auto plain=to_bytes(payload.dump()); std::vector<uint8_t> aadb=to_bytes(aad); auto enc=utils::encrypt_gcm(plain,key,aadb); vf.iv.assign(enc.iv.begin(),enc.iv.end()); vf.ct=std::move(enc.ciphertext); vf.tag.assign(enc.tag.begin(),enc.tag.end()); vf.aad=aad; return vf; }
static json open_vault(const std::string& master,const VaultFile& vf){ auto key=derive_key(master,vf.salt,vf.iters); std::array<uint8_t,12> iv{}; std::copy(vf.iv.begin(),vf.iv.end(),iv.begin()); std::array<uint8_t,16> tag{}; std::copy(vf.tag.begin(),vf.tag.end(),tag.begin()); std::vector<uint8_t> aadb=to_bytes(vf.aad); utils::GcmEncryptedData pkt{std::chrono::system_clock::now(),iv,vf.ct,tag}; auto plain=utils::decrypt_gcm_to_string(pkt,key,aadb); return json::parse(plain); }

static std::string b64url_encode(const std::vector<uint8_t>& d){ auto s=b64enc(d); std::replace(s.begin(),s.end(),'+','-'); std::replace(s.begin(),s.end(),'/','_'); while(!s.empty()&&s.back()=='=') s.pop_back(); return s; }
static std::vector<uint8_t> b64url_decode(const std::string& s){ std::string t=s; std::replace(t.begin(),t.end(),'-','+'); std::replace(t.begin(),t.end(),'_','/'); while(t.size()%4) t.push_back('='); return b64dec(t); }

static void test_json(){
    const std::string master="m", email="e", pass="p";
    auto vf=create_vault(master,email,pass,1000,"t");
    auto text=serialize_vault(vf);
    auto parsed=parse_vault(text);
    auto payload=open_vault(master,parsed);
    assert(payload.at("email").get<std::string>()==email);
    assert(payload.at("password").get<std::string>()==pass);
}

static void test_jwr(){
    const std::string master="m", email="e", pass="p";
    auto vf=create_vault(master,email,pass,1000,"t");
    std::string header=json({{"typ","JWR"}}).dump();
    std::string body=serialize_vault(vf);
    std::string token=b64url_encode(to_bytes(header))+"."+b64url_encode(to_bytes(body));
    auto pos=token.find('.'); assert(pos!=std::string::npos);
    auto body_bytes=b64url_decode(token.substr(pos+1));
    auto parsed=parse_vault(std::string(body_bytes.begin(),body_bytes.end()));
    auto payload=open_vault(master,parsed);
    assert(payload.at("email").get<std::string>()==email);
    assert(payload.at("password").get<std::string>()==pass);
}

int main(){
    test_simple();
    test_json();
    test_jwr();
    return 0;
}

