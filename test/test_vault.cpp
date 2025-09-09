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
#include <hmac_cpp/secure_buffer.hpp>
#include <obfy/obfy_str.hpp>

#include "json.hpp"
using json = nlohmann::json;

using namespace aes_cpp;
using namespace hmac_cpp;

static std::string pepper() { return std::string(OBFY_STR("demo_pepper")); }

static std::string b64enc(const hmac_cpp::secure_buffer<uint8_t, true>& v){
    return hmac_cpp::base64_encode(v.data(), v.size());
}
static hmac_cpp::secure_buffer<uint8_t, true> b64dec(const std::string& s){
    std::vector<uint8_t> tmp; if(!hmac_cpp::base64_decode(s,tmp)) throw std::runtime_error("b64"); return hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp)); }

static hmac_cpp::secure_buffer<uint8_t, true> derive_key(const std::string& password,
                                                         const hmac_cpp::secure_buffer<uint8_t, true>& salt,
                                                         uint32_t iters) {
    std::string pw_copy(password);
    hmac_cpp::secure_buffer<uint8_t, true> pw(std::move(pw_copy));
    hmac_cpp::secure_buffer<uint8_t, true> pep{std::string(pepper())};
    auto vec = pbkdf2_with_pepper(pw.data(), pw.size(),
                                  salt.data(), salt.size(),
                                  pep.data(), pep.size(),
                                  iters, 32);
    return hmac_cpp::secure_buffer<uint8_t, true>(std::move(vec));
}

static void test_simple() {
    const std::string master = "m";
    const std::string payload = "a:b";
    const uint32_t iters = 1000;
    const std::string aad = "t";

    hmac_cpp::secure_buffer<uint8_t, true> salt(random_bytes(16));
    auto key  = derive_key(master, salt, iters);
    std::array<uint8_t,32> key_arr{}; std::copy(key.begin(), key.begin()+key_arr.size(), key_arr.begin());
    std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
    auto enc = utils::encrypt_gcm(payload, key_arr, aad_bytes);
    std::string serialized = std::to_string(iters) + ":" +
       b64enc(salt) + ":" +
       b64enc(hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.iv.begin(), enc.iv.end()))) + ":" +
       b64enc(hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.tag.begin(), enc.tag.end()))) + ":" +
       b64enc(hmac_cpp::secure_buffer<uint8_t,true>(std::move(enc.ciphertext)));
    std::vector<std::string> parts; std::stringstream ss(serialized); std::string item;
    while (std::getline(ss, item, ':')) parts.push_back(item);
    assert(parts.size()==5);
    uint32_t iters2 = static_cast<uint32_t>(std::stoul(parts[0]));
    auto salt2 = b64dec(parts[1]);
    auto iv2 = b64dec(parts[2]);
    auto tag2 = b64dec(parts[3]);
    auto ct2 = b64dec(parts[4]);
    auto key2 = derive_key(master, salt2, iters2);
    std::array<uint8_t,32> key2_arr{}; std::copy(key2.begin(), key2.begin()+key2_arr.size(), key2_arr.begin());
    utils::GcmEncryptedData packet;
    std::copy(iv2.begin(), iv2.begin()+packet.iv.size(), packet.iv.begin());
    packet.ciphertext = std::vector<uint8_t>(ct2.begin(), ct2.end());
    std::copy(tag2.begin(), tag2.begin()+packet.tag.size(), packet.tag.begin());
    auto plain = utils::decrypt_gcm_to_string(packet, key2_arr, aad_bytes);
    hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
    hmac_cpp::secure_zero(key2_arr.data(), key2_arr.size());
    hmac_cpp::secure_buffer<uint8_t, true> plain_buf(std::move(plain));
    hmac_cpp::secure_buffer<uint8_t, true> payload_buf{std::string(payload)};
    assert(hmac_cpp::constant_time_equal(plain_buf.data(), plain_buf.size(),
                                        payload_buf.data(), payload_buf.size()));
}

struct VaultFile {
    uint32_t v = 1;
    uint32_t iters;
    hmac_cpp::secure_buffer<uint8_t, true> salt;
    hmac_cpp::secure_buffer<uint8_t, true> iv;
    hmac_cpp::secure_buffer<uint8_t, true> tag;
    hmac_cpp::secure_buffer<uint8_t, true> ct;
    std::string aad;
};

static std::string serialize_vault(const VaultFile& vf) {
    json j;
    j["v"] = vf.v;
    j["aead"] = "AES-256-GCM";
    j["kdf"] = {{"prf","PBKDF2-HMAC-SHA256"},{"iters",vf.iters},{"salt",b64enc(vf.salt)}};
    j["enc"] = {{"iv",b64enc(vf.iv)},{"ct",b64enc(vf.ct)},{"tag",b64enc(vf.tag)}};
    if(!vf.aad.empty()) j["aad"]=vf.aad;
    return j.dump();
}
static VaultFile parse_vault(const std::string& s) {
    auto j = json::parse(s);
    VaultFile vf; vf.v=j.at("v").get<uint32_t>();
    if(vf.v!=1) throw std::runtime_error("bad version");
    if (j.at("aead").get<std::string>()!="AES-256-GCM") throw std::runtime_error("bad aead");
    auto jk=j.at("kdf"); vf.iters=jk.at("iters").get<uint32_t>();
    if(vf.iters<100000||vf.iters>1000000) throw std::runtime_error("bad iters");
    vf.salt=b64dec(jk.at("salt").get<std::string>());
    if(vf.salt.size()<16||vf.salt.size()>32) throw std::runtime_error("bad salt size");
    auto je=j.at("enc"); vf.iv=b64dec(je.at("iv").get<std::string>()); if(vf.iv.size()!=12) throw std::runtime_error("bad iv size");
    vf.ct=b64dec(je.at("ct").get<std::string>());
    vf.tag=b64dec(je.at("tag").get<std::string>()); if(vf.tag.size()!=16) throw std::runtime_error("bad tag size");
    vf.aad=j.value("aad","");
    return vf;
}
static VaultFile create_vault(const std::string& master,const std::string& email,const std::string& password,uint32_t iters,const std::string& aad){
    VaultFile vf; vf.v=1; vf.iters=iters; vf.salt=hmac_cpp::secure_buffer<uint8_t,true>(random_bytes(16)); auto key=derive_key(master,vf.salt,iters); std::array<uint8_t,32> key_arr{}; std::copy(key.begin(),key.begin()+key_arr.size(),key_arr.begin()); json payload={{"email",email},{"password",password}}; std::string payload_str=payload.dump(); hmac_cpp::secure_buffer<uint8_t,true> plain(std::move(payload_str)); std::vector<uint8_t> aadb(aad.begin(),aad.end()); std::vector<uint8_t> plain_vec(plain.begin(),plain.end()); auto enc=utils::encrypt_gcm(plain_vec,key_arr,aadb); hmac_cpp::secure_zero(key_arr.data(),key_arr.size()); hmac_cpp::secure_zero(plain_vec.data(),plain_vec.size()); vf.iv=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.iv.begin(),enc.iv.end())); vf.ct=hmac_cpp::secure_buffer<uint8_t,true>(std::move(enc.ciphertext)); vf.tag=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.tag.begin(),enc.tag.end())); vf.aad=aad; return vf; }
static json open_vault(const std::string& master,const VaultFile& vf){ auto key=derive_key(master,vf.salt,vf.iters); std::array<uint8_t,32> key_arr{}; std::copy(key.begin(),key.begin()+key_arr.size(),key_arr.begin()); std::array<uint8_t,12> iv{}; std::copy(vf.iv.begin(),vf.iv.begin()+iv.size(),iv.begin()); std::array<uint8_t,16> tag{}; std::copy(vf.tag.begin(),vf.tag.begin()+tag.size(),tag.begin()); std::vector<uint8_t> aadb(vf.aad.begin(),vf.aad.end()); std::vector<uint8_t> ct_vec(vf.ct.begin(),vf.ct.end()); utils::GcmEncryptedData pkt{std::chrono::system_clock::now(),iv,ct_vec,tag}; auto plain=utils::decrypt_gcm_to_string(pkt,key_arr,aadb); hmac_cpp::secure_zero(key_arr.data(),key_arr.size()); hmac_cpp::secure_zero(ct_vec.data(),ct_vec.size()); auto r=json::parse(plain); hmac_cpp::secure_zero(&plain[0],plain.size()); return r; }

static std::string b64url_encode(const hmac_cpp::secure_buffer<uint8_t, true>& d){ auto s=b64enc(d); std::replace(s.begin(),s.end(),'+','-'); std::replace(s.begin(),s.end(),'/','_'); while(!s.empty()&&s.back()=='=') s.pop_back(); return s; }
static hmac_cpp::secure_buffer<uint8_t, true> b64url_decode(const std::string& s){ std::string t=s; std::replace(t.begin(),t.end(),'-','+'); std::replace(t.begin(),t.end(),'_','/'); while(t.size()%4) t.push_back('='); return b64dec(t); }

static void test_json(){
    const std::string master="m", email="e", pass="p";
    auto vf=create_vault(master,email,pass,100000,"t");
    auto text=serialize_vault(vf);
    auto parsed=parse_vault(text);
    auto payload=open_vault(master,parsed);
    auto email_dec = payload.at("email").get<std::string>();
    auto pass_dec = payload.at("password").get<std::string>();
    hmac_cpp::secure_buffer<uint8_t, true> email_buf(std::move(email_dec));
    hmac_cpp::secure_buffer<uint8_t, true> email_exp{std::string(email)};
    assert(hmac_cpp::constant_time_equal(email_buf.data(), email_buf.size(),
                                        email_exp.data(), email_exp.size()));
    hmac_cpp::secure_buffer<uint8_t, true> pass_buf(std::move(pass_dec));
    hmac_cpp::secure_buffer<uint8_t, true> pass_exp{std::string(pass)};
    assert(hmac_cpp::constant_time_equal(pass_buf.data(), pass_buf.size(),
                                        pass_exp.data(), pass_exp.size()));
}

static void test_jwr(){
    const std::string master="m", email="e", pass="p";
    auto vf=create_vault(master,email,pass,100000,"t");
    std::string header=json({{"typ","JWR"}}).dump();
    std::string body=serialize_vault(vf);
    std::string token=b64url_encode(hmac_cpp::secure_buffer<uint8_t,true>(std::string(header)))+"."+b64url_encode(hmac_cpp::secure_buffer<uint8_t,true>(std::string(body)));
    auto pos=token.find('.'); assert(pos!=std::string::npos);
    auto body_bytes=b64url_decode(token.substr(pos+1));
    auto parsed=parse_vault(std::string(body_bytes.begin(),body_bytes.end()));
    auto payload=open_vault(master,parsed);
    auto email_dec = payload.at("email").get<std::string>();
    auto pass_dec = payload.at("password").get<std::string>();
    hmac_cpp::secure_buffer<uint8_t, true> email_buf(std::move(email_dec));
    hmac_cpp::secure_buffer<uint8_t, true> email_exp{std::string(email)};
    assert(hmac_cpp::constant_time_equal(email_buf.data(), email_buf.size(),
                                        email_exp.data(), email_exp.size()));
    hmac_cpp::secure_buffer<uint8_t, true> pass_buf(std::move(pass_dec));
    hmac_cpp::secure_buffer<uint8_t, true> pass_exp{std::string(pass)};
    assert(hmac_cpp::constant_time_equal(pass_buf.data(), pass_buf.size(),
                                        pass_exp.data(), pass_exp.size()));
}

int main(){
    test_simple();
    test_json();
    test_jwr();
    return 0;
}

