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
#include <obfy/obfy_bytes.hpp>

#include "json.hpp"
using json = nlohmann::json;

static const auto aad = OBFY_BYTES_ONCE("app://secrets/blob/v1");

static hmac_cpp::secure_buffer<uint8_t, true> pepper() {
    return hmac_cpp::secure_buffer<uint8_t, true>(std::string(OBFY_STR("demo_pepper")));
}

static std::string b64enc(const hmac_cpp::secure_buffer<uint8_t, true>& v){
    return hmac_cpp::base64_encode(v.data(), v.size());
}
static hmac_cpp::secure_buffer<uint8_t, true> b64dec(std::string s){
    std::vector<uint8_t> tmp; if(!hmac_cpp::base64_decode(s,tmp)) throw std::runtime_error("b64"); hmac_cpp::secure_zero(&s[0], s.size()); return hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp)); }

static hmac_cpp::secure_buffer<uint8_t, true> derive_key(const hmac_cpp::secret_string& password,
                                                         const hmac_cpp::secure_buffer<uint8_t, true>& salt,
                                                         uint32_t iters) {
    std::string pw_copy = password.reveal_copy();
    hmac_cpp::secure_buffer<uint8_t, true> pw(std::move(pw_copy));
    auto pep = pepper();
    auto vec = hmac_cpp::pbkdf2_with_pepper(pw.data(), pw.size(),
                                            salt.data(), salt.size(),
                                            pep.data(), pep.size(),
                                            iters, 32);
    return hmac_cpp::secure_buffer<uint8_t, true>(std::move(vec));
}

static void test_simple() {
    const hmac_cpp::secret_string master("m");
    const hmac_cpp::secret_string payload("a:b");
    const uint32_t iters = 1000;

    hmac_cpp::secure_buffer<uint8_t, true> salt(hmac_cpp::random_bytes(16));
    auto key  = derive_key(master, salt, iters);
    std::array<uint8_t,32> key_arr{}; std::copy(key.begin(), key.begin()+key_arr.size(), key_arr.begin());
    std::vector<uint8_t> aad_bytes(aad.data(), aad.data() + aad.size());
    std::string payload_copy = payload.reveal_copy();
    std::vector<uint8_t> payload_vec(payload_copy.begin(), payload_copy.end());
    hmac_cpp::secure_zero(&payload_copy[0], payload_copy.size());
    auto enc = aes_cpp::utils::encrypt_gcm(payload_vec, key_arr, aad_bytes);
    hmac_cpp::secure_zero(payload_vec.data(), payload_vec.size());
    std::string serialized = std::to_string(iters) + ":" +
       b64enc(salt) + ":" +
       b64enc(hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.iv.begin(), enc.iv.end()))) + ":" +
       b64enc(hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.tag.begin(), enc.tag.end()))) + ":" +
       b64enc(hmac_cpp::secure_buffer<uint8_t,true>(std::move(enc.ciphertext)));
    std::vector<std::string> parts; std::stringstream ss(serialized); std::string item;
    while (std::getline(ss, item, ':')) parts.push_back(item);
    assert(parts.size()==5);
    uint32_t iters2 = static_cast<uint32_t>(std::stoul(parts[0]));
    auto salt2 = b64dec(parts[1]); hmac_cpp::secure_zero(&parts[1][0], parts[1].size());
    auto iv2 = b64dec(parts[2]);   hmac_cpp::secure_zero(&parts[2][0], parts[2].size());
    auto tag2 = b64dec(parts[3]);  hmac_cpp::secure_zero(&parts[3][0], parts[3].size());
    auto ct2 = b64dec(parts[4]);   hmac_cpp::secure_zero(&parts[4][0], parts[4].size());
    auto key2 = derive_key(master, salt2, iters2);
    std::array<uint8_t,32> key2_arr{}; std::copy(key2.begin(), key2.begin()+key2_arr.size(), key2_arr.begin());
    aes_cpp::utils::GcmEncryptedData packet;
    std::copy(iv2.begin(), iv2.begin()+packet.iv.size(), packet.iv.begin());
    packet.ciphertext = std::vector<uint8_t>(ct2.begin(), ct2.end());
    std::copy(tag2.begin(), tag2.begin()+packet.tag.size(), packet.tag.begin());
    auto plain_vec = aes_cpp::utils::decrypt_gcm(packet, key2_arr, aad_bytes);

    packet.tag[0] ^= 1;
    bool failed = false;
    try {
        auto fail_plain = aes_cpp::utils::decrypt_gcm(packet, key2_arr, aad_bytes);
        if (!fail_plain.empty()) {
            hmac_cpp::secure_zero(fail_plain.data(), fail_plain.size());
        }
    } catch (const std::exception&) {
        failed = true;
    }
    assert(failed);

    hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
    hmac_cpp::secure_zero(key2_arr.data(), key2_arr.size());
    hmac_cpp::secure_buffer<uint8_t, true> plain_buf(std::move(plain_vec));
    std::string payload_cmp = payload.reveal_copy();
    hmac_cpp::secure_buffer<uint8_t, true> payload_buf(std::move(payload_cmp));
    hmac_cpp::secure_zero(&payload_cmp[0], payload_cmp.size());
    assert(hmac_cpp::constant_time_equal(plain_buf.data(), plain_buf.size(),
                                        payload_buf.data(), payload_buf.size()));
    hmac_cpp::secure_zero(aad_bytes.data(), aad_bytes.size());
}

struct VaultFile {
    uint32_t v = 1;
    uint32_t iters;
    hmac_cpp::secure_buffer<uint8_t, true> salt;
    hmac_cpp::secure_buffer<uint8_t, true> iv;
    hmac_cpp::secure_buffer<uint8_t, true> tag;
    hmac_cpp::secure_buffer<uint8_t, true> ct;
    hmac_cpp::secure_buffer<uint8_t, true> aad;
};

static std::string serialize_vault(const VaultFile& vf) {
    json j;
    j["v"] = vf.v;
    j["kdf"] = {{"alg","pbkdf2-hmac-sha256"},{"iters",vf.iters},{"salt",b64enc(vf.salt)}};
    j["aead"] = {{"alg","aes-256-gcm"},{"iv",b64enc(vf.iv)},{"aad",b64enc(vf.aad)},{"ct",b64enc(vf.ct)},{"tag",b64enc(vf.tag)}};
    return j.dump();
}
static VaultFile parse_vault(const std::string& s) {
    auto j = json::parse(s);
    VaultFile vf; vf.v=j.at("v").get<uint32_t>();
    if(vf.v!=1) throw std::runtime_error("bad version");
    auto jk=j.at("kdf");
    if(jk.at("alg").get<std::string>()!="pbkdf2-hmac-sha256") throw std::runtime_error("bad kdf alg");
    vf.iters=jk.at("iters").get<uint32_t>();
    if(vf.iters<100000||vf.iters>1000000) throw std::runtime_error("bad iters");
    std::string salt_b64 = jk.at("salt").get<std::string>();
    vf.salt=b64dec(salt_b64); hmac_cpp::secure_zero(&salt_b64[0], salt_b64.size());
    if(vf.salt.size()<16||vf.salt.size()>32) throw std::runtime_error("bad salt size");
    auto ja=j.at("aead");
    if(ja.at("alg").get<std::string>()!="aes-256-gcm") throw std::runtime_error("bad aead alg");
    std::string iv_b64 = ja.at("iv").get<std::string>();
    vf.iv=b64dec(iv_b64); hmac_cpp::secure_zero(&iv_b64[0], iv_b64.size()); if(vf.iv.size()!=12) throw std::runtime_error("bad iv size");
    std::string ct_b64 = ja.at("ct").get<std::string>();
    vf.ct=b64dec(ct_b64); hmac_cpp::secure_zero(&ct_b64[0], ct_b64.size());
    std::string tag_b64 = ja.at("tag").get<std::string>();
    vf.tag=b64dec(tag_b64); hmac_cpp::secure_zero(&tag_b64[0], tag_b64.size()); if(vf.tag.size()!=16) throw std::runtime_error("bad tag size");
    std::string aad_b64 = ja.value("aad","");
    vf.aad=b64dec(aad_b64); hmac_cpp::secure_zero(&aad_b64[0], aad_b64.size());
    return vf;
}
static VaultFile create_vault(const hmac_cpp::secret_string& master,const std::string& email,const hmac_cpp::secret_string& password,uint32_t iters){
    VaultFile vf; vf.v=1; vf.iters=iters; auto salt_vec=hmac_cpp::random_bytes(16); if(salt_vec.size()!=16) throw std::runtime_error("rng"); vf.salt=hmac_cpp::secure_buffer<uint8_t,true>(std::move(salt_vec)); auto key=derive_key(master,vf.salt,iters); std::array<uint8_t,32> key_arr{}; std::copy(key.begin(),key.begin()+key_arr.size(),key_arr.begin()); std::string pass_copy=password.reveal_copy(); json payload={{"email",email},{"password",pass_copy}}; hmac_cpp::secure_zero(&pass_copy[0],pass_copy.size()); std::string payload_str=payload.dump(); hmac_cpp::secure_buffer<uint8_t,true> plain(std::move(payload_str)); std::vector<uint8_t> aadb(aad.data(),aad.data()+aad.size()); std::vector<uint8_t> plain_vec(plain.begin(),plain.end()); auto enc=aes_cpp::utils::encrypt_gcm(plain_vec,key_arr,aadb); hmac_cpp::secure_zero(key_arr.data(),key_arr.size()); hmac_cpp::secure_zero(plain_vec.data(),plain_vec.size()); hmac_cpp::secure_zero(aadb.data(),aadb.size()); vf.iv=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.iv.begin(),enc.iv.end())); vf.ct=hmac_cpp::secure_buffer<uint8_t,true>(std::move(enc.ciphertext)); vf.tag=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.tag.begin(),enc.tag.end())); vf.aad=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(aad.data(),aad.data()+aad.size())); return vf; }
static json open_vault(const hmac_cpp::secret_string& master,const VaultFile& vf){ auto key=derive_key(master,vf.salt,vf.iters); std::array<uint8_t,32> key_arr{}; std::copy(key.begin(),key.begin()+key_arr.size(),key_arr.begin()); std::array<uint8_t,12> iv{}; std::copy(vf.iv.begin(),vf.iv.begin()+iv.size(),iv.begin()); std::array<uint8_t,16> tag{}; std::copy(vf.tag.begin(),vf.tag.begin()+tag.size(),tag.begin()); std::vector<uint8_t> aadb(vf.aad.begin(),vf.aad.end()); std::vector<uint8_t> ct_vec(vf.ct.begin(),vf.ct.end()); aes_cpp::utils::GcmEncryptedData pkt{std::chrono::system_clock::now(),iv,ct_vec,tag}; auto plain_vec=aes_cpp::utils::decrypt_gcm(pkt,key_arr,aadb); hmac_cpp::secure_zero(key_arr.data(),key_arr.size()); hmac_cpp::secure_zero(ct_vec.data(),ct_vec.size()); hmac_cpp::secure_zero(aadb.data(),aadb.size()); auto r=json::parse(plain_vec.begin(),plain_vec.end()); hmac_cpp::secure_zero(plain_vec.data(),plain_vec.size()); return r; }

static std::string b64url_encode(const hmac_cpp::secure_buffer<uint8_t, true>& d){ auto s=b64enc(d); std::replace(s.begin(),s.end(),'+','-'); std::replace(s.begin(),s.end(),'/','_'); while(!s.empty()&&s.back()=='=') s.pop_back(); return s; }
static hmac_cpp::secure_buffer<uint8_t, true> b64url_decode(std::string s){ std::string t=s; hmac_cpp::secure_zero(&s[0],s.size()); std::replace(t.begin(),t.end(),'-','+'); std::replace(t.begin(),t.end(),'_','/'); while(t.size()%4) t.push_back('='); auto r=b64dec(t); hmac_cpp::secure_zero(&t[0],t.size()); return r; }

static void test_json(){
    const hmac_cpp::secret_string master("m"); const std::string email="e"; const hmac_cpp::secret_string pass("p");
    auto vf=create_vault(master,email,pass,100000);
    auto text=serialize_vault(vf);
    auto parsed=parse_vault(text);
    auto payload=open_vault(master,parsed);
    auto email_dec = payload.at("email").get<std::string>();
    auto pass_dec_tmp = payload.at("password").get<std::string>();
    hmac_cpp::secure_buffer<uint8_t, true> email_buf(std::move(email_dec));
    hmac_cpp::secure_buffer<uint8_t, true> email_exp{std::string(email)};
    assert(hmac_cpp::constant_time_equal(email_buf.data(), email_buf.size(),
                                        email_exp.data(), email_exp.size()));
    hmac_cpp::secure_buffer<uint8_t, true> pass_buf(std::move(pass_dec_tmp));
    hmac_cpp::secure_zero(&pass_dec_tmp[0], pass_dec_tmp.size());
    auto pass_exp_copy = pass.reveal_copy();
    hmac_cpp::secure_buffer<uint8_t, true> pass_exp(std::move(pass_exp_copy));
    hmac_cpp::secure_zero(&pass_exp_copy[0], pass_exp_copy.size());
    assert(hmac_cpp::constant_time_equal(pass_buf.data(), pass_buf.size(),
                                        pass_exp.data(), pass_exp.size()));
}

static void test_jwr(){
    const hmac_cpp::secret_string master("m"); const std::string email="e"; const hmac_cpp::secret_string pass("p");
    auto vf=create_vault(master,email,pass,100000);
    std::string header=json({{"typ","JWR"}}).dump();
    std::string body=serialize_vault(vf);
    std::string token=b64url_encode(hmac_cpp::secure_buffer<uint8_t,true>(std::string(header)))+"."+b64url_encode(hmac_cpp::secure_buffer<uint8_t,true>(std::string(body)));
    auto pos=token.find('.'); assert(pos!=std::string::npos);
    std::string body_b64 = token.substr(pos+1);
    auto body_bytes=b64url_decode(body_b64);
    hmac_cpp::secure_zero(&body_b64[0], body_b64.size());
    std::string body_str(body_bytes.begin(),body_bytes.end());
    auto parsed=parse_vault(body_str);
    hmac_cpp::secure_zero(&body_str[0], body_str.size());
    hmac_cpp::secure_zero(body_bytes.data(), body_bytes.size());
    auto payload=open_vault(master,parsed);
    auto email_dec = payload.at("email").get<std::string>();
    auto pass_dec_tmp = payload.at("password").get<std::string>();
    hmac_cpp::secure_buffer<uint8_t, true> email_buf(std::move(email_dec));
    hmac_cpp::secure_buffer<uint8_t, true> email_exp{std::string(email)};
    assert(hmac_cpp::constant_time_equal(email_buf.data(), email_buf.size(),
                                        email_exp.data(), email_exp.size()));
    hmac_cpp::secure_buffer<uint8_t, true> pass_buf(std::move(pass_dec_tmp));
    hmac_cpp::secure_zero(&pass_dec_tmp[0], pass_dec_tmp.size());
    auto pass_exp_copy = pass.reveal_copy();
    hmac_cpp::secure_buffer<uint8_t, true> pass_exp(std::move(pass_exp_copy));
    hmac_cpp::secure_zero(&pass_exp_copy[0], pass_exp_copy.size());
    assert(hmac_cpp::constant_time_equal(pass_buf.data(), pass_buf.size(),
                                        pass_exp.data(), pass_exp.size()));
}

int main(){
    test_simple();
    test_json();
    test_jwr();
    return 0;
}

