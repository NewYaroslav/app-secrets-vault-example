// Force assertions on in Release builds so test invariants are checked.
#undef NDEBUG
#include <cassert>
#include <string>
#include <vector>
#include <array>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <chrono>
#include <fstream>
#include <cstdio>

#include <aes_cpp/aes_utils.hpp>
#include <hmac_cpp/hmac_utils.hpp>
#include <hmac_cpp/encoding.hpp>
#include <hmac_cpp/secret_string.hpp>
#include <hmac_cpp/secure_buffer.hpp>
#include <obfy/obfy_str.hpp>
#include <obfy/obfy_bytes.hpp>

#include "../examples/pepper/pepper_provider.hpp"
#include "../examples/pepper/machine_bound.hpp"

#include "json.hpp"
using json = nlohmann::json;

static const auto aad = OBFY_BYTES_ONCE("app://secrets/blob/v1");

static hmac_cpp::secure_buffer<uint8_t, true> demo_pepper() {
    return hmac_cpp::secure_buffer<uint8_t, true>(std::string(OBFY_STR("demo_pepper")));
}

static std::string b64enc(const hmac_cpp::secure_buffer<uint8_t, true>& v){
    return hmac_cpp::base64_encode(v.data(), v.size());
}
// Decode `s` from Base64 into `out`; return false on invalid input.
static bool b64dec(const std::string& s,
                   hmac_cpp::secure_buffer<uint8_t, true>& out){
    std::vector<uint8_t> tmp;
    if(!hmac_cpp::base64_decode(s,tmp)) return false;
    out = hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp));
    return true;
}

static hmac_cpp::secure_buffer<uint8_t, true> derive_key(const hmac_cpp::secret_string& password,
                                                         const hmac_cpp::secure_buffer<uint8_t, true>& salt,
                                                         uint32_t iters) {
    std::string pw_copy = password.reveal_copy();
    hmac_cpp::secure_buffer<uint8_t, true> pw(std::move(pw_copy));
    auto pep = demo_pepper();
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
    auto salt_vec = hmac_cpp::random_bytes(16);
    if (salt_vec.size() != 16) {
        hmac_cpp::secure_zero(salt_vec.data(), salt_vec.size());
        throw std::runtime_error("rng");
    }
    hmac_cpp::secure_buffer<uint8_t, true> salt(std::move(salt_vec));
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
    hmac_cpp::secure_buffer<uint8_t, true> salt2; assert(b64dec(parts[1], salt2)); hmac_cpp::secure_zero(&parts[1][0], parts[1].size());
    hmac_cpp::secure_buffer<uint8_t, true> iv2;   assert(b64dec(parts[2], iv2));   hmac_cpp::secure_zero(&parts[2][0], parts[2].size());
    hmac_cpp::secure_buffer<uint8_t, true> tag2;  assert(b64dec(parts[3], tag2));  hmac_cpp::secure_zero(&parts[3][0], parts[3].size());
    hmac_cpp::secure_buffer<uint8_t, true> ct2;   assert(b64dec(parts[4], ct2));   hmac_cpp::secure_zero(&parts[4][0], parts[4].size());
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
// Parse the serialized vault and ensure all checks pass.
// Only a bool is returned so tests mirror production behavior.
static bool parse_vault(const std::string& s, VaultFile& vf) {
    try {
        auto j = json::parse(s);
        vf.v=j.at("v").get<uint32_t>();
        if(vf.v!=1) return false; // only version 1 supported
        auto jk=j.at("kdf");
        if(jk.at("alg").get<std::string>()!="pbkdf2-hmac-sha256") return false; // unsupported KDF
        vf.iters=jk.at("iters").get<uint32_t>();
        if(vf.iters<100000||vf.iters>1000000) return false; // enforce PBKDF2 iteration range
        std::string salt_b64 = jk.at("salt").get<std::string>();
        if(!b64dec(salt_b64, vf.salt)) return false;
        hmac_cpp::secure_zero(&salt_b64[0], salt_b64.size());
        if(vf.salt.size()<16) return false; // min salt length
        auto ja=j.at("aead");
        if(ja.at("alg").get<std::string>()!="aes-256-gcm") return false; // unsupported AEAD
        std::string iv_b64 = ja.at("iv").get<std::string>();
        if(!b64dec(iv_b64, vf.iv)) return false;
        hmac_cpp::secure_zero(&iv_b64[0], iv_b64.size());
        if(vf.iv.size()!=12) return false; // GCM standard IV size
        std::string ct_b64 = ja.at("ct").get<std::string>();
        if(!b64dec(ct_b64, vf.ct)) return false;
        hmac_cpp::secure_zero(&ct_b64[0], ct_b64.size());
        std::string tag_b64 = ja.at("tag").get<std::string>();
        if(!b64dec(tag_b64, vf.tag)) return false;
        hmac_cpp::secure_zero(&tag_b64[0], tag_b64.size());
        if(vf.tag.size()!=16) return false; // GCM tag size
        std::string aad_b64 = ja.value("aad","");
        if(!b64dec(aad_b64, vf.aad)) return false;
        hmac_cpp::secure_zero(&aad_b64[0], aad_b64.size());
        return true;
    } catch (...) {
        // Errors are collapsed into a simple false to keep callers agnostic.
        return false;
    }
}
static VaultFile create_vault(const hmac_cpp::secret_string& master,const std::string& email,const hmac_cpp::secret_string& password,uint32_t iters){
    VaultFile vf; vf.v=1; vf.iters=iters; auto salt_vec=hmac_cpp::random_bytes(16); if(salt_vec.size()!=16){ hmac_cpp::secure_zero(salt_vec.data(),salt_vec.size()); throw std::runtime_error("rng"); } vf.salt=hmac_cpp::secure_buffer<uint8_t,true>(std::move(salt_vec)); auto key=derive_key(master,vf.salt,iters); std::array<uint8_t,32> key_arr{}; std::copy(key.begin(),key.begin()+key_arr.size(),key_arr.begin()); std::string pass_copy=password.reveal_copy(); json payload={{"email",email},{"password",pass_copy}}; hmac_cpp::secure_zero(&pass_copy[0],pass_copy.size()); std::string payload_str=payload.dump(); hmac_cpp::secure_buffer<uint8_t,true> plain(std::move(payload_str)); std::vector<uint8_t> aadb(aad.data(),aad.data()+aad.size()); std::vector<uint8_t> plain_vec(plain.begin(),plain.end()); auto enc=aes_cpp::utils::encrypt_gcm(plain_vec,key_arr,aadb); hmac_cpp::secure_zero(key_arr.data(),key_arr.size()); hmac_cpp::secure_zero(plain_vec.data(),plain_vec.size()); hmac_cpp::secure_zero(aadb.data(),aadb.size()); vf.iv=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.iv.begin(),enc.iv.end())); vf.ct=hmac_cpp::secure_buffer<uint8_t,true>(std::move(enc.ciphertext)); vf.tag=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.tag.begin(),enc.tag.end())); vf.aad=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(aad.data(),aad.data()+aad.size())); return vf; }
static json open_vault(const hmac_cpp::secret_string& master,const VaultFile& vf){ auto key=derive_key(master,vf.salt,vf.iters); std::array<uint8_t,32> key_arr{}; std::copy(key.begin(),key.begin()+key_arr.size(),key_arr.begin()); std::array<uint8_t,12> iv{}; std::copy(vf.iv.begin(),vf.iv.begin()+iv.size(),iv.begin()); std::array<uint8_t,16> tag{}; std::copy(vf.tag.begin(),vf.tag.begin()+tag.size(),tag.begin()); std::vector<uint8_t> aadb(vf.aad.begin(),vf.aad.end()); std::vector<uint8_t> ct_vec(vf.ct.begin(),vf.ct.end()); aes_cpp::utils::GcmEncryptedData pkt{std::chrono::system_clock::now(),iv,ct_vec,tag}; auto plain_vec=aes_cpp::utils::decrypt_gcm(pkt,key_arr,aadb); hmac_cpp::secure_zero(key_arr.data(),key_arr.size()); hmac_cpp::secure_zero(ct_vec.data(),ct_vec.size()); hmac_cpp::secure_zero(aadb.data(),aadb.size()); auto r=json::parse(plain_vec.begin(),plain_vec.end()); hmac_cpp::secure_zero(plain_vec.data(),plain_vec.size()); return r; }

static std::string b64url_encode(const hmac_cpp::secure_buffer<uint8_t, true>& d){ auto s=b64enc(d); std::replace(s.begin(),s.end(),'+','-'); std::replace(s.begin(),s.end(),'/','_'); while(!s.empty()&&s.back()=='=') s.pop_back(); return s; }
static hmac_cpp::secure_buffer<uint8_t, true> b64url_decode(std::string s){
    std::string t=s; hmac_cpp::secure_zero(&s[0],s.size());
    std::replace(t.begin(),t.end(),'-','+');
    std::replace(t.begin(),t.end(),'_','/');
    while(t.size()%4) t.push_back('=');
    hmac_cpp::secure_buffer<uint8_t, true> r; if(!b64dec(t,r)) throw std::runtime_error("b64");
    hmac_cpp::secure_zero(&t[0],t.size()); return r;
}

static std::vector<std::string> split(const std::string& s, char delim){
    std::vector<std::string> parts; std::stringstream ss(s); std::string item;
    while(std::getline(ss,item,delim)) parts.push_back(item); return parts;
}

static std::vector<uint8_t> salt16(){
    std::vector<uint8_t> s(16); for(size_t i=0;i<s.size();++i) s[i]=static_cast<uint8_t>(i+1); return s;
}

static std::array<uint8_t,32> derive_key_prov(const hmac_cpp::secret_string& password,
                                              const hmac_cpp::secure_buffer<uint8_t, true>& salt,
                                              uint32_t iters,
                                              pepper::Provider& prov){
    std::vector<uint8_t> pep_tmp; if(!prov.ensure(pep_tmp)) throw std::runtime_error("pepper");
    hmac_cpp::secure_buffer<uint8_t, true> pep(std::move(pep_tmp));
    std::string pw_copy=password.reveal_copy();
    hmac_cpp::secure_buffer<uint8_t, true> pw(std::move(pw_copy));
    auto vec=hmac_cpp::pbkdf2_with_pepper(pw.data(),pw.size(),salt.data(),salt.size(),pep.data(),pep.size(),iters,32);
    hmac_cpp::secure_zero(pw.data(),pw.size()); hmac_cpp::secure_zero(pep.data(),pep.size());
    std::array<uint8_t,32> key{}; std::copy(vec.begin(),vec.end(),key.begin());
    hmac_cpp::secure_zero(vec.data(),vec.size());
    return key;
}

static bool write_vault(const std::string& path,
                        const std::string& email,
                        const hmac_cpp::secret_string& passphrase,
                        pepper::Provider& prov){
    try{
        const uint32_t iters=300000;
        std::vector<uint8_t> aad_bytes(aad.data(),aad.data()+aad.size());
        std::string pass_copy=passphrase.reveal_copy();
        std::string payload=email+":"+pass_copy;
        hmac_cpp::secure_zero(&pass_copy[0],pass_copy.size());
        std::vector<uint8_t> payload_vec(payload.begin(),payload.end());
        hmac_cpp::secure_zero(&payload[0],payload.size());
        auto salt_vec=hmac_cpp::random_bytes(16); if(salt_vec.size()!=16){hmac_cpp::secure_zero(salt_vec.data(),salt_vec.size()); return false;}
        hmac_cpp::secure_buffer<uint8_t,true> salt(std::move(salt_vec));
        auto key=derive_key_prov(passphrase,salt,iters,prov);
        auto enc=aes_cpp::utils::encrypt_gcm(payload_vec,key,aad_bytes);
        hmac_cpp::secure_zero(payload_vec.data(),payload_vec.size());
        hmac_cpp::secure_zero(key.data(),key.size());
        hmac_cpp::secure_zero(aad_bytes.data(),aad_bytes.size());
        auto iv=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.iv.begin(),enc.iv.end()));
        auto tag=hmac_cpp::secure_buffer<uint8_t,true>(std::vector<uint8_t>(enc.tag.begin(),enc.tag.end()));
        auto ct=hmac_cpp::secure_buffer<uint8_t,true>(std::move(enc.ciphertext));
        std::string serialized=std::to_string(iters)+":"+b64enc(salt)+":"+b64enc(iv)+":"+b64enc(tag)+":"+b64enc(ct);
        std::ofstream(path) << serialized;
        hmac_cpp::secure_zero(&serialized[0],serialized.size());
        return true;
    }catch(...){return false;}
}

static bool read_vault(const std::string& path,
                       std::string& out_email,
                       hmac_cpp::secret_string& out_password,
                       const hmac_cpp::secret_string& passphrase,
                       pepper::Provider& prov){
    try{
        std::string in; std::ifstream(path) >> in;
        auto parts=split(in,':'); hmac_cpp::secure_zero(&in[0],in.size());
        if(parts.size()!=5) return false;
        uint32_t iters=static_cast<uint32_t>(std::stoul(parts[0]));
        hmac_cpp::secure_buffer<uint8_t, true> salt; if(!b64dec(parts[1],salt)) return false; hmac_cpp::secure_zero(&parts[1][0],parts[1].size());
        hmac_cpp::secure_buffer<uint8_t, true> iv;   if(!b64dec(parts[2],iv))   return false; hmac_cpp::secure_zero(&parts[2][0],parts[2].size());
        hmac_cpp::secure_buffer<uint8_t, true> tag;  if(!b64dec(parts[3],tag))  return false; hmac_cpp::secure_zero(&parts[3][0],parts[3].size());
        hmac_cpp::secure_buffer<uint8_t, true> ct;   if(!b64dec(parts[4],ct))   return false; hmac_cpp::secure_zero(&parts[4][0],parts[4].size());
        auto key=derive_key_prov(passphrase,salt,iters,prov);
        std::vector<uint8_t> aad_bytes(aad.data(),aad.data()+aad.size());
        aes_cpp::utils::GcmEncryptedData packet; std::copy(iv.begin(),iv.begin()+packet.iv.size(),packet.iv.begin());
        packet.ciphertext=std::vector<uint8_t>(ct.begin(),ct.end());
        std::copy(tag.begin(),tag.begin()+packet.tag.size(),packet.tag.begin());
        auto plain_vec=aes_cpp::utils::decrypt_gcm(packet,key,aad_bytes);
        hmac_cpp::secure_zero(key.data(),key.size());
        hmac_cpp::secure_zero(aad_bytes.data(),aad_bytes.size());
        hmac_cpp::secure_zero(packet.ciphertext.data(),packet.ciphertext.size());
        std::string plain_str(plain_vec.begin(),plain_vec.end());
        hmac_cpp::secure_zero(plain_vec.data(),plain_vec.size());
        auto fields=split(plain_str,':');
        hmac_cpp::secure_zero(&plain_str[0],plain_str.size());
        if(fields.size()!=2) return false;
        out_email=fields[0];
        std::string pwd=fields[1];
        out_password=hmac_cpp::secret_string(pwd);
        hmac_cpp::secure_zero(&pwd[0],pwd.size());
        return true;
    }catch(...){return false;}
}

static void test_json(){
    const hmac_cpp::secret_string master("m"); const std::string email="e"; const hmac_cpp::secret_string pass("p");
    auto vf=create_vault(master,email,pass,100000);
    auto text=serialize_vault(vf);
    VaultFile parsed; assert(parse_vault(text, parsed));
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
    VaultFile parsed; assert(parse_vault(body_str, parsed));
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

// Verify write/read behavior and error cases.
static void test_round_trip(){
    pepper::Config cfg; cfg.primary=pepper::StorageMode::OS_KEYCHAIN;
    cfg.fallbacks={pepper::StorageMode::MACHINE_BOUND,pepper::StorageMode::ENCRYPTED_FILE};
    cfg.app_salt=salt16(); cfg.file_path="pepper_vault.bin";
    pepper::Provider prov(cfg);
    std::string path="vault_round.bin"; std::string email="e"; hmac_cpp::secret_string pass("p");
    assert(write_vault(path,email,pass,prov));
    std::string out_email; hmac_cpp::secret_string out_pass; assert(read_vault(path,out_email,out_pass,pass,prov));
    hmac_cpp::secure_buffer<uint8_t,true> out_email_buf{std::string(out_email)};
    hmac_cpp::secure_zero(&out_email[0],out_email.size());
    hmac_cpp::secure_buffer<uint8_t,true> email_exp{std::string(email)};
    assert(hmac_cpp::constant_time_equal(out_email_buf.data(),out_email_buf.size(),email_exp.data(),email_exp.size()));
    auto out_pass_copy=out_pass.reveal_copy(); hmac_cpp::secure_buffer<uint8_t,true> out_pass_buf(std::move(out_pass_copy));
    hmac_cpp::secure_zero(&out_pass_copy[0],out_pass_copy.size());
    auto pass_copy=pass.reveal_copy(); hmac_cpp::secure_buffer<uint8_t,true> pass_buf(std::move(pass_copy));
    hmac_cpp::secure_zero(&pass_copy[0],pass_copy.size());
    assert(hmac_cpp::constant_time_equal(out_pass_buf.data(),out_pass_buf.size(),pass_buf.data(),pass_buf.size()));
    hmac_cpp::secure_zero(out_email_buf.data(),out_email_buf.size());
    hmac_cpp::secure_zero(email_exp.data(),email_exp.size());
    hmac_cpp::secure_zero(out_pass_buf.data(),out_pass_buf.size());
    hmac_cpp::secure_zero(pass_buf.data(),pass_buf.size());
    std::remove(path.c_str()); std::remove(cfg.file_path.c_str());
}

static void test_tag_tamper(){
    pepper::Config cfg; cfg.primary=pepper::StorageMode::OS_KEYCHAIN;
    cfg.fallbacks={pepper::StorageMode::MACHINE_BOUND,pepper::StorageMode::ENCRYPTED_FILE};
    cfg.app_salt=salt16(); cfg.file_path="pepper_tamper.bin";
    pepper::Provider prov(cfg);
    std::string path="vault_tamper.bin"; std::string email="e"; hmac_cpp::secret_string pass("p");
    assert(write_vault(path,email,pass,prov));
    std::string content; {std::ifstream in(path); in>>content;}
    auto parts=split(content,':'); hmac_cpp::secure_zero(&content[0],content.size()); assert(parts.size()==5);
    hmac_cpp::secure_buffer<uint8_t,true> tag; assert(b64dec(parts[3],tag)); tag[0]^=1; parts[3]=b64enc(tag);
    std::string tam=parts[0]+":"+parts[1]+":"+parts[2]+":"+parts[3]+":"+parts[4];
    std::ofstream(path) << tam; hmac_cpp::secure_zero(&tam[0],tam.size());
    for(auto& p:parts) if(!p.empty()) hmac_cpp::secure_zero(&p[0],p.size());
    std::string out_email; hmac_cpp::secret_string out_pass; bool ok=read_vault(path,out_email,out_pass,pass,prov);
    assert(!ok); if(!out_email.empty()) hmac_cpp::secure_zero(&out_email[0],out_email.size());
    auto tmp = out_pass.reveal_copy(); if(!tmp.empty()) hmac_cpp::secure_zero(&tmp[0], tmp.size());
    std::remove(path.c_str()); std::remove(cfg.file_path.c_str());
}

static void test_bad_passphrase(){
    pepper::Config cfg; cfg.primary=pepper::StorageMode::OS_KEYCHAIN;
    cfg.fallbacks={pepper::StorageMode::MACHINE_BOUND,pepper::StorageMode::ENCRYPTED_FILE};
    cfg.app_salt=salt16(); cfg.file_path="pepper_bad.bin";
    pepper::Provider prov(cfg);
    std::string path="vault_bad.bin"; std::string email="e"; hmac_cpp::secret_string pass("p");
    assert(write_vault(path,email,pass,prov));
    hmac_cpp::secret_string wrong("x"); std::string out_email; hmac_cpp::secret_string out_pass; bool ok=read_vault(path,out_email,out_pass,wrong,prov);
    assert(!ok); if(!out_email.empty()) hmac_cpp::secure_zero(&out_email[0],out_email.size());
    auto tmp = out_pass.reveal_copy(); if(!tmp.empty()) hmac_cpp::secure_zero(&tmp[0], tmp.size());
    std::remove(path.c_str()); std::remove(cfg.file_path.c_str());
}

static void test_pepper_fallback(){
    pepper::Config c1; c1.primary=pepper::StorageMode::MACHINE_BOUND; c1.fallbacks={pepper::StorageMode::ENCRYPTED_FILE}; c1.app_salt=salt16(); c1.file_path="pepper_fb.bin";
    pepper::Provider p1(c1); std::vector<uint8_t> a; assert(p1.ensure(a));
    pepper::Config c2=c1; c2.primary=pepper::StorageMode::ENCRYPTED_FILE; c2.fallbacks={};
    pepper::Provider p2(c2); std::vector<uint8_t> b; assert(p2.ensure(b));
    hmac_cpp::secure_buffer<uint8_t,true> sa(std::move(a)); hmac_cpp::secure_buffer<uint8_t,true> sb(std::move(b));
    auto ms = pepper::machine_bound::get_machine_secret(c1);
    if (!ms.empty()) {
        assert(!hmac_cpp::constant_time_equal(sa.data(),sa.size(),sb.data(),sb.size()));
    } else {
        assert(hmac_cpp::constant_time_equal(sa.data(),sa.size(),sb.data(),sb.size()));
    }
    hmac_cpp::secure_zero(ms.data(), ms.size());
    hmac_cpp::secure_zero(sa.data(),sa.size()); hmac_cpp::secure_zero(sb.data(),sb.size());
    std::remove(c1.file_path.c_str());
}

int main(){
    test_simple();
    test_json();
    test_jwr();
    test_round_trip();
    test_tag_tamper();
    test_bad_passphrase();
    test_pepper_fallback();
    return 0;
}

