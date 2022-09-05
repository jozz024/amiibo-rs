use crate::{
    keys::AmiiboMasterKey,
    utils
};
use hmac::{Hmac, Mac};
use sha2::{Sha256};
use aes_ctr::Aes128Ctr;
use aes_ctr::cipher::{
    NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek,
    generic_array::{
        GenericArray,
    }
};

use ctr::Ctr128;
use aes_soft::Aes128;


#[derive(Clone, Debug)]
pub struct AmiiboDump{
    pub data_master_key: AmiiboMasterKey,
    pub tag_master_key: AmiiboMasterKey,
    pub hmac_tag_key: Option<Vec<u8>>,
    pub hmac_data_key: Option<Vec<u8>>,
    pub size: usize,
    pub data: Vec<u8>
}

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

impl AmiiboDump {
    pub fn derive_key(self, key: AmiiboMasterKey, derive_aes: bool) -> utils::TypeOr {
        // start off with the type string (14 bytes, zero terminated)
        let mut seed = key.type_string;

        // the only two values I've found for magic_size is 14 and 16
        // but this code generic
        let append = 16 - key.magic_size;

        // extract two bytes from the user data section and pad
        let mut extract: Vec<u8> = self.data[0x011..0x013].to_vec();
        extract.append(&mut [b'\x00'; 14].to_vec());
        seed.append(&mut extract[..append.into()].to_vec());

        // add the magic bytes
        seed.append(&mut key.magic_bytes[..key.magic_size.into()].to_vec());

        // extract the first 6 bytes of the tag's uuid
        let uid = &self.data[0x000..0x008];
        seed.append(&mut uid.to_vec());
        seed.append(&mut uid.to_vec());

        // extract some tag data (pages 0x20 - 0x28)
        let user = &self.data[0x060..0x080];
        // and xor it with the key padding
        let user_key_zip = user.iter().zip(key.xor_pad);
        let mut xor = Vec::new();
        for (a, b) in user_key_zip{
            xor.append(&mut [a ^ b].to_vec());
        };

        seed.append(&mut xor);

        assert!(seed.len() == 78);

        let mut mac = HmacSha256::new_from_slice(&key.hmac_key).unwrap();
        mac.update(b"\x00\x01"); // counter (1)
        mac.update(&seed);

        let derived_bytes = mac.finalize().into_bytes();
        let hmac_key: &[u8] = &derived_bytes[..16];
        if !derive_aes {
            utils::TypeOr{
                hmac_key: hmac_key.to_vec(),
                aes_key: None,
                aes_iv: None
            }
        }
        else {
            let mut mac = HmacSha256::new_from_slice(&key.hmac_key).unwrap();
            mac.update(b"\x00\x01"); // counter (1)
            mac.update(&seed);

            let derived_bytes = mac.finalize().into_bytes();
            let aes_key = derived_bytes[..16].to_vec();
            let aes_iv = derived_bytes[16..].to_vec();

            utils::TypeOr{
                hmac_key: hmac_key.to_vec(), aes_key: Some(aes_key), aes_iv: Some(aes_iv)
            }

        }
    }

    fn derive_keys_and_cipher(mut self) -> Ctr128<Aes128> {
        // derive the tag HMAC key
        self.hmac_tag_key = Some(self.clone().derive_key(self.clone().tag_master_key, false).hmac_key);

        // derive the data HMAC key, aes key, and aes initialization vector
        let results = self.clone().derive_key(self.data_master_key, true);
        self.hmac_data_key = Some(results.hmac_key);
        let aes_key: [u8;16] = results.aes_key.unwrap().try_into().unwrap();
        let aes_iv = results.aes_iv.unwrap();

        let generic_aes_key = GenericArray::from_slice(&aes_key);
        let generic_aes_iv = GenericArray::from_slice(&aes_iv[..]);
        Aes128Ctr::new(generic_aes_key, generic_aes_iv)
    }

    pub fn new(master_keys: (AmiiboMasterKey, AmiiboMasterKey), dump: Vec<u8>) -> Self {
        let (data_master_key, tag_master_key) = master_keys;
        let size = dump.len();

        if size < 520 {
            panic!("Amiibo Dump too small!");
        }

        // let (hmac_tag_key, hmac_data_key, aes_key, aes_iv) = self.derive_keys();

        Self {
            data_master_key,
            tag_master_key,
            hmac_data_key: None,
            hmac_tag_key: None,
            size,
            data: dump
        }
    }

    pub fn unlock(mut self) -> Vec<u8> {
        let mut cipher = self.clone().derive_keys_and_cipher();
        cipher.seek(0);
        cipher.apply_keystream(&mut self.data);
        return self.data;
    }
}