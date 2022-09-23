use crate::ntag::NTagBase;
use crate::{
    keys::AmiiboMasterKey,
    utils,
    ntag
};
use hmac::{Hmac, Mac};
use sha2::{Sha256};
use aes_ctr::Aes128Ctr;
use aes_ctr::cipher::{
    NewStreamCipher, StreamCipher, SyncStreamCipherSeek,
    generic_array::{
        GenericArray,
    }
};
use ctr::Ctr128;
use aes_soft::Aes128;


#[derive(Clone, Debug)]
pub struct AmiiboDump {
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
    pub fn derive_key(&self, key: &mut AmiiboMasterKey, derive_aes: bool) -> utils::TypeOr {
        // start off with the type string (14 bytes, zero terminated)
        let seed = &mut key.type_string;

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
        let user_key_zip = user.iter().zip(&key.xor_pad);
        let mut xor = Vec::new();
        for (a, b) in user_key_zip{
            xor.append(&mut [a ^ b].to_vec());
        };

        seed.append(&mut xor);

        assert!(seed.len() == 78);

        let mut mac = HmacSha256::new_from_slice(&key.hmac_key).unwrap();
        mac.update(b"\x00\x01"); // counter (1)
        mac.update(seed);

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
            mac.update(b"\x00\x00"); // counter (0)
            mac.update(seed);

            let derived_bytes = mac.finalize().into_bytes();
            let aes_key = derived_bytes[..16].to_vec();
            let aes_iv = derived_bytes[16..].to_vec();

            utils::TypeOr{
                hmac_key: hmac_key.to_vec(),
                aes_key: Some(aes_key),
                aes_iv: Some(aes_iv)
            }

        }
    }

    fn derive_keys_and_cipher(&mut self) -> Ctr128<Aes128> {
        // derive the tag HMAC key
        self.hmac_tag_key = Some(self.clone().derive_key(&mut self.tag_master_key, false).hmac_key);
        // derive the data HMAC key, aes key, and aes initialization vector
        let results = self.clone().derive_key(&mut self.data_master_key, true);
        self.hmac_data_key = Some(results.hmac_key);
        let aes_key: [u8;16] = results.aes_key.unwrap().try_into().unwrap();
        let aes_iv = results.aes_iv.unwrap();

        let generic_aes_key = GenericArray::from_slice(&aes_key);
        let generic_aes_iv = GenericArray::from_slice(&aes_iv[..]);
        Aes128Ctr::new(generic_aes_key, generic_aes_iv)
    }

    fn get_crypt_block(&self) -> Vec<u8> {
        let mut data = self.data[0x014..0x034].to_vec();
        data.append(&mut self.data[0x0A0..0x208].to_vec());
        data
    }

    fn set_crypt_block(&mut self, data: Vec<u8>) {
        self.data[0x014..0x034].copy_from_slice(&data[..0x020]);
        self.data[0x0A0..0x208].copy_from_slice(&data[0x020..]);
    }

    fn derive_hmacs(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.hmac_tag_key = Some(self.clone().derive_key(&mut self.tag_master_key, false).hmac_key);
        self.hmac_data_key = Some(self.clone().derive_key(&mut self.data_master_key, false).hmac_key);
        let mut tag_hmac = HmacSha256::new_from_slice(self.hmac_tag_key.as_ref().unwrap()).unwrap();
        tag_hmac.update(&self.data[0x000..0x008]);
        tag_hmac.update(&self.data[0x054..0x080]);
        let tag_hmac = tag_hmac.finalize().into_bytes().to_vec();

        let mut data_hmac = HmacSha256::new_from_slice(self.hmac_data_key.as_ref().unwrap()).unwrap();
        data_hmac.update(&self.data[0x011..0x034]);
        data_hmac.update(&self.data[0x0A0..0x208]);
        data_hmac.update(&tag_hmac);
        data_hmac.update(&self.data[0x000..0x008]);
        data_hmac.update(&self.data[0x054..0x080]);
        let data_hmac = data_hmac.finalize().into_bytes().to_vec();

        (tag_hmac, data_hmac)
    }

    fn set_tag_hmac(&mut self, data: Vec<u8>) {
        self.data[0x034..0x054].clone_from_slice(&data);
    }

    fn set_data_hmac(&mut self, data: Vec<u8>) {
        self.data[0x080..0x0A0].clone_from_slice(&data);
    }

    fn set_lock_password(&mut self) {
        let uid = self.get_uid_bin();
        assert!(uid[0] == 0x04);
        self.set_password([
            0xAA ^ uid[1] ^ uid[3],
            0x55 ^ uid[2] ^ uid[4],
            0xAA ^ uid[3] ^ uid[5],
            0x55 ^ uid[4] ^ uid[6],
        ].to_vec());
        self.set_password_ack(b"\x80\x80".to_vec());
    }
    pub fn new(master_keys: (AmiiboMasterKey, AmiiboMasterKey), dump: Vec<u8>) -> Self {
        let (data_master_key, tag_master_key) = master_keys;
        let size = dump.len();

        if size < 520 {
            panic!("Amiibo Dump too small!");
        }

        Self {
            data_master_key,
            tag_master_key,
            hmac_data_key: None,
            hmac_tag_key: None,
            size,
            data: dump
        }
    }

    pub fn unlock(&mut self) {
        let mut cipher = self.clone().derive_keys_and_cipher();
        cipher.seek(0);
        let mut crypt_block = self.get_crypt_block();
        cipher.decrypt(&mut crypt_block);

        self.set_crypt_block(crypt_block)
    }

    pub fn lock(&mut self) {
        let mut cipher = self.clone().derive_keys_and_cipher();
        cipher.seek(0);
        let (tag_hmac, data_hmac) = self.derive_hmacs();
        self.set_tag_hmac(tag_hmac);
        self.set_data_hmac(data_hmac);
        let mut crypt_block = self.get_crypt_block();
        cipher.encrypt(&mut crypt_block);

        self.set_crypt_block(crypt_block);

        self.set_lock_password();
    }
}

impl ntag::NTagBase for AmiiboDump {
    //: The total number of pages in this tag type. (8.5 Memory organization)
    const PAGES: u8 = 135;

    const CT: u8 = 0x88;

    const PAGE_SIZE: u8 = 4;
    //: The total size in bytes of this tag type. (8.5 Memory organization)
    const SIZE: u32 =  AmiiboDump::PAGES as u32 * AmiiboDump::PAGE_SIZE as u32;
    //: The dynamic lock bytes offset in bytes for this tag type.
    //: (8.5 Memory organization)
    const DYN_OFFSET: u32 = (AmiiboDump::PAGES - 5) as u32 * AmiiboDump::PAGE_SIZE as u32;

    //: The initial value of the capability container.
    //: (8.5.6 Memory content at delivery)
    const CAPABILITY_CONTAINER: [u8; 12]  = *b"\xE1\x10\x3E\x00\x03\x00\xFE\x00\x00\x00\x00\x00";

    fn get_uid_raw(&mut self) -> Vec<u8> {
        let mut uid = self.data[0..3].to_vec();
        uid.append(&mut self.data[4..8].to_vec());

        uid
    }

    fn get_uid_bin(&mut self) -> Vec<u8> {
        let uid = self.get_uid_raw();
        assert!(uid.len() == 7);

        let bcc0 = self.data[3];
        let bcc1 = self.data[8];

        let mut check =  AmiiboDump::CT ^ uid[0] ^ uid[1] ^ uid[2];
        if check != bcc0 {
            panic!("BCC0 check failed!");
        }

        check = uid[3] ^ uid[4] ^ uid[5] ^ uid[6];
        if check != bcc1 {
            panic!("BCC1 check failed!");
        }
        uid
    }

    fn set_uid_bin(&mut self, uid: Vec<u8>) {
        // BCC 0
        self.data[3] = AmiiboDump::CT ^ uid[0] ^ uid[1] ^ uid[2];
        // BCC 1
        self.data[8] = uid[3] ^ uid[4] ^ uid[5] ^ uid[6];

        self.data[0..3].clone_from_slice(&uid[0..3]);
        self.data[4..8].clone_from_slice(&uid[3..7]);
    }

    fn set_password(&mut self, value: Vec<u8>) {
        assert!(value.len() == 4);
        self.data[(AmiiboDump::DYN_OFFSET + 12) as usize..(AmiiboDump::DYN_OFFSET + 16) as usize].clone_from_slice(&value);
    }

    fn set_password_ack(&mut self, value: Vec<u8>) {
        assert!(value.len() == 2);
        self.data[(AmiiboDump::DYN_OFFSET + 16) as usize..(AmiiboDump::DYN_OFFSET + 18) as usize].clone_from_slice(&value);
    }
}