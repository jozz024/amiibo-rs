use sha2::{Sha256, Digest};
use binrw::BinRead;
use hex::decode;
use std::io::Cursor;

#[derive(BinRead, Debug, Clone)]
pub struct AmiiboMasterKey {
    #[br(count(16))]
    pub hmac_key: Vec<u8>, // 16 bytes
    #[br(count(14))]
    pub type_string: Vec<u8>, // 14 bytes
    pub rfu: u8, // 1 byte reserved for future use, padding
    pub magic_size: u8, // 1 byte
    #[br(count(16))]
    pub magic_bytes: Vec<u8>, // 16 bytes
    #[br(count(32))]
    pub xor_pad: Vec<u8>
}
const DATA_BIN_SHA256_HEXDIGEST: &str  = "868106135941cbcab3552bd14880a7a34304ef340958a6998b61a38ba3ce13d3";
const TAG_BIN_SHA256_HEXDIGEST: &str = "b48727797cd2548200b99c665b20a78190470163ccb8e5682149f1b2f7a006cf";


impl AmiiboMasterKey {
    fn __init__(data: Vec<u8>, sha256_digest: &str) -> AmiiboMasterKey {
        let count = data.len();

        if count != 80 {
            panic!("Data should be 80 bytes, was {count} bytes");
        }

        let mut hasher = Sha256::new();

        hasher.update(&data);

        let result = hasher.finalize();

        if result[..].to_vec() != decode(sha256_digest).unwrap() {
            panic!("Data check has failed, may be corrupt");
        }
        let mut cursor = Cursor::new(&data);
        AmiiboMasterKey::read(&mut cursor).unwrap()

    }

    pub fn from_separate_bin(data_bin: Vec<u8>, tag_bin: Vec<u8>) -> (AmiiboMasterKey, AmiiboMasterKey) {
        let data = Self::__init__(data_bin, DATA_BIN_SHA256_HEXDIGEST);
        let tag = Self::__init__(tag_bin, TAG_BIN_SHA256_HEXDIGEST);

        (data, tag)
    }

    pub fn from_separate_hex(data_hex: &str, tag_hex: &str) -> (AmiiboMasterKey, AmiiboMasterKey) {
        Self::from_separate_bin(
            decode(data_hex).unwrap(),
            decode(tag_hex).unwrap()
        )
    }

    pub fn from_combined_bin(combined_bin: Vec<u8>) -> (AmiiboMasterKey, AmiiboMasterKey) {
        let count = combined_bin.len();
        if count != 160 {
            panic!("Data should be 160 bytes, was {count}.")
        }

        Self::from_separate_bin(combined_bin[0..80].to_vec(), combined_bin[80..160].to_vec())

    }
}