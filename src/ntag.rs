pub trait NTagBase {
    fn get_uid_raw(&mut self) -> Vec<u8>;
    fn get_uid_bin(&mut self) -> Vec<u8>;
    fn set_uid_bin(&mut self, uid: Vec<u8>);
    fn set_password(&mut self, value: Vec<u8>);
    fn set_password_ack(&mut self, value: Vec<u8>);
    const CT: u8;
    const PAGE_SIZE: u8;
    const SIZE: u32;
    const DYN_OFFSET: u32;
    const PAGES: u8;
    const CAPABILITY_CONTAINER: [u8; 12];
}
