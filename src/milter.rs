#[allow(dead_code)]
pub mod constants {
    pub const SMFIF_VERSION: u32 = 6;

    // actions
    pub const SMFIF_ADDHDRS: u32 = 0x00000001;
    pub const SMFIF_CHGBODY: u32 = 0x00000002;
    pub const SMFIF_ADDRCPT: u32 = 0x00000004;
    pub const SMFIF_DELRCPT: u32 = 0x00000008;
    pub const SMFIF_CHGHDRS: u32 = 0x00000010;
    pub const SMFIF_QUARANTINE: u32 = 0x00000020;
    pub const SMFIF_CHGFROM: u32 = 0x00000040;
    pub const SMFIF_ADDRCPT_PAR: u32 = 0x00000080;
    pub const SMFIF_SETSYMLIST: u32 = 0x00000100;

    // protocol flags

    pub const SMFIP_NOCONNECT: u32 = 0x00000001;
    pub const SMFIP_NOHELO: u32 = 0x00000002;
    pub const SMFIP_NOMAIL: u32 = 0x00000004;
    pub const SMFIP_NORCPT: u32 = 0x00000008;
    pub const SMFIP_NOBODY: u32 = 0x00000010;
    pub const SMFIP_NOHDRS: u32 = 0x00000020;
    pub const SMFIP_NOEOH: u32 = 0x00000040;

    pub const SMFIP_NR_HDR: u32 = 0x00000080;
    pub const SMFIP_NOUNKNOWN: u32 = 0x00000100;
    pub const SMFIP_NODATA: u32 = 0x00000200;
    pub const SMFIP_SKIP: u32 = 0x00000400;
    pub const SMFIP_RCPT_REJ: u32 = 0x00000800;
    pub const SMFIP_NR_CONN: u32 = 0x00001000;
    pub const SMFIP_NR_HELO: u32 = 0x00002000;
    pub const SMFIP_NR_MAIL: u32 = 0x00004000;
    pub const SMFIP_NR_RCPT: u32 = 0x00008000;
    pub const SMFIP_NR_DATA: u32 = 0x00010000;
    pub const SMFIP_NR_UNKN: u32 = 0x00020000;
    pub const SMFIP_NR_EOH: u32 = 0x00040000;
    pub const SMFIP_NR_BODY: u32 = 0x00080000;
    pub const SMFIP_HDR_LEADSPC: u32 = 0x00100000;
    pub const SMFIP_MDS_256K: u32 = 0x10000000;
    pub const SMFIP_MDS_1M: u32 = 0x20000000;
}
