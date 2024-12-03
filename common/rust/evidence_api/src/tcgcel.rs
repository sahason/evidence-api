extern crate lazy_static;

use crate::tcg::*;
use crate::binary_blob::*;
use log::error;
use std::collections::HashMap;
use std::any::Any;

pub struct TcgTpmsCelEvent {
    rec_num: i32,
    digests: Vec<TcgDigest>,
    content_type: Option<i32>,
    imr: Option<i32>,
    nv_index: Option<i32>,
    content: Option<TcgTpmuEventContent>,
    encoding: Option<String>,
}

impl TcgTpmsCelEvent {
    fn new(
        rec_num: i32,
        digests: Vec<TcgDigest>,
        content_type: Option<i32>,
        imr: Option<i32>,
        nv_index: Option<i32>,
        content: Option<TcgTpmuEventContent>,
    ) -> Self {
        if imr.is_some() && nv_index.is_some() {
            error!("Instantiate TPMS_CEL_EVENT with both IMR index and NV index. Failed to instantiate...");
            return Self {
                rec_num,
                digests,
                content_type,
                imr: None,
                nv_index: None,
                content: None,
                encoding: None,
            };
        }

        let content_type = content_type.unwrap_or_default();
        if !TcgTpmiCelContentType::is_valid_content(content_type) {
            error!("Invalid content specified. Failed to instantiate...");
            return Self {
                rec_num,
                digests,
                content_type: None,
                imr: None,
                nv_index: None,
                content: None,
                encoding: None,
            };
        }

        Self {
            rec_num,
            digests,
            content_type: Some(content_type),
            imr,
            nv_index,
            content,
            encoding: None,
        }
    }

    fn rec_num(&self) -> i32 {
        self.rec_num
    }

    fn set_rec_num(&mut self, rec_num: i32) {
        self.rec_num = rec_num;
    }

    fn index(&self) -> Option<i32> {
        self.imr.or(self.nv_index)
    }

    fn set_imr(&mut self, imr: i32) {
        self.imr = Some(imr);
    }

    fn set_nv_index(&mut self, nv_index: i32) {
        self.nv_index = Some(nv_index);
    }

    fn digests(&self) -> &Vec<TcgDigest> {
        &self.digests
    }

    fn set_digests(&mut self, digests: Vec<TcgDigest>) {
        self.digests = digests;
    }

    fn content(&self) -> Option<&TcgTpmuEventContent> {
        self.content.as_ref()
    }

    fn set_content(&mut self, content: TcgTpmuEventContent) {
        self.content = Some(content);
    }

    fn content_type(&self) -> Option<i32> {
        self.content_type
    }

    fn encoding(&self) -> Option<&str> {
        self.encoding.as_ref().map(|x| x.as_str())
    }

    fn to_pcclient_format(&self) -> Option<TcgImrEvent> {
        match self.content_type {
            Some(TcgCelTypes::CEL_IMA_TEMPLATE) => {
                // if let Some(event) = eve
                if let Some(template_content) = self.content.as_ref().unwrap().event_content.downcast_ref::<TcgTpmsEventImaTemplate>() {
                    let event = &template_content.template_data().clone();
                    Some(TcgImrEvent {
                        imr_index: self.imr.unwrap() as u32,
                        event_type: IMA_MEASUREMENT_EVENT,
                        digests: self.digests.clone(),
                        event_size: event.len() as u32,
                        event: <String as Clone>::clone(&event).into_bytes(),
                    })
                }
                else {
                    None
                }
            }
            Some(TcgCelTypes::CEL_PCCLIENT_STD) => {
                if let Some(content) = self.content.as_ref().unwrap().event_content.downcast_ref::<TcgTpmsEventPcClientStd>() {
                    
                    Some(TcgImrEvent {
                        imr_index: self.imr.unwrap() as u32,
                        event_type: content.event_type() as u32,
                        digests: self.digests.clone(),
                        event_size: content.event_data().len() as u32,
                        event: content.event_data().to_vec(),
                    })
            }
            else {
                None
            }
         }
            _ => {
                error!("Unsupported content to parse into TCG PCClient format.");
                None
            }
        }
    }


    fn encode(&self, mut obj: TcgTpmsCelEvent, encoding: i32) -> TcgTpmsCelEvent {
        match encoding {
            2 => {
                obj.encoding = Some("TLV".to_string());
                self.encoded_in_tlv(obj)
            }
            3 => {
                obj.encoding = Some("JSON".to_string());
                self.encoded_in_json(obj)
            }
            4 => {
                obj.encoding = Some("CBOR".to_string());
                self.encoded_in_cbor(obj)
            }
            _ => {
                eprintln!("Invalid encoding specified. Returning the default encoding TLV");
                obj.encoding = Some("TLV".to_string());
                self.encoded_in_tlv(obj)
            }
        }
    }

    fn dump(&self) {
        let encoding = self.encoding();
        match encoding.as_deref() {
            Some("TLV") => {
                let rec_num = self.rec_num();
                let imr_index = self.index().unwrap_or_default();
                println!("-----------------------------Canonical Event Log Entry----------------------------");
                println!("Encoding          : {}", encoding.unwrap());
                println!("Rec Num           : {}", rec_num);
                println!("IMR               : {}", imr_index);
                println!(
                    "Type              : 0x{:X} ({})",
                    self.content_type.unwrap_or_default(),
                    TcgTpmiCelContentType::get_content_type_string(self.content_type.unwrap_or_default())
                );
                println!("Digests:");
                for (count, digest) in self.digests.iter().enumerate() {
                    println!(
                        "Algorithm_id[{}]   : {} ({})",
                        count,
                        digest.algo_id,
                        digest.get_algorithm_id_str(),
                    );
                    println!("Digest[{}]:", count);
                    // let digest_blob = binary_blob::new(digest.hash.clone());
                    // digest_blob.dump();
                    dump_data(&digest.hash.clone());
                }
                println!("Contents:");
                // TODO
                // for (count, cnt) in self.content.as_ref().unwrap().event_content.iter().enumerate() {
                //     println!(
                //         "{}: {} = {}",
                //         count,
                //         cnt.attr_table[cnt.get_type()],
                //         cnt.value
                //     );
                // }
            }
            _ => {
                error!("Unsupported data format for dumping.");
            }
        }
    }

    fn encoded_in_tlv(&self, mut obj: TcgTpmsCelEvent) -> TcgTpmsCelEvent {
        // CEL Record encoded in TLV
        let mut rec_num = TcgCelRecnum::new();
        rec_num.set_type(TcgCelTypes::CEL_SEQNUM);
        rec_num.set_value(obj.rec_num);
        obj.set_rec_num(obj.rec_num);

        let mut digests = TcgCelDigests::new();
        digests.set_type(Some(TcgCelTypes::CEL_DIGESTS));
        let mut d_list = Vec::new();
        for digest in obj.digests.iter() {
            let d = TcgDigest {
                algo_id: digest.algo_id,
                hash: digest.hash.clone(),
            };
            // let mut d = TcgDigest::new();
            // d.set_type(digest.algo_id);
            // d.set_value(digest.hash.clone());
            d_list.push(d);
        }
        // digests.set_value(d_list);
        obj.set_digests(d_list);

        // let mut content = TcgTpmuEventContent::new();
        // content.set_type(obj.content_type.unwrap());
        // content.set_value(obj.content.to_tlv());
        // obj.set_content(content);

        let mut index = TcgCelImrNvindex::new();
        if let Some(imr) = obj.imr {
            index.set_type(TcgCelTypes::CEL_PCR);
            index.set_value(imr);
            obj.set_imr(imr);
        } else {
            index.set_type(TcgCelTypes::CEL_NV_INDEX);
            index.set_value(obj.nv_index.unwrap());
            obj.set_nv_index(obj.nv_index.unwrap());
        }

        obj
    }

    pub fn encoded_in_cbor(&self, obj: TcgTpmsCelEvent) -> TcgTpmsCelEvent {
        // CEL record encoded in CBOR
        // Err("NotImplementedError");
        obj
    }

    pub fn encoded_in_json(&self, obj: TcgTpmsCelEvent) -> TcgTpmsCelEvent {
        // CEL record encoded in JSON
        // Err("NotImplementedError");
        obj
    }
}


struct TcgEventType;

pub struct TcgCelTypes;

impl TcgCelTypes {
    // TCG CEL top level event types
    pub const CEL_SEQNUM: i32 = 0x00000000;
    pub const CEL_PCR: i32 = 0x00000001;
    pub const CEL_NV_INDEX: i32 = 0x00000002;
    pub const CEL_DIGESTS: i32 = 0x00000003;
    pub const CEL_MGT: i32 = 0x00000004;
    pub const CEL_PCCLIENT_STD: i32 = 0x00000005;
    pub const CEL_IMA_TEMPLATE: i32 = 0x00000007;
    pub const CEL_IMA_TLV: i32 = 0x00000008;

    // CEL_MGT types
    pub const CEL_MGT_TYPE: i32 = 0;
    pub const CEL_MGT_DATA: i32 = 1;
    pub const CEL_MGT_CEL_VERSION: i32 = 1;
    pub const CEL_MGT_CEL_VERSION_MAJOR: i32 = 0;
    pub const CEL_MGT_CEL_VERSION_MINOR: i32 = 1;
    pub const CEL_MGT_FIRMWARE_END: i32 = 2;
    pub const CEL_MGT_CEL_TIMESTAMP: i32 = 80;
    pub const CEL_MGT_STATE_TRANS: i32 = 81;
    pub const CEL_MGT_STATE_TRANS_SUSPEND: i32 = 0;
    pub const CEL_MGT_STATE_TRANS_HIBERNATE: i32 = 1;
    pub const CEL_MGT_STATE_TRANS_KEXEC: i32 = 2;

    // IMA-TLV specific content types
    pub const IMA_TLV_PATH: i32 = 0;
    pub const IMA_TLV_DATAHASH: i32 = 1;
    pub const IMA_TLV_DATASIG: i32 = 2;
    pub const IMA_TLV_OWNER: i32 = 3;
    pub const IMA_TLV_GROUP: i32 = 4;
    pub const IMA_TLV_MODE: i32 = 5;
    pub const IMA_TLV_TIMESTAMP: i32 = 6;
    pub const IMA_TLV_LABEL: i32 = 7;

    // IMA_TEMPLATE specific content types
    pub const IMA_TEMPLATE_NAME: i32 = 0;
    pub const IMA_TEMPLATE_DATA: i32 = 1;

    // PCCLIENT_STD content types
    pub const PCCLIENT_STD_TYPE: i32 = 0;
    pub const PCCLIENT_STD_CONTENT: i32 = 1;
}

pub struct TcgTpmiCelContentType {
    content_type: i32,
}

impl TcgTpmiCelContentType {
    const CEL: i32 = 0x4;
    const PCCLIENT_STD: i32 = 0x5;
    const IMA_TEMPLATE: i32 = 0x7;
    const IMA_TLV: i32 = 0x8;

    fn cel_content_table() -> HashMap<i32, &'static str> {
        let mut m = HashMap::new();
        m.insert(Self::CEL, "CEL");
        m.insert(Self::PCCLIENT_STD, "PCCLIENT_STD");
        m.insert(Self::IMA_TEMPLATE, "IMA_TEMPLATE");
        m.insert(Self::IMA_TLV, "IMA_TLV");
        m
    }

    pub fn new(content_type: i32) -> Result<Self, &'static str> {
        if !Self::is_valid_content(content_type) {
            return Err("Invalid CEL content type declared.");
        }
        Ok(Self { content_type })
    }

    pub fn is_valid_content(content_type: i32) -> bool {
        Self::cel_content_table().contains_key(&content_type)
    }

    pub fn get_content_type_string(content_type: i32) -> &'static str {
        match Self::cel_content_table().get(&content_type) {
            Some(&s) => s,
            None => "UNKNOWN",
        }
    }
}

pub struct TcgTpmuEventContent {
    event_content: Box<dyn Any>,
}

impl TcgTpmuEventContent {
    pub fn new(event_content: Box<dyn Any>) -> Result<Self, &'static str> {
        if !event_content.is::<TcgTpmsEventPcClientStd>()
            && !event_content.is::<TcgTpmsEventCelMgt>()
            && !event_content.is::<TcgTpmsEventImaTemplate>()
            && !event_content.is::<TcgImaTlv>()
        {
            return Err("Invalid event content used.");
        }
        Ok(Self { event_content })
    }

    pub fn content_type(&self) -> &str {
        if self.event_content.is::<TcgTpmsEventPcClientStd>() {
            "TcgTpmsEventPcClientStd"
        } else if self.event_content.is::<TcgTpmsEventCelMgt>() {
            "TcgTpmsEventCelMgt"
        } else if self.event_content.is::<TcgTpmsEventImaTemplate>() {
            "TcgTpmsEventImaTemplate"
        } else if self.event_content.is::<TcgImaTlv>() {
            "TcgImaTlv"
        } else {
            "Unknown"
        }
    }

    pub fn event(&self) -> &Box<dyn Any> {
        &self.event_content
    }
}

pub trait TcgTlv {
    fn set_type(&mut self, tlv_type: i32);
    fn set_value(&mut self, value: i32);
    fn set_attr_table(&mut self, value: HashMap<i32, String>);
    fn get_type(&self) -> i32;
    fn get_value(&self) -> i32;
    fn get_attr_table(&self) -> &HashMap<i32, String>;
}

pub struct TcgTlvBase {
    tlv_type: i32,
    value: i32,
    attr_table: HashMap<i32, String>,
}

impl TcgTlvBase {
    pub fn new(tlv_type: i32, value: i32) -> Self {
        Self {
            tlv_type,
            value,
            attr_table: HashMap::new(),
        }
    }
}

impl TcgTlv for TcgTlvBase {
    fn set_type(&mut self, tlv_type: i32) {
        self.tlv_type = tlv_type;
    }

    fn set_value(&mut self, value: i32) {
        self.value = value;
    }

    fn set_attr_table(&mut self, value: HashMap<i32, String>) {
        self.attr_table = value;
    }

    fn get_type(&self) -> i32 {
        self.tlv_type
    }

    fn get_value(&self) -> i32 {
        self.value
    }

    fn get_attr_table(&self) -> &HashMap<i32, String> {
        &self.attr_table
    }
}

pub struct TcgCelRecnum {
    base: TcgTlvBase,
}

impl TcgCelRecnum {
    pub fn new() -> Self {
        let mut base = TcgTlvBase::new(0, 0);
        base.set_type(0);
        base.set_value(0x00000000);
        Self { base }
    }
}

impl TcgTlv for TcgCelRecnum {
    fn set_type(&mut self, tlv_type: i32) {
        if tlv_type != 0 {
            eprintln!("Type for record number shall be 0");
        }
        self.base.set_type(0);
    }

    fn set_value(&mut self, value: i32) {
        self.base.set_value(value);
    }

    fn set_attr_table(&mut self, _value: HashMap<i32, String>) {
        unimplemented!();
    }

    fn get_type(&self) -> i32 {
        self.base.get_type()
    }

    fn get_value(&self) -> i32 {
        self.base.get_value()
    }

    fn get_attr_table(&self) -> &HashMap<i32, String> {
        self.base.get_attr_table()
    }
}

pub struct TcgCelImrNvindex {
    base: TcgTlvBase,
}

impl TcgCelImrNvindex {
    pub fn new() -> Self {
        Self {
            base: TcgTlvBase::new(0, 0),
        }
    }
}

impl TcgTlv for TcgCelImrNvindex {
    fn set_type(&mut self, tlv_type: i32) {
        if tlv_type != TcgCelTypes::CEL_PCR && tlv_type != TcgCelTypes::CEL_NV_INDEX {
            eprintln!("Invalid type declared for TcgCelImrNvindex.");
            return;
        }
        self.base.set_type(tlv_type);
    }

    fn set_value(&mut self, value: i32) {
        self.base.set_value(value);
    }

    fn set_attr_table(&mut self, _value: HashMap<i32, String>) {
        unimplemented!();
    }

    fn get_type(&self) -> i32 {
        self.base.get_type()
    }

    fn get_value(&self) -> i32 {
        self.base.get_value()
    }

    fn get_attr_table(&self) -> &HashMap<i32, String> {
        self.base.get_attr_table()
    }
}

pub struct TcgCelDigests {
    tlv_type: Option<i32>,
    value: Option<String>,
}

impl TcgCelDigests {
    pub fn new() -> Self {
        TcgCelDigests {
            tlv_type: None,
            value: None,
        }
    }

    pub fn set_type(&mut self, tlv_type: Option<i32>) {
        if let Some(t) = tlv_type {
            if t != TcgCelTypes::CEL_DIGESTS {
                error!("Invalid type declared for TcgCelDigests.");
                return;
            }
            self.tlv_type = Some(t);
        }
    }

    pub fn set_value(&mut self, value: Option<String>) {
        self.value = value;
    }
    
    pub fn set_attr_table(&self, _value: Option<String>) {
        unimplemented!("Set the dict of attributes name of the class.");
    }
}

pub struct TcgCelContent {
    base: TcgTlvBase,
}

impl TcgCelContent {
    pub fn new() -> Self {
        Self {
            base: TcgTlvBase::new(0, 0),
        }
    }
}

impl TcgTlv for TcgCelContent {
    fn set_type(&mut self, tlv_type: i32) {
        if !TcgTpmiCelContentType::is_valid_content(tlv_type) {
            eprintln!("Invalid content type {} specified.", tlv_type);
            return;
        }
        self.base.set_type(tlv_type);
    }

    fn set_value(&mut self, value: i32) {
        self.base.set_value(value);
    }

    fn set_attr_table(&mut self, _value: HashMap<i32, String>) {
        unimplemented!();
    }

    fn get_type(&self) -> i32 {
        self.base.get_type()
    }

    fn get_value(&self) -> i32 {
        self.base.get_value()
    }

    fn get_attr_table(&self) -> &HashMap<i32, String> {
        self.base.get_attr_table()
    }
}

pub struct TcgTpmuCelMgt {
    cel_version: i32,
    firmware_end: Option<i32>,
    cel_timestamp: Option<i32>,
    state_trans: i32,
}

impl TcgTpmuCelMgt {
    const TPMS_CEL_VERSION: [i32; 2] = [
        TcgCelTypes::CEL_MGT_CEL_VERSION_MAJOR,
        TcgCelTypes::CEL_MGT_CEL_VERSION_MINOR,
    ];
    const TPMI_STATE_TRANS: [i32; 3] = [
        TcgCelTypes::CEL_MGT_STATE_TRANS_SUSPEND,
        TcgCelTypes::CEL_MGT_STATE_TRANS_HIBERNATE,
        TcgCelTypes::CEL_MGT_STATE_TRANS_KEXEC,
    ];

    pub fn new(
        cel_version: i32,
        cel_timestamp: Option<i32>,
        state_trans: i32,
        firmware_end: Option<i32>,
    ) -> Result<Self, &'static str> {
        if !Self::TPMS_CEL_VERSION.contains(&cel_version) {
            return Err("Invalid value specified for cel_version.");
        }
        if !Self::TPMI_STATE_TRANS.contains(&state_trans) {
            return Err("Invalid value specified for state_trans.");
        }
        Ok(Self {
            cel_version,
            firmware_end,
            cel_timestamp,
            state_trans,
        })
    }

    pub fn cel_version(&self) -> i32 {
        self.cel_version
    }

    pub fn cel_timestamp(&self) -> Option<i32> {
        self.cel_timestamp
    }

    pub fn firmware_end(&self) -> Option<i32> {
        self.firmware_end
    }

    pub fn state_trans(&self) -> i32 {
        self.state_trans
    }

    pub fn to_tlv(&self) {
        unimplemented!();
    }
}

pub struct TcgTpmsEventCelMgt {
    mgt_type: i32,
    mgt_data: TcgTpmuCelMgt,
}

impl TcgTpmsEventCelMgt {
    const TPMI_CELMGTTYPE_VALUE: [(i32, &str); 4] = [
        (TcgCelTypes::CEL_MGT_CEL_VERSION, "cel_version"),
        (TcgCelTypes::CEL_MGT_FIRMWARE_END, "firmware_end"),
        (TcgCelTypes::CEL_MGT_CEL_TIMESTAMP, "cel_timestamp"),
        (TcgCelTypes::CEL_MGT_STATE_TRANS, "State_trans"),
    ];

    pub fn new(mgt_type: i32, mgt_data: TcgTpmuCelMgt) -> Result<Self, &'static str> {
        if !Self::TPMI_CELMGTTYPE_VALUE.iter().any(|&(t, _)| t == mgt_type) {
            return Err("Invalid value for TPMI_CELMGTTYPE.");
        }
        Ok(Self { mgt_type, mgt_data })
    }

    pub fn get_type(&self) -> i32 {
        TcgTpmiCelContentType::CEL
    }

    pub fn to_tlv(&self) {
        eprintln!("Not implemented for TLV encoding.");
    }
}

pub struct TcgTpmsEventPcClientStd {
    event_type: i32,
    event_data: Vec<u8>,
    PCCLIENT_STD_TABLE: HashMap<i32, String>,
}

impl TcgTpmsEventPcClientStd {
    pub fn new(event_type: i32, event_data: Vec<u8>) -> Self {
            let mut PCCLIENT_STD_TABLE: HashMap<i32, String> = HashMap::new();
            PCCLIENT_STD_TABLE.insert(TcgCelTypes::PCCLIENT_STD_TYPE, "PCCLIENT_STD_TYPE".to_string());
            PCCLIENT_STD_TABLE.insert(TcgCelTypes::PCCLIENT_STD_CONTENT, "PCCLIENT_STD_CONTENT".to_string());
        Self {
            event_type,
            event_data,
            PCCLIENT_STD_TABLE,
        }
    }

    pub fn event_type(&self) -> i32 {
        self.event_type
    }

    pub fn event_data(&self) -> &Vec<u8> {
        &self.event_data
    }

    pub fn get_type(&self) -> i32 {
        TcgTpmiCelContentType::PCCLIENT_STD
    }

    pub fn to_tlv(&self) -> Vec<TcgTlvBase> {
        let mut content_list = Vec::new();
        let mut event_type = TcgTlvBase::new(TcgCelTypes::PCCLIENT_STD_TYPE, self.event_type);
        let mut event_data = TcgTlvBase::new(TcgCelTypes::PCCLIENT_STD_CONTENT, 0);
        event_data.set_value(self.event_data.clone().into_iter().map(|b| b as i32).sum());
        event_type.set_attr_table(self.PCCLIENT_STD_TABLE.clone());
        event_data.set_attr_table(self.PCCLIENT_STD_TABLE.clone());
        content_list.push(event_type);
        content_list.push(event_data);
        content_list
    }
}

pub struct TcgTpmsEventImaTemplate {
    template_data: String,
    template_name: String,
    IMA_TEMPLATE_TABLE: HashMap<i32, String>,
}

impl TcgTpmsEventImaTemplate {
    // const IMA_TEMPLATE_TABLE: [(i32, &str); 2] = [
    //     (TcgCelTypes::IMA_TEMPLATE_NAME, "IMA_TEMPLATE_NAME"),
    //     (TcgCelTypes::IMA_TEMPLATE_DATA, "IMA_TEMPLATE_DATA"),
    // ];

    pub fn new(template_data: String, template_name: String) -> Self {
            let mut IMA_TEMPLATE_TABLE: HashMap<i32, String> = HashMap::new();
            IMA_TEMPLATE_TABLE.insert(TcgCelTypes::IMA_TEMPLATE_NAME, "IMA_TEMPLATE_NAME".to_string());
            IMA_TEMPLATE_TABLE.insert(TcgCelTypes::IMA_TEMPLATE_DATA, "IMA_TEMPLATE_DATA".to_string());
        Self {
            template_data,
            template_name,
            IMA_TEMPLATE_TABLE,
        }
    }

    pub fn template_data(&self) -> &String {
        &self.template_data
    }

    pub fn template_name(&self) -> &String {
        &self.template_name
    }

    pub fn get_type(&self) -> i32 {
        TcgTpmiCelContentType::IMA_TEMPLATE
    }

    pub fn to_tlv(&self) -> Vec<TcgTlvBase> {
        let mut content_list = Vec::new();
        let mut template_name = TcgTlvBase::new(TcgCelTypes::IMA_TEMPLATE_NAME, 0);
        let mut template_data = TcgTlvBase::new(TcgCelTypes::IMA_TEMPLATE_DATA, 0);
        template_name.set_value(self.template_name.clone().into_bytes().into_iter().map(|b| b as i32).sum());
        template_data.set_value(self.template_data.clone().into_bytes().into_iter().map(|b| b as i32).sum());
        template_name.set_attr_table(self.IMA_TEMPLATE_TABLE.clone());
        template_data.set_attr_table(self.IMA_TEMPLATE_TABLE.clone());
        content_list.push(template_name);
        content_list.push(template_data);
        content_list
    }
}

pub struct TcgImaTlv;

impl TcgImaTlv {
    pub fn new() -> Self {
        Self
    }

    pub fn get_type(&self) -> i32 {
        TcgTpmiCelContentType::IMA_TLV
    }

    pub fn to_tlv(&self) {
        eprintln!("Not implemented for TLV encoding.");
    }
}

